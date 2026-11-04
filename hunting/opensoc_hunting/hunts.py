"""opensoc-hunt: lists, validates and runs the hypotheses in hypotheses/*.md against the Wazuh Indexer.

Each hypothesis is a Markdown file with YAML front matter and the sections Hypothesis,
Question, Data required, Query and Interpretation. The Query section holds
a ```dql block (for Discover/Threat Hunting in the Wazuh dashboard) and a
```json block with the Query DSL body that this command sends to ``_search``.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .mitre import normalize_technique
from .opensearch import (
    IndexerClient,
    IndexerConfig,
    IndexerError,
    get_path,
    hit_sources,
    hits_total,
    silence_insecure_warning,
)
from .paths import HYPOTHESES_DIR

REQUIRED_SECTIONS = ("Hypothesis", "Question", "Data required", "Query", "Interpretation")
REQUIRED_META = ("id", "title", "techniques", "platforms", "data_sources", "index")
_FRONT_MATTER_RE = re.compile(r"\A---\s*\n(?P<meta>.*?)\n---\s*\n(?P<body>.*)\Z", re.S)
_CODE_BLOCK_RE = re.compile(r"```(?P<lang>[a-zA-Z0-9_-]*)\s*\n(?P<code>.*?)\n```", re.S)
_ID_RE = re.compile(r"^H\d{2}$")


class HypothesisError(ValueError):
    """Malformed hypothesis document."""


@dataclass
class Hypothesis:
    id: str
    title: str
    techniques: list[str]
    platforms: list[str]
    data_sources: list[str]
    index: str
    path: Path
    sections: dict[str, str]
    dql: str
    query: dict[str, Any]
    tactics: list[str] = field(default_factory=list)
    emulation: list[str] = field(default_factory=list)
    legacy_techniques: list[str] = field(default_factory=list)

    @property
    def all_techniques(self) -> list[str]:
        return self.techniques + self.legacy_techniques


def _split_sections(body: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    current = None
    lines: list[str] = []
    in_code = False
    for line in body.splitlines():
        if line.startswith("```"):
            in_code = not in_code
        if not in_code and line.startswith("## "):
            if current:
                sections[current] = "\n".join(lines).strip()
            current, lines = line[3:].strip(), []
        elif current:
            lines.append(line)
    if current:
        sections[current] = "\n".join(lines).strip()
    return sections


def parse_hypothesis(path: Path | str) -> Hypothesis:
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    match = _FRONT_MATTER_RE.match(text)
    if not match:
        raise HypothesisError(f"{path.name}: missing YAML front matter (--- ... ---)")
    meta = yaml.safe_load(match.group("meta")) or {}
    missing = [k for k in REQUIRED_META if not meta.get(k)]
    if missing:
        raise HypothesisError(f"{path.name}: missing front matter fields: {', '.join(missing)}")
    hid = str(meta["id"])
    if not _ID_RE.match(hid):
        raise HypothesisError(f"{path.name}: invalid id {hid!r} (format HNN)")
    try:
        techniques = [normalize_technique(str(t)) for t in meta["techniques"]]
        legacy = [normalize_technique(str(t)) for t in meta.get("legacy_techniques") or []]
    except ValueError as exc:
        raise HypothesisError(f"{path.name}: {exc}") from exc

    sections = _split_sections(match.group("body"))
    missing_sections = [s for s in REQUIRED_SECTIONS if not sections.get(s)]
    if missing_sections:
        raise HypothesisError(f"{path.name}: missing sections: {', '.join(missing_sections)}")

    blocks = {}
    for block in _CODE_BLOCK_RE.finditer(sections["Query"]):
        blocks.setdefault(block.group("lang").lower(), block.group("code").strip())
    if "dql" not in blocks:
        raise HypothesisError(f"{path.name}: the Query section needs a ```dql block")
    if "json" not in blocks:
        raise HypothesisError(f"{path.name}: the Query section needs a ```json block")
    try:
        query = json.loads(blocks["json"])
    except json.JSONDecodeError as exc:
        raise HypothesisError(f"{path.name}: the JSON block is not valid: {exc}") from exc
    if not isinstance(query, dict) or "query" not in query:
        raise HypothesisError(f"{path.name}: the JSON must be a _search body with a 'query' key")

    return Hypothesis(
        id=hid,
        title=str(meta["title"]),
        techniques=techniques,
        tactics=[str(t) for t in meta.get("tactics") or []],
        platforms=[str(p) for p in meta["platforms"]],
        data_sources=[str(d) for d in meta["data_sources"]],
        index=str(meta["index"]),
        emulation=[str(e) for e in meta.get("emulation") or []],
        legacy_techniques=legacy,
        path=path,
        sections=sections,
        dql=blocks["dql"],
        query=query,
    )


def load_hypotheses(directory: Path | str = HYPOTHESES_DIR) -> list[Hypothesis]:
    files = sorted(Path(directory).glob("H[0-9][0-9]-*.md"))
    hypotheses = [parse_hypothesis(f) for f in files]
    ids = [h.id for h in hypotheses]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise HypothesisError(f"duplicate hypothesis IDs: {', '.join(sorted(dupes))}")
    return hypotheses


def apply_time_range(body: Mapping[str, Any], field_name: str, gte: str | None, lte: str | None) -> dict[str, Any]:
    """Replaces the bounds of the ``range`` clauses on the time field; adds one if there is none."""
    result = copy.deepcopy(dict(body))
    if gte is None and lte is None:
        return result
    found = False

    def walk(node: Any) -> None:
        nonlocal found
        if isinstance(node, dict):
            rng = node.get("range")
            if isinstance(rng, dict) and isinstance(rng.get(field_name), dict):
                found = True
                bounds = rng[field_name]
                if gte is not None:
                    bounds.pop("gt", None)
                    bounds["gte"] = gte
                if lte is not None:
                    bounds.pop("lt", None)
                    bounds["lte"] = lte
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(result.get("query"))
    if not found:
        bounds = {k: v for k, v in (("gte", gte), ("lte", lte)) if v is not None}
        result["query"] = {"bool": {"filter": [result.get("query", {"match_all": {}}), {"range": {field_name: bounds}}]}}
    return result


def summarize(result: Mapping[str, Any], time_field: str = "timestamp", limit: int = 20) -> str:
    lines = [f"Hits: {hits_total(result)}"]
    for src in hit_sources(result)[:limit]:
        lines.append(
            f"  {get_path(src, time_field, '')}  {get_path(src, 'agent.name', '-')}  "
            f"[{get_path(src, 'rule.id', '-')}] {get_path(src, 'rule.description', '')}"
        )

    def render_aggs(aggs: Mapping[str, Any], depth: int) -> None:
        for name, agg in aggs.items():
            if not isinstance(agg, Mapping):
                continue
            if "buckets" in agg:
                lines.append("  " * depth + f"{name}:")
                buckets = agg["buckets"]
                if isinstance(buckets, Mapping):
                    items = buckets.items()
                else:
                    items = ((b.get("key_as_string", b.get("key")), b) for b in buckets)
                for key, bucket in list(items)[:limit]:
                    extras = {
                        k: (v.get("value") if "value" in v else {m: v[m] for m in ("avg", "std_deviation", "count") if m in v})
                        for k, v in bucket.items()
                        if isinstance(v, Mapping) and "buckets" not in v
                    }
                    extra_txt = " ".join(f"{k}={v}" for k, v in extras.items())
                    lines.append("  " * (depth + 1) + f"{key}: {bucket.get('doc_count')} {extra_txt}".rstrip())
                    nested = {k: v for k, v in bucket.items() if isinstance(v, Mapping) and "buckets" in v}
                    if nested:
                        render_aggs(nested, depth + 2)
            elif "value" in agg:
                lines.append("  " * depth + f"{name}: {agg['value']}")

    if result.get("aggregations"):
        lines.append("Aggregations:")
        render_aggs(result["aggregations"], 1)
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="opensoc-hunt", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dir", default=str(HYPOTHESES_DIR), help="Hypotheses directory")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="List the hypotheses")
    sub.add_parser("validate", help="Validate the structure and the JSON of every hypothesis")
    p_show = sub.add_parser("show", help="Show the query of a hypothesis")
    p_show.add_argument("id")
    p_run = sub.add_parser("run", help="Run the query against the Wazuh Indexer")
    p_run.add_argument("id")
    p_run.add_argument("--from", dest="gte", help="Start (date math or ISO), e.g. now-30d")
    p_run.add_argument("--to", dest="lte", help="End, e.g. now")
    p_run.add_argument("--index", help="Index (defaults to the hypothesis one)")
    p_run.add_argument("--json", action="store_true", help="Print the full response")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        hypotheses = load_hypotheses(args.dir)
        if args.command == "list":
            for h in hypotheses:
                print(f"{h.id}  {', '.join(h.techniques):<22} {h.title}")
            return 0
        if args.command == "validate":
            print(f"{len(hypotheses)} valid hypotheses in {args.dir}")
            return 0
        by_id = {h.id: h for h in hypotheses}
        wanted = args.id.upper()
        if wanted not in by_id:
            print(f"ERROR: hypothesis {args.id} does not exist", file=sys.stderr)
            return 2
        hypothesis = by_id[wanted]
        if args.command == "show":
            print(f"# {hypothesis.id} · {hypothesis.title}\n\nDQL:\n{hypothesis.dql}\n\nQuery DSL ({hypothesis.index}):")
            print(json.dumps(hypothesis.query, indent=2, ensure_ascii=False))
            return 0
        config = IndexerConfig.from_env()
        silence_insecure_warning(config.verify)
        body = apply_time_range(hypothesis.query, config.time_field, args.gte, args.lte)
        result = IndexerClient(config).search(body, index=args.index or hypothesis.index)
        print(json.dumps(result, indent=2, ensure_ascii=False) if args.json else summarize(result, config.time_field))
        return 0
    except (HypothesisError, IndexerError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
