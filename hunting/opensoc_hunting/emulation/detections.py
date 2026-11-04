"""Reading /detections to know which rules cover each technique.

It does not assume a specific format. It recognizes:

* Wazuh rules (XML): ``<rule id="100200" ...> ... <mitre><id>T1003.001</id></mitre>``
* Sigma rules (YAML): ``tags: [attack.t1003.001]``
* Any other .yml/.yaml/.json/.toml/.xml: technique IDs that appear in the text.

Markdown files are ignored so that a README with a list of techniques does not
count as coverage.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import yaml

from ..mitre import find_techniques, parent_technique
from .scenarios import Scenario

SCANNED_SUFFIXES = {".xml", ".yml", ".yaml", ".json", ".toml"}

_WAZUH_RULE_RE = re.compile(r"<rule\b(?P<attrs>[^>]*)>(?P<body>.*?)</rule>", re.S | re.I)
_ATTR_ID_RE = re.compile(r"""\bid\s*=\s*["'](?P<id>\d+)["']""")
_MITRE_ID_RE = re.compile(r"<id>\s*(?P<id>T\d{4}(?:\.\d{3})?)\s*</id>", re.I)
_DESCRIPTION_RE = re.compile(r"<description>(?P<d>.*?)</description>", re.S | re.I)
_XML_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)


@dataclass(frozen=True)
class DetectionRef:
    path: str
    kind: str  # wazuh-rule | sigma | text
    techniques: tuple[str, ...]
    rule_id: str | None = None
    title: str | None = None

    def label(self) -> str:
        bits = [self.path]
        if self.rule_id:
            bits.append(f"rule {self.rule_id}")
        if self.title:
            bits.append(self.title)
        return " · ".join(bits)


def _scan_wazuh_xml(text: str, rel: str) -> list[DetectionRef]:
    refs = []
    for match in _WAZUH_RULE_RE.finditer(_XML_COMMENT_RE.sub("", text)):
        id_match = _ATTR_ID_RE.search(match.group("attrs"))
        techniques = tuple(dict.fromkeys(m.group("id").upper() for m in _MITRE_ID_RE.finditer(match.group("body"))))
        if not id_match or not techniques:
            continue
        desc = _DESCRIPTION_RE.search(match.group("body"))
        refs.append(
            DetectionRef(
                path=rel,
                kind="wazuh-rule",
                techniques=techniques,
                rule_id=id_match.group("id"),
                title=" ".join(desc.group("d").split()) if desc else None,
            )
        )
    return refs


def _scan_yaml(text: str, rel: str) -> list[DetectionRef]:
    refs = []
    try:
        docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    except yaml.YAMLError:
        docs = []
    for doc in docs:
        if "detection" in doc and "logsource" in doc:  # Sigma
            tags = " ".join(str(t) for t in doc.get("tags") or [])
            techniques = tuple(find_techniques(tags))
            if techniques:
                refs.append(
                    DetectionRef(
                        path=rel,
                        kind="sigma",
                        techniques=techniques,
                        rule_id=str(doc["id"]) if doc.get("id") else None,
                        title=str(doc["title"]) if doc.get("title") else None,
                    )
                )
    if refs:
        return refs
    techniques = tuple(find_techniques(text))
    return [DetectionRef(path=rel, kind="text", techniques=techniques)] if techniques else []


def scan_detections(root: Path | str) -> list[DetectionRef]:
    """Returns the references found; empty list if the directory does not exist."""
    root = Path(root)
    if not root.is_dir():
        return []
    refs: list[DetectionRef] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SCANNED_SUFFIXES:
            continue
        if any(part.startswith(".") for part in path.relative_to(root).parts):
            continue
        rel = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        suffix = path.suffix.lower()
        if suffix == ".xml":
            found = _scan_wazuh_xml(text, rel)
            if not found:
                techniques = tuple(find_techniques(text))
                found = [DetectionRef(path=rel, kind="text", techniques=techniques)] if techniques else []
        elif suffix in {".yml", ".yaml"}:
            found = _scan_yaml(text, rel)
        else:
            techniques = tuple(find_techniques(text))
            found = [DetectionRef(path=rel, kind="text", techniques=techniques)] if techniques else []
        refs.extend(found)
    return refs


class DetectionIndex:
    """Index technique -> /detections rules."""

    def __init__(self, refs: Iterable[DetectionRef]):
        self.refs = list(refs)
        self._by_technique: dict[str, list[DetectionRef]] = defaultdict(list)
        for ref in self.refs:
            for technique in ref.techniques:
                self._by_technique[technique].append(ref)

    @classmethod
    def from_dir(cls, root: Path | str) -> DetectionIndex:
        return cls(scan_detections(root))

    def __bool__(self) -> bool:
        return bool(self.refs)

    def for_techniques(self, techniques: Iterable[str], include_parent: bool = True) -> list[DetectionRef]:
        """Rules that declare any of the techniques (or their parent technique)."""
        wanted = list(techniques)
        if include_parent:
            wanted += [parent_technique(t) for t in wanted]
        result: dict[tuple[str, str | None, str | None], DetectionRef] = {}
        for technique in dict.fromkeys(wanted):
            for ref in self._by_technique.get(technique, []):
                result.setdefault((ref.path, ref.rule_id, ref.title), ref)
        return list(result.values())

    def for_scenario(self, scenario: Scenario) -> list[DetectionRef]:
        return self.for_techniques(scenario.detection.mitre_ids)

    def rule_ids_for(self, scenario: Scenario) -> tuple[str, ...]:
        ids = [r.rule_id for r in self.for_scenario(scenario) if r.kind == "wazuh-rule" and r.rule_id]
        return tuple(dict.fromkeys(ids))
