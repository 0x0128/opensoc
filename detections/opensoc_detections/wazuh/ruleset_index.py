"""Index of the stock Wazuh ruleset, used to hook generated rules at the right place.

Wazuh evaluates the children of a matching rule in this order: level 0 rules first
(``rules.c`` stores level 0 as 99 when sorting), then by decreasing level. The first
child that matches wins and evaluation continues *only* below it. A stock level-0
"grouping" rule (e.g. 92025 *Reg.exe execution* under Sysmon event 1) therefore
swallows every event it matches, and a custom rule that is only a child of 61603
is never evaluated for those events.

To be reached, a generated rule must also be a child of every level-0 rule that can
be reached from its logsource parent through level-0 rules only. This module builds
that closure from an index of the stock ruleset (``data/wazuh_ruleset_index.json``),
regenerated with::

    python -m opensoc_detections wazuh-index --container <wazuh-manager container>
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from functools import lru_cache
from pathlib import Path

INDEX_FILE = Path(__file__).resolve().parent.parent / "data" / "wazuh_ruleset_index.json"


def _split_groups(text: str | None) -> list[str]:
    return [g.strip() for g in (text or "").split(",") if g.strip()]


_COMMENT = re.compile(r"<!--.*?-->", re.S)
_GROUP_OPEN = re.compile(r"<group\s+name\s*=\s*\"([^\"]*)\"")
_RULE = re.compile(r"<rule\b([^>]*)>(.*?)</rule>", re.S)
_ATTR = re.compile(r"(\w+)\s*=\s*\"([^\"]*)\"")


def _elements(body: str, tag: str) -> list[str]:
    return [m.group(1).strip() for m in re.finditer(rf"<{tag}\b[^>]*>(.*?)</{tag}>", body, re.S)]


def parse_rules_xml(text: str) -> list[dict]:
    """Parse one Wazuh rules file.

    Stock rule files are not always well-formed XML (unescaped regex characters), so
    a tolerant regex based scan is used: each <rule> belongs to the closest preceding
    <group name="..."> element.
    """
    text = _COMMENT.sub("", text)
    group_starts = [(m.start(), _split_groups(m.group(1))) for m in _GROUP_OPEN.finditer(text)]
    rules = []
    for m in _RULE.finditer(text):
        attrs = dict(_ATTR.findall(m.group(1)))
        if "id" not in attrs:
            continue
        body = m.group(2)
        base_groups: list[str] = []
        for pos, groups in group_starts:
            if pos < m.start():
                base_groups = groups
            else:
                break
        if_sid = []
        for el in _elements(body, "if_sid"):
            if_sid += [int(x) for x in re.split(r"[,\s]+", el) if x.strip().isdigit()]
        groups = list(base_groups)
        for el in _elements(body, "group"):
            groups += _split_groups(el)
        rules.append(
            {
                "id": int(attrs["id"]),
                "level": int(attrs.get("level", "0")),
                "if_sid": if_sid,
                "if_group": _elements(body, "if_group"),
                "groups": sorted(set(groups)),
                "frequency": "frequency" in attrs or bool(_elements(body, "if_matched_sid"))
                or bool(_elements(body, "if_matched_group")),
            }
        )
    return rules


def build_index(rule_files: dict[str, str], wazuh_version: str) -> dict:
    rules: dict[str, dict] = {}
    for name in sorted(rule_files):
        for r in parse_rules_xml(rule_files[name]):
            rules[str(r["id"])] = {
                "level": r["level"],
                "if_sid": r["if_sid"],
                "if_group": r["if_group"],
                "groups": r["groups"],
                "frequency": r["frequency"],
                "file": name,
            }
    return {"wazuh_version": wazuh_version, "rules": dict(sorted(rules.items(), key=lambda kv: int(kv[0])))}


def index_from_container(container: str, ruleset_dir: str = "/var/ossec/ruleset/rules") -> dict:
    version = subprocess.run(
        ["docker", "exec", container, "/var/ossec/bin/wazuh-control", "info", "-v"],
        capture_output=True, text=True, check=True,
    ).stdout.strip().lstrip("v")
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["docker", "cp", f"{container}:{ruleset_dir}/.", tmp], check=True, capture_output=True)
        files = {p.name: p.read_text(encoding="utf-8", errors="replace") for p in Path(tmp).glob("*.xml")}
    return build_index(files, version)


def write_index(index: dict, path: Path = INDEX_FILE) -> None:
    path.write_text(json.dumps(index, separators=(",", ":"), sort_keys=False) + "\n", encoding="utf-8")
    load_index.cache_clear()


@lru_cache(maxsize=1)
def load_index(path: Path = INDEX_FILE) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _children(index: dict) -> dict[int, list[int]]:
    rules = index["rules"]
    by_group: dict[str, list[int]] = {}
    for rid, r in rules.items():
        for g in r["groups"]:
            by_group.setdefault(g, []).append(int(rid))
    children: dict[int, list[int]] = {}
    for rid, r in rules.items():
        parents = list(r["if_sid"])
        for g in r["if_group"]:
            parents += by_group.get(g, [])
        for p in parents:
            if p != int(rid):
                children.setdefault(p, []).append(int(rid))
    return children


def grouping_closure(parents: list[int], index: dict | None = None) -> list[int]:
    """Parents plus every stock level-0 rule reachable from them through level-0 rules."""
    index = index or load_index()
    rules = index["rules"]
    children = _children(index)
    seen: list[int] = []
    stack = list(parents)
    while stack:
        rid = stack.pop(0)
        if rid in seen:
            continue
        seen.append(rid)
        for child in children.get(rid, []):
            info = rules.get(str(child))
            if info and info["level"] == 0 and not info["frequency"] and child not in seen:
                stack.append(child)
    return list(parents) + sorted(r for r in seen if r not in parents)


def subtree(parents: list[int], index: dict | None = None) -> set[int]:
    """Parents and all their stock descendants (any level)."""
    index = index or load_index()
    children = _children(index)
    seen: set[int] = set()
    stack = list(parents)
    while stack:
        rid = stack.pop()
        if rid in seen:
            continue
        seen.add(rid)
        stack.extend(children.get(rid, []))
    return seen
