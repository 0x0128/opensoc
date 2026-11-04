"""MITRE ATT&CK (Enterprise) reference data.

The repository ships a compact extract of the official STIX bundle
(``opensoc_detections/data/attack_enterprise.json``) so validation and the coverage
matrix work offline and deterministically. Refresh it with::

    python -m opensoc_detections attack-update [--stix path/or/url]
"""

from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable

DATA_FILE = Path(__file__).resolve().parent / "data" / "attack_enterprise.json"
STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)

TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$")
GROUP_TAG = re.compile(r"^attack\.g\d{4}$")
SOFTWARE_TAG = re.compile(r"^attack\.s\d{4}$")


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    url: str
    parent_name: str | None = None

    @property
    def full_name(self) -> str:
        return f"{self.parent_name}: {self.name}" if self.parent_name else self.name

    @property
    def is_subtechnique(self) -> bool:
        return "." in self.id


@dataclass(frozen=True)
class Tactic:
    id: str
    shortname: str
    name: str


class AttackData:
    def __init__(self, raw: dict):
        self.version: str = raw["attack_version"]
        self.tactics: list[Tactic] = [Tactic(**t) for t in raw["tactics"]]
        self.techniques: dict[str, Technique] = {
            tid: Technique(id=tid, tactics=tuple(t["tactics"]), name=t["name"], url=t["url"],
                           parent_name=t.get("parent_name"))
            for tid, t in raw["techniques"].items()
        }
        self.deprecated: dict[str, str] = raw.get("deprecated", {})
        self.legacy_ids: dict[str, str] = raw.get("legacy_ids", {})

    @property
    def tactic_shortnames(self) -> list[str]:
        return [t.shortname for t in self.tactics]

    def tactic_by_tag(self, tag_value: str) -> Tactic | None:
        """Sigma uses the tactic shortname with '-' replaced by '_' (attack.defense_evasion)."""
        wanted = tag_value.replace("_", "-")
        return next((t for t in self.tactics if t.shortname == wanted), None)

    def technique(self, tid: str) -> Technique | None:
        return self.techniques.get(tid.upper())


@lru_cache(maxsize=1)
def load(path: Path = DATA_FILE) -> AttackData:
    with open(path, encoding="utf-8") as fh:
        return AttackData(json.load(fh))


def parse_tags(tags: Iterable[str]) -> tuple[list[str], list[str]]:
    """Split Sigma tags into (technique ids, tactic tag values)."""
    techniques, tactics = [], []
    for tag in tags:
        tag = str(tag).lower()
        if not tag.startswith("attack."):
            continue
        m = TECHNIQUE_TAG.match(tag)
        if m:
            techniques.append(m.group(1).upper())
        elif GROUP_TAG.match(tag) or SOFTWARE_TAG.match(tag):
            continue
        else:
            tactics.append(tag.split(".", 1)[1])
    return techniques, tactics


def _external_id(obj: dict) -> tuple[str | None, str | None]:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id"), ref.get("url")
    return None, None


def build_compact(bundle: dict, source: str) -> dict:
    objects = bundle["objects"]
    version = next(
        (o.get("x_mitre_version") for o in objects if o["type"] == "x-mitre-collection"), "unknown"
    )
    by_ref = {o["id"]: o for o in objects}
    matrix = next(o for o in objects if o["type"] == "x-mitre-matrix" and not o.get("revoked"))
    tactics = []
    for ref in matrix["tactic_refs"]:
        t = by_ref[ref]
        tid, _ = _external_id(t)
        tactics.append({"id": tid, "shortname": t["x_mitre_shortname"], "name": t["name"]})

    patterns = [o for o in objects if o["type"] == "attack-pattern"]
    names = {}
    for o in patterns:
        tid, _ = _external_id(o)
        if tid:
            names[tid] = o["name"]

    revoked_by = {}
    for o in objects:
        if o["type"] == "relationship" and o.get("relationship_type") == "revoked-by":
            src, dst = by_ref.get(o["source_ref"]), by_ref.get(o["target_ref"])
            if src and dst and src["type"] == "attack-pattern":
                revoked_by[_external_id(src)[0]] = _external_id(dst)[0]

    techniques, deprecated = {}, {}
    for o in patterns:
        tid, url = _external_id(o)
        if not tid:
            continue
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            if o.get("revoked"):
                deprecated[tid] = f"revoked by {revoked_by[tid]}" if tid in revoked_by else "revoked"
            else:
                deprecated[tid] = "deprecated"
            continue
        phases = [
            p["phase_name"]
            for p in o.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        entry = {"name": o["name"], "tactics": phases, "url": url}
        if "." in tid:
            entry["parent_name"] = names.get(tid.split(".")[0])
        techniques[tid] = entry

    # Legacy (pre-v18) ID for every technique that replaced revoked ones: tools pinned to an
    # older ATT&CK release (e.g. the Wazuh 4.x MITRE database) only know the old IDs.
    revoked_objs = {}
    for o in patterns:
        tid, _ = _external_id(o)
        if tid and o.get("revoked"):
            revoked_objs[tid] = o
    candidates: dict[str, list[str]] = {}
    for old, new in revoked_by.items():
        if new in techniques and old in revoked_objs:
            candidates.setdefault(new, []).append(old)
    legacy: dict[str, str] = {}
    for new, olds in candidates.items():
        # Prefer an old technique with the same name, then the most recently revoked one.
        olds.sort(
            key=lambda old: (
                revoked_objs[old]["name"] == techniques[new]["name"],
                revoked_objs[old].get("modified", ""),
                old,
            ),
            reverse=True,
        )
        legacy[new] = olds[0]

    return {
        "attack_version": version,
        "domain": "enterprise-attack",
        "source": source,
        "tactics": tactics,
        "techniques": dict(sorted(techniques.items())),
        "deprecated": dict(sorted(deprecated.items())),
        "legacy_ids": dict(sorted(legacy.items())),
    }


def update(stix: str = STIX_URL, out: Path = DATA_FILE) -> dict:
    if re.match(r"^https?://", stix):
        with urllib.request.urlopen(stix, timeout=120) as resp:  # noqa: S310 (trusted MITRE URL)
            bundle = json.load(resp)
    else:
        with open(stix, encoding="utf-8") as fh:
            bundle = json.load(fh)
    compact = build_compact(bundle, STIX_URL)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(compact, fh, indent=1, ensure_ascii=False)
        fh.write("\n")
    load.cache_clear()
    return compact
