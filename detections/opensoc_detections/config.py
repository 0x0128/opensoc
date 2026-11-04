"""Paths and access to the logsource -> Wazuh mapping configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

def _find_root() -> Path:
    """detections/ directory: $OPENSOC_DETECTIONS_ROOT, the source checkout this package
    lives in, or (for a non-editable install used as a sigma-cli plugin) the closest
    parent of the working directory holding config/wazuh_mapping.yml."""
    if os.environ.get("OPENSOC_DETECTIONS_ROOT"):
        return Path(os.environ["OPENSOC_DETECTIONS_ROOT"]).resolve()
    source = Path(__file__).resolve().parent.parent
    if (source / "config" / "wazuh_mapping.yml").exists():
        return source
    for candidate in [Path.cwd(), *Path.cwd().parents]:
        for root in (candidate, candidate / "detections"):
            if (root / "config" / "wazuh_mapping.yml").exists():
                return root
    return source


ROOT = _find_root()
RULES_DIR = ROOT / "rules"
SAMPLES_DIR = ROOT / "tests" / "samples"
CONFIG_DIR = ROOT / "config"
MAPPING_FILE = CONFIG_DIR / "wazuh_mapping.yml"
RULE_IDS_FILE = CONFIG_DIR / "wazuh_rule_ids.yml"
SIGMA_CHECK_CONFIG = CONFIG_DIR / "sigma_validation.yml"
WAZUH_OUTPUT = ROOT / "output" / "wazuh" / "opensoc_sigma_rules.xml"
COVERAGE_DIR = ROOT / "coverage"
LOGTEST_DIR = ROOT / "wazuh" / "logtest"

LOGSOURCE_KEYS = ("product", "category", "service")


@dataclass(frozen=True)
class FieldMapping:
    default: str | None
    map: dict[str, str]
    drop: tuple[str, ...] = ()

    def target(self, sigma_field: str) -> str | None:
        """Wazuh field for a Sigma field, or None if the mapping is strict and has no entry."""
        if sigma_field in self.map:
            return self.map[sigma_field]
        if self.default is None:
            return None
        lcfirst = sigma_field[:1].lower() + sigma_field[1:]
        return self.default.format(field=sigma_field, lcfirst=lcfirst)


@dataclass(frozen=True)
class LogsourceMapping:
    id: str
    logsource: dict[str, str]
    description: str
    parent: dict[str, Any]
    fields: FieldMapping
    anchor: dict[str, str] = field(default_factory=dict)
    options: tuple[str, ...] = ()
    keywords: bool = False
    render: dict[str, Any] = field(default_factory=dict)
    rule_prefix: str = ""

    @property
    def specificity(self) -> int:
        return len(self.logsource)

    def matches(self, logsource: dict[str, str | None]) -> bool:
        return all(logsource.get(k) == v for k, v in self.logsource.items())


@lru_cache(maxsize=None)
def load_mappings(path: Path = MAPPING_FILE) -> tuple[LogsourceMapping, ...]:
    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    mappings = []
    for entry in raw["logsources"]:
        unknown = set(entry["logsource"]) - set(LOGSOURCE_KEYS)
        if unknown:
            raise ValueError(f"{entry['id']}: unknown logsource keys {unknown}")
        f = entry.get("fields", {})
        mappings.append(
            LogsourceMapping(
                id=entry["id"],
                logsource=dict(entry["logsource"]),
                description=entry.get("description", ""),
                parent=dict(entry["parent"]),
                fields=FieldMapping(
                    default=f.get("default"),
                    map=dict(f.get("map") or {}),
                    drop=tuple(f.get("drop") or ()),
                ),
                anchor=dict(entry.get("anchor") or {}),
                options=tuple(entry.get("options") or ()),
                keywords=bool(entry.get("keywords", False)),
                render=dict(entry.get("render") or {}),
                rule_prefix=entry.get("rule_prefix", ""),
            )
        )
    ids = [m.id for m in mappings]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate logsource mapping ids")
    # Every Sigma logsource must resolve to exactly one entry, otherwise the field
    # mappings of two entries would be applied on top of each other.
    for a in mappings:
        for b in mappings:
            if a is not b and a.logsource.items() <= b.logsource.items():
                raise ValueError(f"logsource mappings {a.id} and {b.id} overlap")
    return tuple(mappings)


def logsource_dict(logsource: Any) -> dict[str, str | None]:
    """Normalize a pySigma SigmaLogSource (or dict) into a plain dict."""
    if isinstance(logsource, dict):
        return {k: logsource.get(k) for k in LOGSOURCE_KEYS}
    return {k: getattr(logsource, k, None) for k in LOGSOURCE_KEYS}


def mapping_for(logsource: Any) -> LogsourceMapping | None:
    """Most specific mapping entry for a rule logsource (None if unsupported)."""
    ls = logsource_dict(logsource)
    candidates = [m for m in load_mappings() if m.matches(ls)]
    if not candidates:
        return None
    candidates.sort(key=lambda m: m.specificity, reverse=True)
    if len(candidates) > 1 and candidates[0].specificity == candidates[1].specificity:
        raise ValueError(
            f"ambiguous logsource mapping for {ls}: {candidates[0].id}, {candidates[1].id}"
        )
    return candidates[0]
