"""Loading of Sigma rules and their test samples."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaRuleLocation
from sigma.rule import SigmaRule

from opensoc_detections.config import RULES_DIR, SAMPLES_DIR

EXPECTATIONS = ("match", "no_match")


@dataclass
class SampleCase:
    name: str
    expect: str
    event: dict[str, Any]
    # Stock Wazuh rules that legitimately report this event instead of the generated
    # rule (same or higher level, evaluated first). Only allowed on "match" cases.
    wazuh_shadowed_by: list[int] = field(default_factory=list)

    @property
    def should_match(self) -> bool:
        return self.expect == "match"


@dataclass
class SampleFile:
    path: Path
    rule_id: str
    cases: list[SampleCase]


def rule_files(rules_dir: Path | None = None) -> list[Path]:
    return sorted(p for p in (rules_dir or RULES_DIR).rglob("*.yml") if p.is_file())


def load_rule(path: Path) -> SigmaRule:
    """Parse a rule file into a fresh SigmaRule (pipelines mutate rules, so never share them)."""
    rule = SigmaRule.from_yaml(path.read_text(encoding="utf-8"))
    rule.source = SigmaRuleLocation(path)
    return rule


def load_collection(paths: list[Path] | None = None) -> SigmaCollection:
    paths = paths if paths is not None else rule_files()
    return SigmaCollection([load_rule(p) for p in paths])


def rule_yaml(path: Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def sample_path(rule_path: Path, rules_dir: Path | None = None, samples_dir: Path | None = None) -> Path:
    """tests/samples/<same relative path as the rule under rules/>."""
    rules_dir = rules_dir or RULES_DIR
    samples_dir = samples_dir or SAMPLES_DIR
    return samples_dir / rule_path.resolve().relative_to(rules_dir.resolve())


def load_samples(path: Path) -> SampleFile:
    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    cases = []
    for i, case in enumerate(raw.get("cases") or []):
        expect = case.get("expect")
        if expect not in EXPECTATIONS:
            raise ValueError(f"{path}: case {i} has invalid expect '{expect}' (use {EXPECTATIONS})")
        if not isinstance(case.get("event"), dict) or not case["event"]:
            raise ValueError(f"{path}: case {i} needs a non-empty 'event' mapping")
        shadowed = [int(x) for x in case.get("wazuh_shadowed_by") or []]
        if shadowed and expect != "match":
            raise ValueError(f"{path}: case {i}: wazuh_shadowed_by only makes sense for match cases")
        cases.append(
            SampleCase(
                name=str(case.get("name") or f"case {i}"),
                expect=expect,
                event=case["event"],
                wazuh_shadowed_by=shadowed,
            )
        )
    return SampleFile(path=path, rule_id=str(raw.get("rule_id", "")), cases=cases)
