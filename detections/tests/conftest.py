"""Shared fixtures for the OpenSOC detection tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from opensoc_detections.config import RULES_DIR
from opensoc_detections.loader import load_rule, load_samples, rule_files, sample_path


def rule_ids(paths: list[Path]) -> list[str]:
    return [str(p.relative_to(RULES_DIR)) for p in paths]


RULE_FILES = rule_files()


def sample_cases():
    """(rule path, case index, case) for every sample case of every rule."""
    out = []
    for path in RULE_FILES:
        samples = load_samples(sample_path(path))
        for i, case in enumerate(samples.cases):
            out.append(pytest.param(path, i, case, id=f"{path.stem}::{case.expect}::{i}"))
    return out


SAMPLE_CASES = sample_cases()


@pytest.fixture(scope="session")
def converted():
    """Convert the whole rule set once (in memory, committed ID registry untouched)."""
    from opensoc_detections.loader import load_collection
    from opensoc_detections.wazuh.backend import WazuhBackend
    from opensoc_detections.wazuh.ids import RuleIdRegistry

    registry = RuleIdRegistry()
    backend = WazuhBackend(id_registry=registry)
    xml = backend.convert(load_collection())
    return {"xml": xml, "rules": {c.sigma_id: c for c in backend.converted}, "registry": registry}


@pytest.fixture(scope="session")
def attack_stix() -> str | None:
    return os.environ.get("OPENSOC_ATTACK_STIX")


__all__ = ["RULE_FILES", "SAMPLE_CASES", "rule_ids", "load_rule"]
