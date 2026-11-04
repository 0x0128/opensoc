"""Every rule follows the OpenSOC detection policy (metadata, ATT&CK, FPs, samples)."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from conftest import RULE_FILES, rule_ids
from opensoc_detections import validate
from opensoc_detections.config import RULES_DIR

MIN_RULES = 40


def test_minimum_rule_count():
    assert len(RULE_FILES) >= MIN_RULES


@pytest.mark.parametrize("platform", ["windows", "linux", "network", "cloud"])
def test_every_platform_is_covered(platform):
    assert any(p.relative_to(RULES_DIR).parts[0] == platform for p in RULE_FILES)


@pytest.mark.parametrize("path", RULE_FILES, ids=rule_ids(RULE_FILES))
def test_rule_policy(path: Path):
    issues = [i for i in validate.check_rule_file(path) if i.severity == "error"]
    assert not issues, "\n".join(map(str, issues))


def test_collection_policy():
    issues = validate.check_collection(RULE_FILES, full_ruleset=True)
    assert not issues, "\n".join(map(str, issues))


def test_every_rule_converts_to_wazuh():
    issues = validate.check_conversion(RULE_FILES)
    assert not issues, "\n".join(map(str, issues))


# --------------------------------------------------------------- policy self-tests
GOOD_RULE = """
title: Policy Test Rule
id: 0b7e2f63-3c52-4b8e-9d6e-1f2a3b4c5d6e
status: test
description: Test rule for the policy checker.
references:
  - https://example.com
author: test
date: 2026-11-04
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\powershell.exe'
  condition: selection
falsepositives:
  - Administrators
level: medium
"""


def _check(tmp_path, monkeypatch, body: str, name: str = "proc_creation_win_policy_test.yml"):
    rules = tmp_path / "rules"
    samples = tmp_path / "tests" / "samples"
    (rules / "windows").mkdir(parents=True)
    (samples / "windows").mkdir(parents=True)
    path = rules / "windows" / name
    path.write_text(textwrap.dedent(body))
    (samples / "windows" / name).write_text(
        "rule_id: 0b7e2f63-3c52-4b8e-9d6e-1f2a3b4c5d6e\ncases:\n"
        "  - {name: a, expect: match, event: {Image: 'C:\\\\x\\\\powershell.exe'}}\n"
        "  - {name: b, expect: no_match, event: {Image: 'C:\\\\x\\\\cmd.exe'}}\n"
    )
    monkeypatch.setattr(validate, "RULES_DIR", rules)
    import opensoc_detections.loader as loader

    monkeypatch.setattr(loader, "RULES_DIR", rules)
    monkeypatch.setattr(loader, "SAMPLES_DIR", samples)
    return [i.message for i in validate.check_rule_file(path) if i.severity == "error"]


def test_policy_accepts_good_rule(tmp_path, monkeypatch):
    assert _check(tmp_path, monkeypatch, GOOD_RULE) == []


@pytest.mark.parametrize(
    "old,new,expected",
    [
        ("  - Administrators", "  - Unknown", "concrete false positives"),
        ("  - attack.t1059.001", "  - attack.t1562.001", "revoked by T1685"),
        ("  - attack.t1059.001", "  - attack.t1003.001", "none of which is tagged"),
        ("  - attack.execution", "  - attack.credential_access\n  - attack.execution", "must use '-'"),
        ("  - attack.t1059.001", "  - attack.t1059.001\n  - attack.discovery", "not justified"),
        ("level: medium", "level: severe", "level must be one of"),
        ("status: test", "status: draft", "status must be one of"),
        ("  - https://example.com", "  - see wiki", "references must be URLs"),
        ("  product: windows", "  product: macos", "no Wazuh mapping"),
    ],
)
def test_policy_rejects_bad_rule(tmp_path, monkeypatch, old, new, expected):
    assert old in GOOD_RULE
    errors = _check(tmp_path, monkeypatch, GOOD_RULE.replace(old, new))
    assert any(expected in e for e in errors), errors


def test_policy_requires_logsource_prefix(tmp_path, monkeypatch):
    errors = _check(tmp_path, monkeypatch, GOOD_RULE, name="windows_policy_test.yml")
    assert any("must start with 'proc_creation_win_'" in e for e in errors), errors
