"""Unit tests of the Sigma -> Wazuh conversion (IR, DNF, PCRE2 generation, XML)."""

from __future__ import annotations

import re
import textwrap
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

from opensoc_detections.config import WAZUH_OUTPUT
from opensoc_detections.wazuh.backend import (
    Atom,
    Node,
    WazuhBackend,
    condition_to_branches,
    string_pattern,
    wildcard_pattern,
)
from opensoc_detections.wazuh.ids import BLOCK_SIZE, FIRST_ID, RuleIdRegistry
from opensoc_detections.wazuh.ruleset_index import grouping_closure
from sigma.types import SigmaString

RULE_HEADER = """
title: Unit Test Rule
id: {id}
status: test
level: high
description: unit test
references: ['https://example.com']
author: test
date: 2026-11-04
falsepositives: ['tests']
"""


def convert(body: str, rule_id: str = "6b8f3d0e-1b2a-4c5d-8e9f-0a1b2c3d4e5f", tmp_path: Path | None = None):
    registry = RuleIdRegistry(Path(tmp_path or "/nonexistent") / "ids.yml")
    rule_yaml = RULE_HEADER.format(id=rule_id) + textwrap.dedent(body)
    backend = WazuhBackend(id_registry=registry)
    xml = backend.convert(SigmaCollection.from_yaml(rule_yaml))
    return xml, backend.converted[0]


def fields(xml: str) -> list[tuple[str, str, bool]]:
    root = ET.fromstring(f"<root>{xml}</root>")
    return [
        (f.get("name"), f.text, f.get("negate") == "yes")
        for f in root.iter("field")
    ]


# ------------------------------------------------------------------ patterns
@pytest.mark.parametrize(
    "value,expected",
    [
        ("cmd.exe", r"^cmd\.exe$"),
        ("*\\cmd.exe", r"\\cmd\.exe$"),
        ("C:\\Temp\\\\*", r"^C:\\Temp\\"),  # escaped backslash, then wildcard
        ("C:\\Temp\\*", r"^C:\\Temp\*$"),  # backslash-asterisk is a literal "*" in Sigma
        ("*mimikatz*", "mimikatz"),
        ("a?c", "^a.c$"),
        ("*", "^"),
        ("", "^$"),
        ("1+1=(2)|[x]{y}", r"^1\+1=\(2\)\|\[x\]\{y\}$"),
    ],
)
def test_string_pattern(value, expected):
    pattern = string_pattern(SigmaString(value))
    assert pattern == expected
    assert re.compile(pattern)


@pytest.mark.parametrize(
    "wildcard,expected",
    [("10.*", r"^10\."), ("192.168.1.5", r"^192\.168\.1\.5$"), ("fe8?:*", r"^fe8.:")],
)
def test_wildcard_pattern(wildcard, expected):
    assert wildcard_pattern(wildcard) == expected


# ------------------------------------------------------------- normalization
def test_or_of_same_field_is_merged_into_alternation():
    a, b = Atom("f", "a"), Atom("f", "b")
    assert condition_to_branches(Node("or", (a, b))) == [(Atom("f", "(?:a|b)"),)]


def test_or_of_different_fields_is_split():
    a, b = Atom("f", "a"), Atom("g", "b")
    assert condition_to_branches(Node("or", (a, b))) == [(a,), (b,)]


def test_not_or_becomes_single_negated_alternation():
    a, b, c = Atom("f", "a"), Atom("f", "b"), Atom("g", "c")
    branches = condition_to_branches(Node("and", (c, Node("not", (Node("or", (a, b)),)))))
    assert branches == [(c, Atom("f", "(?:a|b)", negated=True))]


def test_de_morgan_on_not_and():
    a, b, c = Atom("f", "a"), Atom("g", "b"), Atom("h", "c")
    branches = condition_to_branches(Node("and", (c, Node("not", (Node("and", (a, b)),)))))
    assert branches == [(c, a.negate()), (c, b.negate())]


def test_dnf_distribution_and_branch_merge():
    img = Node("or", (Atom("img", "x"), Atom("ofn", "y")))
    cli = Atom("cli", "z")
    assert condition_to_branches(Node("and", (img, cli))) == [
        (Atom("img", "x"), cli),
        (Atom("ofn", "y"), cli),
    ]
    # (A and f=x) or (A and f=y) -> A and f=(x|y)
    a = Atom("a", "1")
    merged = condition_to_branches(Node("or", (Node("and", (a, Atom("f", "x"))), Node("and", (a, Atom("f", "y"))))))
    assert merged == [(a, Atom("f", "(?:x|y)"))]


# ------------------------------------------------------------- full rules
def test_process_creation_rule_conversion(tmp_path):
    xml, conv = convert(
        """
        tags: [attack.execution, attack.t1059.001]
        logsource: {category: process_creation, product: windows}
        detection:
          sel_img:
            - Image|endswith: ['\\powershell.exe', '\\pwsh.exe']
            - OriginalFileName: PowerShell.EXE
          sel_cli:
            CommandLine|contains: ' -enc '
          filter:
            ParentImage|startswith: 'C:\\Program Files\\'
          condition: all of sel_* and not filter
        """,
        tmp_path=tmp_path,
    )
    assert len(conv.branches) == 2
    assert conv.wazuh_ids == [FIRST_ID, FIRST_ID + 1]
    f = fields(xml)
    assert ("win.eventdata.image", r"(?i)(?:\\powershell\.exe$|\\pwsh\.exe$)", False) in f
    assert ("win.eventdata.originalFileName", r"(?i)^PowerShell\.EXE$", False) in f
    assert ("win.eventdata.parentImage", r"(?i)^C:\\Program Files\\", True) in f
    root = ET.fromstring(f"<root>{xml}</root>")
    rules = list(root.iter("rule"))
    assert [r.get("level") for r in rules] == ["12", "12"]
    assert rules[0].find("if_sid").text.startswith("61603, ")
    assert [m.text for m in rules[0].find("mitre")] == ["T1059.001"]
    assert rules[0].find("description").text == "Unit Test Rule (variant 1/2)"


def test_numbers_cidr_and_anchor(tmp_path):
    xml, _ = convert(
        """
        tags: [attack.command-and-control, attack.t1571]
        logsource: {category: firewall}
        detection:
          sel:
            dst_port: 4444
          filter:
            dst_ip|cidr: '10.0.0.0/8'
          condition: sel and not filter
        """,
        tmp_path=tmp_path,
    )
    f = fields(xml)
    assert ("event_type", "^flow$", False) in f  # logsource anchor
    assert ("dest_port", "^4444$", False) in f
    assert ("dest_ip", r"(?i)^10\.", True) in f


def test_keywords_become_single_regex(tmp_path):
    xml, conv = convert(
        """
        tags: [attack.lateral-movement, attack.t1021.004]
        logsource: {product: linux, service: sshd}
        detection:
          keywords: ['Accepted password for root', 'Accepted publickey for root']
          condition: keywords
        """,
        tmp_path=tmp_path,
    )
    regex = ET.fromstring(f"<root>{xml}</root>").find(".//regex")
    assert regex.get("type") == "pcre2"
    assert regex.text == "(?i)(?:Accepted password for root|Accepted publickey for root)"


def test_auditd_record_type_is_dropped(tmp_path):
    xml, _ = convert(
        """
        tags: [attack.execution, attack.t1059.004]
        logsource: {product: linux, service: auditd}
        detection:
          sel:
            type: EXECVE
            a0: nc
          condition: sel
        """,
        tmp_path=tmp_path,
    )
    assert [f[0] for f in fields(xml)] == ["audit.execve.a0"]


def test_legacy_mitre_ids_for_wazuh(tmp_path):
    xml, _ = convert(
        """
        tags: [attack.defense-impairment, attack.t1685.005]
        logsource: {product: windows, service: security}
        detection:
          sel:
            EventID: 1102
          condition: sel
        """,
        tmp_path=tmp_path,
    )
    # ATT&CK v18+ ID T1685.005 is unknown to the Wazuh 4.9 MITRE DB -> legacy T1070.001
    assert "<id>T1070.001</id>" in xml


@pytest.mark.parametrize(
    "detection,message",
    [
        ("sel:\n    Image|exists: false\n  condition: sel", "absence of a field"),
        ("sel:\n    Image|gt: 4\n  condition: sel", "comparison"),
        ("keywords: [foo]\n  condition: keywords", "Keyword detections are not supported"),
        ("sel:\n    Image: a\n  condition: not sel", "positive condition"),
    ],
)
def test_unsupported_constructs_are_rejected(tmp_path, detection, message):
    body = (
        "tags: [attack.execution, attack.t1059.001]\n"
        "logsource: {category: process_creation, product: windows}\n"
        "detection:\n  " + detection + "\n"
    )
    with pytest.raises(SigmaError, match=message):
        convert(body, tmp_path=tmp_path)


def test_unknown_field_fails_for_strict_mapping(tmp_path):
    with pytest.raises(SigmaError, match="not mapped"):
        convert(
            """
            tags: [attack.execution, attack.t1059.004]
            logsource: {product: linux, service: auditd}
            detection:
              sel:
                not_a_field: x
              condition: sel
            """,
            tmp_path=tmp_path,
        )


def test_too_many_branches_rejected(tmp_path):
    sels = "\n".join(f"  s{i}:\n    a{i % 8}: x{i}\n    exe: y{i}" for i in range(BLOCK_SIZE + 1))
    body = (
        "tags: [attack.execution, attack.t1059.004]\n"
        "logsource: {product: linux, service: auditd}\n"
        f"detection:\n{sels}\n  condition: 1 of s*\n"
    )
    with pytest.raises(SigmaError, match="needs .* Wazuh rules"):
        convert(body, tmp_path=tmp_path)


# ------------------------------------------------------------- ids / ruleset
def test_id_registry_is_stable(tmp_path):
    reg = RuleIdRegistry(tmp_path / "ids.yml")
    a, b = reg.assign("a"), reg.assign("b")
    assert (a, b) == (FIRST_ID, FIRST_ID + BLOCK_SIZE)
    reg.save()
    reg2 = RuleIdRegistry(tmp_path / "ids.yml")
    assert reg2.get("a") == a and reg2.assign("c") == FIRST_ID + 2 * BLOCK_SIZE
    assert not RuleIdRegistry(tmp_path / "ids.yml").dirty


def test_grouping_closure_includes_stock_level0_children():
    closure = grouping_closure([61603])
    assert closure[0] == 61603
    assert 92025 in closure  # "Reg.exe execution" swallows reg.exe events (level 0)
    assert 92026 not in closure  # level > 0 rules do not need hooks


def test_committed_ruleset_is_well_formed(converted):
    xml = WAZUH_OUTPUT.read_text(encoding="utf-8")
    root = ET.fromstring(f"<root>{xml}</root>")
    rules = list(root.iter("rule"))
    ids = [int(r.get("id")) for r in rules]
    assert len(ids) == len(set(ids)) == sum(len(c.wazuh_ids) for c in converted["rules"].values())
    assert all(110000 <= i <= 119999 for i in ids)
    for r in rules:
        assert r.find("description").text
        assert r.find("if_sid") is not None
        assert r.find("mitre") is not None
        for f in r.iter("field"):
            assert f.get("type") == "pcre2"
            re.compile(re.sub(r"^\(\?i\)", "", f.text))  # Python re accepts the generated PCRE2
