"""Unit tests of the reference Sigma evaluator used for sample tests."""

import textwrap

import pytest
from sigma.rule import SigmaRule

from opensoc_detections.evaluator import evaluate


def rule(detection: str) -> SigmaRule:
    return SigmaRule.from_yaml(
        "title: t\nid: 2c8b8a52-6d7e-4f0a-9b1c-3d2e1f0a9b8c\nstatus: test\nlevel: low\n"
        "logsource: {product: windows, category: process_creation}\n"
        "detection:\n" + textwrap.indent(textwrap.dedent(detection), "  ")
    )


@pytest.mark.parametrize(
    "detection,event,expected",
    [
        ("sel:\n  Image|endswith: '\\cmd.exe'\ncondition: sel", {"Image": "C:\\W\\CMD.EXE"}, True),
        ("sel:\n  Image|endswith|cased: '\\cmd.exe'\ncondition: sel", {"Image": "C:\\W\\CMD.EXE"}, False),
        ("sel:\n  Image: 'a*c'\ncondition: sel", {"Image": "abbbc"}, True),
        ("sel:\n  Image: a\nfilter:\n  User: x\ncondition: sel and not filter", {"Image": "a"}, True),
        ("sel:\n  Image: a\nfilter:\n  User: x\ncondition: sel and not filter", {"Image": "a", "User": "X"}, False),
        ("sel:\n  ip|cidr: '10.0.0.0/8'\ncondition: sel", {"ip": "10.1.2.3"}, True),
        ("sel:\n  ip|cidr: '10.0.0.0/8'\ncondition: sel", {"ip": "11.1.2.3"}, False),
        ("sel:\n  port: 4444\ncondition: sel", {"port": "4444"}, True),
        ("sel:\n  a.b: x\ncondition: sel", {"a": {"b": "x"}}, True),
        ("sel:\n  items|contains: '0.0.0.0/0'\ncondition: sel", {"items": [{"cidr": "0.0.0.0/0"}]}, True),
        ("sel:\n  x|re: '^a[0-9]{2}$'\ncondition: sel", {"x": "a42"}, True),
        ("sel:\n  x|exists: true\ncondition: sel", {"y": 1}, False),
        ("kw:\n  - 'needle'\ncondition: kw", {"message": "hay NEEDLE hay"}, True),
        ("sel:\n  x|contains|all: [a, b]\ncondition: sel", {"x": "a only"}, False),
    ],
)
def test_evaluate(detection, event, expected):
    assert evaluate(rule(detection), event) is expected
