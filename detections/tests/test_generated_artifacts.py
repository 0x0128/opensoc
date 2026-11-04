"""Committed generated artifacts (Wazuh XML, ID registry, coverage) are up to date."""

import json

from opensoc_detections import attack, coverage
from opensoc_detections.config import COVERAGE_DIR, WAZUH_OUTPUT


def test_wazuh_output_up_to_date(converted):
    assert not converted["registry"].dirty, "new rules without Wazuh IDs: run `python -m opensoc_detections convert`"
    assert WAZUH_OUTPUT.read_text(encoding="utf-8") == converted["xml"], (
        "output/wazuh/opensoc_sigma_rules.xml is stale: run `python -m opensoc_detections convert`"
    )


def _rules(converted):
    counts = {sid: len(c.wazuh_ids) for sid, c in converted["rules"].items()}
    return coverage.collect(registry=converted["registry"], branch_counts=counts)


def test_coverage_up_to_date(converted):
    rules = _rules(converted)
    layer = json.dumps(coverage.navigator_layer(rules), indent=2, ensure_ascii=False) + "\n"
    assert (COVERAGE_DIR / "attack_navigator_layer.json").read_text(encoding="utf-8") == layer, (
        "coverage layer is stale: run `python -m opensoc_detections coverage`"
    )
    assert (COVERAGE_DIR / "COVERAGE.md").read_text(encoding="utf-8") == coverage.markdown(rules)


def test_navigator_layer_is_valid(converted):
    layer = json.loads((COVERAGE_DIR / "attack_navigator_layer.json").read_text(encoding="utf-8"))
    data = attack.load()
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "4.5"
    assert layer["versions"]["attack"] == data.version.split(".")[0]
    assert layer["techniques"], "empty layer"
    for t in layer["techniques"]:
        tech = data.technique(t["techniqueID"])
        assert tech is not None, t["techniqueID"]
        assert t["tactic"] in tech.tactics, (t["techniqueID"], t["tactic"])
        assert t["score"] >= 1
    covered = {t["techniqueID"] for t in layer["techniques"]}
    for r in _rules(converted):
        assert set(r.techniques) <= covered
