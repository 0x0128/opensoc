"""Integration: converted rules evaluated by a real Wazuh manager (wazuh-logtest).

Every sample event is rendered into the raw format the manager ingests, sent to
wazuh-logtest with the generated ruleset installed on top of the stock ruleset, and:

* ``match`` cases must be reported by one of the Wazuh rules generated for the Sigma
  rule (or by a documented stock rule of equal/higher level, ``wazuh_shadowed_by``);
* ``no_match`` cases must not hit the generated rules, *and* must still reach the
  logsource's stock rule tree (proving the sample was decoded and evaluated).

Requires Docker. Skipped when Docker is unavailable unless OPENSOC_REQUIRE_WAZUH=1
(set in CI). Image: $OPENSOC_WAZUH_IMAGE (default wazuh/wazuh-manager:4.9.2).
"""

from __future__ import annotations

import os

import pytest

from conftest import SAMPLE_CASES
from opensoc_detections.config import mapping_for
from opensoc_detections.loader import load_rule
from opensoc_detections.wazuh.logtest import LogtestUnavailable, WazuhLogtest, docker_available
from opensoc_detections.wazuh.render import render
from opensoc_detections.wazuh.ruleset_index import grouping_closure, load_index, subtree

pytestmark = pytest.mark.wazuh
REQUIRED = os.environ.get("OPENSOC_REQUIRE_WAZUH") == "1"


@pytest.fixture(scope="session")
def logtest(converted, tmp_path_factory):
    ok, reason = docker_available()
    if not ok:
        if REQUIRED:
            pytest.fail(f"Wazuh integration tests required but Docker is unavailable: {reason}")
        pytest.skip(f"Docker unavailable: {reason}")
    lt = WazuhLogtest()
    was_running = lt.running()
    try:
        lt.start()
    except LogtestUnavailable as exc:
        if REQUIRED:
            pytest.fail(str(exc))
        pytest.skip(str(exc))
    rules_xml = tmp_path_factory.mktemp("wazuh") / "opensoc_sigma_rules.xml"
    rules_xml.write_text(converted["xml"], encoding="utf-8")
    lt.install(rules_xml)
    yield lt
    if not was_running and os.environ.get("OPENSOC_WAZUH_KEEP") != "1":
        lt.stop()


@pytest.fixture(scope="session")
def results(logtest):
    """Process every sample in one batch; keyed by (rule path, case index)."""
    keys, requests = [], []
    for param in SAMPLE_CASES:
        path, index, case = param.values
        mapping = mapping_for(load_rule(path).logsource)
        keys.append((path, index))
        requests.append(render(case.event, mapping))
    return dict(zip(keys, logtest.process(requests)))


def test_ruleset_loads_without_warnings(logtest):
    warnings = logtest.ruleset_warnings()
    assert warnings == [], warnings


@pytest.mark.parametrize("path,index,case", SAMPLE_CASES)
def test_sample_in_wazuh(results, converted, path, index, case):
    rule = load_rule(path)
    mapping = mapping_for(rule.logsource)
    ours = converted["rules"][str(rule.id)]
    result = results[(path, index)]
    fired = result["rule"] or {}
    fired_id = int(fired.get("id", 0) or 0)
    detail = (
        f"{path.name} / {case.name}: expect {case.expect}, Wazuh reported rule {fired_id} "
        f"'{fired.get('description')}' (level {fired.get('level')}, decoder {result['decoder']})"
    )
    if case.should_match:
        if fired_id in ours.wazuh_ids:
            return
        assert fired_id in case.wazuh_shadowed_by, detail
        our_level = int(ours.xml.split('level="', 1)[1].split('"', 1)[0])
        assert int(fired.get("level", 0)) >= our_level, f"shadowing rule has a lower level: {detail}"
    else:
        assert fired_id not in ours.wazuh_ids, detail
        tree = subtree(grouping_closure(list(mapping.parent["if_sid"])), load_index())
        assert fired_id in tree, f"sample never reached the {mapping.id} rule tree: {detail}"
