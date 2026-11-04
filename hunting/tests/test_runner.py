"""Scenario orchestration with a simulated executor and indexer."""

from __future__ import annotations

import json
from datetime import timedelta
from unittest.mock import MagicMock

import pytest

from opensoc_hunting.emulation.checker import DetectionChecker, build_alert_query
from opensoc_hunting.emulation.detections import DetectionIndex, DetectionRef
from opensoc_hunting.emulation.executor import AtomicExecutor, ExecResult
from opensoc_hunting.emulation.runner import (
    EmulationRunner,
    LabGuardError,
    Status,
    ensure_lab_target,
    parse_lab_targets,
    render_markdown,
    write_reports,
)
from opensoc_hunting.emulation.scenarios import load_scenarios
from opensoc_hunting.opensearch import IndexerError

from .conftest import FakeIndexer, alert, alerts_response


@pytest.fixture(scope="module")
def by_id():
    return {s.id: s for s in load_scenarios()}


def ok(action="run"):
    return ExecResult(action, 0, "Done executing test", "", 1.0)


def make_executor(results=None):
    executor = MagicMock(spec=AtomicExecutor)
    executor.run.side_effect = lambda scenario, action="run", input_args=None: (results or {}).get(action, ok(action))
    executor.build_script.side_effect = lambda scenario, action="run", input_args=None: f"# {action} {scenario.id} {input_args}"
    return executor


def make_runner(executor, indexer, clock, **kwargs):
    checker = DetectionChecker(indexer, poll_interval=15, now=clock.now, sleep=clock.sleep)
    defaults = dict(target="win10-lab", lab_targets={"win10-lab"}, execute=True, now=clock.now, log=lambda m: None)
    defaults.update(kwargs)
    return EmulationRunner(executor, checker, **defaults)


def test_lab_targets_and_guard():
    assert parse_lab_targets(" Win10-Lab, ubuntu-lab ,,") == {"win10-lab", "ubuntu-lab"}
    ensure_lab_target("WIN10-LAB", {"win10-lab"})
    with pytest.raises(LabGuardError, match="empty"):
        ensure_lab_target("win10-lab", set())
    with pytest.raises(LabGuardError, match="is not in"):
        ensure_lab_target("production-01", {"win10-lab"})


def test_execute_outside_the_lab_does_not_run(clock):
    executor = make_executor()
    with pytest.raises(LabGuardError):
        make_runner(executor, FakeIndexer(), clock, target="dc01-production")
    executor.run.assert_not_called()


def test_dry_run_executes_nothing(by_id, clock):
    executor = make_executor()
    runner = EmulationRunner(executor, None, target="win10-lab", lab_targets=set(), execute=False, log=lambda m: None)
    result = runner.run_one(by_id["EMU-01"])
    assert result.status is Status.DRY_RUN
    assert "script" in result.execution and "cleanup_script" in result.execution
    executor.run.assert_not_called()


def test_detected_on_the_second_poll(by_id, clock):
    indexer = FakeIndexer([alerts_response([]), alerts_response([alert("92052", ["T1059.001"])])])
    executor = make_executor()
    result = make_runner(executor, indexer, clock).run_one(by_id["EMU-01"])

    assert result.status is Status.DETECTED
    assert result.alerts[0]["rule_id"] == "92052"
    assert len(indexer.bodies) == 2 and clock.sleeps == [15]
    assert [c.args[1] for c in executor.run.call_args_list] == ["run", "cleanup"]
    # The query filters by agent, technique and a window that starts before the execution.
    query = json.dumps(indexer.bodies[0])
    assert '"agent.name": "win10-lab"' in query and '"T1059.001"' in query
    assert result.started_at == "2026-11-04T09:59:30.000Z"


def test_not_detected_after_timeout(by_id, clock):
    indexer = FakeIndexer([alerts_response([])])
    result = make_runner(make_executor(), indexer, clock).run_one(by_id["EMU-03"])
    assert result.status is Status.MISSED
    # timeout 180 s, polling every 15 s: 13 queries (t=0..180)
    assert len(indexer.bodies) == 13
    assert sum(clock.sleeps) == pytest.approx(180)
    assert any("No alerts" in n for n in result.notes)


def test_detection_timeout_overrides_the_scenario_one(by_id, clock):
    indexer = FakeIndexer([alerts_response([])])
    result = make_runner(make_executor(), indexer, clock, detection_timeout=30).run_one(by_id["EMU-09"])
    assert result.status is Status.MISSED
    assert sum(clock.sleeps) == pytest.approx(30) and len(indexer.bodies) == 3


def test_technique_alias_in_the_query(by_id, clock):
    indexer = FakeIndexer([alerts_response([alert("63103", ["T1070.001"], description="Log cleared")])])
    result = make_runner(make_executor(), indexer, clock, allow_irreversible=True).run_one(by_id["EMU-05"])
    assert result.status is Status.DETECTED
    terms = indexer.bodies[0]["query"]["bool"]["filter"][1]["bool"]["should"][0]["terms"]["rule.mitre.id"]
    assert terms == ["T1685.005", "T1070.001"]


def test_irreversible_is_skipped_without_permission(by_id, clock):
    executor = make_executor()
    result = make_runner(executor, FakeIndexer(), clock).run_one(by_id["EMU-05"])
    assert result.status is Status.SKIPPED
    executor.run.assert_not_called()


def test_execution_failure_and_cleanup(by_id, clock):
    executor = make_executor({"run": ExecResult("run", 1, "", "Access denied", 0.5)})
    result = make_runner(executor, FakeIndexer([alerts_response([])]), clock).run_one(by_id["EMU-02"])
    assert result.status is Status.EXEC_ERROR
    assert result.execution["stderr_tail"] == "Access denied"
    assert executor.run.call_args_list[-1].args[1] == "cleanup"


def test_execution_failure_but_detected(by_id, clock):
    # Invoke-AtomicTest can return an error even if the technique did run.
    executor = make_executor({"run": ExecResult("run", 1, "", "timeout", 0.5)})
    indexer = FakeIndexer([alerts_response([alert("92900", ["T1003.001"])])])
    result = make_runner(executor, indexer, clock).run_one(by_id["EMU-02"])
    assert result.status is Status.DETECTED


def test_indexer_error(by_id, clock):
    executor = make_executor()
    result = make_runner(executor, FakeIndexer([IndexerError("HTTP 401")]), clock).run_one(by_id["EMU-04"])
    assert result.status is Status.CHECK_ERROR
    assert any("HTTP 401" in n for n in result.notes)
    assert executor.run.call_args_list[-1].args[1] == "cleanup"


def test_prereqs_and_no_cleanup(by_id, clock):
    executor = make_executor()
    indexer = FakeIndexer([alerts_response([alert(mitre=["T1547.001"])])])
    result = make_runner(executor, indexer, clock, prereqs=True, cleanup=False).run_one(by_id["EMU-04"])
    assert [c.args[1] for c in executor.run.call_args_list] == ["prereqs", "run"]
    assert any("--no-cleanup" in n for n in result.notes)

    failing = make_executor({"prereqs": ExecResult("prereqs", 1, "", "no", 0)})
    result = make_runner(failing, FakeIndexer(), clock, prereqs=True).run_one(by_id["EMU-04"])
    assert result.status is Status.EXEC_ERROR
    assert [c.args[1] for c in failing.run.call_args_list] == ["prereqs"]


def test_strict_requires_a_detections_rule(by_id, clock):
    index = DetectionIndex([DetectionRef("wazuh/opensoc.xml", "wazuh-rule", ("T1003.001",), "100200", "LSASS")])
    generic = alerts_response([alert("92900", ["T1003.001"], description="Generic Wazuh rule")])

    result = make_runner(make_executor(), FakeIndexer([generic]), clock, strict=True,
                         detection_index=index).run_one(by_id["EMU-02"])
    assert result.status is Status.MISSED
    assert result.expected_rule_ids == ["100200"]
    assert result.detections == ["wazuh/opensoc.xml · rule 100200 · LSASS"]

    own = alerts_response([alert("100200", ["T1003.001"], description="LSASS")])
    result = make_runner(make_executor(), FakeIndexer([own]), clock, strict=True,
                         detection_index=index).run_one(by_id["EMU-02"])
    assert result.status is Status.DETECTED


def test_non_strict_warns_if_only_generic_rules_fire(by_id, clock):
    index = DetectionIndex([DetectionRef("x.xml", "wazuh-rule", ("T1003.001",), "100200")])
    generic = alerts_response([alert("92900", ["T1003.001"])])
    result = make_runner(make_executor(), FakeIndexer([generic]), clock, detection_index=index).run_one(by_id["EMU-02"])
    assert result.status is Status.DETECTED
    assert any("none of the /detections ones" in n for n in result.notes)


def test_input_overrides_reach_the_executor(by_id, clock):
    executor = make_executor()
    indexer = FakeIndexer([alerts_response([alert(mitre=["T1105"])])])
    make_runner(executor, indexer, clock, input_overrides={"emu-06": {"remote_file": "http://x"}}).run_one(by_id["EMU-06"])
    assert executor.run.call_args_list[0].args[2] == {"remote_file": "http://x"}


def test_check_only(by_id, clock):
    indexer = FakeIndexer([alerts_response([alert(mitre=["T1136.001"], agent="ubuntu-lab")])])
    checker = DetectionChecker(indexer, now=clock.now, sleep=clock.sleep)
    runner = EmulationRunner(make_executor(), checker, target="ubuntu-lab", lab_targets=set(), now=clock.now)
    result = runner.check_only(by_id["EMU-07"], clock.now() - timedelta(hours=1))
    assert result.status is Status.DETECTED and len(indexer.bodies) == 1


def test_build_alert_query():
    from datetime import datetime, timezone

    start = datetime(2026, 11, 4, 10, tzinfo=timezone.utc)
    q = build_alert_query(time_field="timestamp", start=start, end=start + timedelta(minutes=5),
                          mitre_ids=["T1105"], rule_ids=["100500"], agent="001", min_level=3)
    filters = q["query"]["bool"]["filter"]
    assert filters[0] == {"range": {"timestamp": {"gte": "2026-11-04T10:00:00.000Z", "lte": "2026-11-04T10:05:00.000Z"}}}
    assert {"terms": {"rule.id": ["100500"]}} in filters[1]["bool"]["should"]
    assert {"range": {"rule.level": {"gte": 3}}} in filters
    with pytest.raises(ValueError):
        build_alert_query(time_field="timestamp", start=start, end=start, mitre_ids=[])


def test_reports(by_id, clock, tmp_path):
    indexer = FakeIndexer([alerts_response([alert()])])
    results = [make_runner(make_executor(), indexer, clock).run_one(by_id["EMU-01"])]
    json_path, md_path = write_reports(results, tmp_path)
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data[0]["status"] == "DETECTED" and data[0]["scenario_id"] == "EMU-01"
    md = md_path.read_text(encoding="utf-8")
    assert "| EMU-01" in md and "**DETECTED**" in md and "92052" in md
    assert "DETECTED=1" in render_markdown(results)
