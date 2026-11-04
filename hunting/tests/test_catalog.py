"""Scenario catalog and its relationship with the hypotheses and with /detections."""

from __future__ import annotations

import copy

import pytest
import yaml

from opensoc_hunting.emulation.detections import DetectionIndex
from opensoc_hunting.emulation.scenarios import (
    CatalogError,
    load_scenarios,
    parse_catalog,
    select_scenarios,
)
from opensoc_hunting.hunts import load_hypotheses
from opensoc_hunting.mitre import is_technique
from opensoc_hunting.paths import DEFAULT_DETECTIONS_DIR, SCENARIOS_FILE


@pytest.fixture(scope="module")
def scenarios():
    return load_scenarios()


@pytest.fixture(scope="module")
def raw_catalog():
    return yaml.safe_load(SCENARIOS_FILE.read_text(encoding="utf-8"))


def test_there_are_ten_scenarios_with_unique_ids(scenarios):
    assert len(scenarios) == 10
    assert [s.id for s in scenarios] == [f"EMU-{i:02d}" for i in range(1, 11)]


def test_covers_windows_and_linux(scenarios):
    assert {s.platform for s in scenarios} == {"windows", "linux"}


def test_valid_techniques_and_guids(scenarios):
    guids = [s.atomic.guid for s in scenarios]
    assert len(set(guids)) == len(guids)
    for s in scenarios:
        assert is_technique(s.technique)
        assert all(is_technique(a) for a in s.technique_aliases)
        assert s.atomic.name, s.id
        # The atomics folder matches the main technique or an alias.
        assert s.atomic.technique in s.techniques
        assert set(s.detection.mitre_ids) >= set(s.techniques)
        assert s.detection.timeout > 0
        assert s.telemetry and s.requirements


def test_aliases_of_renumbered_techniques(scenarios):
    by_id = {s.id: s for s in scenarios}
    clear_logs = by_id["EMU-05"]
    assert clear_logs.technique == "T1685.005"
    assert "T1070.001" in clear_logs.detection.mitre_ids
    assert clear_logs.irreversible


def test_each_scenario_links_hypotheses_that_reference_it(scenarios):
    hypotheses = {h.id: h for h in load_hypotheses()}
    for s in scenarios:
        assert s.hypotheses, f"{s.id} without hypotheses"
        for hid in s.hypotheses:
            assert hid in hypotheses, f"{s.id} references {hid}, which does not exist"
            h = hypotheses[hid]
            assert s.id in h.emulation, f"{hid} does not list {s.id} in 'emulation'"
            assert set(s.techniques) & set(h.all_techniques), f"{s.id} and {hid} share no technique"


def test_hypotheses_only_reference_existing_scenarios(scenarios):
    ids = {s.id for s in scenarios}
    for h in load_hypotheses():
        assert set(h.emulation) <= ids, h.id


def test_select_by_id_and_platform(scenarios):
    assert [s.id for s in select_scenarios(scenarios, ids=["1", "emu-7", "EMU-10"])] == ["EMU-01", "EMU-07", "EMU-10"]
    assert all(s.platform == "linux" for s in select_scenarios(scenarios, platform="linux"))
    with pytest.raises(CatalogError, match="EMU-99"):
        select_scenarios(scenarios, ids=["EMU-99"])


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda c: c["scenarios"][0]["atomic"].__setitem__("guid", "not-a-guid"), "GUID"),
        (lambda c: c["scenarios"][0].__setitem__("technique", "T12"), "technique"),
        (lambda c: c["scenarios"][0].__setitem__("platform", "solaris"), "platform"),
        (lambda c: c["scenarios"][1].__setitem__("id", c["scenarios"][0]["id"]), "duplicate"),
        (lambda c: c["scenarios"][0].pop("atomic"), "atomic"),
        (lambda c: c["scenarios"][0].__setitem__("hypotheses", ["X1"]), "hypothesis"),
    ],
)
def test_invalid_catalog(raw_catalog, mutate, message):
    data = copy.deepcopy(raw_catalog)
    mutate(data)
    with pytest.raises(CatalogError, match=message):
        parse_catalog(data)


@pytest.mark.skipif(not DEFAULT_DETECTIONS_DIR.is_dir(), reason="the repository has no /detections yet")
def test_each_scenario_has_a_detection_in_detections(scenarios):  # pragma: no cover - depends on the repo
    index = DetectionIndex.from_dir(DEFAULT_DETECTIONS_DIR)
    gaps = [s.id for s in scenarios if not index.for_scenario(s)]
    assert not gaps, f"Scenarios without a rule in /detections: {gaps} (opensoc-emulate coverage)"
