from __future__ import annotations

import pytest

from opensoc_hunting.emulation.detections import DetectionIndex, scan_detections
from opensoc_hunting.emulation.scenarios import load_scenarios

WAZUH_XML = """<!-- OpenSOC custom rules -->
<group name="opensoc,sysmon,">
  <!-- <rule id="199999" level="3"><mitre><id>T1003.001</id></mitre></rule> (commented out) -->
  <rule id="100200" level="12">
    <if_group>sysmon_event_10</if_group>
    <field name="win.eventdata.targetImage" type="pcre2">(?i)\\\\lsass\\.exe$</field>
    <description>LSASS memory access</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
  </rule>
  <rule id="100201" level="10">
    <if_sid>100200</if_sid>
    <description>Rule without MITRE</description>
  </rule>
</group>
<group name="opensoc,linux,">
  <rule id="100300" level="8">
    <if_group>syscheck</if_group>
    <description>New file in /etc/cron.d</description>
    <mitre><id>T1053</id></mitre>
  </rule>
</group>
"""

SIGMA = """title: PowerShell with encoded command
id: 0b0a2f5e-1111-4c1e-9d3b-123456789abc
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: ' -enc '
  condition: selection
tags:
  - attack.execution
  - attack.t1059.001
"""


@pytest.fixture
def detections_dir(tmp_path):
    root = tmp_path / "detections"
    (root / "wazuh").mkdir(parents=True)
    (root / "sigma").mkdir()
    (root / "wazuh" / "opensoc_rules.xml").write_text(WAZUH_XML, encoding="utf-8")
    (root / "sigma" / "ps_enc.yml").write_text(SIGMA, encoding="utf-8")
    (root / "others.json").write_text('{"name": "certutil", "mitre": ["T1105"]}', encoding="utf-8")
    (root / "README.md").write_text("We cover T1547.001 and T1136.001", encoding="utf-8")
    (root / ".git").mkdir()
    (root / ".git" / "x.yml").write_text("tags: [attack.t1098.004]", encoding="utf-8")
    return root


def test_scan_recognizes_formats(detections_dir):
    refs = scan_detections(detections_dir)
    by_kind = {(r.kind, r.rule_id) for r in refs}
    assert ("wazuh-rule", "100200") in by_kind
    assert ("wazuh-rule", "100300") in by_kind
    assert ("wazuh-rule", "100201") not in by_kind  # no MITRE
    assert ("wazuh-rule", "199999") not in by_kind  # commented out
    assert ("sigma", "0b0a2f5e-1111-4c1e-9d3b-123456789abc") in by_kind
    assert any(r.kind == "text" and r.techniques == ("T1105",) for r in refs)
    # Markdown and hidden directories do not count as coverage.
    assert not any("T1547.001" in r.techniques or "T1098.004" in r.techniques for r in refs)


def test_index_by_scenario_and_parent_technique(detections_dir):
    index = DetectionIndex.from_dir(detections_dir)
    scenarios = {s.id: s for s in load_scenarios()}
    assert index.rule_ids_for(scenarios["EMU-02"]) == ("100200",)
    # EMU-08 is T1053.003; rule 100300 declares the parent technique T1053.
    assert index.rule_ids_for(scenarios["EMU-08"]) == ("100300",)
    assert [r.kind for r in index.for_scenario(scenarios["EMU-01"])] == ["sigma"]
    assert index.for_scenario(scenarios["EMU-04"]) == []
    assert "rule 100200" in index.for_scenario(scenarios["EMU-02"])[0].label()


def test_missing_directory(tmp_path):
    index = DetectionIndex.from_dir(tmp_path / "does-not-exist")
    assert not index
    assert index.for_techniques(["T1003.001"]) == []
