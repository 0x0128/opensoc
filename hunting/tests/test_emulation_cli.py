from __future__ import annotations

import json
from unittest.mock import patch

from opensoc_hunting.emulation import cli
from opensoc_hunting.emulation.checker import DetectionChecker

from .conftest import FakeClock, FakeIndexer, alert, alerts_response


def test_list(capsys):
    assert cli.main(["list"]) == 0
    out = capsys.readouterr().out
    assert all(f"EMU-{i:02d}" in out for i in range(1, 11))
    assert cli.main(["list", "--platform", "linux", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert [d["id"] for d in data] == ["EMU-07", "EMU-08", "EMU-09", "EMU-10"]


def test_coverage_without_and_with_detections(tmp_path, capsys):
    assert cli.main(["--detections", str(tmp_path / "nothing"), "coverage"]) == 0
    assert "does not exist" in capsys.readouterr().out
    root = tmp_path / "detections"
    root.mkdir()
    (root / "r.xml").write_text('<group><rule id="100200" level="12"><description>LSASS</description>'
                                "<mitre><id>T1003.001</id></mitre></rule></group>", encoding="utf-8")
    assert cli.main(["--detections", str(root), "coverage", "--fail-on-gap"]) == 1
    out = capsys.readouterr().out
    assert "[OK ] EMU-02" in out and "[GAP] EMU-01" in out and "1/10" in out


def test_run_dry_run_shows_script_and_writes_report(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("OPENSOC_LAB_TARGETS", raising=False)
    code = cli.main(["run", "--target", "win10-lab", "-s", "EMU-06", "--report-dir", str(tmp_path),
                     "--input-arg", "EMU-06.remote_file=http://srv.lab.local/x.txt"])
    assert code == 0
    out = capsys.readouterr().out
    assert "Invoke-AtomicTest 'T1105'" in out and "http://srv.lab.local/x.txt" in out and "DRY_RUN" in out
    assert len(list(tmp_path.glob("emulation-*.md"))) == 1


def test_run_requires_scenarios(capsys):
    assert cli.main(["run", "--target", "win10-lab"]) == 2


def test_run_execute_blocked_outside_the_lab(monkeypatch, capsys):
    monkeypatch.setenv("OPENSOC_LAB_TARGETS", "ubuntu-lab")
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://indexer.lab.local:9200")
    with patch("opensoc_hunting.emulation.executor.subprocess.run") as run:
        assert cli.main(["run", "--target", "win10-lab", "-s", "1", "--execute", "--no-report"]) == 2
        run.assert_not_called()
    assert "OPENSOC_LAB_TARGETS" in capsys.readouterr().err


def test_malformed_input_arg(capsys):
    assert cli.main(["run", "--target", "x", "-s", "1", "--input-arg", "no-format"]) == 2


def test_check_with_simulated_indexer(monkeypatch, capsys, tmp_path):
    clock = FakeClock()
    indexer = FakeIndexer([alerts_response([alert("5902", ["T1136.001"], agent="ubuntu-lab",
                                                  description="New user added to the system")])])
    checker = DetectionChecker(indexer, now=clock.now, sleep=clock.sleep)
    monkeypatch.setattr(cli, "_make_checker", lambda args: checker)
    code = cli.main(["check", "--target", "ubuntu-lab", "-s", "EMU-07", "--since", "2026-11-04T09:00:00Z",
                     "--report-dir", str(tmp_path)])
    assert code == 0
    out = capsys.readouterr().out
    assert "DETECTED" in out and "5902" in out


def test_check_not_detected_returns_1(monkeypatch, tmp_path):
    checker = DetectionChecker(FakeIndexer([alerts_response([])]))
    monkeypatch.setattr(cli, "_make_checker", lambda args: checker)
    assert cli.main(["check", "--target", "ubuntu-lab", "-s", "EMU-07", "--since", "2026-11-04T09:00:00",
                     "--no-report"]) == 1
