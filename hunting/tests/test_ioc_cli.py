from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from opensoc_hunting.ioc import cli
from opensoc_hunting.ioc.misp import ExportResult, ImportResult, MispError
from opensoc_hunting.ioc.model import IOC

from .conftest import HUNTING_ROOT

EXAMPLE = str(HUNTING_ROOT / "examples" / "iocs-example.csv")


@pytest.fixture
def fake_client(monkeypatch):
    client = MagicMock()
    client.verify = True
    monkeypatch.setattr(cli.MispClient, "from_env", classmethod(lambda cls, *a, **k: client))
    return client


def test_convert_csv_stix_csv(tmp_path, capsys):
    stix_path = tmp_path / "iocs.json"
    csv_path = tmp_path / "back.csv"
    assert cli.main(["convert", EXAMPLE, str(stix_path)]) == 0
    bundle = json.loads(stix_path.read_text(encoding="utf-8"))
    assert bundle["type"] == "bundle"
    assert cli.main(["convert", str(stix_path), str(csv_path)]) == 0
    assert "csv -> stix" in capsys.readouterr().err
    # CSV -> STIX -> CSV keeps every row (the order may change).
    assert sorted(csv_path.read_text().splitlines()) == sorted(_normalized_example().splitlines())


def _normalized_example() -> str:
    from opensoc_hunting.ioc.csv_io import dumps_csv, read_csv

    return dumps_csv(read_csv(open(EXAMPLE, encoding="utf-8").read()).iocs)


def test_convert_to_stdout_and_defang(capsys):
    assert cli.main(["convert", EXAMPLE, "-", "--to", "csv", "--defang"]) == 0
    assert "update-checker[.]example" in capsys.readouterr().out


def test_validate(tmp_path, capsys):
    assert cli.main(["validate", EXAMPLE]) == 0
    assert "7 valid IOCs" in capsys.readouterr().out
    bad = tmp_path / "bad.csv"
    bad.write_text("type,value\nipv4,999.9.9.9\ndomain,ok.example\n", encoding="utf-8")
    assert cli.main(["validate", str(bad)]) == 1
    out = capsys.readouterr()
    assert "1 valid IOCs" in out.out and "line 2" in out.err
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    assert cli.main(["validate", str(broken)]) == 1


def test_import_applies_tlp_and_calls_misp(fake_client, capsys):
    fake_client.import_iocs.return_value = ImportResult(event_id="42", added=[IOC("domain", "a.example")])
    assert cli.main(["import", EXAMPLE, "--event-info", "Exercise", "--tlp", "white", "--tag", "lab", "--dry-run"]) == 0
    kwargs = fake_client.import_iocs.call_args.kwargs
    iocs = fake_client.import_iocs.call_args.args[0]
    assert kwargs["event_info"] == "Exercise" and kwargs["event_id"] is None and kwargs["dry_run"] is True
    assert kwargs["event_tags"] == ["lab", "tlp:clear"]
    # The ones that already had a TLP keep it; the rest get the --tlp one (none in the example)
    assert {i.tlp for i in iocs} == {"amber", "green"}
    assert "event 42" in capsys.readouterr().out


def test_import_rejects_files_with_errors(fake_client, tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_text("type,value\nipv4,999.9.9.9\ndomain,ok.example\n", encoding="utf-8")
    assert cli.main(["import", str(bad), "--event-id", "7"]) == 1
    fake_client.import_iocs.assert_not_called()
    fake_client.import_iocs.return_value = ImportResult(event_id="7")
    assert cli.main(["import", str(bad), "--event-id", "7", "--skip-invalid"]) == 0
    assert [i.value for i in fake_client.import_iocs.call_args.args[0]] == ["ok.example"]


def test_import_with_failures_returns_1(fake_client):
    ioc = IOC("domain", "a.example")
    fake_client.import_iocs.return_value = ImportResult(event_id="7", failed=[(ioc, "HTTP 500")])
    assert cli.main(["import", EXAMPLE, "--event-id", "7"]) == 1


def test_import_requires_an_event():
    with pytest.raises(SystemExit):
        cli.main(["import", EXAMPLE])


def test_export_to_file(fake_client, tmp_path, capsys):
    fake_client.export_iocs.return_value = ExportResult(
        iocs=[IOC("ipv4", "203.0.113.5", tlp="amber")], skipped={"yara": 2})
    out = tmp_path / "misp.json"
    assert cli.main(["export", "--tag", "tlp:amber", "--last", "30d", "--to-ids-only", "-o", str(out)]) == 0
    kwargs = fake_client.export_iocs.call_args.kwargs
    assert kwargs == {"event_id": None, "tags": ["tlp:amber"], "types": None, "last": "30d", "to_ids": True,
                      "published": None}
    objects = json.loads(out.read_text())["objects"]
    assert any(o.get("pattern") == "[ipv4-addr:value = '203.0.113.5']" for o in objects)
    assert "2 attributes of unsupported type yara" in capsys.readouterr().err

    assert cli.main(["export", "-f", "csv", "--defang"]) == 0
    assert "203[.]0[.]113[.]5" in capsys.readouterr().out


def test_hunt_query(capsys):
    assert cli.main(["hunt-query", EXAMPLE, "--since", "now-30d"]) == 0
    captured = capsys.readouterr()
    query = json.loads(captured.out)
    assert query["query"]["bool"]["filter"][0] == {"range": {"timestamp": {"gte": "now-30d"}}}
    assert "email" in captured.err
    assert cli.main(["hunt-query", EXAMPLE, "--all", "--include-filenames"]) == 0
    text = capsys.readouterr().out
    assert "0cc175b9c0f1b6a831c399e269772661" in text and "evil-dropper.exe" in text


def test_ping_and_misp_errors(fake_client, capsys):
    fake_client.get_version.return_value = "2.5.2"
    assert cli.main(["ping"]) == 0
    assert "MISP 2.5.2 OK" in capsys.readouterr().out
    fake_client.get_version.side_effect = MispError("HTTP 403")
    assert cli.main(["ping"]) == 2
    assert "HTTP 403" in capsys.readouterr().err
