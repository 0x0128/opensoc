from __future__ import annotations

import csv
import io

from opensoc_hunting.ioc.csv_io import COLUMNS, dumps_csv, read_csv
from opensoc_hunting.ioc.model import IOC

from .conftest import HUNTING_ROOT


def test_reads_the_example():
    report = read_csv((HUNTING_ROOT / "examples" / "iocs-example.csv").read_text(encoding="utf-8"))
    assert not report.errors
    types = [i.type for i in report.iocs]
    assert types == ["ipv4", "domain", "url", "sha256", "md5", "filename", "email"]
    domain = report.iocs[1]
    assert domain.value == "update-checker.example"  # it came defanged
    assert domain.tags == ["lab", "c2"] and domain.tlp == "amber" and domain.confidence == 70
    assert report.iocs[4].to_ids is False


def test_value_column_only_and_inferred_types():
    report = read_csv("value\n203.0.113.9\nevil.example\n# comment\n\ninvoice.exe\n")
    assert [(i.type, i.value) for i in report.iocs] == [
        ("ipv4", "203.0.113.9"), ("domain", "evil.example"), ("filename", "invoice.exe")]
    assert all(i.to_ids for i in report.iocs)


def test_errors_with_line_number():
    report = read_csv("type,value,to_ids\nipv4,999.1.1.1,true\nmd5,abc,true\nipv4,203.0.113.1,maybe\nnothing odd here,,\n")
    assert len(report.errors) == 3
    assert report.errors[0].startswith("line 2:") and report.errors[1].startswith("line 3:")
    assert "to_ids" in report.errors[2]


def test_headers():
    assert read_csv("").errors == ["empty CSV"]
    assert "value" in read_csv("type,val\nipv4,1.1.1.1\n").errors[0]
    report = read_csv("﻿Value,TYPE,extra\n203.0.113.1,ipv4,x\n")
    assert report.iocs[0].value == "203.0.113.1"
    assert report.warnings == ["ignored columns: extra"]


def test_formula_injection_protection_round_trip():
    ioc = IOC("filename", "=cmd|'calc'!A0.xls", description="+SUM(1,2)", tags=["@lab"], source="-feed")
    text = dumps_csv([ioc])
    row = list(csv.reader(io.StringIO(text)))[1]
    assert row[1].startswith("'=") and row[2].startswith("'+") and row[3].startswith("'@") and row[7].startswith("'-")
    back = read_csv(text).iocs[0]
    assert (back.value, back.description, back.tags, back.source) == (ioc.value, ioc.description, ioc.tags, ioc.source)


def test_writing_and_defang():
    iocs = [IOC("url", "https://evil.example/a", tags=["a", "b"], tlp="red", confidence=0, to_ids=False)]
    text = dumps_csv(iocs, defanged=True)
    lines = text.splitlines()
    assert lines[0] == ",".join(COLUMNS)
    assert lines[1] == "url,hxxps://evil[.]example/a,,a;b,red,0,,,false"
    assert read_csv(text).iocs[0].value == "https://evil.example/a"
