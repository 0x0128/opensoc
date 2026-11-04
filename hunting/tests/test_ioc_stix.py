from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from opensoc_hunting.ioc.csv_io import read_csv
from opensoc_hunting.ioc.model import IOC
from opensoc_hunting.ioc.stix import (
    TLP_MARKINGS,
    build_pattern,
    from_stix,
    indicator_id,
    parse_pattern,
    to_stix_bundle,
)

from .conftest import HUNTING_ROOT

NOW = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)


def sample_iocs() -> list[IOC]:
    return read_csv((HUNTING_ROOT / "examples" / "iocs-example.csv").read_text(encoding="utf-8")).iocs


def all_types() -> list[IOC]:
    return [
        IOC("ipv4", "203.0.113.45", tlp="clear"),
        IOC("ipv6", "2001:db8::bad"),
        IOC("domain", "evil.example", tlp="amber+strict", confidence=50),
        IOC("hostname", "c2.evil.example"),
        IOC("url", "https://evil.example/it's\\here", description="quotes and backslash"),
        IOC("email", "phish@evil.example", tlp="red"),
        IOC("md5", "d41d8cd98f00b204e9800998ecf8427e", tlp="green"),
        IOC("sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        IOC("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", source="Feed X"),
        IOC("filename", "invoice.exe", to_ids=False, description="context only", tags=["lab"], tlp="amber"),
        IOC("ipv4", "198.51.100.0/24", to_ids=False),
    ]


@pytest.mark.parametrize(
    "ioc, pattern",
    [
        (IOC("ipv4", "203.0.113.45"), "[ipv4-addr:value = '203.0.113.45']"),
        (IOC("ipv6", "2001:db8::1"), "[ipv6-addr:value = '2001:db8::1']"),
        (IOC("domain", "evil.example"), "[domain-name:value = 'evil.example']"),
        (IOC("hostname", "a.evil.example"), "[domain-name:value = 'a.evil.example']"),
        (IOC("email", "x@evil.example"), "[email-addr:value = 'x@evil.example']"),
        (IOC("md5", "a" * 32), f"[file:hashes.MD5 = '{'a' * 32}']"),
        (IOC("sha1", "b" * 40), f"[file:hashes.'SHA-1' = '{'b' * 40}']"),
        (IOC("sha256", "c" * 64), f"[file:hashes.'SHA-256' = '{'c' * 64}']"),
        (IOC("filename", "o'neil.exe"), "[file:name = 'o\\'neil.exe']"),
        (IOC("url", "https://e.example/a\\b"), "[url:value = 'https://e.example/a\\\\b']"),
    ],
)
def test_patterns(ioc, pattern):
    assert build_pattern(ioc) == pattern
    assert parse_pattern(pattern)[0] == [(ioc.type if ioc.type != "hostname" else "domain", ioc.value)]


def test_bundle_structure():
    bundle = to_stix_bundle(all_types(), producer="OpenSOC Lab", now=NOW)
    assert bundle["type"] == "bundle" and bundle["id"].startswith("bundle--")
    objects = bundle["objects"]
    by_type: dict[str, list[dict]] = {}
    for obj in objects:
        by_type.setdefault(obj["type"], []).append(obj)
        assert obj.get("spec_version") == "2.1"
    assert len(by_type["identity"]) == 1
    assert {m["name"] for m in by_type["marking-definition"]} == {"TLP:WHITE", "TLP:AMBER", "TLP:RED", "TLP:GREEN"}
    assert len(by_type["indicator"]) == 9
    assert len(by_type["observed-data"]) == 2 and len(by_type["note"]) == 1
    assert {o["type"] for o in objects} >= {"file", "ipv4-addr"}

    ind = {o["name"]: o for o in by_type["indicator"]}
    domain = ind["domain: evil.example"]
    assert domain["object_marking_refs"] == [TLP_MARKINGS["amber"][0]]
    assert domain["labels"] == ["tlp:amber+strict"] and domain["confidence"] == 50
    assert domain["created"] == "2026-11-04T10:00:00.000Z" and domain["valid_from"] == domain["created"]
    assert domain["created_by_ref"] == by_type["identity"][0]["id"]
    assert ind["sha256: " + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"][
        "external_references"][0]["source_name"] == "Feed X"


def test_deterministic_ids():
    a = to_stix_bundle([IOC("domain", "evil.example")], now=NOW)
    b = to_stix_bundle([IOC("domain", "EVIL.example", description="other")], now=NOW + timedelta(days=1))
    ind_a = [o for o in a["objects"] if o["type"] == "indicator"][0]
    ind_b = [o for o in b["objects"] if o["type"] == "indicator"][0]
    assert ind_a["id"] == ind_b["id"] == indicator_id(IOC("domain", "evil.example"))
    assert a["id"] != b["id"]


def test_validates_with_the_official_stix2_library():
    stix2 = pytest.importorskip("stix2")
    bundle = to_stix_bundle(all_types(), now=NOW)
    parsed = stix2.parse(json.dumps(bundle), allow_custom=False)
    assert len(parsed.objects) == len(bundle["objects"])
    for ind in (o for o in bundle["objects"] if o["type"] == "indicator"):
        stix2.Indicator(**ind)  # also validates the pattern syntax


def test_lossless_round_trip():
    for iocs in (sample_iocs(), all_types()):
        back = from_stix(json.loads(json.dumps(to_stix_bundle(iocs, now=NOW))))
        assert not back.errors
        original = {i.key: i for i in iocs}
        restored = {i.key: i for i in back.iocs}
        # hostname travels as domain-name: it comes back as domain
        original = {(("domain" if k[0] == "hostname" else k[0]), k[1]): v for k, v in original.items()}
        assert restored.keys() == original.keys()
        for key, ioc in original.items():
            got = restored[key]
            # Without its own source, the source becomes the producer of the bundle (identity).
            assert (got.description, got.tags, got.tlp, got.confidence, got.first_seen, got.to_ids, got.source) == (
                ioc.description, ioc.tags, ioc.tlp, ioc.confidence, ioc.first_seen, ioc.to_ids,
                ioc.source or "OpenSOC Lab"), key


def test_compound_and_unsupported_patterns():
    pairs, warnings = parse_pattern(
        "[file:name = 'a.exe' AND file:hashes.'SHA-256' = '" + "d" * 64 + "'] OR [ipv4-addr:value = '203.0.113.1']")
    assert pairs == [("filename", "a.exe"), ("sha256", "d" * 64), ("ipv4", "203.0.113.1")]
    assert any("AND" in w for w in warnings)

    pairs, warnings = parse_pattern("[domain-name:value LIKE '%.evil.example'] OR [url:value = 'http://x.example/']")
    assert pairs == [("url", "http://x.example/")]
    assert any("LIKE" in w for w in warnings)

    pairs, _ = parse_pattern("[network-traffic:dst_ref.value = '2001:db8::5']")
    assert pairs == [("ipv6", "2001:db8::5")]

    pairs, warnings = parse_pattern("[process:name = 'evil.exe'] FOLLOWEDBY [ipv4-addr:value = '1.2.3.4'] WITHIN 60 SECONDS")
    assert pairs == [("ipv4", "1.2.3.4")] and any("temporal" in w for w in warnings)


def test_imports_third_party_bundle():
    expired = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    bundle = {
        "type": "bundle",
        "id": "bundle--6e5bc1a8-5c35-4c6c-9f63-5d3c2b9b8f00",
        "objects": [
            {"type": "identity", "spec_version": "2.1", "id": "identity--1", "name": "CERT Lab"},
            {"type": "marking-definition", "spec_version": "2.1", "id": "marking-definition--tlp2-amber",
             "name": "TLP:AMBER", "extensions": {}},
            {"type": "indicator", "spec_version": "2.1", "id": "indicator--a", "created": "2026-11-01T00:00:00.000Z",
             "pattern": "[domain-name:value = 'Bad.Example']", "pattern_type": "stix",
             "valid_from": "2026-10-30T08:00:00Z", "created_by_ref": "identity--1",
             "labels": ["c2"], "object_marking_refs": ["marking-definition--tlp2-amber"]},
            {"type": "indicator", "spec_version": "2.1", "id": "indicator--b", "revoked": True,
             "pattern": "[ipv4-addr:value = '203.0.113.99']", "pattern_type": "stix", "valid_from": "2026-01-01T00:00:00Z"},
            {"type": "indicator", "spec_version": "2.1", "id": "indicator--c", "valid_until": expired,
             "pattern": "[ipv4-addr:value = '203.0.113.98']", "pattern_type": "stix", "valid_from": "2026-01-01T00:00:00Z"},
            {"type": "indicator", "spec_version": "2.1", "id": "indicator--d", "pattern": "alert tcp any any",
             "pattern_type": "snort", "valid_from": "2026-01-01T00:00:00Z"},
            {"type": "indicator", "spec_version": "2.1", "id": "indicator--e",
             "pattern": "[ipv4-addr:value = '999.1.1.1']", "pattern_type": "stix", "valid_from": "2026-01-01T00:00:00Z"},
            {"type": "url", "spec_version": "2.1", "id": "url--1", "value": "http://standalone.example/x"},
            {"type": "file", "spec_version": "2.1", "id": "file--1", "hashes": {"SHA-256": "f" * 64}, "name": "x.dll"},
        ],
    }
    report = from_stix(bundle)
    got = {i.key: i for i in report.iocs}
    bad = got[("domain", "bad.example")]
    assert bad.description == ""
    assert bad.tlp == "amber" and bad.tags == ["c2"] and bad.source == "CERT Lab" and bad.to_ids
    assert bad.first_seen == "2026-10-30T08:00:00Z"
    assert ("ipv4", "203.0.113.99") not in got  # revoked
    assert got[("ipv4", "203.0.113.98")].to_ids is False  # expired
    assert got[("url", "http://standalone.example/x")].to_ids is False
    assert ("sha256", "f" * 64) in got and ("filename", "x.dll") in got
    assert any("revoked" in w for w in report.warnings)
    assert any("snort" in w for w in report.warnings)
    assert any("indicator--e" in e for e in report.errors)


def test_non_stix_inputs():
    assert from_stix({"hello": 1}).errors
    single = from_stix({"type": "indicator", "id": "indicator--x", "pattern": "[url:value = 'http://a.example/']",
                        "name": "Stage 2 download", "pattern_type": "stix", "valid_from": "2026-01-01T00:00:00Z"})
    assert [i.value for i in single.iocs] == ["http://a.example/"]
    # Without a description, a third party's name is kept as the description.
    assert single.iocs[0].description == "Stage 2 download"
