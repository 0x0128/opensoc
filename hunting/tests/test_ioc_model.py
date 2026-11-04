from __future__ import annotations

import pytest

from opensoc_hunting.ioc.model import (
    IOC,
    IOCError,
    dedupe,
    defang,
    detect_type,
    normalize_timestamp,
    normalize_tlp,
    normalize_value,
    refang,
)


@pytest.mark.parametrize(
    "ioc_type, value, expected",
    [
        ("ipv4", " 203.0.113.45 ", ("ipv4", "203.0.113.45")),
        ("ipv4", "203.0.113[.]45", ("ipv4", "203.0.113.45")),
        ("ipv4", "2001:DB8::1", ("ipv6", "2001:db8::1")),
        ("ipv4", "198.51.100.7/24", ("ipv4", "198.51.100.0/24")),
        ("ipv6", "2001:db8::1/128", ("ipv6", "2001:db8::1")),
        ("domain", "Evil.Example.", ("domain", "evil.example")),
        ("domain", "evil[.]example", ("domain", "evil.example")),
        ("domain", "bücher.example", ("domain", "xn--bcher-kva.example")),
        ("hostname", "srv-01.lab.local", ("hostname", "srv-01.lab.local")),
        ("url", "hxxps://Evil.Example/Path?a=B", ("url", "https://evil.example/Path?a=B")),
        ("email", "Phish[@]Malicious[.]example", ("email", "phish@malicious.example")),
        ("md5", "0CC175B9C0F1B6A831C399E269772661", ("md5", "0cc175b9c0f1b6a831c399e269772661")),
        ("sha1", "a" * 40, ("sha1", "a" * 40)),
        ("sha256", "B" * 64, ("sha256", "b" * 64)),
        ("filename", "C:\\Users\\Public\\evil.exe", ("filename", "evil.exe")),
    ],
)
def test_normalize_value(ioc_type, value, expected):
    assert normalize_value(ioc_type, value) == expected


@pytest.mark.parametrize(
    "ioc_type, value",
    [
        ("ipv4", "300.1.1.1"),
        ("domain", "has_no_tld"),
        ("domain", "-bad.example"),
        ("url", "evil.example/no-scheme"),
        ("email", "not-an-email"),
        ("md5", "abc"),
        ("sha256", "z" * 64),
        ("filename", "C:\\Users\\"),
        ("domain", "evil.example\nother"),
        ("odd-type", "x"),
        ("domain", "   "),
    ],
)
def test_normalize_value_invalid(ioc_type, value):
    with pytest.raises(IOCError):
        normalize_value(ioc_type, value)


@pytest.mark.parametrize(
    "value, expected",
    [
        ("203.0.113.45", "ipv4"),
        ("2001:db8::1", "ipv6"),
        ("10.0.0.0/8", "ipv4"),
        ("d41d8cd98f00b204e9800998ecf8427e", "md5"),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"),
        ("hxxp://evil[.]example/a", "url"),
        ("user@evil.example", "email"),
        ("evil.example", "domain"),
        ("invoice.exe", "filename"),
        ("payload.ps1", "filename"),
        ("Invoice_2026.pdf", "filename"),
    ],
)
def test_detect_type(value, expected):
    assert detect_type(value) == expected


def test_detect_type_impossible():
    with pytest.raises(IOCError):
        detect_type("this is nothing")


def test_refang_defang():
    assert refang("hxxps://evil[.]example[:]8443/x") == "https://evil.example:8443/x"
    assert refang("a(.)b{.}c[dot]d") == "a.b.c.d"
    assert defang("url", "https://evil.example/a.php") == "hxxps://evil[.]example/a.php"
    assert defang("ipv4", "203.0.113.45") == "203[.]0[.]113[.]45"
    assert defang("email", "a.b@evil.example") == "a.b[@]evil[.]example"
    assert defang("md5", "abc") == "abc"
    for t, v in [("url", "https://evil.example/a.php"), ("domain", "evil.example"), ("email", "x@evil.example")]:
        assert normalize_value(t, defang(t, v))[1] == v


def test_tlp():
    assert normalize_tlp("TLP:WHITE") == "clear"
    assert normalize_tlp("amber+strict") == "amber+strict"
    assert normalize_tlp("") is None
    with pytest.raises(IOCError):
        normalize_tlp("tlp:purple")


def test_ioc_post_init():
    ioc = IOC("domain", "Evil.Example", description="  several   spaces ", tags=["c2", "tlp:amber", "c2", " "],
              confidence="80", first_seen=1730000000)
    assert ioc.value == "evil.example"
    assert ioc.description == "several spaces"
    assert ioc.tags == ["c2"] and ioc.tlp == "amber"
    assert ioc.confidence == 80
    assert ioc.first_seen == "2024-10-27T03:33:20Z"
    with pytest.raises(IOCError):
        IOC("domain", "evil.example", confidence=101)
    with pytest.raises(IOCError):
        IOC("domain", "evil.example", confidence="high")


def test_timestamps():
    assert normalize_timestamp("2026-11-04T10:00:00+02:00") == "2026-11-04T08:00:00Z"
    assert normalize_timestamp("2026-11-04T10:00:00.123456Z") == "2026-11-04T10:00:00Z"
    assert normalize_timestamp("2026-11-04") == "2026-11-04T00:00:00Z"
    assert normalize_timestamp(None) is None
    with pytest.raises(IOCError):
        normalize_timestamp("yesterday")


def test_dedupe_merges_tags():
    a = IOC("ipv4", "203.0.113.45", tags=["c2"])
    b = IOC("ipv4", "203.0.113.45", tags=["feed"], description="desc")
    c = IOC("ipv4", "203.0.113.46")
    result = dedupe([a, b, c])
    assert [i.value for i in result] == ["203.0.113.45", "203.0.113.46"]
    assert result[0].tags == ["c2", "feed"] and result[0].description == "desc"
    assert a.tags == ["c2"]  # does not mutate the input
