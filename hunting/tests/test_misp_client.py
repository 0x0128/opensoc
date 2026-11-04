"""MISP client against an API simulated with mocks (no real MISP needed)."""

from __future__ import annotations

from typing import Any

import pytest
import requests

from opensoc_hunting.ioc.misp import (
    EXPORTABLE_MISP_TYPES,
    MispClient,
    MispError,
    attribute_to_iocs,
    ioc_to_attribute,
)
from opensoc_hunting.ioc.model import IOC

from .conftest import FakeResponse, make_session

URL = "https://misp.lab.local"


class FakeMisp:
    """Simulates the endpoints used by the client and records the requests."""

    def __init__(self, attributes: list[dict[str, Any]] | None = None, event_attributes=None):
        self.attributes = attributes or []
        self.event_attributes = event_attributes or []
        self.calls: list[tuple[str, str, Any]] = []
        self.add_errors: dict[str, FakeResponse] = {}
        self.drop_on_create: set[str] = set()

    def __call__(self, method: str, url: str, body: Any) -> FakeResponse:
        path = url[len(URL):]
        self.calls.append((method, path, body))
        if path == "/servers/getVersion":
            return FakeResponse(200, {"version": "2.5.2"})
        if path == "/attributes/restSearch":
            source = self.event_attributes if "eventid" in body else self.attributes
            size, page = body["limit"], body["page"]
            return FakeResponse(200, {"response": {"Attribute": source[(page - 1) * size: page * size]}})
        if path == "/events/add":
            attrs = [a for a in body["Event"]["Attribute"] if a["value"] not in self.drop_on_create]
            return FakeResponse(200, {"Event": {"id": "42", "info": body["Event"]["info"], "Attribute": attrs}})
        if path.startswith("/attributes/add/"):
            if body["value"] in self.add_errors:
                return self.add_errors[body["value"]]
            return FakeResponse(200, {"Attribute": {"id": "900", **body}})
        if path.startswith("/events/publish/"):
            return FakeResponse(200, {"saved": True, "success": True})
        return FakeResponse(404, {"name": "Not Found", "message": "Not Found"})

    def paths(self, method: str | None = None) -> list[str]:
        return [p for m, p, _ in self.calls if method is None or m == method]


def client_for(fake: FakeMisp) -> MispClient:
    return MispClient(URL + "/", "test-key", verify="/ca.pem", session=make_session(fake))


def attr(type_, value, **extra):
    base = {"id": "1", "event_id": "7", "type": type_, "value": value, "to_ids": True, "comment": "",
            "timestamp": "1730000000", "Tag": [], "Event": {"id": "7", "info": "Purple team exercise"}}
    base.update(extra)
    return base


def test_headers_and_version():
    fake = FakeMisp()
    client = client_for(fake)
    assert client.get_version() == "2.5.2"
    headers = client.session.headers
    assert headers["Authorization"] == "test-key"
    assert headers["Accept"] == "application/json"
    assert client.session.request.call_args.kwargs["verify"] == "/ca.pem"


def test_from_env():
    client = MispClient.from_env({"MISP_URL": URL, "MISP_KEY": "k", "MISP_INSECURE": "true"}, session=make_session(FakeMisp()))
    assert client.verify is False
    client = MispClient.from_env({"MISP_URL": URL, "MISP_KEY": "k", "MISP_CA_BUNDLE": "/ca"}, session=make_session(FakeMisp()))
    assert client.verify == "/ca"
    with pytest.raises(MispError, match="MISP_KEY"):
        MispClient.from_env({"MISP_URL": URL})
    with pytest.raises(MispError, match="MISP_URL"):
        MispClient.from_env({"MISP_KEY": "k"})


def test_restsearch_paginates_and_filters():
    fake = FakeMisp([attr("ip-dst", f"203.0.113.{i}") for i in range(5)])
    client = client_for(fake)
    result = client.search_attributes(tags=["tlp:amber"], types=["ip-dst"], last="7d", to_ids=True, page_size=2)
    assert len(result) == 5
    bodies = [b for m, p, b in fake.calls if p == "/attributes/restSearch"]
    assert [b["page"] for b in bodies] == [1, 2, 3]
    assert bodies[0]["tags"] == ["tlp:amber"] and bodies[0]["type"] == ["ip-dst"]
    assert bodies[0]["last"] == "7d" and bodies[0]["to_ids"] == 1 and bodies[0]["returnFormat"] == "json"


def test_attribute_conversion():
    assert [(i.type, i.value) for i in attribute_to_iocs(attr("domain|ip", "evil.example|203.0.113.5"))] == [
        ("domain", "evil.example"), ("ipv4", "203.0.113.5")]
    assert [(i.type, i.value) for i in attribute_to_iocs(attr("filename|sha256", "x.exe|" + "a" * 64))] == [
        ("filename", "x.exe"), ("sha256", "a" * 64)]
    assert [(i.type, i.value) for i in attribute_to_iocs(attr("ip-src|port", "2001:db8::1|443"))] == [("ipv6", "2001:db8::1")]
    assert attribute_to_iocs(attr("yara", "rule x {}")) == []

    ioc = attribute_to_iocs(attr("ip-src", "203.0.113.7", to_ids=False, comment="Scanner",
                                 Tag=[{"name": "tlp:green"}, {"name": "osint"}]))[0]
    assert (ioc.tlp, ioc.tags, ioc.to_ids, ioc.description) == ("green", ["osint"], False, "Scanner")
    assert ioc.source == "MISP event 7: Purple team exercise"
    assert ioc.first_seen == "2024-10-27T03:33:20Z"


def test_export_iocs():
    fake = FakeMisp(event_attributes=[
        attr("ip-dst", "203.0.113.5"),
        attr("ip-src", "203.0.113.5", Tag=[{"name": "c2"}]),
        attr("url", "http://evil.example/a"),
        attr("yara", "rule x {}"),
        attr("md5", "zzz"),
    ])
    result = client_for(fake).export_iocs(event_id=7)
    assert [(i.type, i.value) for i in result.iocs] == [("ipv4", "203.0.113.5"), ("url", "http://evil.example/a")]
    assert result.iocs[0].tags == ["c2"]
    assert result.skipped == {"yara": 1}
    assert len(result.errors) == 1 and "md5" in result.errors[0].lower()
    body = fake.calls[0][2]
    assert body["eventid"] == "7" and body["type"] == EXPORTABLE_MISP_TYPES


def test_ioc_to_attribute():
    a = ioc_to_attribute(IOC("ipv4", "203.0.113.5", description="C2", tags=["lab"], tlp="amber",
                             first_seen="2026-11-01T09:00:00Z"))
    assert a == {"type": "ip-dst", "category": "Network activity", "value": "203.0.113.5", "to_ids": True,
                 "distribution": 5, "comment": "C2", "first_seen": "2026-11-01T09:00:00Z",
                 "Tag": [{"name": "lab"}, {"name": "tlp:amber"}]}
    assert ioc_to_attribute(IOC("ipv4", "203.0.113.5"), ip_type="ip-src")["type"] == "ip-src"
    assert ioc_to_attribute(IOC("sha256", "a" * 64))["category"] == "Payload delivery"
    assert ioc_to_attribute(IOC("email", "x@evil.example"))["type"] == "email-src"


def test_import_into_new_event():
    fake = FakeMisp()
    iocs = [IOC("domain", "evil.example", tlp="amber"), IOC("domain", "evil.example"), IOC("md5", "a" * 32)]
    result = client_for(fake).import_iocs(iocs, event_info="Exercise 2026-11", event_tags=["tlp:amber"], publish=True)
    assert result.event_id == "42" and len(result.added) == 2 and not result.failed
    method, path, body = fake.calls[0]
    assert (method, path) == ("POST", "/events/add")
    event = body["Event"]
    assert event["info"] == "Exercise 2026-11" and event["distribution"] == 0
    assert event["Tag"] == [{"name": "tlp:amber"}]
    assert [a["value"] for a in event["Attribute"]] == ["evil.example", "a" * 32]
    assert fake.paths()[-1] == "/events/publish/42"
    assert "2 added" in result.summary()


def test_import_new_event_with_rejected_attributes():
    fake = FakeMisp()
    fake.drop_on_create = {"b" * 32}
    result = client_for(fake).import_iocs([IOC("md5", "a" * 32), IOC("md5", "b" * 32)], event_info="x")
    assert [i.value for i in result.added] == ["a" * 32]
    assert [i.value for i, _ in result.failed] == ["b" * 32]
    assert "/events/publish/42" not in fake.paths()


def test_import_into_existing_event_skips_duplicates():
    fake = FakeMisp(event_attributes=[attr("ip-src", "203.0.113.5"), attr("domain", "already.example")])
    fake.add_errors = {
        "dup.example": FakeResponse(403, {"name": "Could not add Attribute",
                                          "message": "Could not add Attribute",
                                          "errors": {"value": ["A similar attribute already exists for this event."]}}),
        "broken.example": FakeResponse(500, {"name": "Internal error", "message": "boom"}),
    }
    iocs = [IOC("ipv4", "203.0.113.5"), IOC("domain", "already.example"), IOC("domain", "new.example"),
            IOC("domain", "dup.example"), IOC("domain", "broken.example")]
    result = client_for(fake).import_iocs(iocs, event_id=7)
    assert [i.value for i in result.added] == ["new.example"]
    assert [i.value for i in result.skipped] == ["203.0.113.5", "already.example", "dup.example"]
    assert [i.value for i, _ in result.failed] == ["broken.example"] and "500" in result.failed[0][1]
    assert fake.paths("POST").count("/attributes/add/7") == 3
    assert "1 added, 3 already existed, 1 failed" in result.summary()


def test_dry_run_does_not_write():
    fake = FakeMisp(event_attributes=[attr("domain", "already.example")])
    client = client_for(fake)
    result = client.import_iocs([IOC("domain", "already.example"), IOC("domain", "new.example")], event_id=7, dry_run=True)
    assert [i.value for i in result.added] == ["new.example"] and result.dry_run
    assert fake.paths() == ["/attributes/restSearch"]
    result = client.import_iocs([IOC("domain", "new.example")], event_info="x", dry_run=True)
    assert len(result.added) == 1 and "/events/add" not in fake.paths()


def test_import_arguments():
    client = client_for(FakeMisp())
    with pytest.raises(ValueError):
        client.import_iocs([], event_id=1, event_info="x")
    with pytest.raises(ValueError):
        client.import_iocs([])


def test_http_and_network_errors():
    fake = FakeMisp()
    client = MispClient(URL, "bad", session=make_session(
        lambda m, u, b: FakeResponse(403, {"name": "Authentication failed. Please make sure you pass the API key."})))
    with pytest.raises(MispError, match="403.*Authentication failed") as exc:
        client.get_version()
    assert exc.value.status == 403

    def refused(*a):
        raise requests.ConnectionError("refused")

    with pytest.raises(MispError, match="connect"):
        MispClient(URL, "k", session=make_session(refused)).get_version()
    with pytest.raises(MispError, match="non-JSON"):
        MispClient(URL, "k", session=make_session(lambda *a: FakeResponse(200, None, "<html>"))).get_version()
    with pytest.raises(MispError, match="unexpected"):
        MispClient(URL, "k", session=make_session(lambda *a: FakeResponse(200, {"saved": False}))).create_event("x")
    assert fake.calls == []
