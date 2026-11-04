"""Minimal MISP REST client to import and export IOCs.

It only uses the documented REST API (``/attributes/restSearch``, ``/events/add``,
``/attributes/add/{id}``, ``/events/publish/{id}``, ``/servers/getVersion``),
so PyMISP is not needed and the tests can simulate the HTTP session.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

import requests

from ..opensearch import resolve_verify, truthy
from .model import IOC, IOCError, dedupe

USER_AGENT = "opensoc-hunting/0.1"

# Internal type -> (MISP type, MISP category)
IOC_TO_MISP = {
    "ipv4": ("ip-dst", "Network activity"),
    "ipv6": ("ip-dst", "Network activity"),
    "domain": ("domain", "Network activity"),
    "hostname": ("hostname", "Network activity"),
    "url": ("url", "Network activity"),
    "email": ("email-src", "Payload delivery"),
    "md5": ("md5", "Payload delivery"),
    "sha1": ("sha1", "Payload delivery"),
    "sha256": ("sha256", "Payload delivery"),
    "filename": ("filename", "Payload delivery"),
}

_SIMPLE_MISP_TYPES = {
    "ip-src": "ip",
    "ip-dst": "ip",
    "domain": "domain",
    "hostname": "hostname",
    "url": "url",
    "email": "email",
    "email-src": "email",
    "email-dst": "email",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "filename": "filename",
}
# Composite types "a|b" -> types of each part (None = that part is discarded)
_COMPOSITE_MISP_TYPES = {
    "ip-src|port": ("ip", None),
    "ip-dst|port": ("ip", None),
    "domain|ip": ("domain", "ip"),
    "hostname|port": ("hostname", None),
    "filename|md5": ("filename", "md5"),
    "filename|sha1": ("filename", "sha1"),
    "filename|sha256": ("filename", "sha256"),
}
EXPORTABLE_MISP_TYPES = sorted(set(_SIMPLE_MISP_TYPES) | set(_COMPOSITE_MISP_TYPES))

DISTRIBUTION_ORG_ONLY = 0
THREAT_LEVEL_UNDEFINED = 4
ANALYSIS_INITIAL = 0


class MispError(RuntimeError):
    """Error returned by MISP, or connection error."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


@dataclass
class ImportResult:
    event_id: str | None = None
    added: list[IOC] = field(default_factory=list)
    skipped: list[IOC] = field(default_factory=list)
    failed: list[tuple[IOC, str]] = field(default_factory=list)
    dry_run: bool = False

    def summary(self) -> str:
        prefix = "[dry run] " if self.dry_run else ""
        return (
            f"{prefix}event {self.event_id or '(new)'}: {len(self.added)} added, "
            f"{len(self.skipped)} already existed, {len(self.failed)} failed"
        )


@dataclass
class ExportResult:
    iocs: list[IOC] = field(default_factory=list)
    skipped: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


# ------------------------------------------------------------------ conversion
def _ip_type(value: str) -> str:
    return "ipv6" if ":" in value else "ipv4"


def _tag_names(attribute: Mapping[str, Any]) -> list[str]:
    tags = attribute.get("Tag") or []
    return [str(t.get("name")) for t in tags if isinstance(t, Mapping) and t.get("name")]


def attribute_to_iocs(attribute: Mapping[str, Any]) -> list[IOC]:
    """Converts a MISP attribute into 0, 1 or 2 IOCs (composite types are split)."""
    misp_type = str(attribute.get("type", ""))
    value = str(attribute.get("value", ""))
    if misp_type in _SIMPLE_MISP_TYPES:
        parts = [(_SIMPLE_MISP_TYPES[misp_type], value)]
    elif misp_type in _COMPOSITE_MISP_TYPES:
        left, _, right = value.partition("|")
        kinds = _COMPOSITE_MISP_TYPES[misp_type]
        parts = [(kind, part) for kind, part in zip(kinds, (left, right), strict=True) if kind and part]
    else:
        return []

    tags = _tag_names(attribute)
    event = attribute.get("Event") if isinstance(attribute.get("Event"), Mapping) else {}
    event_id = attribute.get("event_id") or event.get("id")
    source = f"MISP event {event_id}" if event_id else "MISP"
    if event.get("info"):
        source += f": {event['info']}"
    first_seen = attribute.get("first_seen") or attribute.get("timestamp")

    iocs = []
    for kind, part in parts:
        ioc_type = _ip_type(part) if kind == "ip" else kind
        iocs.append(
            IOC(
                type=ioc_type,
                value=part,
                description=str(attribute.get("comment") or ""),
                tags=list(tags),
                first_seen=first_seen,
                source=source,
                to_ids=bool(attribute.get("to_ids", True)),
            )
        )
    return iocs


def ioc_to_attribute(ioc: IOC, *, ip_type: str = "ip-dst") -> dict[str, Any]:
    misp_type, category = IOC_TO_MISP[ioc.type]
    if ioc.type in {"ipv4", "ipv6"}:
        misp_type = ip_type
    attribute: dict[str, Any] = {
        "type": misp_type,
        "category": category,
        "value": ioc.value,
        "to_ids": ioc.to_ids,
        "distribution": 5,  # inherits the distribution of the event
    }
    if ioc.description:
        attribute["comment"] = ioc.description[:65535]
    if ioc.first_seen:
        attribute["first_seen"] = ioc.first_seen
    tags = list(ioc.tags)
    if ioc.tlp:
        tags.append(f"tlp:{ioc.tlp}")
    if tags:
        attribute["Tag"] = [{"name": t} for t in tags]
    return attribute


# ----------------------------------------------------------------------- client
class MispClient:
    def __init__(
        self,
        url: str,
        key: str,
        *,
        verify: bool | str = True,
        timeout: float = 30.0,
        session: requests.Session | None = None,
    ):
        if not url:
            raise MispError("the MISP URL (MISP_URL) is missing")
        if not key:
            raise MispError("the MISP API key (MISP_KEY) is missing")
        self.url = url.rstrip("/")
        self.verify = verify
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "Authorization": key,
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
            }
        )

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, **kwargs: Any) -> MispClient:
        env = os.environ if env is None else env
        verify = resolve_verify(truthy(env.get("MISP_INSECURE")), env.get("MISP_CA_BUNDLE"))
        return cls(env.get("MISP_URL", ""), env.get("MISP_KEY", ""), verify=verify, **kwargs)

    # ------------------------------------------------------------------ HTTP
    def _request(self, method: str, path: str, payload: Any = None) -> Any:
        url = f"{self.url}/{path.lstrip('/')}"
        try:
            response = self.session.request(method, url, json=payload, verify=self.verify, timeout=self.timeout)
        except requests.RequestException as exc:
            raise MispError(f"could not connect to MISP ({url}): {exc}") from exc
        try:
            data = response.json()
        except ValueError:
            data = None
        if response.status_code >= 400:
            message = ""
            if isinstance(data, Mapping):
                message = str(data.get("message") or data.get("name") or "")
                errors = data.get("errors")
                if errors:
                    message = f"{message} {errors}".strip()
            raise MispError(
                f"MISP answered HTTP {response.status_code} on {path}: {message or response.text[:300]}",
                status=response.status_code,
            )
        if data is None:
            raise MispError(f"non-JSON response from MISP on {path}")
        return data

    def get_version(self) -> str:
        return str(self._request("GET", "/servers/getVersion").get("version", ""))

    # -------------------------------------------------------------- export
    def search_attributes(
        self,
        *,
        event_id: str | int | None = None,
        tags: Iterable[str] | None = None,
        types: Iterable[str] | None = None,
        last: str | None = None,
        to_ids: bool | None = None,
        published: bool | None = None,
        page_size: int = 500,
        max_pages: int = 200,
    ) -> list[dict[str, Any]]:
        body: dict[str, Any] = {"returnFormat": "json", "limit": page_size, "includeEventTags": True}
        if event_id is not None:
            body["eventid"] = str(event_id)
        if tags:
            body["tags"] = list(tags)
        if types:
            body["type"] = list(types)
        if last:
            body["last"] = last
        if to_ids is not None:
            body["to_ids"] = 1 if to_ids else 0
        if published is not None:
            body["published"] = published

        attributes: list[dict[str, Any]] = []
        for page in range(1, max_pages + 1):
            data = self._request("POST", "/attributes/restSearch", {**body, "page": page})
            batch = (data.get("response") or {}).get("Attribute") or [] if isinstance(data, Mapping) else []
            attributes.extend(batch)
            if len(batch) < page_size:
                break
        return attributes

    def export_iocs(self, **filters: Any) -> ExportResult:
        if not filters.get("types"):
            filters["types"] = EXPORTABLE_MISP_TYPES
        result = ExportResult()
        collected: list[IOC] = []
        for attribute in self.search_attributes(**filters):
            try:
                iocs = attribute_to_iocs(attribute)
            except IOCError as exc:
                result.errors.append(f"attribute {attribute.get('id')}: {exc}")
                continue
            if not iocs:
                kind = str(attribute.get("type"))
                result.skipped[kind] = result.skipped.get(kind, 0) + 1
            collected.extend(iocs)
        result.iocs = dedupe(collected)
        return result

    # -------------------------------------------------------------- import
    def create_event(
        self,
        info: str,
        *,
        iocs: Iterable[IOC] = (),
        tags: Iterable[str] = (),
        distribution: int = DISTRIBUTION_ORG_ONLY,
        threat_level_id: int = THREAT_LEVEL_UNDEFINED,
        analysis: int = ANALYSIS_INITIAL,
        ip_type: str = "ip-dst",
    ) -> dict[str, Any]:
        event: dict[str, Any] = {
            "info": info,
            "distribution": distribution,
            "threat_level_id": threat_level_id,
            "analysis": analysis,
            "Attribute": [ioc_to_attribute(i, ip_type=ip_type) for i in iocs],
        }
        tag_list = list(dict.fromkeys(tags))
        if tag_list:
            event["Tag"] = [{"name": t} for t in tag_list]
        data = self._request("POST", "/events/add", {"Event": event})
        created = data.get("Event") if isinstance(data, Mapping) else None
        if not isinstance(created, Mapping) or not created.get("id"):
            raise MispError(f"unexpected response when creating the event: {str(data)[:300]}")
        return dict(created)

    def existing_keys(self, event_id: str | int) -> set[tuple[str, str]]:
        keys: set[tuple[str, str]] = set()
        for attribute in self.search_attributes(event_id=event_id):
            keys.add((str(attribute.get("type")), str(attribute.get("value"))))
            try:
                keys.update(("ioc", f"{i.type}|{i.value}") for i in attribute_to_iocs(attribute))
            except IOCError:
                pass
        return keys

    def add_attribute(self, event_id: str | int, ioc: IOC, *, ip_type: str = "ip-dst") -> dict[str, Any]:
        data = self._request("POST", f"/attributes/add/{event_id}", ioc_to_attribute(ioc, ip_type=ip_type))
        return dict(data.get("Attribute") or {}) if isinstance(data, Mapping) else {}

    def publish(self, event_id: str | int) -> None:
        self._request("POST", f"/events/publish/{event_id}")

    def import_iocs(
        self,
        iocs: Iterable[IOC],
        *,
        event_id: str | int | None = None,
        event_info: str | None = None,
        event_tags: Iterable[str] = (),
        distribution: int = DISTRIBUTION_ORG_ONLY,
        ip_type: str = "ip-dst",
        publish: bool = False,
        dry_run: bool = False,
    ) -> ImportResult:
        iocs = dedupe(iocs)
        if (event_id is None) == (event_info is None):
            raise ValueError("pass event_id (existing event) or event_info (new event), not both")

        if event_id is None:
            result = ImportResult(dry_run=dry_run)
            if dry_run:
                result.added = list(iocs)
                return result
            created = self.create_event(
                str(event_info), iocs=iocs, tags=event_tags, distribution=distribution, ip_type=ip_type
            )
            result.event_id = str(created["id"])
            result.added = list(iocs)
            returned = created.get("Attribute")
            if isinstance(returned, list) and len(returned) < len(iocs):
                stored = {(str(a.get("type")), str(a.get("value"))) for a in returned}
                result.added = []
                for ioc in iocs:
                    attr = ioc_to_attribute(ioc, ip_type=ip_type)
                    if (attr["type"], attr["value"]) in stored:
                        result.added.append(ioc)
                    else:
                        result.failed.append((ioc, "MISP did not store the attribute (check the MISP log)"))
            if publish:
                self.publish(result.event_id)
            return result

        result = ImportResult(event_id=str(event_id), dry_run=dry_run)
        existing = self.existing_keys(event_id)
        for ioc in iocs:
            attr = ioc_to_attribute(ioc, ip_type=ip_type)
            if (attr["type"], attr["value"]) in existing or ("ioc", f"{ioc.type}|{ioc.value}") in existing:
                result.skipped.append(ioc)
                continue
            if dry_run:
                result.added.append(ioc)
                continue
            try:
                self.add_attribute(event_id, ioc, ip_type=ip_type)
                result.added.append(ioc)
            except MispError as exc:
                # MISP answers 403 "A similar attribute already exists for this event".
                if exc.status == 403 and "already exists" in str(exc).lower():
                    result.skipped.append(ioc)
                else:
                    result.failed.append((ioc, str(exc)))
        if publish and not dry_run and result.added:
            self.publish(event_id)
        return result
