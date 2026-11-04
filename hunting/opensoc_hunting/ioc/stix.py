"""IOC <-> STIX 2.1 conversion without external dependencies.

Export: a ``bundle`` with an ``identity`` (producer), the TLP ``marking-definition``
objects in use and one ``indicator`` per IOC with a STIX pattern. Indicator IDs
are UUIDv5 of (type, value), so exporting the same IOC twice produces the
same ID (consumers see it as a new version, not as a duplicate).

IOCs with ``to_ids=False`` (context, not suitable for detection) are exported as
``observed-data`` + observable (SCO), which is what MISP does too. Since
observed-data has no description, the text is stored in a ``note`` object.

Import: ``indicator`` (simple patterns, or compound ones with OR/AND of
``=`` comparisons), ``observed-data`` and standalone observables (ipv4-addr,
domain-name, url, file...). Anything that is not an indicator is imported with to_ids=False.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .model import IOC, IOCError, dedupe, normalize_timestamp

# OpenSOC namespace for its UUIDv5 identifiers.
OPENSOC_NAMESPACE = uuid.UUID("6f1c7a3e-2b55-5d0e-9a43-0c5b7d2e9f10")
# Namespace from the specification for deterministic SCO IDs (STIX 2.1, 2.9).
SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

# TLP marking definitions predefined in STIX 2.1 (section 7.2.1.4 of the specification).
TLP_MARKINGS = {
    "clear": ("marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9", "white"),
    "green": ("marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da", "green"),
    "amber": ("marking-definition--f88d31f6-486f-44da-b317-01333bde0b82", "amber"),
    "red": ("marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed", "red"),
}
_MARKING_TO_TLP = {mid: level for level, (mid, _) in TLP_MARKINGS.items()}
_TLP_NAME_TO_LEVEL = {"white": "clear", "clear": "clear", "green": "green", "amber": "amber",
                      "amber+strict": "amber+strict", "red": "red"}

_PATTERN_PATHS = {
    "ipv4": "ipv4-addr:value",
    "ipv6": "ipv6-addr:value",
    "domain": "domain-name:value",
    "hostname": "domain-name:value",
    "url": "url:value",
    "email": "email-addr:value",
    "md5": "file:hashes.MD5",
    "sha1": "file:hashes.'SHA-1'",
    "sha256": "file:hashes.'SHA-256'",
    "filename": "file:name",
}

_COMPARISON_RE = re.compile(
    r"(?P<path>[a-z0-9-]+:[A-Za-z0-9_.'\-\[\]*]+)\s*(?P<op>!=|<=|>=|=|<|>|\bNOT\s+LIKE\b|\bLIKE\b|\bMATCHES\b|\bIN\b)\s*"
    r"(?P<literal>'(?:[^'\\]|\\.)*'|\([^)]*\)|[^\s\]]+)",
    re.I,
)
_STRING_RE = re.compile(r"'(?:[^'\\]|\\.)*'")


@dataclass
class StixImportReport:
    iocs: list[IOC] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def stix_timestamp(moment: datetime | None = None) -> str:
    moment = (moment or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def _stix_from_iso(value: str) -> str:
    """'2026-11-04T10:00:00Z' -> '2026-11-04T10:00:00.000Z'"""
    moment = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return stix_timestamp(moment)


def escape_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def unescape_literal(value: str) -> str:
    return re.sub(r"\\(.)", r"\1", value)


def build_pattern(ioc: IOC) -> str:
    return f"[{_PATTERN_PATHS[ioc.type]} = '{escape_literal(ioc.value)}']"


def indicator_id(ioc: IOC) -> str:
    return f"indicator--{uuid.uuid5(OPENSOC_NAMESPACE, f'{ioc.type}|{ioc.value}')}"


def identity_id(name: str) -> str:
    return f"identity--{uuid.uuid5(OPENSOC_NAMESPACE, 'identity|' + name)}"


_SCO_TYPES = {
    "ipv4": "ipv4-addr",
    "ipv6": "ipv6-addr",
    "domain": "domain-name",
    "hostname": "domain-name",
    "url": "url",
    "email": "email-addr",
}
_SCO_HASH_NAMES = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}


def build_sco(ioc: IOC) -> dict[str, Any]:
    """STIX 2.1 observable with a deterministic ID (UUIDv5 of its identifying properties)."""
    if ioc.type in _SCO_TYPES:
        sco_type, contributing = _SCO_TYPES[ioc.type], {"value": ioc.value}
    elif ioc.type in _SCO_HASH_NAMES:
        sco_type, contributing = "file", {"hashes": {_SCO_HASH_NAMES[ioc.type]: ioc.value}}
    else:  # filename
        sco_type, contributing = "file", {"name": ioc.value}
    canonical = json.dumps(contributing, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    sco = {"type": sco_type, "spec_version": "2.1", "id": f"{sco_type}--{uuid.uuid5(SCO_NAMESPACE, canonical)}"}
    sco.update(contributing)
    return sco


def tlp_marking_object(level: str) -> dict[str, Any]:
    marking_id, name = TLP_MARKINGS[level]
    return {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": marking_id,
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": f"TLP:{name.upper()}",
        "definition": {"tlp": name},
    }


def _marking_level(tlp: str) -> str:
    # TLP 2.0 AMBER+STRICT has no predefined marking in STIX 2.1: it is marked as
    # AMBER and the exact level is kept in the "tlp:amber+strict" label.
    return "amber" if tlp == "amber+strict" else tlp


def to_stix_bundle(
    iocs: Iterable[IOC],
    *,
    producer: str = "OpenSOC Lab",
    now: datetime | None = None,
    indicator_types: tuple[str, ...] = ("malicious-activity",),
) -> dict[str, Any]:
    ts = stix_timestamp(now)
    producer_id = identity_id(producer)
    objects: list[dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": producer_id,
            "created": ts,
            "modified": ts,
            "name": producer,
            "identity_class": "organization",
        }
    ]
    used_levels: list[str] = []
    payload: list[dict[str, Any]] = []
    seen_scos: set[str] = set()
    for ioc in dedupe(iocs):
        common: dict[str, Any] = {"created": ts, "modified": ts, "created_by_ref": producer_id}
        labels = list(ioc.tags)
        if ioc.tlp == "amber+strict":
            labels.append("tlp:amber+strict")
        if labels:
            common["labels"] = labels
        if ioc.confidence is not None:
            common["confidence"] = ioc.confidence
        if ioc.source:
            common["external_references"] = [{"source_name": ioc.source, "description": "IOC source"}]
        markings: list[str] = []
        if ioc.tlp:
            level = _marking_level(ioc.tlp)
            markings = [TLP_MARKINGS[level][0]]
            common["object_marking_refs"] = markings
            if level not in used_levels:
                used_levels.append(level)
        first = _stix_from_iso(ioc.first_seen) if ioc.first_seen else ts

        if ioc.to_ids:
            indicator: dict[str, Any] = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id(ioc),
                **common,
                "name": f"{ioc.type}: {ioc.value}",
                "indicator_types": list(indicator_types),
                "pattern": build_pattern(ioc),
                "pattern_type": "stix",
                "pattern_version": "2.1",
                "valid_from": first,
            }
            if ioc.description:
                indicator["description"] = ioc.description
            payload.append(indicator)
        else:
            sco = build_sco(ioc)
            if markings:
                sco["object_marking_refs"] = markings
            if sco["id"] not in seen_scos:
                seen_scos.add(sco["id"])
                payload.append(sco)
            observed_id = f"observed-data--{uuid.uuid5(OPENSOC_NAMESPACE, f'observed|{ioc.type}|{ioc.value}')}"
            payload.append(
                {
                    "type": "observed-data",
                    "spec_version": "2.1",
                    "id": observed_id,
                    **common,
                    "first_observed": first,
                    "last_observed": max(first, ts),
                    "number_observed": 1,
                    "object_refs": [sco["id"]],
                }
            )
            if ioc.description:
                # observed-data has no "description": the text travels in a note.
                note = {
                    "type": "note",
                    "spec_version": "2.1",
                    "id": f"note--{uuid.uuid5(OPENSOC_NAMESPACE, 'note|' + observed_id)}",
                    "created": ts,
                    "modified": ts,
                    "created_by_ref": producer_id,
                    "content": ioc.description,
                    "object_refs": [observed_id],
                }
                if markings:
                    note["object_marking_refs"] = markings
                payload.append(note)
    objects += [tlp_marking_object(level) for level in used_levels]
    objects += payload
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


# ---------------------------------------------------------------------- import
def _path_to_type(path: str, value: str) -> str | None:
    obj, _, prop = path.partition(":")
    prop_norm = prop.replace("'", "").replace('"', "").lower()
    if obj in {"ipv4-addr", "ipv6-addr"} and prop_norm == "value":
        return "ipv4" if obj == "ipv4-addr" else "ipv6"
    if obj == "network-traffic" and prop_norm in {"dst_ref.value", "src_ref.value"}:
        return "ipv6" if ":" in value else "ipv4"
    if obj == "domain-name" and prop_norm == "value":
        return "domain"
    if obj == "url" and prop_norm == "value":
        return "url"
    if obj == "email-addr" and prop_norm == "value":
        return "email"
    if obj == "email-message" and prop_norm in {"from_ref.value", "sender_ref.value"}:
        return "email"
    if obj == "file":
        if prop_norm in {"hashes.md5"}:
            return "md5"
        if prop_norm in {"hashes.sha-1", "hashes.sha1"}:
            return "sha1"
        if prop_norm in {"hashes.sha-256", "hashes.sha256"}:
            return "sha256"
        if prop_norm == "name":
            return "filename"
    return None


def parse_pattern(pattern: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Extracts (type, value) from the supported ``=`` comparisons of the pattern."""
    found: list[tuple[str, str]] = []
    warnings: list[str] = []
    for match in _COMPARISON_RE.finditer(pattern):
        path, op, literal = match.group("path"), match.group("op").upper(), match.group("literal")
        if op != "=" or not literal.startswith("'"):
            warnings.append(f"unsupported comparison ignored: {match.group(0)!r}")
            continue
        value = unescape_literal(literal[1:-1])
        ioc_type = _path_to_type(path, value)
        if ioc_type is None:
            warnings.append(f"unsupported object/property: {path}")
            continue
        found.append((ioc_type, value))
    skeleton = _STRING_RE.sub("''", pattern).upper()
    if re.search(r"\b(FOLLOWEDBY|WITHIN|REPEATS|START)\b", skeleton):
        warnings.append("pattern with temporal operators: the observables are extracted separately")
    elif re.search(r"\bAND\b", skeleton) and len(found) > 1:
        warnings.append("compound pattern with AND: the observables are extracted separately")
    if not found and not warnings:
        warnings.append("no comparison recognized in the pattern")
    return found, warnings


def _collect_markings(objects: list[Mapping[str, Any]]) -> dict[str, str]:
    markings = dict(_MARKING_TO_TLP)
    for obj in objects:
        if obj.get("type") != "marking-definition":
            continue
        name = str(obj.get("name") or "")
        level = None
        if name.upper().startswith("TLP:"):
            level = _TLP_NAME_TO_LEVEL.get(name[4:].strip().lower())
        elif isinstance(obj.get("definition"), Mapping) and "tlp" in obj["definition"]:
            level = _TLP_NAME_TO_LEVEL.get(str(obj["definition"]["tlp"]).lower())
        if level:
            markings[str(obj.get("id"))] = level
    return markings


def _tlp_from(obj: Mapping[str, Any], markings: Mapping[str, str], labels: list[str]) -> tuple[str | None, list[str]]:
    tlp = None
    for ref in obj.get("object_marking_refs") or []:
        if ref in markings:
            tlp = markings[ref]
            break
    remaining = []
    for label in labels:
        if label.lower().startswith("tlp:"):
            # The label (e.g. tlp:amber+strict) is more precise than the marking.
            tlp = _TLP_NAME_TO_LEVEL.get(label[4:].lower(), tlp)
        else:
            remaining.append(label)
    return tlp, remaining


def _source_for(obj: Mapping[str, Any], identities: Mapping[str, str]) -> str:
    refs = obj.get("external_references") or []
    if refs and isinstance(refs[0], Mapping) and refs[0].get("source_name"):
        return str(refs[0]["source_name"])
    return identities.get(str(obj.get("created_by_ref")), "")


def _is_expired(obj: Mapping[str, Any]) -> bool:
    valid_until = obj.get("valid_until")
    if not valid_until:
        return False
    try:
        until = datetime.fromisoformat(str(valid_until).replace("Z", "+00:00"))
    except ValueError:
        return False
    return until < datetime.now(timezone.utc)


_GENERATED_NAME_RE = re.compile(r"^(ipv4|ipv6|domain|hostname|url|email|md5|sha1|sha256|filename): ")


def _indicator_description(obj: Mapping[str, Any]) -> str:
    """description or, if there is none, name (except the "type: value" generated by this tool)."""
    if obj.get("description"):
        return str(obj["description"])
    name = str(obj.get("name") or "")
    return "" if _GENERATED_NAME_RE.match(name) else name


def _first_seen(obj: Mapping[str, Any], prop: str) -> str | None:
    """valid_from/first_observed equal to created is usually a default value: it is not used as first_seen."""
    value = obj.get(prop)
    if not value or value == obj.get("created"):
        return None
    try:
        return normalize_timestamp(value)
    except IOCError:
        return None


def _sco_values(obj: Mapping[str, Any]) -> list[tuple[str, str]]:
    otype = obj.get("type")
    value = obj.get("value")
    if otype == "ipv4-addr" and value:
        return [("ipv4", value)]
    if otype == "ipv6-addr" and value:
        return [("ipv6", value)]
    if otype == "domain-name" and value:
        return [("domain", value)]
    if otype == "url" and value:
        return [("url", value)]
    if otype == "email-addr" and value:
        return [("email", value)]
    if otype == "file":
        out = []
        hashes = {str(k).replace("-", "").lower(): v for k, v in (obj.get("hashes") or {}).items()}
        for name in ("md5", "sha1", "sha256"):
            if hashes.get(name):
                out.append((name, hashes[name]))
        if obj.get("name"):
            out.append(("filename", obj["name"]))
        return out
    return []


def from_stix(data: Mapping[str, Any] | list[Any]) -> StixImportReport:
    """Imports a STIX 2.1 bundle (or a list of objects / a single object)."""
    report = StixImportReport()
    if isinstance(data, list):
        objects = data
    elif isinstance(data, Mapping) and data.get("type") == "bundle":
        objects = data.get("objects") or []
    elif isinstance(data, Mapping) and data.get("type"):
        objects = [data]
    else:
        report.errors.append("the JSON is neither a bundle nor a STIX object")
        return report
    objects = [o for o in objects if isinstance(o, Mapping)]
    if any(o.get("spec_version") not in (None, "2.1") for o in objects):
        report.warnings.append("some objects have a spec_version other than 2.1; trying to import them anyway")

    markings = _collect_markings(objects)
    identities = {str(o["id"]): str(o.get("name", "")) for o in objects if o.get("type") == "identity" and o.get("id")}
    collected: list[IOC] = []

    for obj in objects:
        if obj.get("type") != "indicator":
            continue
        oid = obj.get("id", "indicator")
        if obj.get("revoked"):
            report.warnings.append(f"{oid}: revoked, ignored")
            continue
        if obj.get("pattern_type", "stix") != "stix":
            report.warnings.append(f"{oid}: unsupported pattern_type {obj.get('pattern_type')!r}")
            continue
        pairs, warnings = parse_pattern(str(obj.get("pattern", "")))
        report.warnings += [f"{oid}: {w}" for w in warnings]
        expired = _is_expired(obj)
        if expired:
            report.warnings.append(f"{oid}: valid_until has passed, imported with to_ids=false")
        tlp, tags = _tlp_from(obj, markings, [str(label) for label in obj.get("labels") or []])
        for ioc_type, value in pairs:
            try:
                collected.append(
                    IOC(
                        type=ioc_type,
                        value=value,
                        description=_indicator_description(obj),
                        tags=tags,
                        tlp=tlp,
                        confidence=obj.get("confidence"),
                        first_seen=_first_seen(obj, "valid_from"),
                        source=_source_for(obj, identities),
                        to_ids=not expired,
                    )
                )
            except IOCError as exc:
                report.errors.append(f"{oid}: {exc}")

    scos = {str(o.get("id")): o for o in objects if _sco_values(o)}
    notes: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") == "note" and obj.get("content"):
            for ref in obj.get("object_refs") or []:
                notes.setdefault(str(ref), str(obj["content"]))
    consumed: set[str] = set()
    for obj in objects:
        if obj.get("type") != "observed-data":
            continue
        refs = [scos[r] for r in obj.get("object_refs") or [] if r in scos]
        consumed.update(str(r.get("id")) for r in refs)
        embedded = obj.get("objects")  # STIX 2.0 form, deprecated in 2.1
        if isinstance(embedded, Mapping):
            refs += [o for o in embedded.values() if isinstance(o, Mapping)]
        tlp, tags = _tlp_from(obj, markings, [str(label) for label in obj.get("labels") or []])
        for sco in refs:
            for ioc_type, value in _sco_values(sco):
                try:
                    collected.append(
                        IOC(
                            type=ioc_type,
                            value=value,
                            description=notes.get(str(obj.get("id")), ""),
                            tags=tags,
                            tlp=tlp or _tlp_from(sco, markings, [])[0],
                            confidence=obj.get("confidence"),
                            first_seen=_first_seen(obj, "first_observed"),
                            source=_source_for(obj, identities),
                            to_ids=False,
                        )
                    )
                except IOCError as exc:
                    report.errors.append(f"{obj.get('id', 'observed-data')}: {exc}")

    for sco_id, obj in scos.items():
        if sco_id in consumed:
            continue
        tlp, _ = _tlp_from(obj, markings, [])
        for ioc_type, value in _sco_values(obj):
            try:
                collected.append(IOC(type=ioc_type, value=value, tlp=tlp, to_ids=False))
            except IOCError as exc:
                report.errors.append(f"{sco_id}: {exc}")

    report.iocs = dedupe(collected)
    return report
