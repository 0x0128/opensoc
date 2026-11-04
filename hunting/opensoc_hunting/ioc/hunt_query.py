"""Generates an OpenSearch query to sweep the Wazuh indices with a list of IOCs (H15)."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .model import IOC

# Fields of the wazuh-alerts-*/wazuh-archives-* indices where each type usually appears.
FIELDS = {
    "ip": [
        "data.srcip",
        "data.dstip",
        "data.src_ip",
        "data.dest_ip",
        "data.win.eventdata.destinationIp",
        "data.win.eventdata.sourceIp",
        "data.win.eventdata.ipAddress",
    ],
    "domain": [
        "data.win.eventdata.queryName",
        "data.win.eventdata.destinationHostname",
        "data.dns.rrname",
        "data.http.hostname",
        "data.tls.sni",
    ],
    "url": ["data.url", "data.http.url"],
    "md5": ["syscheck.md5_after"],
    "sha1": ["syscheck.sha1_after"],
    "sha256": ["syscheck.sha256_after"],
    # Sysmon stores "SHA256=...,MD5=...,IMPHASH=..." in a single field.
    "hash_wildcard": ["data.win.eventdata.hashes"],
    "filename": ["data.win.eventdata.targetFilename", "data.win.eventdata.image", "syscheck.path"],
}

MAX_WILDCARDS = 500


def build_hunt_query(
    iocs: Iterable[IOC],
    *,
    time_field: str = "timestamp",
    since: str = "now-7d",
    include_filenames: bool = False,
    only_to_ids: bool = True,
    size: int = 200,
) -> tuple[dict[str, Any], list[str]]:
    """Returns (query, warnings)."""
    warnings: list[str] = []
    ips: list[str] = []
    domains: list[str] = []
    urls: list[str] = []
    hashes: dict[str, list[str]] = {"md5": [], "sha1": [], "sha256": []}
    filenames: list[str] = []
    for ioc in iocs:
        if only_to_ids and not ioc.to_ids:
            continue
        if ioc.type in {"ipv4", "ipv6"}:
            if "/" in ioc.value:
                warnings.append(f"range {ioc.value} skipped: the Wazuh IP fields are keywords and do not support CIDR")
                continue
            ips.append(ioc.value)
        elif ioc.type in {"domain", "hostname"}:
            domains.append(ioc.value)
        elif ioc.type == "url":
            urls.append(ioc.value)
        elif ioc.type in hashes:
            hashes[ioc.type].append(ioc.value)
        elif ioc.type == "filename":
            if include_filenames:
                filenames.append(ioc.value)
        else:
            warnings.append(f"{ioc.type} {ioc.value} skipped: there are no usual Wazuh fields for that type")

    should: list[dict[str, Any]] = []

    def terms(fields: list[str], values: list[str]) -> None:
        if values:
            should.extend({"terms": {f: sorted(set(values))}} for f in fields)

    terms(FIELDS["ip"], ips)
    terms(FIELDS["domain"], domains)
    terms(FIELDS["url"], urls)
    for hash_type, values in hashes.items():
        terms(FIELDS[hash_type], values)

    wildcards = 0
    all_hashes = sorted({v for values in hashes.values() for v in values})
    for value in all_hashes:
        for f in FIELDS["hash_wildcard"]:
            should.append({"wildcard": {f: {"value": f"*{value}*", "case_insensitive": True}}})
            wildcards += 1
    for value in sorted(set(filenames)):
        escaped = value.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")
        for f in FIELDS["filename"]:
            should.append({"wildcard": {f: {"value": f"*{escaped}", "case_insensitive": True}}})
            wildcards += 1
    if wildcards > MAX_WILDCARDS:
        warnings.append(
            f"{wildcards} wildcard clauses: the query may be slow; split the IOC list"
        )
    if not should:
        warnings.append("no usable IOC for the query")

    query = {
        "size": size,
        "sort": [{time_field: {"order": "desc"}}],
        "_source": [time_field, "agent.name", "rule.id", "rule.description", "location", "data", "syscheck.path"],
        "query": {
            "bool": {
                "filter": [{"range": {time_field: {"gte": since}}}],
                "should": should,
                "minimum_should_match": 1,
            }
        },
        "aggs": {"by_agent": {"terms": {"field": "agent.name", "size": 50}}},
    }
    return query, warnings
