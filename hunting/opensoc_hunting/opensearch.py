"""Minimal client to query the Wazuh Indexer (OpenSearch) over HTTP."""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import requests

DEFAULT_INDEX = "wazuh-alerts-*"
DEFAULT_TIME_FIELD = "timestamp"
USER_AGENT = "opensoc-hunting/0.1"


class IndexerError(RuntimeError):
    """Error while talking to the Wazuh Indexer."""


def truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "si", "sí", "on"}


def resolve_verify(insecure: bool, ca_bundle: str | None) -> bool | str:
    """Value for the ``verify`` parameter of requests."""
    if insecure:
        return False
    if ca_bundle:
        return ca_bundle
    return True


def silence_insecure_warning(verify: bool | str) -> None:
    """Warns only once (instead of on every request) when TLS verification is disabled."""
    if verify is False:
        print(
            "WARNING: TLS verification disabled. Use it only in the lab; "
            "configuring the CA with *_CA / *_CA_BUNDLE is better.",
            file=sys.stderr,
        )
        try:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:  # pragma: no cover - urllib3 always ships with requests
            pass


@dataclass
class IndexerConfig:
    url: str
    username: str | None = None
    password: str | None = None
    verify: bool | str = True
    index: str = DEFAULT_INDEX
    time_field: str = DEFAULT_TIME_FIELD
    timeout: float = 30.0

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> IndexerConfig:
        env = os.environ if env is None else env
        url = (env.get("WAZUH_INDEXER_URL") or "").strip()
        if not url:
            raise IndexerError(
                "WAZUH_INDEXER_URL is missing (e.g. https://wazuh-indexer.lab.local:9200). "
                "See .env.example."
            )
        return cls(
            url=url.rstrip("/"),
            username=env.get("WAZUH_INDEXER_USER") or None,
            password=env.get("WAZUH_INDEXER_PASSWORD") or None,
            verify=resolve_verify(truthy(env.get("WAZUH_INDEXER_INSECURE")), env.get("WAZUH_INDEXER_CA")),
            index=env.get("WAZUH_INDEXER_INDEX") or DEFAULT_INDEX,
            time_field=env.get("WAZUH_INDEXER_TIME_FIELD") or DEFAULT_TIME_FIELD,
        )


class IndexerClient:
    def __init__(self, config: IndexerConfig, session: requests.Session | None = None):
        self.config = config
        self.session = session or requests.Session()
        self.session.headers.setdefault("User-Agent", USER_AGENT)

    def search(self, body: Mapping[str, Any], index: str | None = None) -> dict[str, Any]:
        url = f"{self.config.url}/{index or self.config.index}/_search"
        auth = (self.config.username, self.config.password or "") if self.config.username else None
        try:
            response = self.session.post(
                url,
                json=body,
                auth=auth,
                verify=self.config.verify,
                timeout=self.config.timeout,
            )
        except requests.RequestException as exc:
            raise IndexerError(f"could not connect to the indexer ({url}): {exc}") from exc
        if response.status_code >= 400:
            raise IndexerError(f"the indexer answered HTTP {response.status_code}: {response.text[:500]}")
        try:
            return response.json()
        except ValueError as exc:
            raise IndexerError("the indexer response is not JSON") from exc


def hits_total(result: Mapping[str, Any]) -> int:
    total = (result.get("hits") or {}).get("total", 0)
    if isinstance(total, Mapping):
        return int(total.get("value", 0))
    return int(total or 0)


def hit_sources(result: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [hit.get("_source", {}) for hit in (result.get("hits") or {}).get("hits", [])]


def get_path(doc: Mapping[str, Any], dotted: str, default: Any = None) -> Any:
    """Reads ``a.b.c`` from both nested documents and dotted keys."""
    if dotted in doc:
        return doc[dotted]
    current: Any = doc
    for part in dotted.split("."):
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        else:
            return default
    return current
