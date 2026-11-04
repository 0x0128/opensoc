from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from unittest.mock import MagicMock

import pytest
import requests

HUNTING_ROOT = Path(__file__).resolve().parent.parent


class FakeResponse:
    def __init__(self, status: int = 200, payload: Any = None, text: str | None = None):
        self.status_code = status
        self._payload = payload
        self.text = text if text is not None else (json.dumps(payload) if payload is not None else "")

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("no JSON")
        return self._payload


def make_session(handler: Callable[[str, str, Any], FakeResponse]) -> MagicMock:
    """Simulated requests session: handler(method, url, json) -> FakeResponse."""
    session = MagicMock(spec=requests.Session)
    session.headers = {}
    session.request.side_effect = lambda method, url, json=None, **kw: handler(method.upper(), url, json)
    session.post.side_effect = lambda url, json=None, **kw: handler("POST", url, json)
    session.get.side_effect = lambda url, **kw: handler("GET", url, None)
    return session


class FakeClock:
    def __init__(self, start: datetime | None = None):
        self.value = start or datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)
        self.sleeps: list[float] = []

    def now(self) -> datetime:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.value += timedelta(seconds=seconds)


class FakeIndexer:
    """Replaces IndexerClient: returns scripted responses and records the queries."""

    def __init__(self, responses: list[Any] | None = None):
        self.responses = list(responses or [])
        self.bodies: list[dict[str, Any]] = []
        self.indices: list[str | None] = []

    def search(self, body, index=None):
        self.bodies.append(body)
        self.indices.append(index)
        if not self.responses:
            return alerts_response([])
        item = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(item, Exception):
            raise item
        return item


def alert(rule_id: str = "92052", mitre: list[str] | None = None, agent: str = "win10-lab",
          description: str = "Test rule", level: int = 10) -> dict[str, Any]:
    return {
        "timestamp": "2026-11-04T10:00:30.000+0000",
        "agent": {"name": agent, "id": "001"},
        "rule": {"id": rule_id, "description": description, "level": level, "mitre": {"id": mitre or ["T1059.001"]}},
    }


def alerts_response(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {"hits": {"total": {"value": len(sources)}, "hits": [{"_source": s} for s in sources]}}


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()
