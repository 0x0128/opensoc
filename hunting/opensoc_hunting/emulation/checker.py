"""Checking for alerts in the Wazuh Indexer after running a scenario."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..opensearch import IndexerClient, get_path, hit_sources


def iso_utc(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class Alert:
    timestamp: str
    rule_id: str
    rule_description: str
    rule_level: int
    mitre_ids: tuple[str, ...]
    agent_name: str

    @classmethod
    def from_source(cls, src: dict[str, Any], time_field: str = "timestamp") -> Alert:
        mitre = get_path(src, "rule.mitre.id", []) or []
        if isinstance(mitre, str):
            mitre = [mitre]
        return cls(
            timestamp=str(get_path(src, time_field, "") or get_path(src, "@timestamp", "")),
            rule_id=str(get_path(src, "rule.id", "")),
            rule_description=str(get_path(src, "rule.description", "")),
            rule_level=int(get_path(src, "rule.level", 0) or 0),
            mitre_ids=tuple(str(m) for m in mitre),
            agent_name=str(get_path(src, "agent.name", "")),
        )


@dataclass
class DetectionCheck:
    alerts: list[Alert] = field(default_factory=list)
    query: dict[str, Any] = field(default_factory=dict)
    polls: int = 0

    def matching(self, rule_ids: Iterable[str] | None = None) -> list[Alert]:
        if rule_ids is None:
            return list(self.alerts)
        wanted = set(rule_ids)
        return [a for a in self.alerts if a.rule_id in wanted]


def build_alert_query(
    *,
    time_field: str,
    start: datetime,
    end: datetime,
    mitre_ids: Iterable[str],
    rule_ids: Iterable[str] = (),
    agent: str | None = None,
    min_level: int = 0,
    size: int = 50,
) -> dict[str, Any]:
    """Alerts of the agent in [start, end] with the expected rule.mitre.id or rule.id."""
    should: list[dict[str, Any]] = []
    mitre_ids = list(dict.fromkeys(mitre_ids))
    rule_ids = list(dict.fromkeys(str(r) for r in rule_ids))
    if mitre_ids:
        should.append({"terms": {"rule.mitre.id": mitre_ids}})
    if rule_ids:
        should.append({"terms": {"rule.id": rule_ids}})
    if not should:
        raise ValueError("at least one technique or rule ID is required")

    filters: list[dict[str, Any]] = [
        {"range": {time_field: {"gte": iso_utc(start), "lte": iso_utc(end)}}},
        {"bool": {"should": should, "minimum_should_match": 1}},
    ]
    if min_level:
        filters.append({"range": {"rule.level": {"gte": int(min_level)}}})
    if agent:
        filters.append(
            {
                "bool": {
                    "should": [{"term": {"agent.name": agent}}, {"term": {"agent.id": agent}}],
                    "minimum_should_match": 1,
                }
            }
        )
    return {
        "size": size,
        "sort": [{time_field: {"order": "asc"}}],
        "_source": [time_field, "@timestamp", "rule.id", "rule.description", "rule.level", "rule.mitre.id", "agent.name"],
        "query": {"bool": {"filter": filters}},
    }


class DetectionChecker:
    def __init__(
        self,
        client: IndexerClient,
        *,
        time_field: str = "timestamp",
        poll_interval: float = 15.0,
        now: Callable[[], datetime] = utcnow,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.client = client
        self.time_field = time_field
        self.poll_interval = poll_interval
        self._now = now
        self._sleep = sleep

    def check_once(self, **query_kwargs: Any) -> DetectionCheck:
        query = build_alert_query(time_field=self.time_field, **query_kwargs)
        result = self.client.search(query)
        alerts = [Alert.from_source(src, self.time_field) for src in hit_sources(result)]
        return DetectionCheck(alerts=alerts, query=query, polls=1)

    def wait_for(
        self,
        *,
        start: datetime,
        deadline: datetime,
        accept: Callable[[DetectionCheck], bool] = lambda c: bool(c.alerts),
        end_margin: float = 60.0,
        **query_kwargs: Any,
    ) -> DetectionCheck:
        """Polls until ``accept`` is true or ``deadline`` has passed.

        The end of the window is "now + end_margin" to tolerate clock skew
        between the agent and the indexer.
        """
        polls = 0
        while True:
            polls += 1
            now = self._now()
            end = datetime.fromtimestamp(now.timestamp() + end_margin, tz=timezone.utc)
            check = self.check_once(start=start, end=end, **query_kwargs)
            check.polls = polls
            if accept(check) or now >= deadline:
                return check
            remaining = (deadline - now).total_seconds()
            self._sleep(max(0.0, min(self.poll_interval, remaining)))
