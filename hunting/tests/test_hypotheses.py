from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from opensoc_hunting import hunts
from opensoc_hunting.hunts import (
    REQUIRED_SECTIONS,
    HypothesisError,
    apply_time_range,
    load_hypotheses,
    parse_hypothesis,
    summarize,
)
from opensoc_hunting.ioc.fileio import load_iocs
from opensoc_hunting.ioc.hunt_query import build_hunt_query
from opensoc_hunting.mitre import is_technique

from .conftest import HUNTING_ROOT

ALLOWED_INDICES = {"wazuh-alerts-*", "wazuh-archives-*"}


@pytest.fixture(scope="module")
def hypotheses():
    return load_hypotheses()


def _walk(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item)


def test_there_are_fifteen_numbered_hypotheses(hypotheses):
    assert [h.id for h in hypotheses] == [f"H{i:02d}" for i in range(1, 16)]
    assert len({h.title for h in hypotheses}) == 15


def test_structure_of_each_hypothesis(hypotheses):
    for h in hypotheses:
        for section in REQUIRED_SECTIONS:
            assert len(h.sections[section]) > 80, f"{h.id}: section '{section}' is too short"
        assert h.sections["Question"].count("?") >= 1, f"{h.id}: the question must be a question"
        assert all(is_technique(t) for t in h.all_techniques)
        assert h.index in ALLOWED_INDICES
        assert h.platforms and h.data_sources
        assert h.dql.strip()
        assert h.path.name.startswith(h.id + "-")


def test_json_queries_are_usable(hypotheses):
    for h in hypotheses:
        assert "query" in h.query
        # Every query has a range on "timestamp" so that --from/--to can replace it.
        replaced = apply_time_range(h.query, "timestamp", "SENTINEL", None)
        assert "SENTINEL" in json.dumps(replaced), h.id
        assert replaced["query"] == apply_time_range(h.query, "timestamp", "SENTINEL", None)["query"]
        assert "match_all" not in json.dumps(replaced), f"{h.id}: wrapping the query should not be needed"


def test_wildcards_are_correctly_escaped(hypotheses):
    """In an OpenSearch wildcard '\\' escapes; a literal backslash must be doubled."""
    bad_escape = re.compile(r"\\(?![\\*?])")
    for h in hypotheses:
        for node in _walk(h.query):
            if "wildcard" in node:
                for spec in node["wildcard"].values():
                    value = spec["value"] if isinstance(spec, dict) else spec
                    cleaned = value.replace("\\\\", "")
                    assert not bad_escape.search(cleaned), f"{h.id}: invalid escape in {value!r}"


def test_bool_should_always_has_minimum(hypotheses):
    for h in hypotheses:
        for node in _walk(h.query):
            if "bool" in node and isinstance(node["bool"], dict):
                b = node["bool"]
                if "should" in b and ("filter" in b or "must" in b):
                    assert b.get("minimum_should_match") == 1, f"{h.id}: should without minimum_should_match"


def test_h15_matches_hunt_query(hypotheses):
    h15 = {h.id: h for h in hypotheses}["H15"]
    loaded = load_iocs(str(HUNTING_ROOT / "examples" / "iocs-example.csv"))
    generated, _ = build_hunt_query(loaded.iocs, since="now-30d")
    assert h15.query == generated


def test_h07_keeps_the_legacy_id(hypotheses):
    h07 = {h.id: h for h in hypotheses}["H07"]
    assert h07.techniques == ["T1685.005"] and h07.legacy_techniques == ["T1070.001"]


DOC = """---
id: H99
title: Test
techniques: [T1059.001]
platforms: [windows]
data_sources: [Sysmon]
index: wazuh-alerts-*
---

## Hypothesis
x
## Question
x?
## Data required
x
## Query
```dql
a:b
```
```json
{"query": {"match_all": {}}}
```
## Interpretation
x
"""


def test_parse_errors(tmp_path: Path):
    good = tmp_path / "H99-ok.md"
    good.write_text(DOC, encoding="utf-8")
    assert parse_hypothesis(good).id == "H99"

    cases = {
        "no-front-matter": DOC.split("---\n", 2)[2],
        "no-section": DOC.replace("## Interpretation\nx\n", ""),
        "broken-json": DOC.replace('{"query": {"match_all": {}}}', "{query"),
        "no-dql": DOC.replace("```dql\na:b\n```\n", ""),
        "json-without-query": DOC.replace('{"query": {"match_all": {}}}', '{"size": 1}'),
        "bad-technique": DOC.replace("T1059.001", "X1"),
        "bad-id": DOC.replace("id: H99", "id: 99"),
    }
    for name, text in cases.items():
        path = tmp_path / f"H98-{name}.md"
        path.write_text(text, encoding="utf-8")
        with pytest.raises(HypothesisError):
            parse_hypothesis(path)


def test_apply_time_range_replaces_and_wraps():
    body = {"size": 0, "query": {"bool": {"filter": [{"range": {"timestamp": {"gt": "now-7d"}}}]}}, "aggs": {"a": {}}}
    out = apply_time_range(body, "timestamp", "now-30d", "now-1d")
    assert out["query"]["bool"]["filter"][0] == {"range": {"timestamp": {"gte": "now-30d", "lte": "now-1d"}}}
    assert body["query"]["bool"]["filter"][0]["range"]["timestamp"] == {"gt": "now-7d"}  # does not mutate the original
    assert out["aggs"] == {"a": {}}
    wrapped = apply_time_range({"query": {"term": {"x": 1}}}, "timestamp", "now-1h", None)
    assert wrapped["query"] == {"bool": {"filter": [{"term": {"x": 1}}, {"range": {"timestamp": {"gte": "now-1h"}}}]}}
    assert apply_time_range(body, "timestamp", None, None) == body


def test_summarize_hits_and_aggregations():
    result = {
        "hits": {"total": {"value": 2}, "hits": [{"_source": {"timestamp": "t1", "agent": {"name": "win10-lab"},
                                                               "rule": {"id": "1", "description": "d"}}}]},
        "aggregations": {
            "destinations": {"buckets": [{"key": "203.0.113.45", "doc_count": 24, "processes": {"buckets": [
                {"key": "C:\\x.exe", "doc_count": 24, "hosts": {"value": 1},
                 "regularity": {"count": 24, "avg": 1.0, "std_deviation": 0.0}}]}}]},
            "total": {"value": 7},
        },
    }
    text = summarize(result)
    assert "Hits: 2" in text and "win10-lab" in text
    assert "203.0.113.45: 24" in text and "hosts=1" in text and "std_deviation" in text
    assert "total: 7" in text


def test_cli_list_show_validate(capsys):
    assert hunts.main(["list"]) == 0
    assert "H15" in capsys.readouterr().out
    assert hunts.main(["validate"]) == 0
    assert hunts.main(["show", "h02"]) == 0
    assert "lsass" in capsys.readouterr().out
    assert hunts.main(["show", "H77"]) == 2


def test_cli_run_with_simulated_indexer(monkeypatch, capsys):
    calls = {}

    class FakeClient:
        def __init__(self, config):
            calls["config"] = config

        def search(self, body, index=None):
            calls["body"], calls["index"] = body, index
            return {"hits": {"total": {"value": 0}, "hits": []}}

    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://indexer.lab.local:9200/")
    monkeypatch.setattr(hunts, "IndexerClient", FakeClient)
    assert hunts.main(["run", "H08", "--from", "now-48h"]) == 0
    assert calls["index"] == "wazuh-alerts-*"
    assert calls["config"].url == "https://indexer.lab.local:9200"
    assert '"gte": "now-48h"' in json.dumps(calls["body"])
    assert "Hits: 0" in capsys.readouterr().out


def test_cli_run_without_configuration(monkeypatch, capsys):
    monkeypatch.delenv("WAZUH_INDEXER_URL", raising=False)
    assert hunts.main(["run", "H01"]) == 2
    assert "WAZUH_INDEXER_URL" in capsys.readouterr().err
