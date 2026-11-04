from __future__ import annotations

import pytest
import requests

from opensoc_hunting.opensearch import (
    IndexerClient,
    IndexerConfig,
    IndexerError,
    get_path,
    hits_total,
    resolve_verify,
)

from .conftest import FakeResponse, make_session


def test_config_from_environment():
    with pytest.raises(IndexerError, match="WAZUH_INDEXER_URL"):
        IndexerConfig.from_env({})
    cfg = IndexerConfig.from_env({
        "WAZUH_INDEXER_URL": "https://idx:9200/",
        "WAZUH_INDEXER_USER": "admin",
        "WAZUH_INDEXER_PASSWORD": "pw",
        "WAZUH_INDEXER_CA": "/ca.pem",
    })
    assert (cfg.url, cfg.username, cfg.verify, cfg.index, cfg.time_field) == (
        "https://idx:9200", "admin", "/ca.pem", "wazuh-alerts-*", "timestamp")
    assert IndexerConfig.from_env({"WAZUH_INDEXER_URL": "https://i", "WAZUH_INDEXER_INSECURE": "1"}).verify is False
    assert resolve_verify(False, None) is True


def test_search_sends_auth_and_verify():
    seen = {}

    def handler(method, url, body):
        seen.update(method=method, url=url, body=body)
        return FakeResponse(200, {"hits": {"total": 3, "hits": []}})

    session = make_session(handler)
    client = IndexerClient(IndexerConfig("https://idx:9200", "admin", "pw", verify="/ca.pem"), session=session)
    result = client.search({"query": {"match_all": {}}}, index="wazuh-archives-*")
    assert seen["url"] == "https://idx:9200/wazuh-archives-*/_search"
    kwargs = session.post.call_args.kwargs
    assert kwargs["auth"] == ("admin", "pw") and kwargs["verify"] == "/ca.pem"
    assert hits_total(result) == 3


def test_search_errors():
    client = IndexerClient(IndexerConfig("https://idx"), session=make_session(lambda *a: FakeResponse(401, text="Unauthorized")))
    with pytest.raises(IndexerError, match="401"):
        client.search({"query": {}})

    def boom(*a):
        raise requests.ConnectionError("refused")

    with pytest.raises(IndexerError, match="connect"):
        IndexerClient(IndexerConfig("https://idx"), session=make_session(boom)).search({})
    with pytest.raises(IndexerError, match="JSON"):
        IndexerClient(IndexerConfig("https://idx"), session=make_session(lambda *a: FakeResponse(200, None, "<html>"))).search({})


def test_get_path():
    doc = {"rule": {"mitre": {"id": ["T1"]}}, "data.win.eventdata.image": "x"}
    assert get_path(doc, "rule.mitre.id") == ["T1"]
    assert get_path(doc, "data.win.eventdata.image") == "x"
    assert get_path(doc, "does.not.exist", "def") == "def"
    assert hits_total({"hits": {"total": {"value": 5}}}) == 5
