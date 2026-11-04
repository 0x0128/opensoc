"""The Wazuh integratord script, exercised against a real running ai-triage server."""

from __future__ import annotations

import importlib.util
import json
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import uvicorn

from ai_triage.llm.mock import MockLLMProvider
from ai_triage.main import create_app

from .helpers import AUTH, ROOT, TOKEN, load_alert

SCRIPT = ROOT / "integrations" / "wazuh" / "custom-ai-triage.py"


@pytest.fixture(scope="module")
def bridge() -> ModuleType:
    spec = importlib.util.spec_from_file_location("custom_ai_triage", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def server(make_settings: Any) -> Iterator[str]:
    app = create_app(make_settings(), provider=MockLLMProvider())
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="on")
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    for _ in range(200):
        if srv.started:
            break
        time.sleep(0.02)
    yield f"http://127.0.0.1:{port}/v1/triage"
    srv.should_exit = True
    thread.join(timeout=5)


@pytest.fixture
def queue(tmp_path: Path) -> Iterator[tuple[str, socket.socket]]:
    path = str(tmp_path / "queue")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind(path)
    sock.settimeout(5)
    yield path, sock
    sock.close()


def test_end_to_end_alert_to_wazuh_queue(
    bridge: ModuleType, server: str, queue: tuple[str, socket.socket], tmp_path: Path, monkeypatch: Any
) -> None:
    path, sock = queue
    monkeypatch.setattr(bridge, "QUEUE_SOCKET", path)
    monkeypatch.setattr(bridge, "LOG_FILE", str(tmp_path / "integrations.log"))
    send = bridge.send_to_queue
    monkeypatch.setattr(bridge, "send_to_queue", lambda message: send(message, path))
    alert_file = tmp_path / "alert.json"
    alert_file.write_text(json.dumps(load_alert("ssh_bruteforce")))

    assert bridge.main(["custom-ai-triage.py", str(alert_file), TOKEN, server]) == 0

    message = sock.recv(65536).decode()
    assert message.startswith("1:[003] (web-prod-01) 10.20.0.15->ai-triage:")
    event = json.loads(message.split("->ai-triage:", 1)[1])
    assert event["integration"] == "ai-triage"
    assert event["ai_triage"]["severity"] == "medium"
    assert event["ai_triage"]["mitre_technique_id"] == "T1110.001"
    assert event["ai_triage"]["source"]["rule_id"] == "5712"
    assert event["ai_triage"]["actions"]


def test_wrong_token_is_logged_and_nothing_is_sent(
    bridge: ModuleType, server: str, tmp_path: Path, monkeypatch: Any
) -> None:
    log_file = tmp_path / "integrations.log"
    monkeypatch.setattr(bridge, "LOG_FILE", str(log_file))
    sent: list[str] = []
    monkeypatch.setattr(bridge, "send_to_queue", sent.append)
    alert_file = tmp_path / "alert.json"
    alert_file.write_text(json.dumps(load_alert("ssh_bruteforce")))
    assert bridge.main(["x", str(alert_file), "wrong-token-xxxxxxxx", server]) == 1
    assert sent == [] and "HTTP 401" in log_file.read_text()


def test_loop_guard_on_both_sides(bridge: ModuleType, make_client: Any) -> None:
    own_event = {"rule": {"level": 10, "id": "100902", "groups": ["ai_triage"]}, "data": {"integration": "ai-triage"}}
    assert bridge.should_skip(own_event)
    assert not bridge.should_skip(load_alert("ssh_bruteforce"))
    client, llm = make_client()
    assert client.post("/v1/triage", json=own_event, headers=AUTH).status_code == 409
    assert llm.requests == []


def test_manager_local_alerts_use_short_queue_format(bridge: ModuleType) -> None:
    alert = {"agent": {"id": "000", "name": "wazuh-manager"}, "rule": {"level": 7}}
    assert bridge.format_queue_message(alert, {"a": 1}) == '1:ai-triage:{"a": 1}'


def test_rejects_bad_inputs(bridge: ModuleType, tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(bridge, "LOG_FILE", str(tmp_path / "integrations.log"))
    big = tmp_path / "big.json"
    big.write_bytes(b" " * (bridge.MAX_ALERT_BYTES + 1))
    assert bridge.main(["x", str(big), "t", "http://127.0.0.1:1/v1/triage"]) == 1
    good = tmp_path / "good.json"
    good.write_text("{}")
    assert bridge.main(["x", str(good), "t", "file:///etc/passwd"]) == 1
    assert bridge.main(["x"]) == 2
