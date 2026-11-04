#!/usr/bin/env python3
"""Wazuh integratord -> OpenSOC ai-triage bridge.

integratord calls this script for every alert that matches the <integration> block with:
    argv[1] = path of a temporary file with the alert (JSON)
    argv[2] = <api_key>  (the ai-triage TRIAGE_API_TOKEN)
    argv[3] = <hook_url> (e.g. http://ai-triage:8000/v1/triage)

The triage verdict is sent back to analysisd through the Wazuh queue socket as a JSON event
(``"integration": "ai-triage"``), so ``ai_triage_rules.xml`` can raise new alerts from it and
analysts see it in the dashboard. Only the Python standard library is used.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request
from typing import Any

QUEUE_SOCKET = os.environ.get("AI_TRIAGE_QUEUE_SOCKET", "/var/ossec/queue/sockets/queue")
LOG_FILE = os.environ.get("AI_TRIAGE_LOG_FILE", "/var/ossec/logs/integrations.log")
TIMEOUT_S = float(os.environ.get("AI_TRIAGE_TIMEOUT", "60"))
MAX_ALERT_BYTES = 1024 * 1024
LOOP_GUARD_GROUP = "ai_triage"
EVENT_LOCATION = "ai-triage"


def log(message: str) -> None:
    line = f"{time.strftime('%Y/%m/%d %H:%M:%S')} custom-ai-triage: {message}\n"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError:
        sys.stderr.write(line)


def load_alert(path: str) -> dict[str, Any]:
    with open(path, "rb") as handle:
        raw = handle.read(MAX_ALERT_BYTES + 1)
    if len(raw) > MAX_ALERT_BYTES:
        raise ValueError("alert file too large")
    alert = json.loads(raw)
    if not isinstance(alert, dict):
        raise ValueError("alert is not a JSON object")
    return alert


def should_skip(alert: dict[str, Any]) -> bool:
    """Loop guard: never send ai-triage's own events back to ai-triage."""
    rule = alert.get("rule") or {}
    groups = rule.get("groups") or []
    data = alert.get("data") or {}
    return LOOP_GUARD_GROUP in groups or data.get("integration") == EVENT_LOCATION


def request_triage(alert: dict[str, Any], api_key: str, hook_url: str, timeout: float = TIMEOUT_S) -> dict[str, Any]:
    if not hook_url.startswith(("http://", "https://")):
        raise ValueError("hook_url must be http(s)")
    request = urllib.request.Request(  # noqa: S310 - scheme validated above
        hook_url,
        data=json.dumps(alert).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "X-Request-ID": f"wazuh-{alert.get('id', 'noid')}".replace(" ", "")[:64],
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        return json.loads(response.read(MAX_ALERT_BYTES))


def build_event(alert: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    triage = result.get("triage") or {}
    analysis = result.get("analysis") or {}
    mitre = triage.get("mitre") or {}
    rule = alert.get("rule") or {}
    return {
        "integration": EVENT_LOCATION,
        "ai_triage": {
            "severity": triage.get("severity"),
            "summary": triage.get("summary"),
            "confidence": triage.get("confidence"),
            "mitre_technique_id": mitre.get("technique_id"),
            "mitre_technique": mitre.get("technique_name"),
            "mitre_tactic": mitre.get("tactic"),
            "actions": [a.get("step") for a in triage.get("recommended_actions") or []],
            "requires_human_review": analysis.get("requires_human_review"),
            "engine": analysis.get("engine"),
            "prompt_injection_suspected": (analysis.get("prompt_injection") or {}).get("suspected"),
            "request_id": result.get("request_id"),
            "source": {
                "alert_id": alert.get("id"),
                "rule_id": rule.get("id"),
                "rule_level": rule.get("level"),
                "rule_description": rule.get("description"),
            },
        },
    }


def format_queue_message(alert: dict[str, Any], event: dict[str, Any]) -> str:
    agent = alert.get("agent") or {}
    payload = json.dumps(event, ensure_ascii=False)
    if not agent or agent.get("id") == "000":
        return f"1:{EVENT_LOCATION}:{payload}"
    return f"1:[{agent.get('id')}] ({agent.get('name')}) {agent.get('ip') or 'any'}->{EVENT_LOCATION}:{payload}"


def send_to_queue(message: str, socket_path: str = QUEUE_SOCKET) -> None:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.connect(socket_path)
        sock.send(message.encode("utf-8"))
    finally:
        sock.close()


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        log("usage: custom-ai-triage.py <alert_file> <api_key> <hook_url>")
        return 2
    alert_file, api_key, hook_url = argv[1], argv[2], argv[3]
    alert: dict[str, Any] = {}
    try:
        alert = load_alert(alert_file)
        if should_skip(alert):
            return 0
        result = request_triage(alert, api_key, hook_url)
        send_to_queue(format_queue_message(alert, build_event(alert, result)))
    except urllib.error.HTTPError as exc:
        log(f"ai-triage returned HTTP {exc.code} for alert {alert.get('id')}")
        return 1
    except (OSError, ValueError) as exc:
        log(f"error: {type(exc).__name__}: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
