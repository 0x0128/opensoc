"""Simulated LLM used by the test-suite and for offline/demo deployments.

``MockLLMProvider`` records every request it receives (so tests can assert what would have
been sent to a real provider) and answers through a pluggable ``responder``. The default
responder is a deterministic heuristic that reads the structured prompt and produces a
schema-valid triage, which lets the whole service run without network access or API keys.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any, ClassVar

from ..rag.retriever import is_response_section
from ..security.limits import estimate_tokens
from .base import LLMProvider, LLMRequest, LLMResponse

Responder = Callable[[LLMRequest], "str | LLMResponse | Exception"]

_ALERT_RE = re.compile(r"<alert_data_([0-9a-f]+)>\n(.*?)\n</alert_data_\1>", re.DOTALL)
_BASELINE_RE = re.compile(r"baseline severity: (\w+)")
_RUNBOOK_RE = re.compile(r"^### runbook_id: ([a-z0-9-]+)", re.MULTILINE)
_ITEM_RE = re.compile(r"^\s*(?:\d+[.)]|[-*])\s+(.+)$", re.MULTILINE)


def extract_alert(request: LLMRequest) -> dict[str, Any] | None:
    """Return the JSON alert embedded in the first user message (test helper)."""
    match = _ALERT_RE.search(request.messages[0].content)
    return json.loads(match.group(2)) if match else None


def heuristic_responder(request: LLMRequest) -> str:
    prompt = request.messages[0].content
    alert = extract_alert(request) or {}
    rule = alert.get("rule") or {}
    baseline_match = _BASELINE_RE.search(prompt)
    baseline = baseline_match.group(1) if baseline_match else "medium"
    spanish = "in Spanish" in request.system

    mitre = None
    wazuh_mitre = rule.get("mitre") or {}
    ids, names, tactics = (wazuh_mitre.get(k) or [] for k in ("id", "technique", "tactic"))
    if ids and names and tactics:
        mitre = {"technique_id": ids[0], "technique_name": names[0], "tactic": tactics[0]}

    actions: list[dict[str, Any]] = []
    runbook_ids = _RUNBOOK_RE.findall(prompt)
    if runbook_ids:
        block = prompt.split(f"### runbook_id: {runbook_ids[0]}", 1)[1].split("### runbook_id:", 1)[0]
        block = block.split("</runbook_context>", 1)[0]
        response_items = [
            item
            for section in block.split("\n#### ")[1:]
            if is_response_section(section.split("\n", 1)[0])
            for item in _ITEM_RE.findall(section)
        ]
        actions = [{"step": item.strip()[:400], "runbook_id": runbook_ids[0]} for item in response_items[:4]]
    if not actions:
        step = (
            "Revisar la alerta y los eventos relacionados del agente en Wazuh."
            if spanish
            else "Review the alert and related events for the agent in Wazuh."
        )
        actions = [{"step": step, "runbook_id": None}]

    agent = (alert.get("agent") or {}).get("name", "?")
    description = str(rule.get("description", ""))[:300]
    if spanish:
        summary = f"[simulado] Alerta '{description}' (regla {rule.get('id')}, nivel {rule.get('level')}) en {agent}."
    else:
        summary = f"[simulated] Alert '{description}' (rule {rule.get('id')}, level {rule.get('level')}) on {agent}."
    return json.dumps(
        {
            "severity": baseline,
            "summary": summary,
            "mitre": mitre,
            "recommended_actions": actions,
            "confidence": 0.6,
        },
        ensure_ascii=False,
    )


class MockLLMProvider(LLMProvider):
    name: ClassVar[str] = "mock"

    def __init__(self, model: str = "mock-heuristic", responder: Responder | None = None) -> None:
        super().__init__(model)
        self._responder = responder or heuristic_responder
        self.requests: list[LLMRequest] = []

    async def complete(self, request: LLMRequest) -> LLMResponse:
        self.requests.append(request)
        answer = self._responder(request)
        if isinstance(answer, Exception):
            raise answer
        if isinstance(answer, LLMResponse):
            return answer
        prompt_size = estimate_tokens(request.system + "".join(m.content for m in request.messages))
        return LLMResponse(
            text=answer, model=self.model, input_tokens=prompt_size, output_tokens=estimate_tokens(answer)
        )
