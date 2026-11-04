"""Shared test helpers: sample alerts and a scripted (simulated) LLM."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ai_triage.llm.base import LLMRequest, LLMResponse
from ai_triage.llm.mock import MockLLMProvider

ROOT = Path(__file__).resolve().parents[1]
DATA = Path(__file__).resolve().parent / "data"
RUNBOOKS = ROOT / "runbooks"
TOKEN = "test-token-0123456789abcdef"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def load_alert(name: str) -> dict[str, Any]:
    return json.loads((DATA / f"{name}.json").read_text(encoding="utf-8"))


def good_answer(**overrides: Any) -> str:
    """A schema-valid LLM answer, as a well-behaved model would return it."""
    answer: dict[str, Any] = {
        "severity": "high",
        "summary": "SSH brute force from [IP_EXTERNAL_1] against user [USER_1] on web-prod-01.",
        "mitre": {"technique_id": "T1110.001", "technique_name": "Password Guessing", "tactic": "Credential Access"},
        "recommended_actions": [
            {"step": "Block [IP_EXTERNAL_1] on the perimeter firewall.", "runbook_id": "ssh-brute-force"},
            {"step": "Check for later successful logons by [USER_1].", "runbook_id": "ssh-brute-force"},
        ],
        "confidence": 0.85,
    }
    answer.update(overrides)
    return json.dumps(answer, ensure_ascii=False)


class ScriptedLLM(MockLLMProvider):
    """Simulated LLM that replays a script of answers (str, LLMResponse or Exception)."""

    def __init__(self, *answers: str | LLMResponse | Exception | Callable[[LLMRequest], Any]) -> None:
        self._answers = list(answers)
        super().__init__(model="scripted-test-model", responder=self._next)

    def _next(self, request: LLMRequest) -> Any:
        answer = self._answers.pop(0) if len(self._answers) > 1 else self._answers[0]
        return answer(request) if callable(answer) else answer

    @property
    def prompts(self) -> list[str]:
        return [request.system + "\n" + "\n".join(m.content for m in request.messages) for request in self.requests]


def read_audit(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
