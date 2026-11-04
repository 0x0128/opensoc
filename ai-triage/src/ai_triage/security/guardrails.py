"""Deterministic policy applied on top of the (validated) LLM verdict (OWASP LLM01/06/09).

The LLM can only *propose*. Hard invariants that an attacker-controlled alert must never be
able to change are enforced here, in code:

* severity can be lowered at most ``max_downgrade`` levels below the Wazuh baseline
  (the rule level is set by the defender-controlled ruleset and is an integer, not text);
* when prompt injection is suspected the severity can never be lower than
  ``max(baseline, medium)``, confidence is capped and human review is mandatory;
* critical or low-confidence verdicts always require human review.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import MAX_ACTIONS, LLMTriageOutput, RecommendedAction, Severity, TriageResult
from .injection import InjectionReport

INJECTION_CONFIDENCE_CAP = 0.5
MITRE_MISMATCH_CONFIDENCE_CAP = 0.75
LOW_CONFIDENCE_REVIEW = 0.5

_REVIEW_ACTION = {
    "es": (
        "Revisión manual obligatoria: la alerta contiene texto que intenta manipular el triaje automático "
        "(posible prompt injection). Trate ese intento como indicador de actividad maliciosa."
    ),
    "en": (
        "Mandatory manual review: the alert contains text that tries to manipulate automated triage "
        "(possible prompt injection). Treat the attempt itself as an indicator of malicious activity."
    ),
}


def review_action_text(language: str) -> str:
    return _REVIEW_ACTION.get(language.split("-")[0], _REVIEW_ACTION["en"])


@dataclass
class GuardrailOutcome:
    result: TriageResult
    applied: list[str] = field(default_factory=list)
    requires_review: bool = False


def _related(technique: str, candidates: list[str]) -> bool:
    parent = technique.split(".")[0]
    return any(parent == other.split(".")[0] for other in candidates)


def apply_guardrails(
    output: LLMTriageOutput,
    *,
    baseline: Severity,
    injection: InjectionReport,
    max_downgrade: int,
    wazuh_mitre_ids: list[str],
    language: str,
    requires_review: bool = False,
) -> GuardrailOutcome:
    applied: list[str] = []
    severity = output.severity
    confidence = output.confidence
    actions = list(output.recommended_actions)

    floor = baseline.rank - max_downgrade
    if injection.suspected:
        floor = max(baseline.rank, Severity.MEDIUM.rank)
    if severity.rank < floor:
        new = Severity.from_rank(floor)
        applied.append(f"severity_floor:{severity.value}->{new.value}")
        severity = new

    if injection.suspected:
        requires_review = True
        if confidence > INJECTION_CONFIDENCE_CAP:
            confidence = INJECTION_CONFIDENCE_CAP
            applied.append("confidence_capped:prompt_injection")
        actions.insert(0, RecommendedAction(step=review_action_text(language), runbook_id=None))
        applied.append("prompt_injection_review")

    if output.mitre and wazuh_mitre_ids and not _related(output.mitre.technique_id, wazuh_mitre_ids):
        applied.append("mitre_differs_from_wazuh_rule")
        confidence = min(confidence, MITRE_MISMATCH_CONFIDENCE_CAP)

    if severity is Severity.CRITICAL:
        requires_review = True
        applied.append("critical_requires_review")
    if confidence < LOW_CONFIDENCE_REVIEW:
        requires_review = True

    result = TriageResult(
        severity=severity,
        summary=output.summary,
        mitre=output.mitre,
        recommended_actions=actions[:MAX_ACTIONS],
        confidence=round(confidence, 3),
    )
    return GuardrailOutcome(result=result, applied=applied, requires_review=requires_review)
