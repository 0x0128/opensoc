from __future__ import annotations

import json

import pytest

from ai_triage.models import LLMTriageOutput, Severity, baseline_severity
from ai_triage.security.guardrails import apply_guardrails, review_action_text
from ai_triage.security.injection import InjectionFinding, InjectionReport

from .helpers import good_answer


def output(**overrides: object) -> LLMTriageOutput:
    return LLMTriageOutput.model_validate(json.loads(good_answer(**overrides)))


CLEAN = InjectionReport(threshold=3)
SUSPECT = InjectionReport(threshold=3, findings=[InjectionFinding("ignore_instructions", "full_log", 4)])


def guard(out: LLMTriageOutput, *, baseline: Severity = Severity.MEDIUM, injection: InjectionReport = CLEAN,
          mitre: list[str] | None = None, max_downgrade: int = 1):  # fmt: skip
    return apply_guardrails(
        out,
        baseline=baseline,
        injection=injection,
        max_downgrade=max_downgrade,
        wazuh_mitre_ids=mitre or [],
        language="en",
    )


@pytest.mark.parametrize(
    ("level", "expected"),
    [
        (0, "informational"),
        (2, "informational"),
        (3, "low"),
        (6, "low"),
        (7, "medium"),
        (11, "medium"),
        (12, "high"),
        (14, "high"),
        (15, "critical"),
    ],
)
def test_baseline_mapping(level: int, expected: str) -> None:
    assert baseline_severity(level).value == expected


def test_llm_can_raise_severity() -> None:
    outcome = guard(output(severity="high"), baseline=Severity.LOW)
    assert outcome.result.severity is Severity.HIGH and outcome.applied == []


def test_one_level_downgrade_is_allowed() -> None:
    assert guard(output(severity="low"), baseline=Severity.MEDIUM).result.severity is Severity.LOW


def test_downgrade_beyond_limit_is_clamped() -> None:
    outcome = guard(output(severity="informational"), baseline=Severity.HIGH)
    assert outcome.result.severity is Severity.MEDIUM
    assert "severity_floor:informational->medium" in outcome.applied


def test_zero_downgrade_policy() -> None:
    outcome = guard(output(severity="low"), baseline=Severity.MEDIUM, max_downgrade=0)
    assert outcome.result.severity is Severity.MEDIUM


def test_prompt_injection_forces_floor_review_and_confidence_cap() -> None:
    outcome = guard(output(severity="informational", confidence=0.99), baseline=Severity.LOW, injection=SUSPECT)
    result = outcome.result
    assert result.severity is Severity.MEDIUM  # max(baseline, medium)
    assert result.confidence <= 0.5
    assert outcome.requires_review
    assert result.recommended_actions[0].step.startswith("Mandatory manual review")
    assert "prompt_injection_review" in outcome.applied


def test_review_action_is_localised() -> None:
    assert review_action_text("en").startswith("Mandatory manual review")
    assert review_action_text("es-ES").startswith("Revisión manual obligatoria")
    assert review_action_text("fr") == review_action_text("en")


def test_injection_floor_respects_higher_baseline() -> None:
    outcome = guard(output(severity="low"), baseline=Severity.HIGH, injection=SUSPECT)
    assert outcome.result.severity is Severity.HIGH


def test_critical_always_requires_review() -> None:
    outcome = guard(output(severity="critical", confidence=0.95), baseline=Severity.HIGH)
    assert outcome.requires_review and "critical_requires_review" in outcome.applied


def test_low_confidence_requires_review() -> None:
    assert guard(output(confidence=0.3)).requires_review
    assert not guard(output(confidence=0.9)).requires_review


def test_mitre_mismatch_caps_confidence() -> None:
    outcome = guard(output(confidence=0.95), mitre=["T1190"])
    assert "mitre_differs_from_wazuh_rule" in outcome.applied and outcome.result.confidence == 0.75


def test_mitre_subtechnique_of_rule_technique_is_consistent() -> None:
    outcome = guard(output(confidence=0.95), mitre=["T1110"])
    assert outcome.applied == [] and outcome.result.confidence == 0.95


def test_action_list_never_exceeds_maximum() -> None:
    actions = [{"step": f"Action number {i}", "runbook_id": None} for i in range(8)]
    outcome = guard(output(recommended_actions=actions), injection=SUSPECT)
    assert len(outcome.result.recommended_actions) == 8
