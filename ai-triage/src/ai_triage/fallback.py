"""Deterministic, LLM-free triage used when the LLM is unavailable, over budget, blocked by
policy or returns invalid output. Alerts are never dropped because the LLM failed."""

from __future__ import annotations

from typing import Any

from .models import (
    MAX_ACTIONS,
    LLMTriageOutput,
    MitreTechnique,
    RecommendedAction,
    Severity,
    WazuhAlert,
    normalize_tactic,
    normalize_technique_id,
)
from .rag.retriever import RetrievedChunk, is_response_section
from .rag.runbooks import Runbook
from .security.output_validation import clean_text

FALLBACK_CONFIDENCE = 0.3

_GENERIC_ACTIONS = {
    "es": [
        "Revisar la alerta original y los eventos correlacionados del mismo agente en Wazuh (±30 min).",
        "Validar con el propietario del activo si la actividad es esperada o autorizada.",
        "Escalar a nivel 2 si se confirma actividad maliciosa o no puede descartarse.",
    ],
    "en": [
        "Review the original alert and correlated events from the same agent in Wazuh (±30 min).",
        "Check with the asset owner whether the activity is expected or authorised.",
        "Escalate to tier 2 if malicious activity is confirmed or cannot be ruled out.",
    ],
}
_SUMMARY = {
    "es": (
        "Triaje determinista sin LLM ({reason}). Regla Wazuh {rule_id} (nivel {level}): {description}. Agente: {agent}."
    ),
    "en": (
        "Deterministic triage without LLM ({reason}). Wazuh rule {rule_id} (level {level}): {description}. "
        "Agent: {agent}."
    ),
}


def _lang(language: str) -> str:
    return "es" if language.split("-")[0] == "es" else "en"


def _mitre_from_rule(alert: WazuhAlert) -> MitreTechnique | None:
    mitre = alert.rule.mitre
    if not mitre or not mitre.id:
        return None
    technique_id = normalize_technique_id(mitre.id[0])
    tactic = normalize_tactic(mitre.tactic[0]) if mitre.tactic else None
    name = (mitre.technique[0] if mitre.technique else "").strip()[:120]
    if not technique_id or not tactic or len(name) < 2:
        return None
    return MitreTechnique(technique_id=technique_id, technique_name=name, tactic=tactic)


def _runbook_actions(chunks: list[RetrievedChunk], runbooks: dict[str, Runbook]) -> list[RecommendedAction]:
    if not chunks:
        return []
    runbook = runbooks.get(chunks[0].runbook_id)
    if runbook is None:
        return []
    selected = {c.section for c in chunks if c.runbook_id == runbook.id}
    actions: list[RecommendedAction] = []
    for section in runbook.sections:
        if section.title not in selected or not is_response_section(section.title):
            continue
        for item in section.list_items():
            text = clean_text(item.replace("**", ""), ())[:400]
            if len(text) >= 3:
                actions.append(RecommendedAction(step=text, runbook_id=runbook.id))
            if len(actions) >= 5:
                return actions
    return actions


def fallback_triage(
    *,
    alert: WazuhAlert,
    redacted_view: dict[str, Any],
    baseline: Severity,
    chunks: list[RetrievedChunk],
    runbooks: dict[str, Runbook],
    language: str,
    reason: str,
) -> LLMTriageOutput:
    lang = _lang(language)
    rule = redacted_view.get("rule") or {}
    agent = (redacted_view.get("agent") or {}).get("name") or "?"
    summary = _SUMMARY[lang].format(
        reason=reason,
        rule_id=alert.safe_rule_id or "?",
        level=alert.rule.level,
        description=str(rule.get("description") or "-")[:300],
        agent=str(agent)[:80],
    )
    actions = _runbook_actions(chunks, runbooks) or [
        RecommendedAction(step=step, runbook_id=None) for step in _GENERIC_ACTIONS[lang]
    ]
    return LLMTriageOutput(
        severity=baseline,
        summary=clean_text(summary, ())[:1200],
        mitre=_mitre_from_rule(alert),
        recommended_actions=actions[:MAX_ACTIONS],
        confidence=FALLBACK_CONFIDENCE,
    )
