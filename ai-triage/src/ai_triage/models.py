"""Data models: Wazuh alert input, strict LLM output schema and API response."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ---------------------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------------------


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)

    @classmethod
    def from_rank(cls, rank: int) -> Severity:
        return _SEVERITY_ORDER[max(0, min(rank, len(_SEVERITY_ORDER) - 1))]


_SEVERITY_ORDER = [Severity.INFORMATIONAL, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def baseline_severity(rule_level: int) -> Severity:
    """Map a Wazuh rule level (0-15) to a severity, following Wazuh dashboard buckets."""
    if rule_level >= 15:
        return Severity.CRITICAL
    if rule_level >= 12:
        return Severity.HIGH
    if rule_level >= 7:
        return Severity.MEDIUM
    if rule_level >= 3:
        return Severity.LOW
    return Severity.INFORMATIONAL


# ---------------------------------------------------------------------------------------
# MITRE ATT&CK
# ---------------------------------------------------------------------------------------

TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

TACTICS: dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}
_TACTIC_LOOKUP = {re.sub(r"[^a-z]", "", name.lower()): name for name in TACTICS.values()}


def normalize_tactic(value: str) -> str | None:
    """Return the canonical ATT&CK Enterprise tactic name, accepting TA ids and loose spellings."""
    value = value.strip()
    if value.upper() in TACTICS:
        return TACTICS[value.upper()]
    return _TACTIC_LOOKUP.get(re.sub(r"[^a-z]", "", value.lower()))


def normalize_technique_id(value: str) -> str | None:
    value = value.strip().upper()
    return value if TECHNIQUE_ID_RE.match(value) else None


# ---------------------------------------------------------------------------------------
# Wazuh alert (input). Permissive: Wazuh alerts carry many decoder-specific fields.
# ---------------------------------------------------------------------------------------


class WazuhMitre(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: list[str] = Field(default_factory=list)
    tactic: list[str] = Field(default_factory=list)
    technique: list[str] = Field(default_factory=list)


class WazuhRule(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: str | None = None
    level: int = Field(ge=0, le=16)
    description: str = ""
    groups: list[str] = Field(default_factory=list)
    mitre: WazuhMitre | None = None
    firedtimes: int | None = None

    @field_validator("id", mode="before")
    @classmethod
    def _coerce_id(cls, value: Any) -> Any:
        return str(value) if isinstance(value, int) else value


class WazuhAgent(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: str | None = None
    name: str | None = None
    ip: str | None = None


class WazuhAlert(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: str | None = None
    timestamp: str | None = None
    rule: WazuhRule
    agent: WazuhAgent | None = None
    manager: dict[str, Any] | None = None
    decoder: dict[str, Any] | None = None
    location: str | None = None
    full_log: str | None = None
    data: dict[str, Any] | None = None

    @property
    def safe_alert_id(self) -> str | None:
        return self.id if self.id and re.fullmatch(r"[0-9A-Za-z._:-]{1,64}", self.id) else None

    @property
    def safe_rule_id(self) -> str | None:
        rule_id = self.rule.id
        return rule_id if rule_id and re.fullmatch(r"\d{1,10}", rule_id) else None

    @property
    def mitre_ids(self) -> list[str]:
        if not self.rule.mitre:
            return []
        return [tid for raw in self.rule.mitre.id if (tid := normalize_technique_id(raw))]


# ---------------------------------------------------------------------------------------
# Triage output. ``LLMTriageOutput`` is the strict contract the LLM must satisfy.
# ---------------------------------------------------------------------------------------

MAX_ACTIONS = 8
MAX_SUMMARY_CHARS = 1200
MAX_STEP_CHARS = 400


class MitreTechnique(BaseModel):
    model_config = ConfigDict(extra="forbid")
    technique_id: str = Field(description="ATT&CK Enterprise technique id, e.g. T1110 or T1110.001")
    technique_name: str = Field(min_length=2, max_length=120)
    tactic: str = Field(description="ATT&CK Enterprise tactic name, e.g. Credential Access")

    @field_validator("technique_id")
    @classmethod
    def _check_technique(cls, value: str) -> str:
        normalized = normalize_technique_id(value)
        if normalized is None:
            raise ValueError("technique_id must look like T1234 or T1234.001")
        return normalized

    @field_validator("tactic")
    @classmethod
    def _check_tactic(cls, value: str) -> str:
        normalized = normalize_tactic(value)
        if normalized is None:
            raise ValueError("tactic must be an ATT&CK Enterprise tactic")
        return normalized


class RecommendedAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    step: str = Field(min_length=3, max_length=MAX_STEP_CHARS)
    runbook_id: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")


class LLMTriageOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    severity: Severity
    summary: str = Field(min_length=10, max_length=MAX_SUMMARY_CHARS)
    mitre: MitreTechnique | None
    recommended_actions: list[RecommendedAction] = Field(min_length=1, max_length=MAX_ACTIONS)
    confidence: float = Field(ge=0.0, le=1.0)

    @field_validator("severity", mode="before")
    @classmethod
    def _lower_severity(cls, value: Any) -> Any:
        return value.strip().lower() if isinstance(value, str) else value


class TriageResult(LLMTriageOutput):
    """Final triage after guardrails (same shape as the LLM contract)."""


class Engine(StrEnum):
    LLM = "llm"
    FALLBACK = "fallback"


class PromptInjectionInfo(BaseModel):
    suspected: bool
    score: int
    indicators: list[str]


class PIIInfo(BaseModel):
    redacted: dict[str, int]
    rehydrated: bool


class TokenUsage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_prompt_tokens: int = 0


class TriageAnalysis(BaseModel):
    engine: Engine
    provider: str
    model: str | None
    baseline_severity: Severity
    requires_human_review: bool
    guardrails: list[str]
    prompt_injection: PromptInjectionInfo
    pii: PIIInfo
    runbooks: list[str]
    alert_truncated: bool
    fallback_reason: str | None = None
    attempts: int = 0
    usage: TokenUsage
    latency_ms: int


class TriageResponse(BaseModel):
    request_id: str
    alert_id: str | None
    rule_id: str | None
    triage: TriageResult
    analysis: TriageAnalysis


def llm_output_json_schema() -> dict[str, Any]:
    """JSON schema sent to providers that support schema-constrained decoding."""
    return LLMTriageOutput.model_json_schema()
