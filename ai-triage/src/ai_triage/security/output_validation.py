"""Strict validation and sanitisation of LLM output (OWASP LLM05, LLM07, LLM09).

The LLM answer is treated as untrusted: it must be exactly one JSON object matching
``LLMTriageOutput`` (unknown fields rejected), free of system-prompt leakage, with URLs
outside the allow-list removed, HTML/markdown neutralised, runbook references grounded in
the runbooks actually retrieved, and dangerous recommendations dropped.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from pydantic import ValidationError

from ..models import LLMTriageOutput, RecommendedAction
from .sanitize import map_strings, normalize_text

MAX_RAW_OUTPUT_CHARS = 20_000

_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`)\]]+", re.IGNORECASE)
_MD_IMAGE_RE = re.compile(r"!\[[^\]]{0,200}\]\([^)]{0,500}\)")
_HTML_TAG_RE = re.compile(r"</?[A-Za-z][^<>]{0,300}>")

UNSAFE_ACTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "remote_code_pipe",
        re.compile(
            r"\b(curl|wget|iwr|invoke-webrequest|irm)\b[^\n]{0,200}\|\s*(?:sudo\s+)?(ba|z|k|da)?sh\b|\|\s*iex\b", re.I
        ),
    ),
    ("invoke_expression", re.compile(r"\b(invoke-expression|iex)\s*\(", re.I)),
    ("destructive_command", re.compile(r"\brm\s+-[a-z]*r[a-z]*f?\s+/(?:\s|$|\*)|\bmkfs(\.\w+)?\b|\bformat\s+c:", re.I)),
    (
        "disable_security_control",
        re.compile(
            r"\b(disable|stop|uninstall|turn\s+off|kill|desactiva\w*|deshabilita\w*|det[eé]n\w*|desinstala\w*|apaga\w*)\b"
            r"[^.\n]{0,40}\b(wazuh|ossec|edr|antivirus|anti-virus|defender|firewall|cortafuegos|selinux|apparmor|"
            r"auditd|sysmon|security\s+agent|agente\s+de\s+seguridad|logging|registro\s+de\s+eventos)\b",
            re.I,
        ),
    ),
    ("defender_tampering", re.compile(r"set-mppreference\s+-disable|add-mppreference\s+-exclusion", re.I)),
]
_EXCLUSION_RE = re.compile(
    r"\b(whitelist|allowlist|allow-list|lista\s+blanca|add\s+an?\s+exception|a[ñn]ad\w+\s+una\s+excepci[oó]n|"
    r"exclude|excluir|suppress|silenciar|suprimir)\b",
    re.I,
)


class OutputValidationError(Exception):
    def __init__(self, reason: str, details: Iterable[str] = ()) -> None:
        self.reason = reason
        self.details = list(details)[:10]
        super().__init__(f"{reason}: {'; '.join(self.details)}" if self.details else reason)


class SystemPromptLeakError(OutputValidationError):
    pass


@dataclass
class ValidatedOutput:
    output: LLMTriageOutput
    notes: list[str] = field(default_factory=list)
    requires_review: bool = False


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OutputValidationError("duplicate_key", [key[:40]])
        result[key] = value
    return result


def extract_json_object(text: str) -> dict[str, Any]:
    if len(text) > MAX_RAW_OUTPUT_CHARS:
        raise OutputValidationError("output_too_large")
    stripped = text.strip()
    # Strip a surrounding ``` fence without regex backtracking over long whitespace runs.
    if stripped.startswith("```") and stripped.endswith("```") and len(stripped) >= 6:
        stripped = stripped[3:-3]
        first_line, _, rest = stripped.partition("\n")
        if first_line.strip().isalpha() or not first_line.strip():
            stripped = rest
        stripped = stripped.strip()
    start = stripped.find("{")
    if start == -1:
        raise OutputValidationError("no_json_object")
    decoder = json.JSONDecoder(object_pairs_hook=_reject_duplicate_keys)
    try:
        obj, end = decoder.raw_decode(stripped, start)
    except json.JSONDecodeError as exc:
        raise OutputValidationError("invalid_json", [exc.msg]) from None
    if stripped[end:].strip():
        raise OutputValidationError("trailing_content_after_json")
    if not isinstance(obj, dict):
        raise OutputValidationError("json_is_not_an_object")
    return obj


def _host_allowed(url: str, allowed_hosts: Iterable[str]) -> bool:
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return False
    return any(host == allowed or host.endswith("." + allowed) for allowed in allowed_hosts)


def clean_text(text: str, allowed_hosts: Iterable[str]) -> str:
    allowed = list(allowed_hosts)
    text = normalize_text(text)
    text = _MD_IMAGE_RE.sub("", text)
    text = _HTML_TAG_RE.sub("", text)
    text = _URL_RE.sub(lambda m: m.group(0) if _host_allowed(m.group(0), allowed) else "[URL_REMOVED]", text)
    return re.sub(r"[ \t]+", " ", text).strip()


def _condense(error: ValidationError) -> list[str]:
    # Never echo the offending values: only location and message.
    return [f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in error.errors(include_input=False)]


def validate_llm_output(
    text: str,
    *,
    canary: str,
    leak_markers: Iterable[str] = (),
    allowed_runbook_ids: Iterable[str] = (),
    allowed_url_hosts: Iterable[str] = (),
) -> ValidatedOutput:
    if canary and canary in text:
        raise SystemPromptLeakError("system_prompt_leak", ["canary token found in output"])
    lowered = text.lower()
    for marker in leak_markers:
        if marker.lower() in lowered:
            raise SystemPromptLeakError("system_prompt_leak", ["system prompt fragment found in output"])

    hosts = list(allowed_url_hosts)
    data = map_strings(extract_json_object(text), lambda value: clean_text(value, hosts))
    try:
        output = LLMTriageOutput.model_validate(data)
    except ValidationError as exc:
        raise OutputValidationError("schema_violation", _condense(exc)) from None

    notes: list[str] = []
    requires_review = False
    allowed_ids = set(allowed_runbook_ids)
    actions: list[RecommendedAction] = []
    seen: set[str] = set()
    for action in output.recommended_actions:
        unsafe = [name for name, pattern in UNSAFE_ACTION_PATTERNS if pattern.search(action.step)]
        if unsafe:
            notes.append(f"unsafe_action_removed:{unsafe[0]}")
            continue
        if _EXCLUSION_RE.search(action.step):
            notes.append("exclusion_suggested")
            requires_review = True
        runbook_id = action.runbook_id
        if runbook_id is not None and runbook_id not in allowed_ids:
            notes.append("ungrounded_runbook_reference")
            runbook_id = None
        key = action.step.casefold()
        if key in seen:
            continue
        seen.add(key)
        actions.append(RecommendedAction(step=action.step, runbook_id=runbook_id))
    if not actions:
        raise OutputValidationError("no_safe_actions", notes)
    output = output.model_copy(update={"recommended_actions": actions})
    return ValidatedOutput(output=output, notes=sorted(set(notes)), requires_review=requires_review)
