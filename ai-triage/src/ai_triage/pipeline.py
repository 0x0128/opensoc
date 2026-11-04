"""Triage pipeline: sanitise → detect injection → redact PII → retrieve runbooks → prompt →
LLM (bounded) → validate → guardrails → re-hydrate → audit."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from .config import InjectionPolicy, Settings
from .fallback import fallback_triage
from .llm.base import ChatMessage, LLMProvider, LLMRequest, LLMResponse, ProviderError
from .models import (
    MAX_STEP_CHARS,
    MAX_SUMMARY_CHARS,
    Engine,
    LLMTriageOutput,
    PIIInfo,
    PromptInjectionInfo,
    TokenUsage,
    TriageAnalysis,
    TriageResponse,
    TriageResult,
    WazuhAlert,
    baseline_severity,
    llm_output_json_schema,
)
from .prompts import LEAK_MARKERS, BuiltPrompt, build_alert_view, build_prompt
from .rag.retriever import RetrievalQuery, RetrievedChunk, Retriever
from .security.audit import AuditLogger, sha256_hex
from .security.guardrails import apply_guardrails
from .security.injection import InjectionReport, scan_for_injection
from .security.limits import TokenBudget, estimate_tokens
from .security.output_validation import (
    OutputValidationError,
    SystemPromptLeakError,
    ValidatedOutput,
    validate_llm_output,
)
from .security.redaction import PIIRedactor
from .security.sanitize import sanitize_structure, truncate

logger = logging.getLogger(__name__)

MAX_RETRY_ECHO_CHARS = 2000


@dataclass
class _Attempts:
    count: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    errors: list[str] = field(default_factory=list)
    model: str | None = None
    raw_output_hashes: list[str] = field(default_factory=list)


def _retrieval_query(alert: WazuhAlert, view: dict[str, Any]) -> RetrievalQuery:
    rule = view.get("rule") or {}
    mitre = rule.get("mitre") or {}
    parts: list[str] = [str(rule.get("description", "")), " ".join(map(str, rule.get("groups") or []))]
    parts += [" ".join(map(str, mitre.get(key) or [])) for key in ("technique", "tactic", "id")]
    parts.append(str((view.get("decoder") or {}).get("name", "")))
    parts.append(str(view.get("location", "")))
    data = view.get("data")
    if isinstance(data, dict):
        parts.append(" ".join(map(str, data.keys())))
    parts.append(str(view.get("full_log", ""))[:600])
    return RetrievalQuery(
        text=" ".join(parts),
        mitre_ids=alert.mitre_ids,
        groups=list(alert.rule.groups),
        rule_id=alert.safe_rule_id,
    )


class TriageService:
    def __init__(
        self,
        *,
        settings: Settings,
        provider: LLMProvider,
        retriever: Retriever,
        audit: AuditLogger,
        token_budget: TokenBudget,
    ) -> None:
        self.settings = settings
        self.provider = provider
        self.retriever = retriever
        self.audit = audit
        self.token_budget = token_budget
        self._semaphore = asyncio.Semaphore(settings.llm_max_concurrency)
        self._schema = llm_output_json_schema()

    # ------------------------------------------------------------------ LLM loop
    async def _bounded_complete(self, request: LLMRequest) -> LLMResponse:
        async with self._semaphore:
            return await self.provider.complete(request)

    async def _call_llm(
        self, prompt: BuiltPrompt, chunks: list[RetrievedChunk], attempts: _Attempts
    ) -> ValidatedOutput | str:
        """Return validated output, or a fallback reason string."""
        s = self.settings
        messages: list[ChatMessage] = [ChatMessage("user", prompt.user)]
        allowed_ids = {c.runbook_id for c in chunks}
        for _ in range(1 + s.llm_max_retries):
            request = LLMRequest(
                system=prompt.system,
                messages=tuple(messages),
                max_output_tokens=s.llm_max_output_tokens,
                temperature=s.llm_temperature,
                json_schema=self._schema,
            )
            prompt_tokens = estimate_tokens(request.system) + sum(estimate_tokens(m.content) for m in messages)
            if prompt_tokens > s.llm_max_input_tokens + s.llm_max_output_tokens:
                return "input_token_limit"
            if not self.token_budget.try_consume(prompt_tokens + s.llm_max_output_tokens):
                return "token_budget_exhausted"
            attempts.count += 1
            try:
                # The timeout covers queueing for a concurrency slot too: when the LLM is saturated,
                # alerts degrade to deterministic triage instead of piling up (LLM10).
                response = await asyncio.wait_for(
                    self._bounded_complete(request), timeout=s.llm_timeout_s + min(5.0, s.llm_timeout_s)
                )
            except TimeoutError:
                attempts.errors.append("timeout")
                return "llm_timeout"
            except ProviderError as exc:
                attempts.errors.append(f"provider_error:{exc.reason}")
                return "llm_provider_error"
            except Exception as exc:  # noqa: BLE001 - a provider bug must not lose the alert
                logger.error("unexpected provider failure: %s", type(exc).__name__)
                attempts.errors.append(f"unexpected:{type(exc).__name__}")
                return "llm_unexpected_error"
            attempts.model = response.model
            attempts.input_tokens += response.input_tokens
            attempts.output_tokens += response.output_tokens
            attempts.raw_output_hashes.append(sha256_hex(response.text))
            try:
                if response.truncated:
                    raise OutputValidationError("output_truncated_at_token_limit")
                return validate_llm_output(
                    response.text,
                    canary=prompt.canary,
                    leak_markers=LEAK_MARKERS,
                    allowed_runbook_ids=allowed_ids,
                    allowed_url_hosts=s.allowed_url_hosts,
                )
            except SystemPromptLeakError:
                attempts.errors.append("system_prompt_leak")
                return "system_prompt_leak"
            except OutputValidationError as exc:
                attempts.errors.append(exc.reason)
                messages += [
                    ChatMessage("assistant", response.text[:MAX_RETRY_ECHO_CHARS]),
                    ChatMessage(
                        "user",
                        f"Your previous answer was rejected by the validator ({exc}). Reply again with "
                        "ONLY the JSON object that satisfies the schema; keep the security rules.",
                    ),
                ]
        return "invalid_llm_output"

    # ------------------------------------------------------------------ public API
    async def triage(self, alert: WazuhAlert, *, request_id: str, client_id: str) -> TriageResponse:
        started = time.perf_counter()
        s = self.settings
        raw = alert.model_dump(mode="json", exclude_none=True)
        baseline = baseline_severity(alert.rule.level)

        injection: InjectionReport = scan_for_injection(raw, threshold=s.injection_threshold)
        sanitized = sanitize_structure(raw)
        redactor = PIIRedactor(
            redact_ips=s.pii_redact_ips, extra_user_keys=s.extra_user_keys, keep_usernames=s.keep_usernames
        )
        redacted = redactor.redact(sanitized)
        view = build_alert_view(redacted)

        rag_budget = min(s.rag_max_context_tokens, s.llm_max_input_tokens // 3)
        chunks = self.retriever.search(_retrieval_query(alert, view), top_k=s.rag_top_k, max_tokens=rag_budget)
        prompt = build_prompt(
            alert_view=view,
            chunks=chunks,
            injection=injection,
            rule_id=alert.safe_rule_id,
            rule_level=alert.rule.level,
            baseline=baseline,
            pii_counts=dict(redactor.counts),
            language=s.output_language,
            max_input_tokens=s.llm_max_input_tokens,
        )

        attempts = _Attempts()
        fallback_reason: str | None = None
        validated: ValidatedOutput | None = None
        if injection.suspected and s.injection_policy is InjectionPolicy.BLOCK:
            fallback_reason = "prompt_injection_blocked"
        else:
            outcome = await self._call_llm(prompt, chunks, attempts)
            if isinstance(outcome, str):
                fallback_reason = outcome
            else:
                validated = outcome

        output: LLMTriageOutput
        notes: list[str] = []
        needs_review = False
        if validated is not None:
            output, notes, needs_review = validated.output, list(validated.notes), validated.requires_review
        else:
            assert fallback_reason is not None
            output = fallback_triage(
                alert=alert,
                redacted_view=view,
                baseline=baseline,
                chunks=chunks,
                runbooks=self.retriever.runbooks,
                language=s.output_language,
                reason=fallback_reason,
            )
            needs_review = True
            logger.warning("request %s: fallback triage (%s)", request_id, fallback_reason)

        guarded = apply_guardrails(
            output,
            baseline=baseline,
            injection=injection,
            max_downgrade=s.severity_max_downgrade,
            wazuh_mitre_ids=alert.mitre_ids,
            language=s.output_language,
            requires_review=needs_review,
        )
        redacted_result = guarded.result
        final_result = self._rehydrate(redacted_result, redactor) if s.pii_rehydrate_output else redacted_result

        latency_ms = int((time.perf_counter() - started) * 1000)
        engine = Engine.LLM if validated is not None else Engine.FALLBACK
        analysis = TriageAnalysis(
            engine=engine,
            provider=self.provider.name,
            model=attempts.model or (self.provider.model if attempts.count else None),
            baseline_severity=baseline,
            requires_human_review=guarded.requires_review,
            guardrails=notes + guarded.applied,
            prompt_injection=PromptInjectionInfo(
                suspected=injection.suspected, score=injection.score, indicators=injection.indicators
            ),
            pii=PIIInfo(redacted=dict(redactor.counts), rehydrated=s.pii_rehydrate_output),
            runbooks=list(dict.fromkeys(c.runbook_id for c in chunks)),
            alert_truncated=prompt.alert_truncated,
            fallback_reason=fallback_reason,
            attempts=attempts.count,
            usage=TokenUsage(
                input_tokens=attempts.input_tokens,
                output_tokens=attempts.output_tokens,
                estimated_prompt_tokens=prompt.estimated_tokens,
            ),
            latency_ms=latency_ms,
        )
        response = TriageResponse(
            request_id=request_id,
            alert_id=alert.safe_alert_id,
            rule_id=alert.safe_rule_id,
            triage=final_result,
            analysis=analysis,
        )
        audit_fields: dict[str, Any] = {
            "request_id": request_id,
            "client": client_id,
            "alert_id": alert.safe_alert_id,
            "rule_id": alert.safe_rule_id,
            "rule_level": alert.rule.level,
            "alert_sha256": sha256_hex(json.dumps(raw, sort_keys=True, default=str)),
            "prompt_sha256": sha256_hex(prompt.system + prompt.user),
            "llm_output_sha256": attempts.raw_output_hashes,
            "llm_errors": attempts.errors,
            # Triage as produced *before* re-hydration: contains placeholders, not PII.
            "triage": redacted_result.model_dump(mode="json"),
            "analysis": analysis.model_dump(mode="json"),
        }
        if s.audit_include_prompts:
            audit_fields["prompt"] = {"system_len": len(prompt.system), "user": prompt.user}
        self.audit.record("triage", **audit_fields)
        return response

    @staticmethod
    def _rehydrate(result: TriageResult, redactor: PIIRedactor) -> TriageResult:
        """Restore original values locally, re-validating so the output contract still holds.

        Restored values come from the (attacker-controlled) alert and can be arbitrarily long,
        so the expanded text is truncated to the schema limits instead of breaking the response.
        """
        actions = [
            {"step": truncate(redactor.rehydrate(a.step), MAX_STEP_CHARS), "runbook_id": a.runbook_id}
            for a in result.recommended_actions
        ]
        data = result.model_dump()
        data.update(
            summary=truncate(redactor.rehydrate(result.summary), MAX_SUMMARY_CHARS), recommended_actions=actions
        )
        return TriageResult.model_validate(data)
