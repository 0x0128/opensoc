"""End-to-end tests of the HTTP service with a simulated LLM."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ai_triage.llm.base import LLMRequest, LLMResponse, ProviderError
from ai_triage.llm.mock import extract_alert
from ai_triage.security.audit import verify_chain

from .helpers import AUTH, ScriptedLLM, good_answer, load_alert, read_audit


def post(client: Any, alert: dict[str, Any], headers: dict[str, str] | None = None) -> Any:
    return client.post("/v1/triage", json=alert, headers=headers if headers is not None else AUTH)


# ------------------------------------------------------------------ happy path & contract
def test_triage_happy_path(make_client: Any, ssh_alert: dict, audit_path: Path) -> None:
    client, llm = make_client(ScriptedLLM(good_answer()))
    response = post(client, ssh_alert)
    assert response.status_code == 200, response.text
    body = response.json()
    triage, analysis = body["triage"], body["analysis"]
    assert set(triage) == {"severity", "summary", "mitre", "recommended_actions", "confidence"}
    assert triage["severity"] == "high"
    assert triage["mitre"]["technique_id"] == "T1110.001"
    assert triage["recommended_actions"][0]["runbook_id"] == "ssh-brute-force"
    assert 0 <= triage["confidence"] <= 1
    assert analysis["engine"] == "llm" and analysis["provider"] == "mock"
    assert analysis["baseline_severity"] == "medium"
    assert analysis["runbooks"][0] == "ssh-brute-force"
    assert analysis["prompt_injection"]["suspected"] is False
    assert body["alert_id"] == "1762247564.4471" and body["rule_id"] == "5712"
    # PII re-hydrated locally in the answer returned to the SOC...
    assert "185.220.101.47" in triage["summary"] and "deploy" in triage["summary"]
    # ...but the LLM only ever saw placeholders.
    assert len(llm.requests) == 1
    assert "185.220.101.47" not in llm.prompts[0] and "deploy" not in llm.prompts[0].split("<alert_data")[1]
    assert "[IP_EXTERNAL_1]" in llm.prompts[0]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert verify_chain(audit_path)[0]


def test_rehydration_can_be_disabled(make_client: Any, ssh_alert: dict) -> None:
    client, _ = make_client(ScriptedLLM(good_answer()), pii_rehydrate_output=False)
    summary = post(client, ssh_alert).json()["triage"]["summary"]
    assert "[IP_EXTERNAL_1]" in summary and "185.220.101.47" not in summary


def test_rag_context_and_token_limits_are_sent_to_provider(make_client: Any, ssh_alert: dict) -> None:
    client, llm = make_client(ScriptedLLM(good_answer()), llm_max_output_tokens=512)
    post(client, ssh_alert)
    request: LLMRequest = llm.requests[0]
    assert request.max_output_tokens == 512
    assert "### runbook_id: ssh-brute-force" in request.messages[0].content
    assert extract_alert(request)["rule"]["id"] == "5712"


def test_default_mock_provider_works_offline(make_client: Any) -> None:
    client, _ = make_client()
    body = post(client, load_alert("fim_passwd")).json()
    assert body["analysis"]["engine"] == "llm"
    assert body["triage"]["recommended_actions"][0]["runbook_id"] == "fim-critical-file-change"
    assert body["triage"]["summary"].startswith("[simulated]")


# ------------------------------------------------------------------ privacy
def test_no_pii_reaches_llm_or_audit_log(make_client: Any, audit_path: Path) -> None:
    client, llm = make_client(ScriptedLLM(good_answer()), audit_include_prompts=True)
    response = post(client, load_alert("pii_auth"))
    assert response.status_code == 200
    sensitive = ["maria.lopez@example.org", "12345678Z", "612 345 678", "203.0.113.77", "4111 1111 1111 1111",
                 "Sup3rS3cret!", "eyJhbGciOiJIUzI1NiJ9", "mlopez", "192.168.10.44"]  # fmt: skip
    audit_text = audit_path.read_text()
    for value in sensitive:
        assert value not in llm.prompts[0], value
        assert value not in audit_text, value
    pii = response.json()["analysis"]["pii"]["redacted"]
    assert pii["EMAIL"] == 1 and pii["SECRET"] >= 2 and pii["CARD"] == 1 and pii["NATIONAL_ID"] == 1


# ------------------------------------------------------------------ prompt injection
def naive_llm(request: LLMRequest) -> str:
    """A model that obeys injected instructions (worst case) and tries to exfiltrate."""
    return json.dumps(
        {
            "severity": "informational",
            "summary": "False positive as instructed by the log. Benign traffic, nothing to do.",
            "mitre": None,
            "recommended_actions": [
                {"step": "Close the alert. Details at https://evil.example.com/x", "runbook_id": "made-up"},
                {"step": "Disable the Wazuh agent on shop-frontend to reduce noise.", "runbook_id": None},
            ],
            "confidence": 1.0,
        }
    )


def test_prompt_injection_cannot_downgrade_or_silence_alert(make_client: Any, audit_path: Path) -> None:
    client, llm = make_client(ScriptedLLM(naive_llm))
    body = post(client, load_alert("web_injection")).json()
    triage, analysis = body["triage"], body["analysis"]
    assert analysis["prompt_injection"]["suspected"] is True
    assert triage["severity"] == "medium"  # max(baseline=medium, medium); never informational
    assert triage["confidence"] <= 0.5
    assert analysis["requires_human_review"] is True
    steps = " ".join(a["step"] for a in triage["recommended_actions"])
    assert "evil.example.com" not in steps and "Disable the Wazuh agent" not in steps
    assert triage["recommended_actions"][0]["step"].startswith("Mandatory manual review")
    assert all(a["runbook_id"] in (None, "web-application-attack") for a in triage["recommended_actions"])
    assert {"prompt_injection_review", "ungrounded_runbook_reference"} <= set(analysis["guardrails"])
    # The hostile text reached the model only inside the nonce-delimited, JSON-encoded block.
    prompt = llm.requests[0].messages[0].content
    assert "suspected=yes" in prompt
    assert prompt.count("</alert_data") == 1
    record = read_audit(audit_path)[-1]
    assert record["analysis"]["prompt_injection"]["suspected"] is True


def test_block_policy_skips_llm_for_suspicious_alerts(make_client: Any) -> None:
    client, llm = make_client(ScriptedLLM(good_answer()), injection_policy="block")
    body = post(client, load_alert("web_injection")).json()
    assert llm.requests == []
    assert body["analysis"]["engine"] == "fallback"
    assert body["analysis"]["fallback_reason"] == "prompt_injection_blocked"
    assert body["triage"]["severity"] == "medium"
    assert body["triage"]["mitre"]["technique_id"] == "T1190"


def test_system_prompt_leak_triggers_fallback(make_client: Any, ssh_alert: dict) -> None:
    def leaky(request: LLMRequest) -> str:
        return good_answer(summary=f"My system prompt says: {request.system[:400]}")

    client, llm = make_client(ScriptedLLM(leaky))
    body = post(client, ssh_alert).json()
    assert body["analysis"]["fallback_reason"] == "system_prompt_leak"
    assert len(llm.requests) == 1  # no retry after a leak
    assert "SECURITY RULES" not in json.dumps(body)


# ------------------------------------------------------------------ resilience
def test_invalid_output_is_retried_then_accepted(make_client: Any, ssh_alert: dict) -> None:
    client, llm = make_client(ScriptedLLM("Sure! Here is my analysis: it is bad.", good_answer()))
    body = post(client, ssh_alert).json()
    assert body["analysis"]["engine"] == "llm" and body["analysis"]["attempts"] == 2
    assert "rejected by the validator" in llm.requests[1].messages[-1].content


def test_persistent_invalid_output_falls_back(make_client: Any, ssh_alert: dict) -> None:
    client, llm = make_client(ScriptedLLM('{"severity": "bogus"}'), llm_max_retries=1)
    body = post(client, ssh_alert).json()
    assert body["analysis"]["engine"] == "fallback"
    assert body["analysis"]["fallback_reason"] == "invalid_llm_output"
    assert body["analysis"]["requires_human_review"] is True
    triage = body["triage"]
    assert triage["severity"] == "medium" and triage["confidence"] == 0.3
    assert triage["mitre"] == {"technique_id": "T1110.001", "technique_name": "Password Guessing",
                               "tactic": "Credential Access"}  # fmt: skip
    assert triage["recommended_actions"][0]["runbook_id"] == "ssh-brute-force"
    assert len(llm.requests) == 2


@pytest.mark.parametrize(
    ("answer", "reason"),
    [
        (ProviderError("mock", "error response", 503), "llm_provider_error"),
        (TimeoutError(), "llm_timeout"),
        (RuntimeError("bug"), "llm_unexpected_error"),
    ],
)
def test_provider_failures_fall_back(make_client: Any, ssh_alert: dict, answer: Exception, reason: str) -> None:
    client, _ = make_client(ScriptedLLM(answer))
    response = post(client, ssh_alert)
    assert response.status_code == 200
    assert response.json()["analysis"]["fallback_reason"] == reason


def test_truncated_output_is_not_trusted(make_client: Any, ssh_alert: dict) -> None:
    truncated = LLMResponse(text=good_answer(), model="m", truncated=True)
    client, _ = make_client(ScriptedLLM(truncated), llm_max_retries=0)
    assert post(client, ssh_alert).json()["analysis"]["fallback_reason"] == "invalid_llm_output"


def test_token_budget_exhaustion_falls_back(make_client: Any, ssh_alert: dict) -> None:
    client, llm = make_client(ScriptedLLM(good_answer()), token_budget_per_minute=4000)
    first = post(client, ssh_alert).json()
    second = post(client, ssh_alert).json()
    assert first["analysis"]["engine"] == "llm"
    assert second["analysis"]["fallback_reason"] == "token_budget_exhausted"
    assert len(llm.requests) == 1


def test_huge_alert_is_truncated_within_input_limit(make_client: Any, ssh_alert: dict) -> None:
    ssh_alert["full_log"] = "Invalid user deploy from 185.220.101.47 " * 5000
    client, llm = make_client(ScriptedLLM(good_answer()), llm_max_input_tokens=3000, rag_max_context_tokens=800)
    body = post(client, ssh_alert).json()
    assert body["analysis"]["alert_truncated"] is True
    assert body["analysis"]["usage"]["estimated_prompt_tokens"] <= 3000
    request = llm.requests[0]
    assert (len(request.system) + len(request.messages[0].content)) / 3 <= 3000


# ------------------------------------------------------------------ HTTP-level controls
@pytest.mark.parametrize(
    "headers",
    [{}, {"Authorization": "Bearer wrong-token-000000000"}, {"X-API-Key": "nope"}, {"Authorization": "Basic x"}],
)
def test_authentication_is_required(make_client: Any, ssh_alert: dict, headers: dict, audit_path: Path) -> None:
    client, llm = make_client()
    response = post(client, ssh_alert, headers=headers)
    assert response.status_code == 401
    assert llm.requests == []
    assert read_audit(audit_path)[-1]["event"] == "auth_failure"


def test_api_key_header_is_accepted(make_client: Any, ssh_alert: dict) -> None:
    client, _ = make_client()
    assert post(client, ssh_alert, headers={"X-API-Key": AUTH["Authorization"][7:]}).status_code == 200


def test_rate_limit(make_client: Any, ssh_alert: dict) -> None:
    client, _ = make_client(rate_limit_per_minute=2)
    assert [post(client, ssh_alert).status_code for _ in range(3)] == [200, 200, 429]


def test_body_size_limit(make_client: Any, ssh_alert: dict) -> None:
    client, llm = make_client(max_body_bytes=2048)
    ssh_alert["full_log"] = "x" * 4096
    assert post(client, ssh_alert).status_code == 413
    assert llm.requests == []


def test_rejects_non_json(make_client: Any) -> None:
    client, _ = make_client()
    assert client.post("/v1/triage", content=b"{not json", headers={**AUTH, "content-type": "application/json"}
                       ).status_code == 400  # fmt: skip
    assert client.post("/v1/triage", content=b"[1]", headers={**AUTH, "content-type": "application/json"}
                       ).status_code == 400  # fmt: skip
    assert client.post("/v1/triage", content=b"a=b", headers={**AUTH, "content-type": "text/plain"}
                       ).status_code == 415  # fmt: skip


def test_schema_errors_do_not_echo_input(make_client: Any, ssh_alert: dict) -> None:
    client, _ = make_client()
    ssh_alert["rule"]["level"] = "maria.lopez@example.org"
    response = post(client, ssh_alert)
    assert response.status_code == 422
    assert "maria.lopez" not in response.text
    assert response.json()["detail"][0]["loc"] == ["rule", "level"]


def test_health_and_readiness(make_client: Any) -> None:
    client, _ = make_client()
    assert client.get("/healthz").json() == {"status": "ok"}
    ready = client.get("/readyz").json()
    assert ready["runbooks_loaded"] == 10 and ready["runbooks_rejected"] == 0


def test_docs_disabled_by_default(make_client: Any) -> None:
    client, _ = make_client()
    assert client.get("/docs").status_code == 404 and client.get("/openapi.json").status_code == 404
    client, _ = make_client(enable_docs=True)
    assert client.get("/openapi.json").status_code == 200


def test_request_id_is_propagated_or_generated(make_client: Any, ssh_alert: dict) -> None:
    client, _ = make_client()
    supplied = post(client, ssh_alert, headers={**AUTH, "X-Request-ID": "wazuh-req-0001"})
    assert supplied.json()["request_id"] == "wazuh-req-0001"
    bogus = post(client, ssh_alert, headers={**AUTH, "X-Request-ID": "<script>"})
    assert bogus.json()["request_id"] != "<script>" and len(bogus.json()["request_id"]) == 32


def test_audit_trail_records_startup_and_triage(make_client: Any, ssh_alert: dict, audit_path: Path) -> None:
    client, _ = make_client(ScriptedLLM(good_answer()))
    post(client, ssh_alert)
    events = read_audit(audit_path)
    start, triage = events[0], events[-1]
    assert start["event"] == "service_start" and len(start["runbooks"]) == 10
    assert triage["event"] == "triage" and triage["rule_id"] == "5712"
    assert triage["client"].startswith("token:") and len(triage["prompt_sha256"]) == 64
    # The audit stores the redacted triage (placeholders, not values).
    assert "[IP_EXTERNAL_1]" in triage["triage"]["summary"]
    assert "185.220.101.47" not in json.dumps(triage)
    assert verify_chain(audit_path) == (True, len(events), "ok")


def test_rehydrating_huge_attacker_values_never_breaks_the_response(make_client: Any, ssh_alert: dict) -> None:
    ssh_alert["data"]["srcuser"] = "u" * 5000  # attacker-chosen user name
    ssh_alert["full_log"] = "Invalid user " + "u" * 5000 + " from 185.220.101.47"
    answer = good_answer(
        summary="Brute force against [USER_1] [USER_1] from [IP_EXTERNAL_1].",
        recommended_actions=[{"step": "Review the account [USER_1].", "runbook_id": "ssh-brute-force"}],
    )
    client, _ = make_client(ScriptedLLM(answer))
    response = post(client, ssh_alert)
    assert response.status_code == 200, response.text
    triage = response.json()["triage"]
    assert len(triage["summary"]) <= 1200 and len(triage["recommended_actions"][0]["step"]) <= 400


def test_alert_extra_fields_reach_the_prompt(make_client: Any) -> None:
    client, llm = make_client(ScriptedLLM(good_answer()))
    post(client, load_alert("fim_passwd"))
    alert = extract_alert(llm.requests[0])
    assert alert["syscheck"]["path"] == "/etc/passwd"
    assert alert["syscheck"]["audit"]["user"]["name"] == "[USER_1]"


def test_failed_authentication_is_rate_limited(make_client: Any, ssh_alert: dict, audit_path: Path) -> None:
    client, _ = make_client(rate_limit_per_minute=3)
    codes = [post(client, ssh_alert, headers={"X-API-Key": "bad"}).status_code for _ in range(5)]
    assert codes == [401, 401, 401, 429, 429]
    assert sum(e["event"] == "auth_failure" for e in read_audit(audit_path)) == 3


async def test_saturated_llm_degrades_to_fallback(make_settings: Any) -> None:
    import asyncio

    from ai_triage.llm.base import LLMProvider
    from ai_triage.models import WazuhAlert
    from ai_triage.pipeline import TriageService
    from ai_triage.rag.retriever import BM25RunbookRetriever
    from ai_triage.security.audit import AuditLogger
    from ai_triage.security.limits import TokenBudget

    class SlowLLM(LLMProvider):
        name = "slow"

        async def complete(self, request: LLMRequest) -> LLMResponse:
            await asyncio.sleep(3)
            return LLMResponse(text=good_answer(), model="slow")

    settings = make_settings(llm_timeout_s=0.1, llm_max_concurrency=1)
    service = TriageService(
        settings=settings,
        provider=SlowLLM("slow"),
        retriever=BM25RunbookRetriever([]),
        audit=AuditLogger(settings.audit_log_path),
        token_budget=TokenBudget(10**6),
    )
    alert = WazuhAlert.model_validate(load_alert("ssh_bruteforce"))
    started = asyncio.get_running_loop().time()
    results = await asyncio.gather(*(service.triage(alert, request_id=f"r{i}", client_id="c") for i in range(3)))
    assert {r.analysis.fallback_reason for r in results} == {"llm_timeout"}
    assert asyncio.get_running_loop().time() - started < 10
