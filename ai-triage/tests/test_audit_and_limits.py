from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_triage.config import Settings
from ai_triage.security.audit import AuditLogger, main, verify_chain
from ai_triage.security.limits import SlidingWindowRateLimiter, TokenBudget, estimate_tokens


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_audit_chain_verifies(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    log = AuditLogger(path)
    for i in range(5):
        log.record("triage", n=i)
    assert verify_chain(path) == (True, 5, "ok")


def test_audit_chain_resumes_after_restart(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    AuditLogger(path).record("one")
    second = AuditLogger(path).record("two")
    assert second["seq"] == 2
    assert verify_chain(path)[0]


@pytest.mark.parametrize("tamper", ["edit", "delete", "reorder"])
def test_audit_tampering_is_detected(tmp_path: Path, tamper: str) -> None:
    path = tmp_path / "a.jsonl"
    log = AuditLogger(path)
    for i in range(4):
        log.record("triage", severity="high", n=i)
    lines = path.read_text().splitlines()
    if tamper == "edit":
        lines[1] = lines[1].replace('"high"', '"low"')
    elif tamper == "delete":
        del lines[2]
    else:
        lines[1], lines[2] = lines[2], lines[1]
    path.write_text("\n".join(lines) + "\n")
    ok, _, message = verify_chain(path)
    assert not ok, message


def test_audit_hmac_requires_key(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    AuditLogger(path, hmac_key=b"k" * 32).record("triage")
    assert verify_chain(path, hmac_key=b"k" * 32)[0]
    assert not verify_chain(path, hmac_key=b"wrong")[0]
    assert not verify_chain(path)[0]


def test_audit_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "a.jsonl"
    AuditLogger(path).record("x")
    assert main(["verify", str(path)]) == 0
    assert "OK: 1 records" in capsys.readouterr().out


def test_audit_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    AuditLogger("-").record("hello", a=1)
    record = json.loads(capsys.readouterr().out)
    assert record["event"] == "hello" and record["prev"] == "0" * 64


def test_rate_limiter_sliding_window() -> None:
    clock = FakeClock()
    limiter = SlidingWindowRateLimiter(2, window_s=60, clock=clock)
    assert limiter.check("a") == (True, 0)
    assert limiter.check("a") == (True, 0)
    allowed, retry = limiter.check("a")
    assert not allowed and 1 <= retry <= 60
    assert limiter.check("b")[0]  # per-key
    clock.now += 61
    assert limiter.check("a")[0]


def test_token_budget() -> None:
    clock = FakeClock()
    budget = TokenBudget(1000, window_s=60, clock=clock)
    assert budget.try_consume(600)
    assert not budget.try_consume(500)
    assert budget.remaining() == 400
    clock.now += 60
    assert budget.try_consume(1000)


def test_token_estimate_is_conservative() -> None:
    assert estimate_tokens("a" * 300) == 100
    assert estimate_tokens("") == 0


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"llm_provider": "anthropic"}, "TRIAGE_LLM_MODEL is required"),
        ({"llm_provider": "anthropic", "llm_model": "m"}, "ANTHROPIC_API_KEY is required"),
        ({"llm_provider": "openai", "llm_model": "m"}, "OPENAI_API_KEY is required"),
        ({"api_token": None}, "TRIAGE_API_TOKEN is required"),
        ({"api_token": "short"}, "at least 16 characters"),
        ({"rag_max_context_tokens": 7000}, "lower than"),
    ],
)
def test_insecure_or_incomplete_configuration_is_rejected(overrides: dict, message: str) -> None:
    values = {"api_token": "x" * 20, **overrides}
    with pytest.raises(ValueError, match=message):
        Settings(**values)


def test_unauthenticated_mode_must_be_explicit() -> None:
    assert Settings(api_token=None, allow_unauthenticated=True).api_token is None


def test_settings_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRIAGE_LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("TRIAGE_LLM_MODEL", "pinned-model")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-env")
    monkeypatch.setenv("TRIAGE_API_TOKEN", "y" * 24)
    monkeypatch.setenv("TRIAGE_URL_ALLOWLIST", "attack.mitre.org, Example.COM")
    monkeypatch.setenv("TRIAGE_LLM_TEMPERATURE", "none")
    settings = Settings()
    assert settings.anthropic_api_key is not None and settings.anthropic_api_key.get_secret_value() == "sk-env"
    assert settings.allowed_url_hosts == ["attack.mitre.org", "example.com"]
    assert settings.llm_temperature is None
    assert "sk-env" not in repr(settings)


def test_audit_fails_closed_when_not_writable(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x")
    with pytest.raises(RuntimeError, match="not writable"):
        AuditLogger(blocker / "audit.jsonl")
