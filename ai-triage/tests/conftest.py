from __future__ import annotations

import copy
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from ai_triage.config import Settings
from ai_triage.llm.mock import MockLLMProvider
from ai_triage.main import create_app

from .helpers import RUNBOOKS, TOKEN, load_alert


@pytest.fixture
def audit_path(tmp_path: Path) -> Path:
    return tmp_path / "audit" / "audit.jsonl"


@pytest.fixture
def make_settings(audit_path: Path) -> Callable[..., Settings]:
    def _make(**overrides: Any) -> Settings:
        values: dict[str, Any] = {
            "api_token": TOKEN,
            "runbooks_dir": RUNBOOKS,
            "audit_log_path": str(audit_path),
            "llm_provider": "mock",
        }
        values.update(overrides)
        return Settings(**values)

    return _make


@pytest.fixture
def make_client(make_settings: Callable[..., Settings]) -> Callable[..., tuple[TestClient, MockLLMProvider]]:
    def _make(provider: MockLLMProvider | None = None, **settings_overrides: Any) -> tuple[TestClient, MockLLMProvider]:
        provider = provider or MockLLMProvider()
        app = create_app(make_settings(**settings_overrides), provider=provider)
        return TestClient(app), provider

    return _make


@pytest.fixture
def ssh_alert() -> dict[str, Any]:
    return copy.deepcopy(load_alert("ssh_bruteforce"))
