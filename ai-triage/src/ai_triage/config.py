"""Service configuration, loaded from environment variables (prefix ``TRIAGE_``)."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import AliasChoices, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_RUNBOOKS_DIR = Path(__file__).resolve().parents[2] / "runbooks"


class ProviderName(StrEnum):
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    OLLAMA = "ollama"
    MOCK = "mock"


class InjectionPolicy(StrEnum):
    # Send hardened prompt to the LLM, then apply strict guardrails to the answer.
    FLAG = "flag"
    # Never send suspicious alerts to the LLM: use deterministic fallback triage.
    BLOCK = "block"


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TRIAGE_", extra="ignore", env_parse_none_str="none")

    # --- LLM provider -----------------------------------------------------------------
    llm_provider: ProviderName = ProviderName.MOCK
    # Exact model identifier. Mandatory for real providers: pin it explicitly (LLM03).
    llm_model: str | None = None
    llm_base_url: str | None = None
    anthropic_api_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("TRIAGE_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY")
    )
    openai_api_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("TRIAGE_OPENAI_API_KEY", "OPENAI_API_KEY")
    )
    llm_timeout_s: float = Field(default=30.0, gt=0, le=300)
    llm_temperature: float | None = Field(default=0.0, ge=0, le=2)
    llm_max_input_tokens: int = Field(default=6000, ge=1500, le=200_000)
    llm_max_output_tokens: int = Field(default=1024, ge=256, le=8192)
    llm_max_retries: int = Field(default=1, ge=0, le=3)
    llm_max_concurrency: int = Field(default=4, ge=1, le=64)

    # --- Consumption limits (LLM10) ------------------------------------------------
    token_budget_per_minute: int = Field(default=150_000, ge=1000)
    rate_limit_per_minute: int = Field(default=120, ge=1)
    max_body_bytes: int = Field(default=256 * 1024, ge=1024, le=10 * 1024 * 1024)

    # --- API authentication ----------------------------------------------------------
    api_token: SecretStr | None = None
    allow_unauthenticated: bool = False
    enable_docs: bool = False

    # --- RAG ---------------------------------------------------------------------------
    runbooks_dir: Path = DEFAULT_RUNBOOKS_DIR
    rag_top_k: int = Field(default=3, ge=1, le=10)
    rag_max_context_tokens: int = Field(default=2000, ge=200)

    # --- Audit ---------------------------------------------------------------------------
    # Path of the JSONL audit log. "-" writes the audit trail to stdout.
    audit_log_path: str = "-"
    audit_hmac_key: SecretStr | None = None
    audit_include_prompts: bool = False

    # --- Privacy (LLM02) -------------------------------------------------------------
    pii_redact_ips: bool = True
    pii_rehydrate_output: bool = True
    pii_extra_user_keys: str = ""
    pii_keep_usernames: str = (
        "root,admin,administrator,system,nobody,daemon,www-data,guest,sshd,local service,network service"
    )

    # --- Guardrails --------------------------------------------------------------------
    injection_policy: InjectionPolicy = InjectionPolicy.FLAG
    injection_threshold: int = Field(default=3, ge=1)
    severity_max_downgrade: int = Field(default=1, ge=0, le=4)
    url_allowlist: str = "attack.mitre.org,documentation.wazuh.com"
    output_language: str = Field(default="en", pattern=r"^[a-z]{2}(-[A-Z]{2})?$")

    @field_validator("llm_model", "llm_base_url")
    @classmethod
    def _blank_to_none(cls, value: str | None) -> str | None:
        if isinstance(value, str):
            return value.strip() or None
        return value

    @model_validator(mode="after")
    def _check_consistency(self) -> Settings:
        if self.llm_provider is not ProviderName.MOCK and not self.llm_model:
            raise ValueError(f"TRIAGE_LLM_MODEL is required when TRIAGE_LLM_PROVIDER={self.llm_provider.value}")
        if self.llm_provider is ProviderName.ANTHROPIC and not self.anthropic_api_key:
            raise ValueError("ANTHROPIC_API_KEY is required for the anthropic provider")
        if self.llm_provider is ProviderName.OPENAI and not (self.openai_api_key or self.llm_base_url):
            raise ValueError("OPENAI_API_KEY is required for the openai provider (unless a base URL is set)")
        if not self.allow_unauthenticated:
            if self.api_token is None:
                raise ValueError("TRIAGE_API_TOKEN is required (or set TRIAGE_ALLOW_UNAUTHENTICATED=true)")
            if len(self.api_token.get_secret_value()) < 16:
                raise ValueError("TRIAGE_API_TOKEN must be at least 16 characters long")
        if self.rag_max_context_tokens >= self.llm_max_input_tokens:
            raise ValueError("TRIAGE_RAG_MAX_CONTEXT_TOKENS must be lower than TRIAGE_LLM_MAX_INPUT_TOKENS")
        return self

    @property
    def extra_user_keys(self) -> list[str]:
        return _split_csv(self.pii_extra_user_keys)

    @property
    def keep_usernames(self) -> list[str]:
        return _split_csv(self.pii_keep_usernames)

    @property
    def allowed_url_hosts(self) -> list[str]:
        return [host.lower() for host in _split_csv(self.url_allowlist)]
