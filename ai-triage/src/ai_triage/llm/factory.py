"""Build the configured provider. Adding a provider = implement LLMProvider + one branch here."""

from __future__ import annotations

import httpx

from ..config import ProviderName, Settings
from .anthropic import AnthropicProvider
from .base import LLMProvider
from .mock import MockLLMProvider
from .ollama import OllamaProvider
from .openai import OpenAIProvider


def build_provider(settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None) -> LLMProvider:
    model = settings.llm_model or ""
    common = {"base_url": settings.llm_base_url, "timeout_s": settings.llm_timeout_s, "transport": transport}
    match settings.llm_provider:
        case ProviderName.ANTHROPIC:
            assert settings.anthropic_api_key is not None
            return AnthropicProvider(model, api_key=settings.anthropic_api_key.get_secret_value(), **common)
        case ProviderName.OPENAI:
            key = settings.openai_api_key.get_secret_value() if settings.openai_api_key else None
            return OpenAIProvider(model, api_key=key, **common)
        case ProviderName.OLLAMA:
            context = settings.llm_max_input_tokens + settings.llm_max_output_tokens + 256
            return OllamaProvider(model, context_tokens=context, **common)
        case ProviderName.MOCK:
            return MockLLMProvider(model or "mock-heuristic")
    raise ValueError(f"unsupported provider {settings.llm_provider}")
