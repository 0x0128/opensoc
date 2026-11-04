"""Provider adapters, tested against simulated HTTP backends (no network access)."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from ai_triage.config import Settings
from ai_triage.llm import ChatMessage, LLMRequest, ProviderError, build_provider
from ai_triage.llm.anthropic import AnthropicProvider
from ai_triage.llm.mock import MockLLMProvider, heuristic_responder
from ai_triage.llm.ollama import OllamaProvider
from ai_triage.llm.openai import OpenAIProvider

REQUEST = LLMRequest(
    system="SYSTEM PROMPT",
    messages=(ChatMessage("user", "alert data"),),
    max_output_tokens=777,
    temperature=0.0,
    json_schema={"type": "object"},
)


def transport(status: int, body: Any, seen: list[httpx.Request]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        content = body if isinstance(body, bytes) else json.dumps(body).encode()
        return httpx.Response(status, content=content, headers={"content-type": "application/json"})

    return httpx.MockTransport(handler)


async def test_anthropic_request_and_response_mapping() -> None:
    seen: list[httpx.Request] = []
    body = {
        "model": "test-model",
        "content": [{"type": "text", "text": '{"ok": '}, {"type": "text", "text": "true}"}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 120, "output_tokens": 30},
    }
    provider = AnthropicProvider("test-model", api_key="sk-test", transport=transport(200, body, seen))
    response = await provider.complete(REQUEST)
    sent = json.loads(seen[0].content)
    assert str(seen[0].url) == "https://api.anthropic.com/v1/messages"
    assert seen[0].headers["x-api-key"] == "sk-test"
    assert seen[0].headers["anthropic-version"] == "2023-06-01"
    assert sent == {
        "model": "test-model",
        "max_tokens": 777,
        "system": "SYSTEM PROMPT",
        "messages": [{"role": "user", "content": "alert data"}],
        "temperature": 0.0,
    }
    assert response.text == '{"ok": true}'
    assert (response.input_tokens, response.output_tokens, response.truncated) == (120, 30, False)
    await provider.aclose()


async def test_anthropic_max_tokens_and_refusal() -> None:
    seen: list[httpx.Request] = []
    truncated = {"content": [{"type": "text", "text": "{"}], "stop_reason": "max_tokens", "usage": {}}
    provider = AnthropicProvider("m", api_key="k", transport=transport(200, truncated, seen))
    assert (await provider.complete(REQUEST)).truncated
    refusal = {"content": [], "stop_reason": "refusal"}
    provider = AnthropicProvider("m", api_key="k", transport=transport(200, refusal, seen))
    with pytest.raises(ProviderError, match="refused"):
        await provider.complete(REQUEST)


async def test_openai_request_and_response_mapping() -> None:
    seen: list[httpx.Request] = []
    body = {
        "model": "gpt-test",
        "choices": [{"message": {"role": "assistant", "content": "{}"}, "finish_reason": "length"}],
        "usage": {"prompt_tokens": 50, "completion_tokens": 5},
    }
    provider = OpenAIProvider("gpt-test", api_key="sk-oai", transport=transport(200, body, seen))
    response = await provider.complete(REQUEST)
    sent = json.loads(seen[0].content)
    assert str(seen[0].url) == "https://api.openai.com/v1/chat/completions"
    assert seen[0].headers["authorization"] == "Bearer sk-oai"
    assert sent["messages"][0] == {"role": "system", "content": "SYSTEM PROMPT"}
    assert sent["max_completion_tokens"] == 777
    assert sent["response_format"] == {"type": "json_object"}
    assert response.truncated and response.input_tokens == 50


async def test_openai_compatible_base_url_without_key() -> None:
    seen: list[httpx.Request] = []
    body = {"choices": [{"message": {"content": "{}"}, "finish_reason": "stop"}]}
    provider = OpenAIProvider(
        "local", api_key=None, base_url="http://vllm:8000/v1/", transport=transport(200, body, seen)
    )
    await provider.complete(REQUEST)
    assert str(seen[0].url) == "http://vllm:8000/v1/chat/completions"
    assert "authorization" not in seen[0].headers


async def test_ollama_request_and_response_mapping() -> None:
    seen: list[httpx.Request] = []
    body = {"model": "local", "message": {"role": "assistant", "content": "{}"}, "done_reason": "stop",
            "prompt_eval_count": 400, "eval_count": 60}  # fmt: skip
    provider = OllamaProvider("local", context_tokens=8192, transport=transport(200, body, seen))
    response = await provider.complete(REQUEST)
    sent = json.loads(seen[0].content)
    assert str(seen[0].url) == "http://ollama:11434/api/chat"
    assert sent["stream"] is False
    assert sent["format"] == {"type": "object"}
    assert sent["options"] == {"num_predict": 777, "num_ctx": 8192, "temperature": 0.0}
    assert sent["messages"][0]["role"] == "system"
    assert (response.input_tokens, response.output_tokens) == (400, 60)


@pytest.mark.parametrize(
    "factory",
    [
        lambda t: AnthropicProvider("m", api_key="k", transport=t),
        lambda t: OpenAIProvider("m", api_key="k", transport=t),
        lambda t: OllamaProvider("m", context_tokens=4096, transport=t),
    ],
)
@pytest.mark.parametrize(
    ("status", "body", "reason"),
    [
        (500, {"error": "boom: SYSTEM PROMPT echoed"}, "error response"),
        (200, b"not json", "invalid JSON"),
        (200, [1, 2], "unexpected response shape"),
        (200, b"x" * (1024 * 1024 + 1), "response too large"),
    ],
)
async def test_provider_errors_are_mapped_without_leaking_content(
    factory: Callable[[httpx.MockTransport], Any], status: int, body: Any, reason: str
) -> None:
    provider = factory(transport(status, body, []))
    with pytest.raises(ProviderError) as exc:
        await provider.complete(REQUEST)
    assert reason in str(exc.value) and "SYSTEM PROMPT" not in str(exc.value)


async def test_transport_failures_are_provider_errors() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    with pytest.raises(ProviderError, match="transport error"):
        await OllamaProvider("m", context_tokens=1, transport=httpx.MockTransport(boom)).complete(REQUEST)
    with pytest.raises(ProviderError, match="timeout"):
        await OllamaProvider("m", context_tokens=1, transport=httpx.MockTransport(slow)).complete(REQUEST)


def test_factory_builds_each_provider() -> None:
    common = {"api_token": "x" * 20, "llm_model": "pinned-model-id"}
    assert isinstance(build_provider(Settings(llm_provider="anthropic", anthropic_api_key="k", **common)),
                      AnthropicProvider)  # fmt: skip
    assert isinstance(build_provider(Settings(llm_provider="openai", openai_api_key="k", **common)), OpenAIProvider)
    ollama = build_provider(Settings(llm_provider="ollama", llm_max_input_tokens=6000, llm_max_output_tokens=1024,
                                     **common))  # fmt: skip
    assert isinstance(ollama, OllamaProvider) and ollama._num_ctx == 6000 + 1024 + 256
    assert isinstance(build_provider(Settings(llm_provider="mock", api_token="x" * 20)), MockLLMProvider)


async def test_mock_provider_records_requests_and_heuristic_is_valid_json() -> None:
    provider = MockLLMProvider()
    response = await provider.complete(REQUEST)
    assert provider.requests == [REQUEST]
    assert json.loads(response.text)["severity"] == "medium"
    assert json.loads(heuristic_responder(REQUEST))["recommended_actions"]
