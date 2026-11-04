"""Anthropic Messages API provider."""

from __future__ import annotations

from typing import Any, ClassVar

import httpx

from .base import HTTPLLMProvider, LLMRequest, LLMResponse, ProviderError

ANTHROPIC_VERSION = "2023-06-01"


class AnthropicProvider(HTTPLLMProvider):
    name: ClassVar[str] = "anthropic"
    default_base_url: ClassVar[str] = "https://api.anthropic.com"

    def __init__(
        self,
        model: str,
        *,
        api_key: str,
        base_url: str | None = None,
        timeout_s: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(model, base_url=base_url, timeout_s=timeout_s, transport=transport)
        self._api_key = api_key

    def _headers(self) -> dict[str, str]:
        return {
            "content-type": "application/json",
            "x-api-key": self._api_key,
            "anthropic-version": ANTHROPIC_VERSION,
        }

    async def complete(self, request: LLMRequest) -> LLMResponse:
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": request.max_output_tokens,
            "system": request.system,
            "messages": [{"role": m.role, "content": m.content} for m in request.messages],
        }
        if request.temperature is not None:
            payload["temperature"] = request.temperature
        data = await self._post_json("/v1/messages", payload)
        stop_reason = data.get("stop_reason")
        if stop_reason == "refusal":
            raise ProviderError(self.name, "model refused the request")
        blocks = data.get("content")
        if not isinstance(blocks, list):
            raise ProviderError(self.name, "missing content")
        text = "".join(b.get("text", "") for b in blocks if isinstance(b, dict) and b.get("type") == "text")
        usage = data.get("usage") or {}
        return LLMResponse(
            text=text,
            model=str(data.get("model") or self.model),
            input_tokens=int(usage.get("input_tokens") or 0),
            output_tokens=int(usage.get("output_tokens") or 0),
            truncated=stop_reason == "max_tokens",
        )
