"""OpenAI Chat Completions provider (also works with OpenAI-compatible servers via base URL)."""

from __future__ import annotations

from typing import Any, ClassVar

import httpx

from .base import HTTPLLMProvider, LLMRequest, LLMResponse, ProviderError


class OpenAIProvider(HTTPLLMProvider):
    name: ClassVar[str] = "openai"
    default_base_url: ClassVar[str] = "https://api.openai.com/v1"

    def __init__(
        self,
        model: str,
        *,
        api_key: str | None,
        base_url: str | None = None,
        timeout_s: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(model, base_url=base_url, timeout_s=timeout_s, transport=transport)
        self._api_key = api_key

    def _headers(self) -> dict[str, str]:
        headers = {"content-type": "application/json"}
        if self._api_key:
            headers["authorization"] = f"Bearer {self._api_key}"
        return headers

    async def complete(self, request: LLMRequest) -> LLMResponse:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": request.system},
                *({"role": m.role, "content": m.content} for m in request.messages),
            ],
            "max_completion_tokens": request.max_output_tokens,
            # JSON mode: guarantees syntactically valid JSON; the schema is enforced by our validator.
            "response_format": {"type": "json_object"},
        }
        if request.temperature is not None:
            payload["temperature"] = request.temperature
        data = await self._post_json("/chat/completions", payload)
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise ProviderError(self.name, "missing choices")
        choice = choices[0]
        message = choice.get("message") or {}
        if message.get("refusal"):
            raise ProviderError(self.name, "model refused the request")
        usage = data.get("usage") or {}
        return LLMResponse(
            text=str(message.get("content") or ""),
            model=str(data.get("model") or self.model),
            input_tokens=int(usage.get("prompt_tokens") or 0),
            output_tokens=int(usage.get("completion_tokens") or 0),
            truncated=choice.get("finish_reason") == "length",
        )
