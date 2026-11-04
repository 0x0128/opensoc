"""Ollama (local models) provider using the native ``/api/chat`` endpoint."""

from __future__ import annotations

from typing import Any, ClassVar

import httpx

from .base import HTTPLLMProvider, LLMRequest, LLMResponse, ProviderError


class OllamaProvider(HTTPLLMProvider):
    name: ClassVar[str] = "ollama"
    default_base_url: ClassVar[str] = "http://ollama:11434"

    def __init__(
        self,
        model: str,
        *,
        context_tokens: int,
        base_url: str | None = None,
        timeout_s: float = 60.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(model, base_url=base_url, timeout_s=timeout_s, transport=transport)
        # Ollama silently drops the *beginning* of the prompt when it exceeds num_ctx, which
        # would remove the system prompt and its security rules. Size the window explicitly.
        self._num_ctx = context_tokens

    async def complete(self, request: LLMRequest) -> LLMResponse:
        options: dict[str, Any] = {"num_predict": request.max_output_tokens, "num_ctx": self._num_ctx}
        if request.temperature is not None:
            options["temperature"] = request.temperature
        payload: dict[str, Any] = {
            "model": self.model,
            "stream": False,
            "messages": [
                {"role": "system", "content": request.system},
                *({"role": m.role, "content": m.content} for m in request.messages),
            ],
            # Schema-constrained decoding when a schema is supplied, JSON mode otherwise.
            "format": request.json_schema or "json",
            "options": options,
        }
        data = await self._post_json("/api/chat", payload)
        message = data.get("message")
        if not isinstance(message, dict):
            raise ProviderError(self.name, "missing message")
        return LLMResponse(
            text=str(message.get("content") or ""),
            model=str(data.get("model") or self.model),
            input_tokens=int(data.get("prompt_eval_count") or 0),
            output_tokens=int(data.get("eval_count") or 0),
            truncated=data.get("done_reason") == "length",
        )
