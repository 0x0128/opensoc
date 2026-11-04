"""Provider-agnostic LLM interface.

Every provider implements :class:`LLMProvider.complete`, receiving a fully built
:class:`LLMRequest` (system prompt, messages, output token cap) and returning the raw text
plus usage metadata. Providers never see alert objects: only the already redacted,
delimited prompt built by :mod:`ai_triage.prompts`.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, ClassVar, Literal

import httpx

logger = logging.getLogger(__name__)

MAX_PROVIDER_RESPONSE_BYTES = 1024 * 1024


@dataclass(frozen=True)
class ChatMessage:
    role: Literal["user", "assistant"]
    content: str


@dataclass(frozen=True)
class LLMRequest:
    system: str
    messages: tuple[ChatMessage, ...]
    max_output_tokens: int
    temperature: float | None = 0.0
    json_schema: dict[str, Any] | None = None


@dataclass(frozen=True)
class LLMResponse:
    text: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    truncated: bool = False


class ProviderError(Exception):
    """Any provider failure. The message never contains prompt or response content."""

    def __init__(self, provider: str, reason: str, status: int | None = None) -> None:
        self.provider, self.reason, self.status = provider, reason, status
        super().__init__(f"{provider}: {reason}" + (f" (HTTP {status})" if status else ""))


class LLMProvider(ABC):
    name: ClassVar[str] = "abstract"

    def __init__(self, model: str) -> None:
        self.model = model

    @abstractmethod
    async def complete(self, request: LLMRequest) -> LLMResponse: ...

    async def aclose(self) -> None:  # noqa: B027 - optional hook
        """Release network resources."""


class HTTPLLMProvider(LLMProvider):
    """Shared plumbing for HTTP/JSON providers (timeouts, size limits, error mapping)."""

    default_base_url: ClassVar[str] = ""

    def __init__(
        self,
        model: str,
        *,
        base_url: str | None = None,
        timeout_s: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(model)
        self.base_url = (base_url or self.default_base_url).rstrip("/")
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_s, connect=min(10.0, timeout_s)),
            transport=transport,
            follow_redirects=False,
            trust_env=True,
        )

    def _headers(self) -> dict[str, str]:
        return {"content-type": "application/json"}

    async def _post_json(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            response = await self._client.post(f"{self.base_url}{path}", json=payload, headers=self._headers())
        except httpx.TimeoutException:
            raise ProviderError(self.name, "timeout") from None
        except httpx.HTTPError as exc:
            raise ProviderError(self.name, f"transport error: {type(exc).__name__}") from None
        if len(response.content) > MAX_PROVIDER_RESPONSE_BYTES:
            raise ProviderError(self.name, "response too large", response.status_code)
        if response.status_code >= 400:
            # Do not log the body: some providers echo the prompt back in error messages.
            raise ProviderError(self.name, "error response", response.status_code)
        try:
            data = response.json()
        except ValueError:
            raise ProviderError(self.name, "invalid JSON response", response.status_code) from None
        if not isinstance(data, dict):
            raise ProviderError(self.name, "unexpected response shape", response.status_code)
        return data

    async def aclose(self) -> None:
        await self._client.aclose()
