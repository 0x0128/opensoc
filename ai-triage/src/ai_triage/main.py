"""FastAPI application. Run with ``uvicorn --factory ai_triage.main:create_app``."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from . import __version__
from .config import Settings
from .llm.base import LLMProvider
from .llm.factory import build_provider
from .models import TriageResponse, WazuhAlert
from .pipeline import TriageService
from .rag.retriever import BM25RunbookRetriever
from .rag.runbooks import load_runbooks
from .security.audit import AuditLogger
from .security.limits import SlidingWindowRateLimiter, TokenBudget

logger = logging.getLogger("ai_triage")

LOOP_GUARD_GROUP = "ai_triage"
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
}


class _BodyTooLarge(Exception):
    pass


async def _read_limited_body(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
        raise _BodyTooLarge
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise _BodyTooLarge
        chunks.append(chunk)
    return b"".join(chunks)


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "ts": self.formatTime(record),
                "level": record.levelname,
                "logger": record.name,
                "msg": record.getMessage(),
            },
            ensure_ascii=False,
        )


def _configure_logging() -> None:
    root = logging.getLogger()
    if not root.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(_JsonFormatter())
        root.addHandler(handler)
        root.setLevel(logging.INFO)
    # httpx logs full request lines at INFO; keep provider traffic out of the service log.
    logging.getLogger("httpx").setLevel(logging.WARNING)


def create_app(settings: Settings | None = None, *, provider: LLMProvider | None = None) -> FastAPI:
    _configure_logging()
    settings = settings or Settings()
    provider = provider or build_provider(settings)

    hmac_key = settings.audit_hmac_key.get_secret_value().encode() if settings.audit_hmac_key else None
    audit = AuditLogger(settings.audit_log_path, hmac_key=hmac_key)
    loaded = load_runbooks(settings.runbooks_dir, injection_threshold=settings.injection_threshold)
    retriever = BM25RunbookRetriever(loaded.runbooks)
    service = TriageService(
        settings=settings,
        provider=provider,
        retriever=retriever,
        audit=audit,
        token_budget=TokenBudget(settings.token_budget_per_minute),
    )
    rate_limiter = SlidingWindowRateLimiter(settings.rate_limit_per_minute)
    audit.record(
        "service_start",
        version=__version__,
        provider=provider.name,
        model=provider.model,
        runbooks={rb.id: rb.sha256 for rb in loaded.runbooks},
        rejected_runbooks=loaded.rejected,
        injection_policy=settings.injection_policy.value,
        limits={
            "max_input_tokens": settings.llm_max_input_tokens,
            "max_output_tokens": settings.llm_max_output_tokens,
            "token_budget_per_minute": settings.token_budget_per_minute,
            "rate_limit_per_minute": settings.rate_limit_per_minute,
            "max_body_bytes": settings.max_body_bytes,
        },
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        await provider.aclose()
        audit.record("service_stop")

    app = FastAPI(
        title="OpenSOC AI Triage",
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs" if settings.enable_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
    )
    app.state.settings = settings
    app.state.service = service
    app.state.audit = audit
    app.state.runbooks = loaded

    @app.middleware("http")
    async def _security_headers(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        supplied = request.headers.get("x-request-id", "")
        request.state.request_id = supplied if _REQUEST_ID_RE.match(supplied) else uuid.uuid4().hex
        response = await call_next(request)
        response.headers.update(_SECURITY_HEADERS)
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        logger.error("unhandled error %s on %s", type(exc).__name__, request.url.path)
        request_id = getattr(request.state, "request_id", None)
        return JSONResponse({"detail": "internal error", "request_id": request_id}, status_code=500)

    def authenticate(request: Request) -> str:
        expected = settings.api_token.get_secret_value() if settings.api_token else None
        if expected is None:  # only reachable with TRIAGE_ALLOW_UNAUTHENTICATED=true
            return f"anonymous:{request.client.host if request.client else 'unknown'}"
        supplied = request.headers.get("x-api-key", "")
        authorization = request.headers.get("authorization", "")
        if authorization.lower().startswith("bearer "):
            supplied = authorization[7:].strip()
        if not supplied or not hmac.compare_digest(supplied.encode(), expected.encode()):
            host = request.client.host if request.client else "unknown"
            # Failed attempts share the per-client limiter so they cannot flood the audit log.
            allowed, retry_after = rate_limiter.check(f"auth-failure:{host}")
            if not allowed:
                raise HTTPException(status_code=429, detail="too many failed authentication attempts",
                                    headers={"Retry-After": str(retry_after)})  # fmt: skip
            audit.record("auth_failure", client=host)
            raise HTTPException(status_code=401, detail="invalid or missing API token",
                                headers={"WWW-Authenticate": "Bearer"})  # fmt: skip
        return "token:" + hashlib.sha256(supplied.encode()).hexdigest()[:12]

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> dict[str, Any]:
        return {
            "status": "ready",
            "provider": provider.name,
            "runbooks_loaded": len(loaded.runbooks),
            "runbooks_rejected": len(loaded.rejected),
        }

    @app.post("/v1/triage", response_model=TriageResponse)
    async def triage(request: Request, client_id: str = Depends(authenticate)) -> TriageResponse:
        allowed, retry_after = rate_limiter.check(client_id)
        if not allowed:
            audit.record("rate_limited", client=client_id)
            raise HTTPException(status_code=429, detail="rate limit exceeded",
                                headers={"Retry-After": str(retry_after)})  # fmt: skip
        content_type = request.headers.get("content-type", "")
        if content_type.split(";")[0].strip().lower() != "application/json":
            raise HTTPException(status_code=415, detail="content-type must be application/json")
        try:
            body = await _read_limited_body(request, settings.max_body_bytes)
        except _BodyTooLarge:
            audit.record("request_rejected", client=client_id, reason="body_too_large")
            raise HTTPException(status_code=413, detail="alert too large") from None
        try:
            payload = json.loads(body)
        except (ValueError, RecursionError):
            raise HTTPException(status_code=400, detail="body is not valid JSON") from None
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="body must be a JSON object (a Wazuh alert)")
        try:
            alert = WazuhAlert.model_validate(payload)
        except ValidationError as exc:
            # Never echo the input back: it may contain PII or hostile content.
            errors = [
                {"loc": [str(p) for p in err["loc"]], "msg": err["msg"]}
                for err in exc.errors(include_input=False, include_url=False)
            ][:10]
            raise HTTPException(status_code=422, detail=errors) from None
        if LOOP_GUARD_GROUP in alert.rule.groups:
            # Our own verdicts re-injected into Wazuh must never be triaged again (cost loop).
            raise HTTPException(status_code=409, detail="refusing to triage ai-triage events (loop guard)")
        return await service.triage(alert, request_id=request.state.request_id, client_id=client_id)

    return app
