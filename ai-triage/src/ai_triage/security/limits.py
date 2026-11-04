"""Consumption controls (OWASP LLM10): token estimation, rate limiting and token budgets."""

from __future__ import annotations

import math
import threading
import time
from collections import deque
from collections.abc import Callable

# Logs (IPs, hashes, paths) tokenise worse than prose: 3 chars/token is a conservative bound
# for the tokenizers of the supported providers, so budgets are not exceeded in practice.
CHARS_PER_TOKEN = 3.0


def estimate_tokens(text: str) -> int:
    return math.ceil(len(text) / CHARS_PER_TOKEN)


class SlidingWindowRateLimiter:
    """Per-key request limiter over a sliding time window."""

    def __init__(self, limit: int, window_s: float = 60.0, clock: Callable[[], float] = time.monotonic):
        self._limit = limit
        self._window = window_s
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, int]:
        """Register a hit. Returns ``(allowed, retry_after_seconds)``."""
        now = self._clock()
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] >= self._window:
                hits.popleft()
            if len(hits) >= self._limit:
                return False, max(1, math.ceil(self._window - (now - hits[0])))
            hits.append(now)
            if len(self._hits) > 10_000:  # bound memory with many distinct keys
                for stale in [k for k, v in self._hits.items() if not v or now - v[-1] >= self._window]:
                    del self._hits[stale]
            return True, 0


class TokenBudget:
    """Global token budget per sliding window, shared by all requests."""

    def __init__(self, tokens_per_window: int, window_s: float = 60.0, clock: Callable[[], float] = time.monotonic):
        self._capacity = tokens_per_window
        self._window = window_s
        self._clock = clock
        self._spent: deque[tuple[float, int]] = deque()
        self._lock = threading.Lock()

    def _used(self, now: float) -> int:
        while self._spent and now - self._spent[0][0] >= self._window:
            self._spent.popleft()
        return sum(tokens for _, tokens in self._spent)

    def try_consume(self, tokens: int) -> bool:
        now = self._clock()
        with self._lock:
            if self._used(now) + tokens > self._capacity:
                return False
            self._spent.append((now, tokens))
            return True

    def remaining(self) -> int:
        with self._lock:
            return max(0, self._capacity - self._used(self._clock()))
