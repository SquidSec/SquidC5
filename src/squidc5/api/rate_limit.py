"""In-memory sliding-window rate limits for the HTTP API."""

from __future__ import annotations

import time
from collections import defaultdict, deque


class SlidingWindowLimiter:
    """Per-key sliding window counter."""

    def __init__(self, limit: int, window_sec: float = 60.0) -> None:
        self.limit = max(0, int(limit))
        self.window = float(window_sec)
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    @property
    def disabled(self) -> bool:
        return self.limit <= 0

    def _prune(self, key: str, now: float) -> deque[float]:
        q = self._hits[key]
        while q and now - q[0] > self.window:
            q.popleft()
        return q

    def would_allow(self, key: str) -> bool:
        if self.disabled:
            return True
        q = self._prune(key, time.time())
        return len(q) < self.limit

    def allow(self, key: str) -> bool:
        if self.disabled:
            return True
        now = time.time()
        q = self._prune(key, now)
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True

    def record(self, key: str) -> None:
        if self.disabled:
            return
        now = time.time()
        q = self._prune(key, now)
        q.append(now)

    def retry_after_sec(self, key: str) -> int:
        if self.disabled:
            return 0
        q = self._hits[key]
        if not q:
            return max(1, int(self.window))
        now = time.time()
        remain = self.window - (now - q[0])
        return max(1, int(remain) + 1)


class ApiRateLimitState:
    """IP request limit + stricter auth-failure limit."""

    def __init__(
        self,
        limit_per_minute: int = 60,
        auth_fail_limit_per_minute: int = 20,
        window_sec: float = 60.0,
    ) -> None:
        self.requests = SlidingWindowLimiter(limit_per_minute, window_sec)
        self.auth_fails = SlidingWindowLimiter(auth_fail_limit_per_minute, window_sec)

    def check_request(self, client_key: str) -> tuple[bool, int]:
        """Return (allowed, retry_after_seconds). Records a general request hit when allowed."""
        if not self.auth_fails.would_allow(client_key):
            return False, self.auth_fails.retry_after_sec(client_key)
        if not self.requests.allow(client_key):
            return False, self.requests.retry_after_sec(client_key)
        return True, 0

    def record_auth_failure(self, client_key: str) -> None:
        self.auth_fails.record(client_key)


def client_key_from_request(request) -> str:
    if request.client and request.client.host:
        return request.client.host
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip() or "unknown"
    return "unknown"


def path_is_rate_limit_exempt(path: str) -> bool:
    """Public liveness probes must not be starved."""
    p = path.rstrip("/") or "/"
    return p == "/api/v1/health"
