"""Sliding-window limiter (in-process). For multi-instance production swap the store for Redis."""
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

from .config import get_settings

_hits: dict[tuple[str, str], deque] = defaultdict(deque)


def reset() -> None:
    _hits.clear()


def _check(bucket: str, key: str, limit: int, window: int) -> None:
    now = time.monotonic()
    q = _hits[(bucket, key)]
    while q and now - q[0] > window:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(429, "Too many requests. Please slow down.", headers={"Retry-After": str(window)})
    q.append(now)


def limit(bucket: str, per_min: int | None = None, setting: str | None = None):
    def dep(request: Request) -> None:
        s = get_settings()
        if not s.rate_limit_enabled:
            return
        n = per_min if per_min is not None else getattr(s, setting or "global_rate_per_min")
        _check(bucket, request.client.host if request.client else "?", n, 60)
    return dep
