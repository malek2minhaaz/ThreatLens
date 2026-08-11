"""Tiny in-memory sliding-window rate limiter (auth brute-force guard).

Per-process only — suitable for the default single-worker setup. For
multi-worker deployments, move this to Redis or use a proxy-level limiter.
"""
from __future__ import annotations

import time
from collections import defaultdict
from threading import Lock


class SlidingWindowLimiter:
    def __init__(self, max_attempts: int, window_seconds: int) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._hits: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            window_start = now - self.window_seconds
            self._hits[key] = [t for t in self._hits[key] if t > window_start]
            if len(self._hits[key]) >= self.max_attempts:
                return False
            self._hits[key].append(now)
            return True

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)


# Login: 10 attempts / 15 min per IP. Register: 5 / hour per IP.
# Phishing tools that make outbound requests (link inspector, sender check): 30 / hour.
login_limiter = SlidingWindowLimiter(max_attempts=10, window_seconds=900)
register_limiter = SlidingWindowLimiter(max_attempts=5, window_seconds=3600)
tool_limiter = SlidingWindowLimiter(max_attempts=30, window_seconds=3600)
