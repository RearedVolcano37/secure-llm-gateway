"""
Rate Limiter — sliding-window per API key, in-memory.

For a distributed deployment (multiple replicas), swap the in-memory
store for a Redis backend using the commented-out RedisRateLimiter class.
"""

import time
import threading
from collections import deque
from dataclasses import dataclass, field


@dataclass
class _Window:
    """Tracks request timestamps for a single key."""
    timestamps: deque = field(default_factory=deque)
    lock: threading.Lock = field(default_factory=threading.Lock)


class RateLimiter:
    """
    Sliding-window rate limiter.

    Args:
        max_requests:    Max allowed requests per window.
        window_seconds:  Length of the sliding window in seconds.
    """

    def __init__(self, max_requests: int = 20, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._store: dict[str, _Window] = {}
        self._store_lock = threading.Lock()

    def _get_window(self, key: str) -> _Window:
        with self._store_lock:
            if key not in self._store:
                self._store[key] = _Window()
            return self._store[key]

    def check(self, key: str) -> tuple[bool, int]:
        """
        Check whether `key` is within rate limits.

        Returns:
            (allowed: bool, retry_after_seconds: int)
            retry_after is 0 when allowed=True.
        """
        window = self._get_window(key)
        now = time.time()
        cutoff = now - self.window_seconds

        with window.lock:
            # Evict timestamps outside the window
            while window.timestamps and window.timestamps[0] < cutoff:
                window.timestamps.popleft()

            if len(window.timestamps) >= self.max_requests:
                # Oldest request in window determines when a slot frees up
                oldest = window.timestamps[0]
                retry_after = int(oldest + self.window_seconds - now) + 1
                return False, retry_after

            window.timestamps.append(now)
            return True, 0

    def get_usage(self, key: str) -> dict:
        """Return current usage stats for a key."""
        window = self._get_window(key)
        now = time.time()
        cutoff = now - self.window_seconds
        with window.lock:
            active = sum(1 for ts in window.timestamps if ts >= cutoff)
        return {
            "key_hint": key[:8] + "…",
            "requests_in_window": active,
            "limit": self.max_requests,
            "window_seconds": self.window_seconds,
            "remaining": max(0, self.max_requests - active),
        }


# ── Redis-backed version (uncomment for distributed deployments) ─────────────
#
# import redis
# class RedisRateLimiter:
#     def __init__(self, redis_url: str, max_requests: int, window_seconds: int):
#         self.r = redis.from_url(redis_url)
#         self.max_requests = max_requests
#         self.window_seconds = window_seconds
#
#     def check(self, key: str) -> tuple[bool, int]:
#         pipe = self.r.pipeline()
#         now = time.time()
#         cutoff = now - self.window_seconds
#         rkey = f"rl:{key}"
#         pipe.zremrangebyscore(rkey, "-inf", cutoff)
#         pipe.zadd(rkey, {str(now): now})
#         pipe.zcard(rkey)
#         pipe.expire(rkey, self.window_seconds)
#         _, _, count, _ = pipe.execute()
#         if count > self.max_requests:
#             return False, self.window_seconds
#         return True, 0
