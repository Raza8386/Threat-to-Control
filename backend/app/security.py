"""API protections for a public demo: per-IP rate limits, a daily spend cap, client IP resolution.

In-memory, so limits are per process. That fits a single Render instance; with several instances,
move the counters to Redis (e.g. Upstash) behind the same interface.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from fastapi import Request


class RateLimiter:
    """Sliding-window limits per key, e.g. 8 per minute and 60 per day."""

    def __init__(self, per_minute: int, per_day: int):
        self.windows = ((60.0, per_minute), (86_400.0, per_day))
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, now: float | None = None) -> tuple[bool, int]:
        """Return (allowed, retry_after_seconds). Records the hit only when allowed."""
        now = time.time() if now is None else now
        with self._lock:
            q = self._hits[key]
            longest = max(w for w, _ in self.windows)
            while q and now - q[0] > longest:
                q.popleft()
            for window, limit in self.windows:
                recent = [t for t in q if now - t <= window]
                if len(recent) >= limit:
                    return False, int(window - (now - recent[0])) + 1
            q.append(now)
            return True, 0


class DailyBudget:
    """Stops answering once the day's model spend reaches the cap (UTC day). Protects the API bill."""

    def __init__(self, cap_usd: float):
        self.cap = cap_usd
        self._day = ""
        self._spent = 0.0
        self._lock = threading.Lock()

    def _roll(self) -> None:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if today != self._day:
            self._day, self._spent = today, 0.0

    def available(self) -> bool:
        with self._lock:
            self._roll()
            return self.cap <= 0 or self._spent < self.cap

    def add(self, usd: float) -> None:
        """Add spend; a negative value reconciles an earlier reservation (never below zero)."""
        with self._lock:
            self._roll()
            self._spent = max(0.0, self._spent + usd)

    @property
    def spent(self) -> float:
        with self._lock:
            self._roll()
            return round(self._spent, 4)


def client_ip(request: Request, trust_proxy: bool) -> str:
    """Client IP. X-Forwarded-For is trusted only behind a known proxy (TRUST_PROXY=1, e.g. Render).

    Use the RIGHT-most entry: it is the one appended by our proxy. Entries to its left come from the
    client and can be forged to rotate identities and dodge the rate limit.
    """
    if trust_proxy:
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            return fwd.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


_IP_SALT = secrets.token_bytes(16)  # per process: tags correlate within a run, cannot be reversed by brute force


def ip_tag(ip: str) -> str:
    """Short pseudonymous tag for logs, so raw IPs are never stored."""
    return hashlib.sha256(_IP_SALT + ip.encode()).hexdigest()[:10]


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-site",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
