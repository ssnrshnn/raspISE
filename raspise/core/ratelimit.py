"""Simple in-memory per-IP rate limiter shared by the web UI and the REST API."""
from __future__ import annotations

import time as _time
from collections import defaultdict
from threading import Lock as _Lock

# Lock out after this many failures within the time window
_RATE_MAX_HITS: int   = 5
_RATE_WINDOW:   float = 300.0   # seconds (5 minutes)

_login_failures: dict[str, list[float]] = defaultdict(list)
_lock = _Lock()
_last_cleanup: float = 0.0
_CLEANUP_INTERVAL: float = 60.0  # run cleanup at most once per minute


def _maybe_cleanup() -> None:
    """Remove stale IPs to prevent unbounded memory growth."""
    global _last_cleanup
    now = _time.monotonic()
    if now - _last_cleanup < _CLEANUP_INTERVAL:
        return
    _last_cleanup = now
    stale = [ip for ip, hits in _login_failures.items()
             if not hits or (now - max(hits)) >= _RATE_WINDOW]
    for ip in stale:
        _login_failures.pop(ip, None)


def check_rate_limit(ip: str) -> bool:
    """Return True if the IP is still allowed (has not exceeded the threshold)."""
    with _lock:
        now  = _time.monotonic()
        hits = _login_failures[ip]
        hits[:] = [t for t in hits if now - t < _RATE_WINDOW]
        if not hits:
            _login_failures.pop(ip, None)
        _maybe_cleanup()
        return len(hits) < _RATE_MAX_HITS


def record_failure(ip: str) -> None:
    """Record a failed login attempt for *ip*."""
    with _lock:
        _login_failures[ip].append(_time.monotonic())


def clear_failures(ip: str) -> None:
    """Clear the failure counter for *ip* (called on successful login)."""
    with _lock:
        _login_failures.pop(ip, None)
