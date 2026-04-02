"""Misc utility functions shared across RaspISE modules."""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import string
from datetime import datetime, time, timezone


# ---------------------------------------------------------------------------
# MAC address helpers
# ---------------------------------------------------------------------------

def normalise_mac(mac: str) -> str:
    """Return MAC in lower-colon format: aa:bb:cc:dd:ee:ff"""
    raw = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(raw) != 12:
        raise ValueError(f"Invalid MAC address: {mac!r}")
    return ":".join(raw[i:i+2].lower() for i in range(0, 12, 2))


def mac_oui(mac: str) -> str:
    """Return the 6-char OUI prefix (lower, no separator)."""
    return normalise_mac(mac).replace(":", "")[:6]


# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------

def generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def constant_time_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------

def generate_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def is_within_time_range(start: str, end: str, now: time | None = None) -> bool:
    """Return True if current time is within [HH:MM, HH:MM] range."""
    if now is None:
        now = datetime.now().time()
    t_start = time.fromisoformat(start)
    t_end   = time.fromisoformat(end)
    if t_start <= t_end:
        return t_start <= now <= t_end
    # Overnight range (e.g. 22:00 – 06:00)
    return now >= t_start or now <= t_end


# ---------------------------------------------------------------------------
# CHAP helpers
# ---------------------------------------------------------------------------

def chap_verify(identifier: bytes, password: str, chap_response: bytes) -> bool:
    """Verify CHAP-Password (RFC 1994, MD5 based)."""
    expected = hashlib.md5(identifier + password.encode() + b"\x00").digest()
    return hmac.compare_digest(expected, chap_response[:16])
