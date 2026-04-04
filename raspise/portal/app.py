"""
RaspISE Captive / Guest Portal
================================
A standalone FastAPI app served on port 8082 (configurable).

Guest flow
----------
  1. Guest device connects to the guest SSID / VLAN.
  2. All HTTP traffic is redirected here by iptables (see install.sh).
  3. Guest fills in the registration form (name + email).
  4. A timed GuestSession is created in the DB.
  5. The device MAC is authorised for the configured session duration.
  6. Guest is shown a success page with the Wi-Fi QR code.

Endpoints
---------
  GET  /          – Landing / registration page
  POST /register  – Submit registration form
  GET  /success   – Success page (after registration)
  GET  /status    – JSON {active: bool, expires_at: ...} for a given MAC
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import re
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import FastAPI, Form, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from raspise.config import get_config
from raspise.core.logger import get_logger
from raspise.core.utils import generate_token, normalise_mac, utcnow
from raspise.core.ratelimit import check_rate_limit, record_failure
from raspise.db import get_db
from raspise.db.models import GuestSession

log = get_logger(__name__)

app = FastAPI(title="RaspISE Guest Portal", docs_url=None, redoc_url=None)

import os
_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=_TEMPLATE_DIR)


# ---------------------------------------------------------------------------
# CSRF helpers
# ---------------------------------------------------------------------------

_CSRF_SECRET = os.environ.get("RASPISE_CSRF_SECRET", generate_token(32))


def _csrf_generate(session_id: str) -> str:
    """Create an HMAC-based CSRF token tied to a pseudo-session."""
    return hmac.new(_CSRF_SECRET.encode(), session_id.encode(), hashlib.sha256).hexdigest()


def _csrf_validate(token: str, session_id: str) -> bool:
    expected = _csrf_generate(session_id)
    return hmac.compare_digest(token, expected)


# ---------------------------------------------------------------------------
# Periodic cleanup: expire guest sessions whose expires_at has passed.
# Called from main.py _lifespan so it shares the application event loop.
# ---------------------------------------------------------------------------

async def expire_guest_sessions_loop() -> None:
    """Background task: mark overdue guest sessions inactive every 60 s."""
    from sqlalchemy import update
    from raspise.db.database import AsyncSessionLocal
    while True:
        try:
            async with AsyncSessionLocal() as db:
                now = utcnow()
                await db.execute(
                    update(GuestSession)
                    .where(GuestSession.active == True, GuestSession.expires_at <= now)
                    .values(active=False)
                )
                await db.commit()
        except Exception as exc:
            log.warning("Guest-session expiry cleanup failed: %s", exc)
        await asyncio.sleep(60)


# ---------------------------------------------------------------------------
# Helper: extract client MAC from request
# ---------------------------------------------------------------------------

def _get_client_mac(request: Request) -> str:
    """
    In a real deployment, the NAS/AP inserts the MAC into a custom header
    (e.g. X-Client-MAC) or uses the redirect URL as query param.
    We also support ?mac= from the iptables redirect rule.
    """
    mac_raw = (
        request.query_params.get("mac")
        or request.headers.get("X-Client-MAC", "")
    )
    try:
        return normalise_mac(mac_raw) if mac_raw else ""
    except ValueError:
        return ""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def landing(request: Request):
    cfg = get_config().portal
    mac = _get_client_mac(request)
    # Use client IP as pseudo-session for CSRF
    session_id = request.client.host if request.client else "unknown"
    csrf_token = _csrf_generate(session_id)
    return templates.TemplateResponse(request, "portal.html", {
        "request":    request,
        "mac":        mac,
        "ssid":       cfg.guest_ssid,
        "redirect":   request.query_params.get("redirect", "http://example.com"),
        "csrf_token": csrf_token,
    })


@app.post("/register", response_class=HTMLResponse)
async def register(
    request:      Request,
    full_name:    Annotated[str, Form()],
    email:        Annotated[str, Form()],
    mac:          Annotated[str, Form()] = "",
    csrf_token:   Annotated[str, Form()] = "",
    db:           AsyncSession = Depends(get_db),
):
    cfg = get_config().portal
    ip = request.client.host if request.client else "unknown"

    # CSRF validation
    if not csrf_token or not _csrf_validate(csrf_token, ip):
        return templates.TemplateResponse(request, "portal.html", {
            "request": request, "mac": mac, "ssid": cfg.guest_ssid,
            "error": "Invalid form submission. Please reload and try again.",
            "redirect": "", "csrf_token": _csrf_generate(ip),
        })

    # Rate limit: prevent flooding
    if not check_rate_limit(f"portal:{ip}"):
        return templates.TemplateResponse(request, "portal.html", {
            "request": request, "mac": mac, "ssid": cfg.guest_ssid,
            "error": "Too many registration attempts. Please try again later.",
            "redirect": "", "csrf_token": _csrf_generate(ip),
        })

    # Basic input validation
    if not full_name.strip() or len(full_name) > 128:
        return templates.TemplateResponse(request, "portal.html", {
            "request": request, "mac": mac, "ssid": cfg.guest_ssid,
            "error": "Please enter your full name.",
            "redirect": "", "csrf_token": _csrf_generate(ip),
        })
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return templates.TemplateResponse(request, "portal.html", {
            "request": request, "mac": mac, "ssid": cfg.guest_ssid,
            "error": "Please enter a valid email address.",
            "redirect": "", "csrf_token": _csrf_generate(ip),
        })

    try:
        norm_mac = normalise_mac(mac) if mac else _get_client_mac(request)
    except ValueError:
        norm_mac = ""

    if not norm_mac:
        return templates.TemplateResponse(request, "portal.html", {
            "request": request, "mac": mac, "ssid": cfg.guest_ssid,
            "error": "Could not determine your device MAC address.",
            "redirect": "", "csrf_token": _csrf_generate(ip),
        })

    # Expire any existing active sessions for this MAC atomically
    if norm_mac:
        from sqlalchemy import update
        await db.execute(
            update(GuestSession)
            .where(GuestSession.mac_address == norm_mac, GuestSession.active == True)
            .values(active=False)
        )
        await db.flush()

    expires_at = utcnow() + timedelta(hours=cfg.session_hours)
    session = GuestSession(
        token       = generate_token(32),
        email       = email.strip().lower()[:128],
        full_name   = full_name.strip()[:128],
        mac_address = norm_mac,
        ip_address  = request.client.host if request.client else "",
        expires_at  = expires_at,
    )
    db.add(session)
    await db.commit()

    log.info("Guest registered: name=%r email=%r mac=%s expires=%s",
             full_name, email, norm_mac, expires_at.isoformat())

    # Redirect to success page using only the opaque session token
    # (PSK is never placed in the URL — /success reads it from server config)
    return RedirectResponse(
        url=f"/success?token={session.token}",
        status_code=303,
    )


@app.get("/success", response_class=HTMLResponse)
async def success(request: Request, token: str = "", db: AsyncSession = Depends(get_db)):
    from sqlalchemy import select
    cfg = get_config().portal

    # Verify the token maps to a real, active session
    sess = None
    if token:
        stmt = select(GuestSession).where(GuestSession.token == token)
        sess = (await db.execute(stmt)).scalar_one_or_none()

    if not sess:
        # No valid token — redirect to the registration page
        return RedirectResponse(url="/", status_code=302)

    # Generate QR code image from server-side config — PSK never leaves the server
    qr_base64 = ""
    import io, base64, qrcode
    qr_payload = f"WIFI:T:WPA;S:{cfg.guest_ssid};P:{cfg.guest_psk};;"
    img = qrcode.make(qr_payload)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_base64 = base64.b64encode(buf.getvalue()).decode()

    return templates.TemplateResponse(request, "success.html", {
        "request":   request,
        "ssid":      cfg.guest_ssid,
        "qr_base64": qr_base64,
    })


@app.get("/status")
async def session_status(mac: str, db: AsyncSession = Depends(get_db)):
    from sqlalchemy import select
    try:
        norm_mac = normalise_mac(mac)
    except ValueError:
        return {"active": False, "error": "invalid MAC"}

    stmt = (
        select(GuestSession)
        .where(
            GuestSession.mac_address == norm_mac,
            GuestSession.active == True,
            GuestSession.expires_at > utcnow(),
        )
        .order_by(GuestSession.created_at.desc())
    )
    sess = (await db.execute(stmt)).scalar_one_or_none()
    if sess:
        return {"active": True, "expires_at": sess.expires_at.isoformat()}
    return {"active": False}
