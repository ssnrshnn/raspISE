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
from raspise.db import get_db
from raspise.db.models import GuestSession

log = get_logger(__name__)

app = FastAPI(title="RaspISE Guest Portal", docs_url=None, redoc_url=None)

import os
_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=_TEMPLATE_DIR)


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
    return templates.TemplateResponse("portal.html", {
        "request":  request,
        "mac":      mac,
        "ssid":     cfg.guest_ssid,
        "redirect": request.query_params.get("redirect", "http://example.com"),
    })


@app.post("/register", response_class=HTMLResponse)
async def register(
    request:   Request,
    full_name: Annotated[str, Form()],
    email:     Annotated[str, Form()],
    mac:       Annotated[str, Form()] = "",
    db:        AsyncSession = Depends(get_db),
):
    cfg = get_config().portal

    # Basic input validation
    if not full_name.strip() or len(full_name) > 128:
        return templates.TemplateResponse("portal.html", {
            "request": request, "mac": mac, "ssid": cfg.guest_ssid,
            "error": "Please enter your full name.",
            "redirect": "",
        })
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return templates.TemplateResponse("portal.html", {
            "request": request, "mac": mac, "ssid": cfg.guest_ssid,
            "error": "Please enter a valid email address.",
            "redirect": "",
        })

    try:
        norm_mac = normalise_mac(mac) if mac else _get_client_mac(request)
    except ValueError:
        norm_mac = ""

    # Expire any existing session for this MAC
    if norm_mac:
        from sqlalchemy import select, update
        stmt = (
            select(GuestSession)
            .where(GuestSession.mac_address == norm_mac, GuestSession.active == True)
        )
        existing = (await db.execute(stmt)).scalars().all()
        for s in existing:
            s.active = False
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

    # Build Wi-Fi QR code payload (WPA format)
    qr_payload = f"WIFI:T:WPA;S:{cfg.guest_ssid};P:{cfg.guest_psk};;"
    return RedirectResponse(
        url=f"/success?token={session.token}&qr={qr_payload}",
        status_code=303,
    )


@app.get("/success", response_class=HTMLResponse)
async def success(request: Request, token: str = "", qr: str = ""):
    cfg = get_config().portal

    # Generate QR code image as base64
    qr_base64 = ""
    if qr:
        import io, base64, qrcode
        img = qrcode.make(qr)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_base64 = base64.b64encode(buf.getvalue()).decode()

    return templates.TemplateResponse("success.html", {
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
        return {"active": True, "expires_at": sess.expires_at.isoformat(), "email": sess.email}
    return {"active": False}
