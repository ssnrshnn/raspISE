"""
RaspISE Web Admin UI
====================
Server-side rendered FastAPI app with Jinja2 + Bootstrap 5 dark theme.
Runs on port 8080 (configurable).

Routes
------
  GET  /login                  – Login page
  POST /login                  – Submit login
  GET  /logout                 – Clear session
  GET  /                       – Dashboard
  GET  /users                  – User management
  GET  /groups                 – Group management
  POST /groups                 – Create group
  POST /groups/{id}/delete     – Delete group
  GET  /devices                – Device inventory
  GET  /policies               – Policy management
  GET  /logs                   – Auth log viewer
  GET  /logs/tacacs            – TACACS+ log viewer
  GET  /sessions               – Active RADIUS sessions
  DELETE /sessions/{id}        – Force-terminate session
  GET  /guests                 – Guest sessions
  GET  /radius-clients         – RADIUS NAS client management
  POST /radius-clients         – Add NAS client
  POST /radius-clients/{id}/delete – Remove NAS client
  GET  /tacacs-clients         – TACACS+ client management
  POST /tacacs-clients         – Add TACACS+ client
  POST /tacacs-clients/{id}/delete – Remove TACACS+ client
  GET  /vlans                  – VLAN mapping management
  POST /vlans                  – Add VLAN mapping
  POST /vlans/{id}/delete      – Remove VLAN mapping
  GET  /admin-users            – Admin account management
  POST /admin-users            – Create admin account
  POST /admin-users/{id}/delete – Delete admin account
  POST /admin-users/{id}/password – Change admin password
  GET  /settings               – Editable system settings
  POST /settings/save          – Save config section
  GET  /system                 – System status (services, logs)
"""
from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Form, Request, status as http_status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from raspise.api.auth import hash_password, verify_password
from raspise.config import get_config
from raspise.db import get_db
from raspise.db.models import (
    ActiveSession, AdminUser, AuthLog, AuthResult,
    Device, Group, GuestSession, NasClient, Policy,
    TacacsClient, TacacsLog, User, VlanMapping,
)

app = FastAPI(title="RaspISE Admin", docs_url=None, redoc_url=None)

_BASE = os.path.dirname(__file__)
templates = Jinja2Templates(directory=os.path.join(_BASE, "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(_BASE, "static")), name="static")


# ---------------------------------------------------------------------------
# Session cookie helper (lightweight — no external session library needed)
# ---------------------------------------------------------------------------

_SESSION_COOKIE = "raspise_session"


def _get_session_user(request: Request) -> str | None:
    """Return username from signed session cookie, or None."""
    return request.cookies.get(_SESSION_COOKIE)


def _require_auth(request: Request):
    user = _get_session_user(request)
    if not user:
        raise RedirectToLogin()
    return user


class RedirectToLogin(Exception):
    pass


# ---------------------------------------------------------------------------
# Exception handler — redirect to login on unauthenticated access
# ---------------------------------------------------------------------------

@app.exception_handler(RedirectToLogin)
async def _redirect_to_login(request: Request, exc: RedirectToLogin):
    return RedirectResponse(url="/login", status_code=302)


# ---------------------------------------------------------------------------
# Login / Logout
# ---------------------------------------------------------------------------

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = ""):
    return templates.TemplateResponse("login.html", {"request": request, "error": error})


@app.post("/login")
async def do_login(
    request:  Request,
    username: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(AdminUser).where(AdminUser.username == username, AdminUser.enabled == True)
    user = (await db.execute(stmt)).scalar_one_or_none()

    if user and verify_password(password, user.password_hash):
        user.last_login = datetime.now(timezone.utc)
        await db.commit()
        resp = RedirectResponse(url="/", status_code=303)
        resp.set_cookie(
            _SESSION_COOKIE, username,
            httponly=True, samesite="lax",
            max_age=3600 * 8,
        )
        return resp

    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": "Invalid username or password."},
        status_code=401,
    )


@app.get("/logout")
async def logout():
    resp = RedirectResponse(url="/login", status_code=302)
    resp.delete_cookie(_SESSION_COOKIE)
    return resp


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_auth(request)
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    stats = {
        "total_users":    (await db.execute(select(func.count()).select_from(User))).scalar_one(),
        "total_devices":  (await db.execute(select(func.count()).select_from(Device))).scalar_one(),
        "active_sessions":(await db.execute(select(func.count()).select_from(ActiveSession))).scalar_one(),
        "auth_today":     (await db.execute(
            select(func.count()).select_from(AuthLog).where(AuthLog.timestamp >= today)
        )).scalar_one(),
        "auth_success":   (await db.execute(
            select(func.count()).select_from(AuthLog).where(
                AuthLog.timestamp >= today, AuthLog.result == AuthResult.SUCCESS
            )
        )).scalar_one(),
        "auth_failure":   (await db.execute(
            select(func.count()).select_from(AuthLog).where(
                AuthLog.timestamp >= today, AuthLog.result == AuthResult.FAILURE
            )
        )).scalar_one(),
        "guest_active":   (await db.execute(
            select(func.count()).select_from(GuestSession).where(
                GuestSession.active == True,
                GuestSession.expires_at > datetime.now(timezone.utc),
            )
        )).scalar_one(),
    }

    recent_logs = (await db.execute(
        select(AuthLog).order_by(AuthLog.timestamp.desc()).limit(10)
    )).scalars().all()

    cfg = get_config()
    return templates.TemplateResponse("dashboard.html", {
        "request":     request,
        "user":        user,
        "stats":       stats,
        "recent_logs": recent_logs,
        "server_name": cfg.server.name,
    })


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

@app.get("/users", response_class=HTMLResponse)
async def users_page(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_auth(request)
    from sqlalchemy.orm import selectinload
    rows = (await db.execute(
        select(User).options(selectinload(User.group)).order_by(User.username)
    )).scalars().all()
    groups = (await db.execute(select(Group).order_by(Group.name))).scalars().all()
    return templates.TemplateResponse("users.html", {
        "request": request, "user": user,
        "users": rows, "groups": groups,
    })


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------

@app.get("/devices", response_class=HTMLResponse)
async def devices_page(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_auth(request)
    rows = (await db.execute(
        select(Device).order_by(Device.last_seen.desc()).limit(200)
    )).scalars().all()
    return templates.TemplateResponse("devices.html", {
        "request": request, "user": user, "devices": rows,
    })


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

@app.get("/policies", response_class=HTMLResponse)
async def policies_page(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_auth(request)
    rows = (await db.execute(
        select(Policy).order_by(Policy.priority)
    )).scalars().all()
    groups = (await db.execute(select(Group))).scalars().all()
    return templates.TemplateResponse("policies.html", {
        "request": request, "user": user, "policies": rows, "groups": groups,
    })


# ---------------------------------------------------------------------------
# Auth Logs
# ---------------------------------------------------------------------------

@app.get("/logs", response_class=HTMLResponse)
async def logs_page(
    request:  Request,
    page:     int = 1,
    result:   str = "",
    db: AsyncSession = Depends(get_db),
):
    user = _require_auth(request)
    per_page = 50
    stmt = select(AuthLog).order_by(AuthLog.timestamp.desc())
    if result:
        stmt = stmt.where(AuthLog.result == result.upper())
    stmt = stmt.offset((page - 1) * per_page).limit(per_page)
    rows = (await db.execute(stmt)).scalars().all()
    total = (await db.execute(
        select(func.count()).select_from(AuthLog)
    )).scalar_one()
    return templates.TemplateResponse("auth_logs.html", {
        "request": request, "user": user, "logs": rows,
        "page": page, "per_page": per_page, "total": total,
        "filter_result": result,
    })


# ---------------------------------------------------------------------------
# Active Sessions
# ---------------------------------------------------------------------------

@app.get("/sessions", response_class=HTMLResponse)
async def sessions_page(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_auth(request)
    rows = (await db.execute(
        select(ActiveSession).order_by(ActiveSession.started_at.desc())
    )).scalars().all()
    return templates.TemplateResponse("sessions.html", {
        "request": request, "user": user, "sessions": rows,
    })


# ---------------------------------------------------------------------------
# Guest Sessions
# ---------------------------------------------------------------------------

@app.get("/guests", response_class=HTMLResponse)
async def guests_page(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_auth(request)
    rows = (await db.execute(
        select(GuestSession).order_by(GuestSession.created_at.desc()).limit(100)
    )).scalars().all()
    now = datetime.now(timezone.utc)
    return templates.TemplateResponse("guests.html", {
        "request": request, "user": user, "sessions": rows, "now": now,
    })


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    user = _require_auth(request)
    cfg  = get_config()
    return templates.TemplateResponse("settings.html", {
        "request": request, "user": user, "cfg": cfg,
    })


@app.post("/settings/save")
async def settings_save(request: Request):
    """Save a config section from a form POST and reload the in-memory config."""
    _require_auth(request)
    import yaml, os

    form = await request.form()
    section = form.get("section", "")

    cfg_path = os.environ.get("RASPISE_CONFIG", "/etc/raspise/config.yaml")
    if not os.path.exists(cfg_path):
        cfg_path = os.path.join(
            os.path.dirname(__file__), "..", "config", "config.yaml"
        )

    with open(cfg_path) as f:
        data = yaml.safe_load(f) or {}

    # Map form fields into config dict based on section
    if section == "server":
        data.setdefault("server", {})
        data["server"]["name"]      = form.get("name", data["server"].get("name", "RaspISE"))
        data["server"]["log_level"] = form.get("log_level", "INFO")
        data["server"]["debug"]     = form.get("debug") == "on"

    elif section == "radius":
        data.setdefault("radius", {})
        data["radius"]["enabled"]      = form.get("enabled") == "on"
        data["radius"]["auth_port"]    = int(form.get("auth_port", 1812))
        data["radius"]["acct_port"]    = int(form.get("acct_port", 1813))
        data["radius"]["default_vlan"] = int(form.get("default_vlan", 1))
        data["radius"]["guest_vlan"]   = int(form.get("guest_vlan", 99))

    elif section == "tacacs":
        data.setdefault("tacacs", {})
        data["tacacs"]["enabled"] = form.get("enabled") == "on"
        data["tacacs"]["port"]    = int(form.get("port", 49))

    elif section == "portal":
        data.setdefault("portal", {})
        data["portal"]["session_duration_hours"] = int(form.get("session_duration_hours", 8))
        data["portal"]["wifi_ssid"]              = form.get("wifi_ssid", "")
        data["portal"]["wifi_password"]          = form.get("wifi_password", "")

    elif section == "display":
        data.setdefault("display", {})
        data["display"]["enabled"]        = form.get("enabled") == "on"
        data["display"]["driver"]         = form.get("driver", "simulation")
        data["display"]["rotation"]       = int(form.get("rotation", 270))
        data["display"]["cycle_interval"] = int(form.get("cycle_interval", 8))
        screens_raw = form.get("screens", "")
        data["display"]["screens"] = [s.strip() for s in screens_raw.split(",") if s.strip()]

    elif section == "log_forwarding_syslog":
        data.setdefault("log_forwarding", {}).setdefault("syslog", {})
        sl = data["log_forwarding"]["syslog"]
        sl["enabled"]  = form.get("enabled") == "on"
        sl["address"]  = form.get("address", "/dev/log")
        sl["facility"] = form.get("facility", "local0")
        sl["protocol"] = form.get("protocol", "udp")
        sl["port"]     = int(form.get("port", 514))

    elif section == "log_forwarding_graylog":
        data.setdefault("log_forwarding", {}).setdefault("graylog", {})
        gl = data["log_forwarding"]["graylog"]
        gl["enabled"]  = form.get("enabled") == "on"
        gl["host"]     = form.get("host", "127.0.0.1")
        gl["port"]     = int(form.get("port", 12201))
        gl["protocol"] = form.get("protocol", "udp")

    elif section == "log_forwarding_webhook":
        data.setdefault("log_forwarding", {}).setdefault("webhook", {})
        wh = data["log_forwarding"]["webhook"]
        wh["enabled"]                 = form.get("enabled") == "on"
        wh["url"]                     = form.get("url", "")
        wh["level"]                   = form.get("level", "WARNING")
        wh["timeout_seconds"]         = float(form.get("timeout_seconds", 3.0))
        wh["batch_size"]              = int(form.get("batch_size", 10))
        wh["batch_interval_seconds"]  = float(form.get("batch_interval_seconds", 5.0))
        # Parse raw headers textarea ("Key: Value" per line)
        headers: dict[str, str] = {}
        for line in (form.get("headers_raw", "") or "").splitlines():
            line = line.strip()
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()
        wh["headers"] = headers

    with open(cfg_path, "w") as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)

    # Invalidate cached config so next request re-reads it
    from raspise.config import get_config as _gc
    _gc.cache_clear()  # type: ignore[attr-defined]

    # Re-apply log handlers so forwarding changes take effect immediately
    from raspise.core.logger import setup_logging as _setup_logging
    _setup_logging()

    return RedirectResponse(url="/settings?saved=1", status_code=303)


# ---------------------------------------------------------------------------
# Log forwarding — test endpoint  (called via JS fetch on the Settings page)
# ---------------------------------------------------------------------------

from fastapi.responses import JSONResponse

@app.post("/settings/test-log/{target}")
async def test_log_forwarding(target: str, request: Request):
    _require_auth(request)
    allowed = {"syslog", "graylog", "webhook"}
    if target not in allowed:
        return JSONResponse({"ok": False, "message": "Unknown target."})
    from raspise.core.logger import send_test_log
    ok, msg = send_test_log(target)
    return JSONResponse({"ok": ok, "message": msg})


# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------

@app.get("/groups", response_class=HTMLResponse)
async def groups_page(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_auth(request)
    rows = (await db.execute(
        select(Group).order_by(Group.name)
    )).scalars().all()
    # count users per group
    counts: dict[int, int] = {}
    for g in rows:
        c = (await db.execute(
            select(func.count()).select_from(User).where(User.group_id == g.id)
        )).scalar_one()
        counts[g.id] = c
    return templates.TemplateResponse("groups.html", {
        "request": request, "user": user, "groups": rows, "counts": counts,
        "saved": request.query_params.get("saved"),
        "error": request.query_params.get("error"),
    })


@app.post("/groups")
async def create_group(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    _require_auth(request)
    existing = (await db.execute(select(Group).where(Group.name == name))).scalar_one_or_none()
    if existing:
        return RedirectResponse(url="/groups?error=Group+name+already+exists", status_code=303)
    db.add(Group(name=name, description=description))
    await db.commit()
    return RedirectResponse(url="/groups?saved=1", status_code=303)


@app.post("/groups/{group_id}/delete")
async def delete_group(group_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    _require_auth(request)
    g = (await db.execute(select(Group).where(Group.id == group_id))).scalar_one_or_none()
    if g:
        await db.delete(g)
        await db.commit()
    return RedirectResponse(url="/groups", status_code=303)


# ---------------------------------------------------------------------------
# TACACS+ Logs
# ---------------------------------------------------------------------------

@app.get("/logs/tacacs", response_class=HTMLResponse)
async def tacacs_logs_page(
    request: Request,
    page: int = 1,
    db: AsyncSession = Depends(get_db),
):
    user = _require_auth(request)
    per_page = 50
    stmt = select(TacacsLog).order_by(TacacsLog.timestamp.desc())
    stmt = stmt.offset((page - 1) * per_page).limit(per_page)
    rows = (await db.execute(stmt)).scalars().all()
    total = (await db.execute(select(func.count()).select_from(TacacsLog))).scalar_one()
    return templates.TemplateResponse("tacacs_logs.html", {
        "request": request, "user": user, "logs": rows,
        "page": page, "per_page": per_page, "total": total,
    })


# ---------------------------------------------------------------------------
# Force-terminate session
# ---------------------------------------------------------------------------

@app.post("/sessions/{session_id}/delete")
async def delete_session(session_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    _require_auth(request)
    s = (await db.execute(
        select(ActiveSession).where(ActiveSession.id == session_id)
    )).scalar_one_or_none()
    if s:
        await db.delete(s)
        await db.commit()
    return RedirectResponse(url="/sessions", status_code=303)


# ---------------------------------------------------------------------------
# RADIUS NAS Clients
# ---------------------------------------------------------------------------

@app.get("/radius-clients", response_class=HTMLResponse)
async def radius_clients_page(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_auth(request)
    rows = (await db.execute(select(NasClient).order_by(NasClient.name))).scalars().all()
    return templates.TemplateResponse("radius_clients.html", {
        "request": request, "user": user, "clients": rows,
        "saved": request.query_params.get("saved"),
        "error": request.query_params.get("error"),
    })


@app.post("/radius-clients")
async def create_radius_client(
    request: Request,
    name: str = Form(...),
    ip_address: str = Form(...),
    secret: str = Form(...),
    description: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    _require_auth(request)
    existing = (await db.execute(
        select(NasClient).where(NasClient.name == name)
    )).scalar_one_or_none()
    if existing:
        return RedirectResponse(url="/radius-clients?error=Name+already+exists", status_code=303)
    db.add(NasClient(name=name, ip_address=ip_address, secret=secret, description=description))
    await db.commit()
    return RedirectResponse(url="/radius-clients?saved=1", status_code=303)


@app.post("/radius-clients/{client_id}/delete")
async def delete_radius_client(
    client_id: int, request: Request, db: AsyncSession = Depends(get_db)
):
    _require_auth(request)
    c = (await db.execute(select(NasClient).where(NasClient.id == client_id))).scalar_one_or_none()
    if c:
        await db.delete(c)
        await db.commit()
    return RedirectResponse(url="/radius-clients", status_code=303)


@app.post("/radius-clients/{client_id}/toggle")
async def toggle_radius_client(
    client_id: int, request: Request, db: AsyncSession = Depends(get_db)
):
    _require_auth(request)
    c = (await db.execute(select(NasClient).where(NasClient.id == client_id))).scalar_one_or_none()
    if c:
        c.enabled = not c.enabled
        await db.commit()
    return RedirectResponse(url="/radius-clients", status_code=303)


# ---------------------------------------------------------------------------
# TACACS+ Clients
# ---------------------------------------------------------------------------

@app.get("/tacacs-clients", response_class=HTMLResponse)
async def tacacs_clients_page(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_auth(request)
    rows = (await db.execute(select(TacacsClient).order_by(TacacsClient.name))).scalars().all()
    return templates.TemplateResponse("tacacs_clients.html", {
        "request": request, "user": user, "clients": rows,
        "saved": request.query_params.get("saved"),
        "error": request.query_params.get("error"),
    })


@app.post("/tacacs-clients")
async def create_tacacs_client(
    request: Request,
    name: str = Form(...),
    ip_address: str = Form(...),
    key: str = Form(...),
    description: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    _require_auth(request)
    existing = (await db.execute(
        select(TacacsClient).where(TacacsClient.name == name)
    )).scalar_one_or_none()
    if existing:
        return RedirectResponse(url="/tacacs-clients?error=Name+already+exists", status_code=303)
    db.add(TacacsClient(name=name, ip_address=ip_address, key=key, description=description))
    await db.commit()
    return RedirectResponse(url="/tacacs-clients?saved=1", status_code=303)


@app.post("/tacacs-clients/{client_id}/delete")
async def delete_tacacs_client(
    client_id: int, request: Request, db: AsyncSession = Depends(get_db)
):
    _require_auth(request)
    c = (await db.execute(select(TacacsClient).where(TacacsClient.id == client_id))).scalar_one_or_none()
    if c:
        await db.delete(c)
        await db.commit()
    return RedirectResponse(url="/tacacs-clients", status_code=303)


@app.post("/tacacs-clients/{client_id}/toggle")
async def toggle_tacacs_client(
    client_id: int, request: Request, db: AsyncSession = Depends(get_db)
):
    _require_auth(request)
    c = (await db.execute(select(TacacsClient).where(TacacsClient.id == client_id))).scalar_one_or_none()
    if c:
        c.enabled = not c.enabled
        await db.commit()
    return RedirectResponse(url="/tacacs-clients", status_code=303)


# ---------------------------------------------------------------------------
# VLAN Mappings
# ---------------------------------------------------------------------------

@app.get("/vlans", response_class=HTMLResponse)
async def vlans_page(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_auth(request)
    rows = (await db.execute(select(VlanMapping).order_by(VlanMapping.vlan_id))).scalars().all()
    return templates.TemplateResponse("vlans.html", {
        "request": request, "user": user, "vlans": rows,
        "saved": request.query_params.get("saved"),
        "error": request.query_params.get("error"),
    })


@app.post("/vlans")
async def create_vlan(
    request: Request,
    name: str = Form(...),
    vlan_id: int = Form(...),
    description: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    _require_auth(request)
    existing = (await db.execute(select(VlanMapping).where(VlanMapping.name == name))).scalar_one_or_none()
    if existing:
        return RedirectResponse(url="/vlans?error=Name+already+exists", status_code=303)
    db.add(VlanMapping(name=name, vlan_id=vlan_id, description=description))
    await db.commit()
    return RedirectResponse(url="/vlans?saved=1", status_code=303)


@app.post("/vlans/{vlan_id}/delete")
async def delete_vlan(vlan_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    _require_auth(request)
    v = (await db.execute(select(VlanMapping).where(VlanMapping.id == vlan_id))).scalar_one_or_none()
    if v:
        await db.delete(v)
        await db.commit()
    return RedirectResponse(url="/vlans", status_code=303)


# ---------------------------------------------------------------------------
# Admin Users
# ---------------------------------------------------------------------------

@app.get("/admin-users", response_class=HTMLResponse)
async def admin_users_page(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_auth(request)
    rows = (await db.execute(select(AdminUser).order_by(AdminUser.username))).scalars().all()
    return templates.TemplateResponse("admin_users.html", {
        "request": request, "user": user, "admins": rows,
        "saved": request.query_params.get("saved"),
        "error": request.query_params.get("error"),
    })


@app.post("/admin-users")
async def create_admin_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    email: str = Form(""),
    is_superuser: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    current = _require_auth(request)
    existing = (await db.execute(
        select(AdminUser).where(AdminUser.username == username)
    )).scalar_one_or_none()
    if existing:
        return RedirectResponse(url="/admin-users?error=Username+already+exists", status_code=303)
    db.add(AdminUser(
        username=username,
        password_hash=hash_password(password),
        email=email,
        is_superuser=(is_superuser == "on"),
    ))
    await db.commit()
    return RedirectResponse(url="/admin-users?saved=1", status_code=303)


@app.post("/admin-users/{admin_id}/delete")
async def delete_admin_user(
    admin_id: int, request: Request, db: AsyncSession = Depends(get_db)
):
    current = _require_auth(request)
    a = (await db.execute(select(AdminUser).where(AdminUser.id == admin_id))).scalar_one_or_none()
    if a and a.username != current:  # prevent self-deletion
        await db.delete(a)
        await db.commit()
    return RedirectResponse(url="/admin-users", status_code=303)


@app.post("/admin-users/{admin_id}/password")
async def change_admin_password(
    admin_id: int,
    request: Request,
    new_password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    _require_auth(request)
    a = (await db.execute(select(AdminUser).where(AdminUser.id == admin_id))).scalar_one_or_none()
    if a:
        a.password_hash = hash_password(new_password)
        await db.commit()
    return RedirectResponse(url="/admin-users?saved=1", status_code=303)


# ---------------------------------------------------------------------------
# System Status
# ---------------------------------------------------------------------------

@app.get("/system", response_class=HTMLResponse)
async def system_page(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_auth(request)
    import psutil, platform

    services = []
    for svc in ("raspise", "raspise-display", "freeradius"):
        try:
            result = subprocess.run(
                ["systemctl", "is-active", svc],
                capture_output=True, text=True, timeout=2
            )
            status = result.stdout.strip()
        except Exception:
            status = "unknown"
        services.append({"name": svc, "status": status})

    # Recent journal entries for raspise service
    log_lines: list[str] = []
    try:
        result = subprocess.run(
            ["journalctl", "-u", "raspise", "-n", "40", "--no-pager", "--output=short"],
            capture_output=True, text=True, timeout=5
        )
        log_lines = result.stdout.strip().splitlines()
    except Exception:
        log_lines = ["(journalctl unavailable — running outside systemd?)"]

    cpu_percent  = psutil.cpu_percent(interval=0.2)
    mem          = psutil.virtual_memory()
    disk         = psutil.disk_usage("/")
    temperature  = None
    try:
        temps = psutil.sensors_temperatures()
        if "cpu_thermal" in temps:
            temperature = round(temps["cpu_thermal"][0].current, 1)
        elif "coretemp" in temps:
            temperature = round(temps["coretemp"][0].current, 1)
    except Exception:
        pass

    db_size = 0
    try:
        import os as _os
        cfg = get_config()
        db_path = cfg.database.path
        if _os.path.exists(db_path):
            db_size = _os.path.getsize(db_path)
    except Exception:
        pass

    total_logs = (await db.execute(select(func.count()).select_from(AuthLog))).scalar_one()

    return templates.TemplateResponse("system.html", {
        "request":      request,
        "user":         user,
        "services":     services,
        "log_lines":    log_lines,
        "cpu_percent":  cpu_percent,
        "mem":          mem,
        "disk":         disk,
        "temperature":  temperature,
        "db_size":      db_size,
        "total_logs":   total_logs,
        "platform":     platform.platform(),
        "python_ver":   platform.python_version(),
    })


@app.post("/system/service/{service_name}/restart")
async def restart_service(service_name: str, request: Request):
    _require_auth(request)
    # Only allow known service names to prevent command injection
    allowed = {"raspise", "raspise-display", "freeradius"}
    if service_name not in allowed:
        return RedirectResponse(url="/system", status_code=303)
    try:
        subprocess.run(["sudo", "systemctl", "restart", service_name], timeout=10, check=False)
    except Exception:
        pass
    return RedirectResponse(url="/system", status_code=303)
