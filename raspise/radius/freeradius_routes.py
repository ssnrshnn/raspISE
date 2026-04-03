"""
FreeRADIUS rlm_rest callback endpoints.
========================================
Mounted on the RaspISE REST API app at ``/radius/*``.

When FreeRADIUS is deployed as the outer RADIUS listener (EAP-PEAP, EAP-TLS),
its ``rlm_rest`` module calls these endpoints to delegate authentication,
authorization, and accounting to RaspISE.

These endpoints do **not** require a Bearer token — they are called by
FreeRADIUS running on the same host (127.0.0.1).  Access is restricted by
bind address and the shared connect_uri in the rlm_rest config.
"""
from __future__ import annotations

from datetime import datetime, timezone

import bcrypt
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy import delete as sa_delete, select, update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from raspise.core.events import bus, EventType
from raspise.core.logger import get_logger
from raspise.core.utils import normalise_mac
from raspise.db import get_db
from raspise.db.models import (
    ActiveSession, AuthLog, AuthMethod, AuthResult, User,
)
from raspise.policy.engine import AuthContext, engine as policy_engine

log = get_logger(__name__)

router = APIRouter(prefix="/radius", tags=["FreeRADIUS Hooks"])


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------

class RadiusAuthRequest(BaseModel):
    username: str
    password: str | None = None
    nas_ip: str | None = None
    nas_port: str | None = None
    calling_station_id: str | None = None
    called_station_id: str | None = None


class RadiusAuthzRequest(BaseModel):
    username: str
    nas_ip: str | None = None
    calling_station_id: str | None = None


class RadiusAcctRequest(BaseModel):
    status_type: str | None = None
    username: str | None = None
    session_id: str | None = None
    nas_ip: str | None = None
    framed_ip: str | None = None
    calling_station: str | None = None
    input_octets: str | None = None
    output_octets: str | None = None
    session_time: str | None = None


# ---------------------------------------------------------------------------
# Restrict to localhost
# ---------------------------------------------------------------------------

def _is_local(request: Request) -> bool:
    host = request.client.host if request.client else ""
    return host in ("127.0.0.1", "::1", "localhost")


# ---------------------------------------------------------------------------
# Authenticate
# ---------------------------------------------------------------------------

@router.post("/auth")
async def radius_auth(
    body: RadiusAuthRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Called by FreeRADIUS rlm_rest during the authentication phase."""
    if not _is_local(request):
        return {"Reply-Message": "Forbidden"}

    mac = ""
    if body.calling_station_id:
        try:
            mac = normalise_mac(body.calling_station_id)
        except ValueError:
            mac = body.calling_station_id

    # 1. Verify credentials
    user = (await db.execute(
        select(User).where(User.username == body.username, User.enabled == True)
    )).scalar_one_or_none()

    if user is None or not body.password:
        # User not found locally — try LDAP before rejecting
        if body.password:
            from raspise.auth.ldap import ldap_authenticate, ldap_auto_provision
            ldap_result = await ldap_authenticate(body.username, body.password)
            if ldap_result is not None:
                await ldap_auto_provision(body.username, ldap_result, db)
                # Re-fetch user after auto-provisioning
                user = (await db.execute(
                    select(User).where(User.username == body.username, User.enabled == True)
                )).scalar_one_or_none()

        if user is None:
            await _log_auth(db, body.username, mac, body.nas_ip or "", AuthResult.FAILURE, "Unknown user", "")
            return {"Reply-Message": "Access denied"}
    else:
        if not bcrypt.checkpw(body.password.encode(), user.password_hash.encode()):
            await _log_auth(db, body.username, mac, body.nas_ip or "", AuthResult.FAILURE, "Wrong password", "")
            return {"Reply-Message": "Access denied"}

    # 2. Policy evaluation
    group_name = ""
    if user.group_id:
        from sqlalchemy.orm import selectinload
        u2 = (await db.execute(
            select(User).options(selectinload(User.group)).where(User.id == user.id)
        )).scalar_one()
        group_name = u2.group.name if u2.group else ""

    ctx = AuthContext(
        username=body.username,
        mac_address=mac,
        nas_ip=body.nas_ip or "",
        auth_method="PEAP",
        group_name=group_name,
    )
    decision = await policy_engine.evaluate(ctx, db)

    if decision.action.value == "DENY":
        await _log_auth(db, body.username, mac, body.nas_ip or "", AuthResult.FAILURE,
                        decision.reason or "Policy denied", decision.policy_name or "")
        await bus.publish(EventType.AUTH_FAILURE, {
            "username": body.username, "mac": mac, "reason": decision.reason,
        })
        return {"Reply-Message": decision.reason or "Access denied"}

    # Accept
    await _log_auth(db, body.username, mac, body.nas_ip or "", AuthResult.SUCCESS,
                    "", decision.policy_name or "")
    await bus.publish(EventType.AUTH_SUCCESS, {
        "username": body.username, "mac": mac, "vlan": decision.vlan,
    })

    response: dict = {"Reply-Message": "Welcome", "control:Auth-Type": "Accept"}
    if decision.vlan:
        response.update({
            "Tunnel-Type": "13",
            "Tunnel-Medium-Type": "6",
            "Tunnel-Private-Group-Id": str(decision.vlan),
        })
    return response


# ---------------------------------------------------------------------------
# Authorize
# ---------------------------------------------------------------------------

@router.post("/authorize")
async def radius_authorize(
    body: RadiusAuthzRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Called by FreeRADIUS rlm_rest during the authorization phase."""
    if not _is_local(request):
        return {"Reply-Message": "Forbidden"}

    mac = ""
    if body.calling_station_id:
        try:
            mac = normalise_mac(body.calling_station_id)
        except ValueError:
            mac = body.calling_station_id

    group_name = ""
    user = (await db.execute(
        select(User).where(User.username == body.username, User.enabled == True)
    )).scalar_one_or_none()
    if user and user.group_id:
        from sqlalchemy.orm import selectinload
        u2 = (await db.execute(
            select(User).options(selectinload(User.group)).where(User.id == user.id)
        )).scalar_one()
        group_name = u2.group.name if u2.group else ""

    ctx = AuthContext(
        username=body.username,
        mac_address=mac,
        nas_ip=body.nas_ip or "",
        auth_method="PEAP",
        group_name=group_name,
    )
    decision = await policy_engine.evaluate(ctx, db)

    if decision.action.value in ("PERMIT", "GUEST"):
        resp: dict = {"control:Auth-Type": "EAP"}
        if decision.vlan:
            resp.update({
                "Tunnel-Type": "13",
                "Tunnel-Medium-Type": "6",
                "Tunnel-Private-Group-Id": str(decision.vlan),
            })
        return resp
    return {"Reply-Message": "Not authorized"}


# ---------------------------------------------------------------------------
# Accounting
# ---------------------------------------------------------------------------

@router.post("/accounting")
async def radius_accounting(
    body: RadiusAcctRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Called by FreeRADIUS rlm_rest for accounting Start/Interim/Stop."""
    if not _is_local(request):
        return {"ok": False}

    status = (body.status_type or "").lower()
    sid = body.session_id or ""

    if "start" in status and sid:
        mac = ""
        if body.calling_station:
            try:
                mac = normalise_mac(body.calling_station)
            except ValueError:
                mac = body.calling_station
        sess = ActiveSession(
            session_id=sid,
            username=body.username or "",
            mac_address=mac,
            ip_address=body.framed_ip or "",
            nas_ip=body.nas_ip or "",
        )
        db.add(sess)
        await db.commit()

    elif ("stop" in status or "interim" in status) and sid:
        vals: dict = {}
        if body.input_octets:
            vals["bytes_in"] = int(body.input_octets)
        if body.output_octets:
            vals["bytes_out"] = int(body.output_octets)
        if vals:
            await db.execute(
                sa_update(ActiveSession)
                .where(ActiveSession.session_id == sid)
                .values(**vals)
            )
        if "stop" in status:
            await db.execute(
                sa_delete(ActiveSession).where(ActiveSession.session_id == sid)
            )
        await db.commit()

    return {"ok": True}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _log_auth(
    db: AsyncSession,
    username: str,
    mac: str,
    nas_ip: str,
    result: AuthResult,
    reason: str,
    policy_name: str,
) -> None:
    entry = AuthLog(
        username=username,
        mac_address=mac,
        nas_ip=nas_ip,
        result=result,
        reason=reason,
        policy_name=policy_name,
        auth_method=AuthMethod.PAP,
    )
    db.add(entry)
    await db.commit()
