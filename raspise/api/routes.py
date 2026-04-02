"""
RaspISE REST API
================
All endpoints require Bearer token (JWT) unless noted.

Auth
  POST /api/v1/auth/login      → {access_token, token_type, expires_in}

Users
  GET  /api/v1/users           → list
  POST /api/v1/users           → create
  GET  /api/v1/users/{id}      → detail
  PUT  /api/v1/users/{id}      → update
  DELETE /api/v1/users/{id}    → delete

Groups
  GET  /api/v1/groups
  POST /api/v1/groups
  DELETE /api/v1/groups/{id}

Devices
  GET  /api/v1/devices
  GET  /api/v1/devices/{id}
  PUT  /api/v1/devices/{id}    → authorize / block / add notes
  DELETE /api/v1/devices/{id}

Policies
  GET  /api/v1/policies
  POST /api/v1/policies
  PUT  /api/v1/policies/{id}
  DELETE /api/v1/policies/{id}

Logs
  GET  /api/v1/logs/auth       → query auth events
  GET  /api/v1/logs/tacacs     → TACACS+ log

Sessions
  GET  /api/v1/sessions        → active RADIUS sessions
  DELETE /api/v1/sessions/{id} → terminate session (CoA not implemented)

Dashboard
  GET  /api/v1/dashboard       → summary stats
"""
from __future__ import annotations

import json
from datetime import date, datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from raspise.api.auth import (
    create_access_token, get_current_admin,
    hash_password, verify_password,
)
from raspise.api.schemas import (
    ActiveSessionOut, AuthLogOut, DashboardStats,
    GroupCreate, GroupOut,
    GuestSessionCreate, GuestSessionOut,
    LoginRequest, PolicyCreate, PolicyOut, PolicyUpdate,
    StatusResponse, TokenResponse,
    UserCreate, UserOut, UserUpdate,
    DeviceOut, DeviceUpdate,
)
from raspise.config import get_config
from raspise.db import get_db
from raspise.db.models import (
    ActiveSession, AdminUser, AuthLog, AuthResult,
    Device, Group, GuestSession, Policy, TacacsLog, User,
)

router = APIRouter(prefix="/api/v1")


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@router.post("/auth/login", response_model=TokenResponse, tags=["Auth"])
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    cfg  = get_config()
    stmt = select(AdminUser).where(AdminUser.username == body.username, AdminUser.enabled == True)
    user = (await db.execute(stmt)).scalar_one_or_none()

    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    user.last_login = datetime.now(timezone.utc)
    await db.commit()

    token = create_access_token(user.username)
    return TokenResponse(
        access_token=token,
        expires_in=cfg.api.token_expire_minutes * 60,
    )


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

@router.get("/users", response_model=list[UserOut], tags=["Users"])
async def list_users(
    skip: int = 0, limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(get_current_admin),
):
    stmt   = select(User).options(selectinload(User.group)).offset(skip).limit(limit)
    result = (await db.execute(stmt)).scalars().all()
    out    = []
    for u in result:
        d = UserOut.model_validate(u)
        d.group_name = u.group.name if u.group else None
        out.append(d)
    return out


@router.post("/users", response_model=UserOut, status_code=201, tags=["Users"])
async def create_user(
    body: UserCreate,
    db:   AsyncSession = Depends(get_db),
    _:    AdminUser    = Depends(get_current_admin),
):
    # Unique username check
    existing = (await db.execute(select(User).where(User.username == body.username))).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="Username already exists")

    user = User(
        username      = body.username,
        password_hash = hash_password(body.password),
        email         = body.email,
        full_name     = body.full_name,
        group_id      = body.group_id,
        enabled       = body.enabled,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return UserOut.model_validate(user)


@router.get("/users/{user_id}", response_model=UserOut, tags=["Users"])
async def get_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(get_current_admin),
):
    stmt = select(User).options(selectinload(User.group)).where(User.id == user_id)
    user = (await db.execute(stmt)).scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    d = UserOut.model_validate(user)
    d.group_name = user.group.name if user.group else None
    return d


@router.put("/users/{user_id}", response_model=UserOut, tags=["Users"])
async def update_user(
    user_id: int,
    body:    UserUpdate,
    db:      AsyncSession = Depends(get_db),
    _:       AdminUser    = Depends(get_current_admin),
):
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    if body.email     is not None: user.email     = body.email
    if body.full_name is not None: user.full_name = body.full_name
    if body.group_id  is not None: user.group_id  = body.group_id
    if body.enabled   is not None: user.enabled   = body.enabled
    if body.password  is not None: user.password_hash = hash_password(body.password)
    await db.commit()
    await db.refresh(user)
    return UserOut.model_validate(user)


@router.delete("/users/{user_id}", response_model=StatusResponse, tags=["Users"])
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(get_current_admin),
):
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    await db.delete(user)
    await db.commit()
    return StatusResponse(status="ok", message=f"User {user_id} deleted")


# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------

@router.get("/groups", response_model=list[GroupOut], tags=["Groups"])
async def list_groups(
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(get_current_admin),
):
    result = (await db.execute(select(Group))).scalars().all()
    return [GroupOut.model_validate(g) for g in result]


@router.post("/groups", response_model=GroupOut, status_code=201, tags=["Groups"])
async def create_group(
    body: GroupCreate,
    db:   AsyncSession = Depends(get_db),
    _:    AdminUser    = Depends(get_current_admin),
):
    existing = (await db.execute(select(Group).where(Group.name == body.name))).scalar_one_or_none()
    if existing:
        raise HTTPException(409, "Group name already exists")
    grp = Group(name=body.name, description=body.description)
    db.add(grp)
    await db.commit()
    await db.refresh(grp)
    return GroupOut.model_validate(grp)


@router.delete("/groups/{group_id}", response_model=StatusResponse, tags=["Groups"])
async def delete_group(
    group_id: int,
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(get_current_admin),
):
    grp = (await db.execute(select(Group).where(Group.id == group_id))).scalar_one_or_none()
    if not grp:
        raise HTTPException(404, "Group not found")
    await db.delete(grp)
    await db.commit()
    return StatusResponse(status="ok", message=f"Group {group_id} deleted")


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------

@router.get("/devices", response_model=list[DeviceOut], tags=["Devices"])
async def list_devices(
    skip: int = 0, limit: int = Query(100, le=500),
    authorized: bool | None = None,
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(get_current_admin),
):
    stmt = select(Device).offset(skip).limit(limit)
    if authorized is not None:
        stmt = stmt.where(Device.authorized == authorized)
    result = (await db.execute(stmt)).scalars().all()
    return [DeviceOut.model_validate(d) for d in result]


@router.get("/devices/{device_id}", response_model=DeviceOut, tags=["Devices"])
async def get_device(
    device_id: int,
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(get_current_admin),
):
    dev = (await db.execute(select(Device).where(Device.id == device_id))).scalar_one_or_none()
    if not dev:
        raise HTTPException(404, "Device not found")
    return DeviceOut.model_validate(dev)


@router.put("/devices/{device_id}", response_model=DeviceOut, tags=["Devices"])
async def update_device(
    device_id: int,
    body: DeviceUpdate,
    db:   AsyncSession = Depends(get_db),
    _:    AdminUser    = Depends(get_current_admin),
):
    dev = (await db.execute(select(Device).where(Device.id == device_id))).scalar_one_or_none()
    if not dev:
        raise HTTPException(404, "Device not found")
    if body.authorized   is not None: dev.authorized   = body.authorized
    if body.notes        is not None: dev.notes        = body.notes
    if body.device_type  is not None: dev.device_type  = body.device_type
    await db.commit()
    await db.refresh(dev)
    return DeviceOut.model_validate(dev)


@router.delete("/devices/{device_id}", response_model=StatusResponse, tags=["Devices"])
async def delete_device(
    device_id: int,
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(get_current_admin),
):
    dev = (await db.execute(select(Device).where(Device.id == device_id))).scalar_one_or_none()
    if not dev:
        raise HTTPException(404, "Device not found")
    await db.delete(dev)
    await db.commit()
    return StatusResponse(status="ok", message=f"Device {device_id} deleted")


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

@router.get("/policies", response_model=list[PolicyOut], tags=["Policies"])
async def list_policies(
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(get_current_admin),
):
    stmt   = select(Policy).order_by(Policy.priority)
    result = (await db.execute(stmt)).scalars().all()
    return [PolicyOut.model_validate(p) for p in result]


@router.post("/policies", response_model=PolicyOut, status_code=201, tags=["Policies"])
async def create_policy(
    body: PolicyCreate,
    db:   AsyncSession = Depends(get_db),
    _:    AdminUser    = Depends(get_current_admin),
):
    pol = Policy(
        name        = body.name,
        description = body.description,
        priority    = body.priority,
        conditions  = json.dumps(body.conditions),
        action      = body.action,
        vlan        = body.vlan,
        group_id    = body.group_id,
        enabled     = body.enabled,
    )
    db.add(pol)
    await db.commit()
    await db.refresh(pol)
    return PolicyOut.model_validate(pol)


@router.put("/policies/{policy_id}", response_model=PolicyOut, tags=["Policies"])
async def update_policy(
    policy_id: int,
    body: PolicyUpdate,
    db:   AsyncSession = Depends(get_db),
    _:    AdminUser    = Depends(get_current_admin),
):
    pol = (await db.execute(select(Policy).where(Policy.id == policy_id))).scalar_one_or_none()
    if not pol:
        raise HTTPException(404, "Policy not found")
    if body.name        is not None: pol.name        = body.name
    if body.description is not None: pol.description = body.description
    if body.priority    is not None: pol.priority    = body.priority
    if body.conditions  is not None: pol.conditions  = json.dumps(body.conditions)
    if body.action      is not None: pol.action      = body.action
    if body.vlan        is not None: pol.vlan        = body.vlan
    if body.group_id    is not None: pol.group_id    = body.group_id
    if body.enabled     is not None: pol.enabled     = body.enabled
    await db.commit()
    await db.refresh(pol)
    return PolicyOut.model_validate(pol)


@router.delete("/policies/{policy_id}", response_model=StatusResponse, tags=["Policies"])
async def delete_policy(
    policy_id: int,
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(get_current_admin),
):
    pol = (await db.execute(select(Policy).where(Policy.id == policy_id))).scalar_one_or_none()
    if not pol:
        raise HTTPException(404, "Policy not found")
    await db.delete(pol)
    await db.commit()
    return StatusResponse(status="ok", message=f"Policy {policy_id} deleted")


# ---------------------------------------------------------------------------
# Auth Logs
# ---------------------------------------------------------------------------

@router.get("/logs/auth", response_model=list[AuthLogOut], tags=["Logs"])
async def auth_logs(
    skip:    int = 0,
    limit:   int = Query(100, le=500),
    result:  str | None = None,
    username: str | None = None,
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(get_current_admin),
):
    stmt = select(AuthLog).order_by(AuthLog.timestamp.desc()).offset(skip).limit(limit)
    if result:
        stmt = stmt.where(AuthLog.result == result.upper())
    if username:
        stmt = stmt.where(AuthLog.username.ilike(f"%{username}%"))
    rows = (await db.execute(stmt)).scalars().all()
    return [AuthLogOut.model_validate(r) for r in rows]


@router.get("/logs/tacacs", tags=["Logs"])
async def tacacs_logs(
    skip: int = 0, limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(get_current_admin),
):
    from raspise.db.models import TacacsLog
    stmt = select(TacacsLog).order_by(TacacsLog.timestamp.desc()).offset(skip).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": r.id, "timestamp": r.timestamp, "type": r.packet_type,
            "username": r.username, "remote_ip": r.remote_ip,
            "command": r.command, "result": r.result, "priv_lvl": r.privilege_level,
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Active Sessions
# ---------------------------------------------------------------------------

@router.get("/sessions", response_model=list[ActiveSessionOut], tags=["Sessions"])
async def active_sessions(
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(get_current_admin),
):
    rows = (await db.execute(select(ActiveSession))).scalars().all()
    return [ActiveSessionOut.model_validate(r) for r in rows]


@router.delete("/sessions/{session_id}", response_model=StatusResponse, tags=["Sessions"])
async def terminate_session(
    session_id: int,
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(get_current_admin),
):
    sess = (await db.execute(select(ActiveSession).where(ActiveSession.id == session_id))).scalar_one_or_none()
    if not sess:
        raise HTTPException(404, "Session not found")
    await db.delete(sess)
    await db.commit()
    return StatusResponse(status="ok", message="Session removed (CoA not sent — remove from switch manually)")


# ---------------------------------------------------------------------------
# Guest Sessions (admin management)
# ---------------------------------------------------------------------------

@router.post("/guests", response_model=GuestSessionOut, status_code=201, tags=["Guests"])
async def create_guest_session(
    body: GuestSessionCreate,
    db:   AsyncSession = Depends(get_db),
    _:    AdminUser    = Depends(get_current_admin),
):
    from datetime import timedelta
    from raspise.core.utils import generate_token, normalise_mac, utcnow

    mac = ""
    if body.mac_address:
        try:
            mac = normalise_mac(body.mac_address)
        except ValueError:
            raise HTTPException(400, "Invalid MAC address format")

    expires_at = utcnow() + timedelta(hours=max(1, min(body.duration_hours, 168)))
    session = GuestSession(
        token       = generate_token(32),
        full_name   = body.full_name.strip()[:128],
        email       = (body.email or "").strip().lower()[:128],
        mac_address = mac,
        ip_address  = "",
        expires_at  = expires_at,
    )
    db.add(session)
    await db.commit()
    await db.refresh(session)
    return GuestSessionOut.model_validate(session)


# ---------------------------------------------------------------------------

@router.get("/dashboard", response_model=DashboardStats, tags=["Dashboard"])
async def dashboard_stats(
    db: AsyncSession = Depends(get_db),
    _:  AdminUser    = Depends(get_current_admin),
):
    from datetime import datetime, timezone, timedelta
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    total_users    = (await db.execute(select(func.count()).select_from(User))).scalar_one()
    total_devices  = (await db.execute(select(func.count()).select_from(Device))).scalar_one()
    active_sess    = (await db.execute(select(func.count()).select_from(ActiveSession))).scalar_one()
    auth_today     = (await db.execute(
        select(func.count()).select_from(AuthLog).where(AuthLog.timestamp >= today_start)
    )).scalar_one()
    auth_success_today = (await db.execute(
        select(func.count()).select_from(AuthLog).where(
            AuthLog.timestamp >= today_start, AuthLog.result == AuthResult.SUCCESS
        )
    )).scalar_one()
    auth_fail_today = (await db.execute(
        select(func.count()).select_from(AuthLog).where(
            AuthLog.timestamp >= today_start, AuthLog.result == AuthResult.FAILURE
        )
    )).scalar_one()
    guest_active = (await db.execute(
        select(func.count()).select_from(GuestSession).where(
            GuestSession.active == True,
            GuestSession.expires_at > datetime.now(timezone.utc),
        )
    )).scalar_one()

    return DashboardStats(
        total_users=total_users, total_devices=total_devices,
        active_sessions=active_sess, auth_today=auth_today,
        auth_success_today=auth_success_today, auth_failure_today=auth_fail_today,
        guest_sessions_active=guest_active,
    )
