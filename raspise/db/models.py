"""
RaspISE Database Models
=======================
Full SQLAlchemy ORM models covering every entity in the system.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum as PyEnum

from sqlalchemy import (
    Boolean, DateTime, Enum, ForeignKey, Integer, String, Text,
    func, text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from raspise.db.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class AuthResult(str, PyEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    CHALLENGE = "CHALLENGE"


class AuthMethod(str, PyEnum):
    PAP       = "PAP"
    CHAP      = "CHAP"
    PEAP      = "PEAP"
    EAP_TLS   = "EAP_TLS"
    MAB       = "MAB"
    WEB_AUTH  = "WEB_AUTH"
    PAP_CHAP  = "PAP/CHAP"


class PolicyAction(str, PyEnum):
    PERMIT = "PERMIT"
    DENY   = "DENY"
    GUEST  = "GUEST"


class TacacsPacketType(str, PyEnum):
    AUTHEN = "AUTHEN"
    AUTHOR = "AUTHOR"
    ACCTING = "ACCTING"


# ---------------------------------------------------------------------------
# Users & Groups
# ---------------------------------------------------------------------------

class Group(Base):
    __tablename__ = "groups"

    id: Mapped[int]           = mapped_column(Integer, primary_key=True)
    name: Mapped[str]         = mapped_column(String(64), unique=True, nullable=False)
    description: Mapped[str]  = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )

    users: Mapped[list["User"]] = relationship("User", back_populates="group")
    policies: Mapped[list["Policy"]] = relationship("Policy", back_populates="group")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int]            = mapped_column(Integer, primary_key=True)
    username: Mapped[str]      = mapped_column(String(64), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    email: Mapped[str]         = mapped_column(String(128), default="")
    full_name: Mapped[str]     = mapped_column(String(128), default="")
    group_id: Mapped[int | None] = mapped_column(ForeignKey("groups.id"), nullable=True)
    enabled: Mapped[bool]      = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    group: Mapped["Group | None"] = relationship("Group", back_populates="users")
    auth_logs: Mapped[list["AuthLog"]] = relationship("AuthLog", back_populates="user")


# ---------------------------------------------------------------------------
# Devices / Inventory
# ---------------------------------------------------------------------------

class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int]             = mapped_column(Integer, primary_key=True)
    mac_address: Mapped[str]    = mapped_column(String(17), unique=True, nullable=False, index=True)
    ip_address: Mapped[str]     = mapped_column(String(45), default="")
    hostname: Mapped[str]       = mapped_column(String(128), default="")
    vendor: Mapped[str]         = mapped_column(String(128), default="")  # OUI lookup
    device_type: Mapped[str]    = mapped_column(String(64), default="unknown")
    os_type: Mapped[str]        = mapped_column(String(64), default="unknown")
    user_agent: Mapped[str]     = mapped_column(String(512), default="")
    dhcp_fingerprint: Mapped[str] = mapped_column(String(256), default="")
    authorized: Mapped[bool]    = mapped_column(Boolean, default=True)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow,
        server_default=func.now(),
    )
    notes: Mapped[str]          = mapped_column(Text, default="")

    auth_logs: Mapped[list["AuthLog"]] = relationship("AuthLog", back_populates="device")


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

class Policy(Base):
    """
    A policy rule evaluated by the policy engine.

    conditions (JSON text):
        [
          {"type": "group",       "op": "in",         "value": ["employees"]},
          {"type": "mac",         "op": "startswith",  "value": "aa:bb:cc"},
          {"type": "time",        "op": "between",     "start": "08:00", "end": "18:00"},
          {"type": "device_type", "op": "in",          "value": ["laptop"]},
          {"type": "username",    "op": "equals",      "value": "alice"}
        ]

    All conditions in a rule are AND-ed together.
    Rules are evaluated in ascending priority order; first match wins.
    """
    __tablename__ = "policies"

    id: Mapped[int]           = mapped_column(Integer, primary_key=True)
    name: Mapped[str]         = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str]  = mapped_column(String(512), default="")
    priority: Mapped[int]     = mapped_column(Integer, default=100)
    conditions: Mapped[str]   = mapped_column(Text, default="[]")  # JSON
    action: Mapped[str]       = mapped_column(
        Enum(PolicyAction), default=PolicyAction.PERMIT, nullable=False
    )
    vlan: Mapped[int | None]  = mapped_column(Integer, nullable=True)
    group_id: Mapped[int | None] = mapped_column(ForeignKey("groups.id"), nullable=True)
    enabled: Mapped[bool]     = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )

    group: Mapped["Group | None"] = relationship("Group", back_populates="policies")


# ---------------------------------------------------------------------------
# Authentication Logs
# ---------------------------------------------------------------------------

class AuthLog(Base):
    __tablename__ = "auth_logs"

    id: Mapped[int]             = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now(), index=True
    )
    username: Mapped[str]       = mapped_column(String(64), default="", index=True)
    mac_address: Mapped[str]    = mapped_column(String(17), default="", index=True)
    ip_address: Mapped[str]     = mapped_column(String(45), default="")
    nas_ip: Mapped[str]         = mapped_column(String(45), default="")
    nas_port: Mapped[str]       = mapped_column(String(64), default="")
    auth_method: Mapped[str]    = mapped_column(Enum(AuthMethod), default=AuthMethod.PAP)
    result: Mapped[str]         = mapped_column(Enum(AuthResult), nullable=False)
    reason: Mapped[str]         = mapped_column(String(255), default="")
    policy_name: Mapped[str]    = mapped_column(String(128), default="")
    vlan: Mapped[int | None]    = mapped_column(Integer, nullable=True)
    session_id: Mapped[str]     = mapped_column(String(64), default="")

    user_id: Mapped[int | None]   = mapped_column(ForeignKey("users.id"), nullable=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"), nullable=True)

    user:   Mapped["User | None"]   = relationship("User",   back_populates="auth_logs")
    device: Mapped["Device | None"] = relationship("Device", back_populates="auth_logs")


# ---------------------------------------------------------------------------
# Active Sessions (RADIUS Accounting)
# ---------------------------------------------------------------------------

class ActiveSession(Base):
    __tablename__ = "active_sessions"

    id: Mapped[int]              = mapped_column(Integer, primary_key=True)
    session_id: Mapped[str]      = mapped_column(String(64), unique=True, nullable=False, index=True)
    username: Mapped[str]        = mapped_column(String(64), nullable=False)
    mac_address: Mapped[str]     = mapped_column(String(17), default="")
    ip_address: Mapped[str]      = mapped_column(String(45), default="")
    nas_ip: Mapped[str]          = mapped_column(String(45), default="")
    nas_port: Mapped[str]        = mapped_column(String(64), default="")
    vlan: Mapped[int | None]     = mapped_column(Integer, nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow,
        server_default=func.now(),
    )
    bytes_in: Mapped[int]        = mapped_column(Integer, default=0)
    bytes_out: Mapped[int]       = mapped_column(Integer, default=0)


# ---------------------------------------------------------------------------
# Guest / Captive Portal Sessions
# ---------------------------------------------------------------------------

class GuestSession(Base):
    __tablename__ = "guest_sessions"

    id: Mapped[int]             = mapped_column(Integer, primary_key=True)
    token: Mapped[str]          = mapped_column(String(64), unique=True, nullable=False, index=True)
    email: Mapped[str]          = mapped_column(String(128), default="")
    full_name: Mapped[str]      = mapped_column(String(128), default="")
    mac_address: Mapped[str]    = mapped_column(String(17), default="", index=True)
    ip_address: Mapped[str]     = mapped_column(String(45), default="")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )
    active: Mapped[bool]        = mapped_column(Boolean, default=True)


# ---------------------------------------------------------------------------
# TACACS+ Logs
# ---------------------------------------------------------------------------

class TacacsLog(Base):
    __tablename__ = "tacacs_logs"

    id: Mapped[int]              = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime]  = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now(), index=True
    )
    packet_type: Mapped[str]     = mapped_column(Enum(TacacsPacketType), nullable=False)
    username: Mapped[str]        = mapped_column(String(64), default="", index=True)
    remote_ip: Mapped[str]       = mapped_column(String(45), default="")
    nas_port: Mapped[str]        = mapped_column(String(64), default="")
    privilege_level: Mapped[int] = mapped_column(Integer, default=1)
    command: Mapped[str]         = mapped_column(Text, default="")
    result: Mapped[str]          = mapped_column(String(16), default="PASS")
    reason: Mapped[str]          = mapped_column(String(255), default="")


# ---------------------------------------------------------------------------
# Admin Users (Web UI / REST API login — separate from network users)
# ---------------------------------------------------------------------------

class AdminUser(Base):
    __tablename__ = "admin_users"

    id: Mapped[int]             = mapped_column(Integer, primary_key=True)
    username: Mapped[str]       = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str]  = mapped_column(String(128), nullable=False)
    email: Mapped[str]          = mapped_column(String(128), default="")
    is_superuser: Mapped[bool]  = mapped_column(Boolean, default=False)
    enabled: Mapped[bool]       = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# ---------------------------------------------------------------------------
# RADIUS NAS Clients (editable via Web UI)
# ---------------------------------------------------------------------------

class NasClient(Base):
    __tablename__ = "nas_clients"

    id: Mapped[int]           = mapped_column(Integer, primary_key=True)
    name: Mapped[str]         = mapped_column(String(64), unique=True, nullable=False)
    ip_address: Mapped[str]   = mapped_column(String(45), nullable=False, index=True)
    secret: Mapped[str]       = mapped_column(String(128), nullable=False)
    description: Mapped[str]  = mapped_column(String(255), default="")
    enabled: Mapped[bool]     = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )


# ---------------------------------------------------------------------------
# TACACS+ Device Clients (editable via Web UI)
# ---------------------------------------------------------------------------

class TacacsClient(Base):
    __tablename__ = "tacacs_clients"

    id: Mapped[int]           = mapped_column(Integer, primary_key=True)
    name: Mapped[str]         = mapped_column(String(64), unique=True, nullable=False)
    ip_address: Mapped[str]   = mapped_column(String(45), nullable=False, index=True)
    key: Mapped[str]          = mapped_column(String(128), nullable=False)
    description: Mapped[str]  = mapped_column(String(255), default="")
    enabled: Mapped[bool]     = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )


# ---------------------------------------------------------------------------
# VLAN Assignments (group → VLAN mapping, editable via Web UI)
# ---------------------------------------------------------------------------

class VlanMapping(Base):
    __tablename__ = "vlan_mappings"

    id: Mapped[int]          = mapped_column(Integer, primary_key=True)
    name: Mapped[str]        = mapped_column(String(64), unique=True, nullable=False)
    vlan_id: Mapped[int]     = mapped_column(Integer, nullable=False)
    description: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )
