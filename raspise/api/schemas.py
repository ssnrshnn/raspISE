"""Pydantic schemas for the REST API."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator

from raspise.db.models import AuthMethod, AuthResult, CommandRuleAction, PolicyAction


def _validate_password_complexity(password: str) -> str:
    """Enforce minimum password complexity: 8+ chars, at least one letter and one digit."""
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    if not any(c.isalpha() for c in password):
        raise ValueError("Password must contain at least one letter")
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one digit")
    return password


# ---------------------------------------------------------------------------
# Common
# ---------------------------------------------------------------------------

class StatusResponse(BaseModel):
    status: str
    message: str = ""


# ---------------------------------------------------------------------------
# Auth token
# ---------------------------------------------------------------------------

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1)
    totp_code: str | None = Field(None, min_length=6, max_length=6)


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

class UserCreate(BaseModel):
    username: str = Field(..., min_length=2, max_length=64, pattern=r"^[a-zA-Z0-9._\-]+$")
    password: str = Field(..., min_length=8, max_length=128)
    email:    str = Field("", max_length=128)
    full_name: str = Field("", max_length=128)
    group_id: int | None = None
    enabled:  bool = True

    @field_validator("password")
    @classmethod
    def check_password_complexity(cls, v):
        return _validate_password_complexity(v)


class UserUpdate(BaseModel):
    email:     str | None = Field(None, max_length=128)
    full_name: str | None = Field(None, max_length=128)
    group_id:  int | None = None
    enabled:   bool | None = None
    password:  str | None = Field(None, min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def check_password_complexity(cls, v):
        if v is not None:
            return _validate_password_complexity(v)
        return v


class UserOut(BaseModel):
    id:         int
    username:   str
    email:      str
    full_name:  str
    group_id:   int | None
    group_name: str | None = None
    enabled:    bool
    created_at: datetime
    last_login: datetime | None

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------

class GroupCreate(BaseModel):
    name:           str = Field(..., min_length=1, max_length=64)
    description:    str = Field("", max_length=255)
    command_set_id: int | None = None


class GroupOut(BaseModel):
    id:             int
    name:           str
    description:    str
    command_set_id: int | None = None
    created_at:     datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------

class DeviceUpdate(BaseModel):
    authorized: bool | None = None
    notes:      str | None = Field(None, max_length=1024)
    device_type: str | None = None


class DeviceOut(BaseModel):
    id:                int
    mac_address:       str
    ip_address:        str
    hostname:          str
    vendor:            str
    device_type:       str
    os_type:           str
    dhcp_fingerprint:  str
    authorized:        bool
    first_seen:        datetime
    last_seen:         datetime
    notes:             str

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

class PolicyCreate(BaseModel):
    name:        str = Field(..., min_length=1, max_length=128)
    description: str = Field("", max_length=512)
    priority:    int = Field(100, ge=1, le=9999)
    conditions:  list[dict[str, Any]] = []
    action:      PolicyAction = PolicyAction.PERMIT
    vlan:        int | None = Field(None, ge=1, le=4094)
    group_id:    int | None = None
    enabled:     bool = True

    @field_validator("conditions")
    @classmethod
    def validate_conditions(cls, v):
        import re
        _VALID_TYPES = {"username", "group", "mac", "time", "device_type", "nas_ip", "always"}
        _VALID_OPS = {"equals", "startswith", "endswith", "contains", "regex", "in", "between"}
        for cond in v:
            ctype = cond.get("type", "")
            if ctype not in _VALID_TYPES:
                raise ValueError(f"Unknown condition type: {ctype!r}. Must be one of: {', '.join(sorted(_VALID_TYPES))}")
            op = cond.get("op", "equals")
            if ctype != "always" and op not in _VALID_OPS:
                raise ValueError(f"Unknown operator: {op!r}. Must be one of: {', '.join(sorted(_VALID_OPS))}")
            # Validate regex patterns compile and aren't too long
            if op == "regex":
                pattern = cond.get("value", "")
                if isinstance(pattern, str):
                    if len(pattern) > 256:
                        raise ValueError(f"Regex pattern too long ({len(pattern)} chars, max 256)")
                    try:
                        re.compile(pattern)
                    except re.error as exc:
                        raise ValueError(f"Invalid regex pattern: {exc}")
        return v


class PolicyUpdate(BaseModel):
    name:        str | None = Field(None, min_length=1, max_length=128)
    description: str | None = None
    priority:    int | None = Field(None, ge=1, le=9999)
    conditions:  list[dict[str, Any]] | None = None
    action:      PolicyAction | None = None
    vlan:        int | None = None
    group_id:    int | None = None
    enabled:     bool | None = None

    @field_validator("conditions")
    @classmethod
    def validate_conditions(cls, v):
        if v is not None:
            return PolicyCreate.validate_conditions(v)
        return v


class PolicyOut(BaseModel):
    id:          int
    name:        str
    description: str
    priority:    int
    conditions:  list[dict[str, Any]]
    action:      str
    vlan:        int | None
    group_id:    int | None
    enabled:     bool
    created_at:  datetime

    model_config = {"from_attributes": True}

    @field_validator("conditions", mode="before")
    @classmethod
    def parse_conditions(cls, v):
        import json
        if isinstance(v, str):
            return json.loads(v)
        return v


# ---------------------------------------------------------------------------
# Auth Logs
# ---------------------------------------------------------------------------

class AuthLogOut(BaseModel):
    id:          int
    timestamp:   datetime
    username:    str
    mac_address: str
    ip_address:  str
    nas_ip:      str
    auth_method: str
    result:      str
    reason:      str
    policy_name: str
    vlan:        int | None

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Active Sessions
# ---------------------------------------------------------------------------

class ActiveSessionOut(BaseModel):
    id:          int
    session_id:  str
    username:    str
    mac_address: str
    ip_address:  str
    nas_ip:      str
    vlan:        int | None
    started_at:  datetime
    bytes_in:    int
    bytes_out:   int

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Dashboard summary
# ---------------------------------------------------------------------------

class DashboardStats(BaseModel):
    total_users:      int
    total_devices:    int
    active_sessions:  int
    auth_today:       int
    auth_success_today: int
    auth_failure_today: int
    guest_sessions_active: int


# ---------------------------------------------------------------------------
# Guest session (manual admin creation)
# ---------------------------------------------------------------------------

class GuestSessionCreate(BaseModel):
    full_name:      str
    email:          str | None = None
    mac_address:    str | None = None
    duration_hours: int        = Field(8, ge=1, le=168)


class GuestSessionOut(BaseModel):
    id:          int
    full_name:   str
    email:       str
    mac_address: str
    expires_at:  datetime
    active:      bool

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# TACACS+ Logs
# ---------------------------------------------------------------------------

class TacacsLogOut(BaseModel):
    id:              int
    timestamp:       datetime
    packet_type:     str
    username:        str
    remote_ip:       str
    command:         str
    result:          str
    privilege_level: int

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# TACACS+ Command Sets
# ---------------------------------------------------------------------------

class CommandRuleIn(BaseModel):
    priority:        int = Field(100, ge=1, le=9999)
    action:          CommandRuleAction = CommandRuleAction.PERMIT
    command_pattern: str = Field(..., min_length=1, max_length=256)
    args_pattern:    str = Field("", max_length=256)


class CommandRuleOut(BaseModel):
    id:              int
    priority:        int
    action:          str
    command_pattern: str
    args_pattern:    str

    model_config = {"from_attributes": True}


class CommandSetCreate(BaseModel):
    name:        str = Field(..., min_length=1, max_length=64)
    description: str = Field("", max_length=255)
    rules:       list[CommandRuleIn] = []


class CommandSetUpdate(BaseModel):
    name:        str | None = Field(None, min_length=1, max_length=64)
    description: str | None = None
    rules:       list[CommandRuleIn] | None = None


class CommandSetOut(BaseModel):
    id:          int
    name:        str
    description: str
    created_at:  datetime
    rules:       list[CommandRuleOut] = []

    model_config = {"from_attributes": True}
