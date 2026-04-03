"""
RaspISE Policy Engine
=====================
Evaluates access-control policies against an authentication request context.

A policy is a prioritised rule with JSON conditions.  The engine returns the
first matching policy's action (PERMIT / DENY / GUEST) plus an optional VLAN.

Condition types
---------------
  username    – "equals" | "startswith" | "endswith" | "contains" | "regex"
  group       – "in" (list of group names)
  mac         – "equals" | "startswith" (OUI prefix) | "in" (list)
  time        – "between" {"start": "HH:MM", "end": "HH:MM"}
  device_type – "in" (list of strings returned by the profiler)
  nas_ip      – "equals" | "in"
  always      – matches every request (used for catch-all rules)

Example rule JSON
-----------------
  [
    {"type": "group",       "op": "in",       "value": ["employees"]},
    {"type": "time",        "op": "between",  "start": "07:00", "end": "19:00"},
    {"type": "device_type", "op": "in",       "value": ["laptop", "workstation"]}
  ]
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from raspise.core.logger import get_logger
from raspise.core.utils import normalise_mac, is_within_time_range, utcnow
from raspise.db.models import Policy, PolicyAction

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Request context — passed to engine for every auth attempt
# ---------------------------------------------------------------------------

@dataclass
class AuthContext:
    username: str           = ""
    mac_address: str        = ""        # normalised lower-colon
    ip_address: str         = ""
    nas_ip: str             = ""
    nas_port: str           = ""
    auth_method: str        = ""
    group_name: str         = ""        # resolved from DB
    device_type: str        = "unknown" # from profiler
    os_type: str            = "unknown"
    timestamp: datetime     = field(default_factory=utcnow)


@dataclass
class PolicyDecision:
    action: PolicyAction
    vlan: int | None
    policy_name: str
    reason: str


# ---------------------------------------------------------------------------
# Condition evaluators
# ---------------------------------------------------------------------------

def _eval_condition(cond: dict[str, Any], ctx: AuthContext) -> bool:
    ctype = cond.get("type", "")
    op    = cond.get("op",   "equals")
    val   = cond.get("value", "")

    if ctype == "always":
        return True

    if ctype == "username":
        return _string_match(ctx.username, op, val)

    if ctype == "group":
        groups = val if isinstance(val, list) else [val]
        return ctx.group_name in groups

    if ctype == "mac":
        try:
            mac = normalise_mac(ctx.mac_address)
        except ValueError:
            return False
        if op == "equals":
            return mac == normalise_mac(val)
        if op == "startswith":
            return mac.startswith(val.lower())
        if op == "in":
            norms = []
            for m in (val if isinstance(val, list) else [val]):
                try:
                    norms.append(normalise_mac(m))
                except ValueError:
                    pass
            return mac in norms

    if ctype == "time":
        start = cond.get("start", "00:00")
        end   = cond.get("end",   "23:59")
        return is_within_time_range(start, end, ctx.timestamp.time())

    if ctype == "device_type":
        device_types = val if isinstance(val, list) else [val]
        return ctx.device_type.lower() in [d.lower() for d in device_types]

    if ctype == "nas_ip":
        if op == "equals":
            return ctx.nas_ip == val
        if op == "startswith":
            return ctx.nas_ip.startswith(val)
        if op == "in":
            return ctx.nas_ip in (val if isinstance(val, list) else [val])

    log.warning("Unknown condition type %r — treating as no-match", ctype)
    return False


def _string_match(subject: str, op: str, pattern: str) -> bool:
    s = subject.lower()
    p = pattern.lower() if isinstance(pattern, str) else pattern
    if op == "equals":     return s == p
    if op == "startswith": return s.startswith(p)
    if op == "endswith":   return s.endswith(p)
    if op == "contains":   return p in s
    if op == "regex":
        try:
            # Compile with a size guard — reject patterns over 256 chars to mitigate ReDoS
            if len(pattern) > 256:
                log.warning("Regex pattern too long (%d chars) — treating as no-match", len(pattern))
                return False
            compiled = re.compile(pattern, re.IGNORECASE)
            # Use re.search with a bounded subject
            return bool(compiled.search(subject[:1024]))
        except re.error as exc:
            log.warning("Invalid regex pattern %r in policy condition: %s", pattern, exc)
            return False
    return False


# ---------------------------------------------------------------------------
# Policy Engine
# ---------------------------------------------------------------------------

class PolicyEngine:
    """
    Stateless engine; results depend only on DB policies + request context.
    Call evaluate() for each authentication request.
    """

    async def evaluate(
        self, ctx: AuthContext, db: AsyncSession
    ) -> PolicyDecision:
        """
        Load active policies ordered by priority, evaluate each until a match.
        Returns a DENY decision if no rule matches (default-deny).
        """
        stmt = (
            select(Policy)
            .where(Policy.enabled == True)
            .order_by(Policy.priority.asc())
        )
        result = await db.execute(stmt)
        policies: list[Policy] = result.scalars().all()

        for policy in policies:
            try:
                conditions: list[dict] = json.loads(policy.conditions or "[]")
            except (json.JSONDecodeError, TypeError):
                log.warning("Policy %r has invalid conditions JSON — skipping", policy.name)
                continue

            if _matches_all(conditions, ctx):
                log.debug(
                    "Policy match: [%s] → %s (vlan=%s) for user=%r mac=%r",
                    policy.name, policy.action, policy.vlan,
                    ctx.username, ctx.mac_address,
                )
                return PolicyDecision(
                    action=PolicyAction(policy.action),
                    vlan=policy.vlan,
                    policy_name=policy.name,
                    reason=f"Matched policy: {policy.name}",
                )

        # No rule matched → default deny
        log.info("No policy matched for user=%r mac=%r → DEFAULT_DENY", ctx.username, ctx.mac_address)
        return PolicyDecision(
            action=PolicyAction.DENY,
            vlan=None,
            policy_name="DEFAULT_DENY",
            reason="No matching policy found",
        )


def _matches_all(conditions: list[dict], ctx: AuthContext) -> bool:
    """All conditions must match (logical AND)."""
    if not conditions:          # empty list = match everything
        return True
    return all(_eval_condition(c, ctx) for c in conditions)


# Module-level singleton
engine = PolicyEngine()
