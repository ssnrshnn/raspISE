"""Tests for raspise.policy.engine — condition evaluators and engine logic."""
from __future__ import annotations

import json
from datetime import time

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from raspise.db.models import Group, Policy, PolicyAction
from raspise.policy.engine import (
    AuthContext,
    PolicyDecision,
    PolicyEngine,
    _eval_condition,
    _string_match,
)


# ---------------------------------------------------------------------------
# _string_match
# ---------------------------------------------------------------------------

class TestStringMatch:
    def test_equals(self):
        assert _string_match("alice", "equals", "Alice") is True

    def test_equals_mismatch(self):
        assert _string_match("alice", "equals", "bob") is False

    def test_startswith(self):
        assert _string_match("admin_user", "startswith", "admin") is True

    def test_endswith(self):
        assert _string_match("user_admin", "endswith", "admin") is True

    def test_contains(self):
        assert _string_match("hello_world_test", "contains", "world") is True

    def test_regex(self):
        assert _string_match("user123", "regex", r"^user\d+$") is True

    def test_regex_no_match(self):
        assert _string_match("admin", "regex", r"^user\d+$") is False

    def test_regex_invalid(self):
        assert _string_match("test", "regex", r"[invalid") is False

    def test_unknown_op(self):
        assert _string_match("test", "nonexistent", "test") is False


# ---------------------------------------------------------------------------
# _eval_condition
# ---------------------------------------------------------------------------

class TestEvalCondition:
    def test_always(self):
        ctx = AuthContext()
        assert _eval_condition({"type": "always"}, ctx) is True

    def test_username_equals(self):
        ctx = AuthContext(username="alice")
        assert _eval_condition({"type": "username", "op": "equals", "value": "Alice"}, ctx) is True

    def test_group_in(self):
        ctx = AuthContext(group_name="employees")
        cond = {"type": "group", "op": "in", "value": ["employees", "contractors"]}
        assert _eval_condition(cond, ctx) is True

    def test_group_not_in(self):
        ctx = AuthContext(group_name="guests")
        cond = {"type": "group", "op": "in", "value": ["employees"]}
        assert _eval_condition(cond, ctx) is False

    def test_mac_equals(self):
        ctx = AuthContext(mac_address="aa:bb:cc:dd:ee:ff")
        cond = {"type": "mac", "op": "equals", "value": "AA:BB:CC:DD:EE:FF"}
        assert _eval_condition(cond, ctx) is True

    def test_mac_startswith(self):
        ctx = AuthContext(mac_address="aa:bb:cc:dd:ee:ff")
        cond = {"type": "mac", "op": "startswith", "value": "aa:bb:cc"}
        assert _eval_condition(cond, ctx) is True

    def test_mac_in(self):
        ctx = AuthContext(mac_address="aa:bb:cc:dd:ee:ff")
        cond = {"type": "mac", "op": "in", "value": ["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"]}
        assert _eval_condition(cond, ctx) is True

    def test_mac_invalid(self):
        ctx = AuthContext(mac_address="not-a-mac")
        cond = {"type": "mac", "op": "equals", "value": "AA:BB:CC:DD:EE:FF"}
        assert _eval_condition(cond, ctx) is False

    def test_time_within(self):
        ctx = AuthContext()
        ctx.timestamp = ctx.timestamp.replace(hour=12, minute=0)
        cond = {"type": "time", "op": "between", "start": "08:00", "end": "17:00"}
        assert _eval_condition(cond, ctx) is True

    def test_time_outside(self):
        ctx = AuthContext()
        ctx.timestamp = ctx.timestamp.replace(hour=20, minute=0)
        cond = {"type": "time", "op": "between", "start": "08:00", "end": "17:00"}
        assert _eval_condition(cond, ctx) is False

    def test_device_type_in(self):
        ctx = AuthContext(device_type="laptop")
        cond = {"type": "device_type", "op": "in", "value": ["Laptop", "Workstation"]}
        assert _eval_condition(cond, ctx) is True

    def test_nas_ip_equals(self):
        ctx = AuthContext(nas_ip="192.168.1.1")
        cond = {"type": "nas_ip", "op": "equals", "value": "192.168.1.1"}
        assert _eval_condition(cond, ctx) is True

    def test_nas_ip_in(self):
        ctx = AuthContext(nas_ip="10.0.0.1")
        cond = {"type": "nas_ip", "op": "in", "value": ["10.0.0.1", "10.0.0.2"]}
        assert _eval_condition(cond, ctx) is True

    def test_unknown_type(self):
        ctx = AuthContext()
        assert _eval_condition({"type": "foobar"}, ctx) is False


# ---------------------------------------------------------------------------
# PolicyEngine.evaluate (needs a real async session with policies)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestPolicyEngineEvaluate:
    async def test_first_match_wins(self, db: AsyncSession):
        """Higher-priority (lower number) rule wins."""
        grp = Group(name="staff")
        db.add(grp)
        await db.flush()

        p1 = Policy(
            name="deny-all",
            priority=200,
            conditions=json.dumps([{"type": "always"}]),
            action=PolicyAction.DENY,
            enabled=True,
        )
        p2 = Policy(
            name="permit-staff",
            priority=100,
            conditions=json.dumps([{"type": "group", "op": "in", "value": ["staff"]}]),
            action=PolicyAction.PERMIT,
            vlan=10,
            enabled=True,
        )
        db.add_all([p1, p2])
        await db.commit()

        engine = PolicyEngine()
        ctx = AuthContext(username="alice", group_name="staff")
        result = await engine.evaluate(ctx, db)

        assert result.action == PolicyAction.PERMIT
        assert result.vlan == 10
        assert result.policy_name == "permit-staff"

    async def test_default_deny_when_no_match(self, db: AsyncSession):
        """No enabled policies → default deny."""
        engine = PolicyEngine()
        ctx = AuthContext(username="nobody")
        result = await engine.evaluate(ctx, db)

        assert result.action == PolicyAction.DENY
        assert result.vlan is None

    async def test_disabled_policy_skipped(self, db: AsyncSession):
        p = Policy(
            name="disabled-rule",
            priority=1,
            conditions=json.dumps([{"type": "always"}]),
            action=PolicyAction.PERMIT,
            enabled=False,
        )
        db.add(p)
        await db.commit()

        engine = PolicyEngine()
        ctx = AuthContext(username="alice")
        result = await engine.evaluate(ctx, db)

        assert result.action == PolicyAction.DENY  # skipped disabled → default deny

    async def test_invalid_conditions_json_skipped(self, db: AsyncSession):
        p = Policy(
            name="broken-json",
            priority=1,
            conditions="NOT VALID JSON",
            action=PolicyAction.PERMIT,
            enabled=True,
        )
        db.add(p)
        await db.commit()

        engine = PolicyEngine()
        ctx = AuthContext(username="alice")
        result = await engine.evaluate(ctx, db)

        assert result.action == PolicyAction.DENY  # invalid JSON → skipped

    async def test_multi_condition_and_logic(self, db: AsyncSession):
        """All conditions within a rule must match (AND)."""
        p = Policy(
            name="mac-and-group",
            priority=1,
            conditions=json.dumps([
                {"type": "group", "op": "in", "value": ["devs"]},
                {"type": "mac", "op": "startswith", "value": "aa:bb:cc"},
            ]),
            action=PolicyAction.PERMIT,
            enabled=True,
        )
        db.add(p)
        await db.commit()

        engine = PolicyEngine()

        # Both match → PERMIT
        ctx = AuthContext(group_name="devs", mac_address="aa:bb:cc:dd:ee:ff")
        assert (await engine.evaluate(ctx, db)).action == PolicyAction.PERMIT

        # Group doesn't match → default deny
        ctx2 = AuthContext(group_name="other", mac_address="aa:bb:cc:dd:ee:ff")
        assert (await engine.evaluate(ctx2, db)).action == PolicyAction.DENY
