"""
RaspISE LDAP / Active Directory authentication helper.
======================================================
Performs a simple bind against an LDAP/AD server to verify user credentials,
and optionally resolves group membership for auto-provisioning.

Usage::

    from raspise.auth.ldap import ldap_authenticate

    result = await ldap_authenticate("alice", "s3cret")
    if result is not None:
        # result = {"dn": "...", "groups": ["admins"], "email": "alice@..."}
"""
from __future__ import annotations

import asyncio
from typing import Any

from raspise.config import get_config
from raspise.core.logger import get_logger

log = get_logger(__name__)


async def ldap_authenticate(username: str, password: str) -> dict[str, Any] | None:
    """
    Authenticate *username* / *password* against the configured LDAP server.

    Returns a dict with user attributes on success, or ``None`` on failure.
    The dict contains:
      - ``dn``:     the user's distinguished name
      - ``groups``: list of RaspISE group names (resolved via ``group_map``)
      - ``email``:  user's mail attribute (if present)
    """
    cfg = get_config().ldap
    if not cfg.enabled:
        return None

    try:
        import ldap3
        from ldap3 import Server, Connection, SUBTREE, ALL_ATTRIBUTES
    except ImportError:
        log.warning("ldap3 package not installed — LDAP auth unavailable (pip install ldap3)")
        return None

    # Run the blocking LDAP operations in a thread to avoid blocking asyncio
    return await asyncio.to_thread(_ldap_auth_sync, cfg, username, password)


def _ldap_auth_sync(cfg, username: str, password: str) -> dict[str, Any] | None:
    import ldap3
    from ldap3 import Server, Connection, SUBTREE, ALL_ATTRIBUTES

    try:
        server = Server(cfg.server, port=cfg.port, use_ssl=cfg.use_ssl, get_info=ldap3.NONE)

        # 1. Bind with service account to search for the user
        conn = Connection(server, user=cfg.bind_dn, password=cfg.bind_password, auto_bind=True)

        search_filter = cfg.user_filter.replace("{username}", ldap3.utils.conv.escape_filter_chars(username))
        conn.search(
            search_base=cfg.base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=ALL_ATTRIBUTES,
        )

        if not conn.entries:
            log.debug("LDAP: user %r not found with filter %s", username, search_filter)
            conn.unbind()
            return None

        user_entry = conn.entries[0]
        user_dn = str(user_entry.entry_dn)
        conn.unbind()

        # 2. Bind as the user to verify password
        user_conn = Connection(server, user=user_dn, password=password, auto_bind=True)
        user_conn.unbind()

        # 3. Resolve group membership
        groups: list[str] = []
        if cfg.group_attribute and cfg.group_map:
            member_of = getattr(user_entry, cfg.group_attribute, None)
            if member_of:
                for group_dn in member_of.values:
                    group_dn_str = str(group_dn)
                    mapped = cfg.group_map.get(group_dn_str)
                    if mapped:
                        groups.append(mapped)

        # 4. Extract email
        email = ""
        if hasattr(user_entry, "mail"):
            vals = user_entry.mail.values
            email = str(vals[0]) if vals else ""

        log.info("LDAP auth success: user=%r dn=%r groups=%r", username, user_dn, groups)
        return {"dn": user_dn, "groups": groups, "email": email}

    except ldap3.core.exceptions.LDAPBindError:
        log.debug("LDAP bind failed for user %r — wrong password", username)
        return None
    except ldap3.core.exceptions.LDAPException as exc:
        log.warning("LDAP error for user %r: %s", username, exc)
        return None
    except Exception as exc:
        log.warning("LDAP unexpected error for %r: %s", username, exc)
        return None


async def ldap_auto_provision(
    username: str, ldap_result: dict[str, Any], db
) -> None:
    """
    Create or update a local User record based on LDAP auth result.
    Maps the first matching LDAP group to a RaspISE group.
    """
    from sqlalchemy import select
    from raspise.db.models import Group, User
    from raspise.api.auth import hash_password
    import secrets

    user = (await db.execute(
        select(User).where(User.username == username)
    )).scalar_one_or_none()

    # Resolve group_id from LDAP groups
    group_id = None
    for gname in ldap_result.get("groups", []):
        g = (await db.execute(select(Group).where(Group.name == gname))).scalar_one_or_none()
        if g:
            group_id = g.id
            break

    if user is None:
        # Auto-provision: create local user with random password (LDAP will always auth)
        user = User(
            username=username,
            password_hash=hash_password(secrets.token_urlsafe(32)),
            email=ldap_result.get("email", ""),
            group_id=group_id,
            enabled=True,
        )
        db.add(user)
        log.info("Auto-provisioned LDAP user %r into group_id=%s", username, group_id)
    else:
        # Update group mapping if changed
        if group_id and user.group_id != group_id:
            user.group_id = group_id
    await db.commit()
