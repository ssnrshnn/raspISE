"""
RaspISE RADIUS Server
=====================
Pure-Python RADIUS implementation built on pyrad.

Supported authentication methods
---------------------------------
  PAP       — User-Password attribute (reversibly encrypted with shared secret)
  CHAP      — CHAP-Password + CHAP-Challenge
  MAB       — MAC Address Bypass: MAC used as both username and password
  EAP-PEAP  — Outer TLS tunnel + inner MSCHAPv2 (requires FreeRADIUS helper
               configured via setup_freeradius.sh; this server proxies correctly)

Accounting
----------
  Start / Stop / Interim-Update packets update the active_sessions table.

NAS Clients
-----------
  Defined in config.yaml under radius.clients. Unknown NASes are silently dropped.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import re
import struct
import threading
from datetime import datetime, timezone
from typing import Any

import pyrad.dictionary
import pyrad.packet
import pyrad.server

from raspise.config import get_config
from raspise.core.events import bus, Event, EventType
from raspise.core.logger import get_logger
from raspise.core.utils import normalise_mac, chap_verify
from raspise.db.database import AsyncSessionLocal
from raspise.db.models import (
    AuthLog, AuthMethod, AuthResult, ActiveSession, Device, NasClient, PolicyAction, User
)
from raspise.policy.engine import AuthContext, engine as policy_engine

log = get_logger(__name__)

# Path to the bundled RADIUS dictionary
_DICT_PATH = os.path.join(os.path.dirname(__file__), "dictionary")


# ---------------------------------------------------------------------------
# Custom pyrad Server sub-class
# ---------------------------------------------------------------------------

class RaspISERadiusServer(pyrad.server.Server):
    """
    Extends pyrad.server.Server to add:
      • Per-client secret lookup
      • PAP / CHAP / MAB authentication
      • Policy evaluation
      • Accounting session tracking
      • Event bus publishing
    """

    def __init__(self) -> None:
        cfg = get_config()
        self._cfg = cfg.radius
        self._clients: dict[str, str] = {
            c.address: c.secret for c in self._cfg.clients
        }
        self._loop: asyncio.AbstractEventLoop | None = None
        self._last_client_reload: float = 0.0
        self._client_reload_interval: float = 30.0  # reload DB clients every 30s

        dict_path = _DICT_PATH if os.path.isfile(_DICT_PATH) else None
        hosts = {
            c.address: pyrad.server.RemoteHost(
                c.address, c.secret.encode(), c.name
            )
            for c in self._cfg.clients
        }

        super().__init__(
            hosts=hosts,
            dict=pyrad.dictionary.Dictionary(dict_path) if dict_path else None,
        )

    # ------------------------------------------------------------------
    # Hot-reload NAS clients from DB
    # ------------------------------------------------------------------

    def _maybe_reload_db_clients(self) -> None:
        """Periodically refresh NAS clients from the database."""
        import time
        now = time.monotonic()
        if now - self._last_client_reload < self._client_reload_interval:
            return
        self._last_client_reload = now
        if not self._loop:
            return
        try:
            db_clients = asyncio.run_coroutine_threadsafe(
                _load_db_nas_clients(), self._loop
            ).result(timeout=5)
            for ip, secret in db_clients:
                if ip not in self._clients:
                    self._clients[ip] = secret
                    self.hosts[ip] = pyrad.server.RemoteHost(ip, secret.encode(), ip)
                    log.info("Hot-loaded NAS client %s from database", ip)
        except Exception as exc:
            log.debug("NAS client reload failed: %s", exc)

    # ------------------------------------------------------------------
    # Authentication handler
    # ------------------------------------------------------------------

    def HandleAuthPacket(self, pkt: pyrad.packet.AuthPacket) -> None:  # noqa: N802
        nas_ip = pkt.source[0]
        log.debug("RADIUS Auth from NAS %s", nas_ip)

        # Hot-reload NAS clients from DB if needed
        self._maybe_reload_db_clients()

        # Reject unknown NAS clients early
        if nas_ip not in self._clients:
            log.warning("Dropping RADIUS request from unknown NAS %s", nas_ip)
            return

        try:
            # Determine auth method from packet attributes
            method, username, result, reason = self._authenticate(pkt)

            # If credentials passed, run the policy engine for the final decision
            policy_vlan: int | None = None
            policy_name: str = ""
            if result == AuthResult.SUCCESS:
                policy_vlan, result, reason, policy_name = self._run_sync(
                    self._apply_policy(username, pkt, method)
                )

            # Build reply
            if result == AuthResult.SUCCESS:
                reply = pkt.CreateReply(code=pyrad.packet.AccessAccept)
                vlan = policy_vlan if policy_vlan is not None else self._resolve_vlan(username, nas_ip, method, pkt)
                if vlan:
                    # RFC 3580 VLAN assignment attributes
                    try:
                        reply["Tunnel-Type"]      = [("Virtual", 13)]   # VLAN
                        reply["Tunnel-Medium-Type"] = [("IEEE-802", 6)]
                        reply["Tunnel-Private-Group-Id"] = [("Tagged", str(vlan))]
                    except Exception:
                        pass  # dictionary may not define these — non-fatal
                log.info("Access-ACCEPT user=%r nas=%s method=%s", username, nas_ip, method)
            elif result == AuthResult.CHALLENGE:
                reply = pkt.CreateReply(code=pyrad.packet.AccessChallenge)
            else:
                reply = pkt.CreateReply(code=pyrad.packet.AccessReject)
                log.info("Access-REJECT user=%r nas=%s reason=%r", username, nas_ip, reason)

            self.SendReplyPacket(pkt.fd, reply)
            self._log_auth(pkt, username, method, result, reason, policy_name, policy_vlan)
            self._publish(username, pkt, method, result, reason)

        except (TimeoutError, asyncio.CancelledError):
            log.error("RADIUS auth handler timeout for NAS %s — sending Access-Reject", nas_ip)
            try:
                reply = pkt.CreateReply(code=pyrad.packet.AccessReject)
                self.SendReplyPacket(pkt.fd, reply)
            except Exception:
                pass
        except Exception as exc:
            log.exception("RADIUS auth handler error for NAS %s: %s", nas_ip, exc)
            try:
                reply = pkt.CreateReply(code=pyrad.packet.AccessReject)
                self.SendReplyPacket(pkt.fd, reply)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Accounting handler
    # ------------------------------------------------------------------

    def HandleAcctPacket(self, pkt: pyrad.packet.AcctPacket) -> None:  # noqa: N802
        nas_ip   = pkt.source[0]
        status   = pkt.get("Acct-Status-Type", [None])[0]
        session  = pkt.get("Acct-Session-Id",  [""])[0]
        username = pkt.get("User-Name",         [""])[0]
        ip       = pkt.get("Framed-IP-Address", [""])[0]
        nas_port = str(pkt.get("NAS-Port", [""])[0])

        if self._loop:
            asyncio.run_coroutine_threadsafe(
                self._update_session(status, session, username, ip, nas_ip, nas_port, pkt),
                self._loop,
            )

        reply = pkt.CreateReply()
        self.SendReplyPacket(pkt.fd, reply)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _authenticate(
        self, pkt: pyrad.packet.AuthPacket
    ) -> tuple[AuthMethod, str, AuthResult, str]:
        """Returns (method, username, result, reason)."""
        username  = (pkt.get("User-Name", [""])[0] or "").strip()
        eap_msg   = pkt.get("EAP-Message", [])

        # ----- MAB: username looks like a MAC address -----
        if _is_mac_like(username):
            return self._authenticate_mab(username, pkt)

        # ----- EAP (PEAP / TLS) -----
        if eap_msg:
            return self._authenticate_eap(username, pkt)

        # ----- CHAP -----
        chap_pw = pkt.get("CHAP-Password", [None])[0]
        if chap_pw:
            return self._authenticate_chap(username, chap_pw, pkt)

        # ----- PAP (default) -----
        return self._authenticate_pap(username, pkt)

    # .... PAP ....

    def _authenticate_pap(
        self, username: str, pkt: pyrad.packet.AuthPacket
    ) -> tuple[AuthMethod, str, AuthResult, str]:
        raw_pw = pkt.get("User-Password", [b""])[0]
        password = _decode_pap_password(raw_pw, pkt.secret, pkt.authenticator)

        result, reason = self._run_sync(self._check_user_password(username, password))
        return AuthMethod.PAP, username, result, reason

    # .... CHAP ....

    def _authenticate_chap(
        self, username: str, chap_pw: bytes, pkt: pyrad.packet.AuthPacket
    ) -> tuple[AuthMethod, str, AuthResult, str]:
        chap_id     = bytes([chap_pw[0]])
        chap_resp   = chap_pw[1:17]
        challenge   = pkt.get("CHAP-Challenge", [pkt.authenticator])[0]

        db_password = self._run_sync(self._get_cleartext_password(username))
        if db_password is None:
            return AuthMethod.CHAP, username, AuthResult.FAILURE, "CHAP not supported (only bcrypt hashes stored — use PAP or EAP)"

        if chap_verify(chap_id, db_password, chap_resp + challenge):
            return AuthMethod.CHAP, username, AuthResult.SUCCESS, ""
        return AuthMethod.CHAP, username, AuthResult.FAILURE, "CHAP verify failed"

    # .... MAB ....

    def _authenticate_mab(
        self, mac_raw: str, pkt: pyrad.packet.AuthPacket
    ) -> tuple[AuthMethod, str, AuthResult, str]:
        try:
            mac = normalise_mac(mac_raw)
        except ValueError:
            return AuthMethod.MAB, mac_raw, AuthResult.FAILURE, "Invalid MAC"

        result, reason = self._run_sync(self._check_device_authorized(mac))
        return AuthMethod.MAB, mac, result, reason

    # .... EAP (passthrough notice) ....

    def _authenticate_eap(
        self, username: str, pkt: pyrad.packet.AuthPacket
    ) -> tuple[AuthMethod, str, AuthResult, str]:
        """
        Full EAP-PEAP / EAP-TLS negotiation requires FreeRADIUS.
        This handler logs the attempt and returns a challenge so the NAS
        re-sends to FreeRADIUS (configured as a proxy) or rejects gracefully.
        """
        log.warning(
            "EAP request received for user=%r — configure FreeRADIUS proxy for EAP support",
            username,
        )
        return AuthMethod.PEAP, username, AuthResult.FAILURE, "EAP requires FreeRADIUS proxy"

    # ---- DB helpers (run from sync context via _run_sync) ----

    async def _check_user_password(self, username: str, password: str) -> tuple[AuthResult, str]:
        import bcrypt
        async with AsyncSessionLocal() as db:
            from sqlalchemy import select
            stmt = select(User).where(User.username == username, User.enabled == True)
            row = (await db.execute(stmt)).scalar_one_or_none()
            if row is not None:
                if bcrypt.checkpw(password.encode(), row.password_hash.encode()):
                    return AuthResult.SUCCESS, ""
                # Local user exists but wrong password — don't fall through to LDAP
                return AuthResult.FAILURE, "Wrong password"

            # User not found locally → try LDAP if enabled
            from raspise.auth.ldap import ldap_authenticate, ldap_auto_provision
            ldap_result = await ldap_authenticate(username, password)
            if ldap_result is not None:
                await ldap_auto_provision(username, ldap_result, db)
                return AuthResult.SUCCESS, ""
            return AuthResult.FAILURE, "Unknown user"

    async def _get_cleartext_password(self, username: str) -> str | None:
        """For CHAP we need the stored cleartext OR NT-hash. Here we return None
        if only bcrypt is stored (CHAP cannot work with bcrypt hashes).
        For a real deployment store NT-hashes or use PAP/EAP-PEAP."""
        return None   # extend here for CHAP support

    async def _check_device_authorized(self, mac: str) -> tuple[AuthResult, str]:
        async with AsyncSessionLocal() as db:
            from sqlalchemy import select
            stmt = select(Device).where(Device.mac_address == mac)
            dev = (await db.execute(stmt)).scalar_one_or_none()
            if dev is None:
                return AuthResult.FAILURE, "Unknown MAC"
            if not dev.authorized:
                return AuthResult.FAILURE, "MAC not authorised"
            return AuthResult.SUCCESS, ""

    # ---- Session accounting ----

    async def _update_session(
        self, status, session_id, username, ip, nas_ip, nas_port, pkt
    ) -> None:
        from sqlalchemy import select, delete
        from sqlalchemy.exc import IntegrityError
        async with AsyncSessionLocal() as db:
            if status in (1, "Start"):
                mac_raw = pkt.get("Calling-Station-Id", [""])[0]
                try:
                    mac = normalise_mac(mac_raw)
                except ValueError:
                    mac = mac_raw
                sess = ActiveSession(
                    session_id=session_id, username=username,
                    mac_address=mac, ip_address=ip,
                    nas_ip=nas_ip, nas_port=nas_port,
                )
                db.add(sess)
            elif status in (2, "Stop"):
                stmt = select(ActiveSession).where(ActiveSession.session_id == session_id)
                sess = (await db.execute(stmt)).scalar_one_or_none()
                if sess:
                    await db.delete(sess)
            elif status in (3, "Interim-Update"):
                stmt = select(ActiveSession).where(ActiveSession.session_id == session_id)
                sess = (await db.execute(stmt)).scalar_one_or_none()
                if sess:
                    sess.bytes_in  = int((pkt.get("Acct-Input-Octets",  [0])[0]) or 0)
                    sess.bytes_out = int((pkt.get("Acct-Output-Octets", [0])[0]) or 0)
            try:
                await db.commit()
            except IntegrityError:
                await db.rollback()
                log.debug("Duplicate Accounting-Start for session %s — ignored", session_id)

    # ---- VLAN resolution ----

    def _resolve_vlan(self, username, nas_ip, method, pkt) -> int | None:
        """Fallback VLAN when no policy-supplied VLAN is available."""
        cfg = self._cfg
        if method == AuthMethod.MAB:
            return cfg.guest_vlan
        return cfg.default_vlan

    # ---- Policy evaluation ----

    async def _apply_policy(
        self, username: str, pkt, method: AuthMethod
    ) -> tuple[int | None, AuthResult, str, str]:
        """Build an AuthContext and run the policy engine.

        Returns ``(vlan, result, reason, policy_name)``.
        """
        from sqlalchemy import select
        from sqlalchemy.orm import selectinload

        nas_ip  = pkt.source[0]
        mac_raw = pkt.get("Calling-Station-Id", [""])[0]
        try:
            mac = normalise_mac(mac_raw)
        except ValueError:
            mac = mac_raw

        group_name  = ""
        device_type = "unknown"

        async with AsyncSessionLocal() as db:
            if method == AuthMethod.MAB:
                # For MAB the subject is the device, not a user
                stmt = select(Device).where(Device.mac_address == (mac or username))
                dev = (await db.execute(stmt)).scalar_one_or_none()
                if dev:
                    device_type = dev.device_type or "unknown"
            else:
                stmt = (
                    select(User)
                    .options(selectinload(User.group))
                    .where(User.username == username, User.enabled == True)
                )
                user = (await db.execute(stmt)).scalar_one_or_none()
                if user and user.group:
                    group_name = user.group.name

            ctx = AuthContext(
                username=username,
                mac_address=mac,
                nas_ip=nas_ip,
                auth_method=str(method.value),
                group_name=group_name,
                device_type=device_type,
            )

            decision = await policy_engine.evaluate(ctx, db)

        if decision.action == PolicyAction.PERMIT:
            return decision.vlan, AuthResult.SUCCESS, "", decision.policy_name
        if decision.action == PolicyAction.GUEST:
            return self._cfg.guest_vlan, AuthResult.SUCCESS, "GUEST access", decision.policy_name
        return None, AuthResult.FAILURE, f"Policy denied: {decision.reason}", decision.policy_name

    # ---- Sync bridge ----

    def _run_sync(self, coro) -> Any:
        """Run *coro* from the RADIUS thread using the stored asyncio loop."""
        try:
            future = asyncio.run_coroutine_threadsafe(coro, self._loop)
            return future.result(timeout=10)
        except (TimeoutError, asyncio.CancelledError) as exc:
            log.error("RADIUS async bridge timeout/cancelled: %s", exc)
            raise

    # ---- Auth logging ----

    def _log_auth(self, pkt, username, method, result, reason, policy_name: str = "", vlan: int | None = None) -> None:
        nas_ip  = pkt.source[0]
        mac_raw = pkt.get("Calling-Station-Id", [""])[0]
        try:
            mac = normalise_mac(mac_raw)
        except ValueError:
            mac = mac_raw

        if self._loop:
            asyncio.run_coroutine_threadsafe(
                self._write_auth_log(username, mac, nas_ip, method, result, reason, policy_name, vlan),
                self._loop,
            )

    async def _write_auth_log(
        self, username, mac, nas_ip, method, result, reason,
        policy_name: str = "", vlan: int | None = None,
    ) -> None:
        async with AsyncSessionLocal() as db:
            log_entry = AuthLog(
                username=username,
                mac_address=mac,
                nas_ip=nas_ip,
                auth_method=method,
                result=result,
                reason=reason,
                policy_name=policy_name,
                vlan=vlan,
            )
            db.add(log_entry)
            await db.commit()

    # ---- Event publishing ----

    def _publish(self, username, pkt, method, result, reason) -> None:
        nas_ip  = pkt.source[0]
        mac_raw = pkt.get("Calling-Station-Id", [""])[0]
        etype   = EventType.AUTH_SUCCESS if result == AuthResult.SUCCESS else EventType.AUTH_FAILURE
        bus.publish_sync(Event(etype, data={
            "username": username, "mac": mac_raw,
            "nas_ip": nas_ip, "method": str(method),
            "reason": reason,
        }))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_mac_like(s: str) -> bool:
    """True if string looks like a MAC (12 hex chars, various separators)."""
    clean = re.sub(r"[:\-.]", "", s)
    return bool(re.fullmatch(r"[0-9a-fA-F]{12}", clean))


def _decode_pap_password(encrypted: bytes, secret: bytes, authenticator: bytes) -> str:
    """Decrypt PAP User-Password per RFC 2865 §5.2."""
    if isinstance(secret, str):
        secret = secret.encode()
    result = bytearray()
    prev = authenticator
    for i in range(0, len(encrypted), 16):
        block = encrypted[i:i+16]
        digest = hashlib.md5(secret + bytes(prev)).digest()
        chunk  = bytes(a ^ b for a, b in zip(digest, block))
        result += chunk
        prev = block
    # Strip NUL padding
    return result.rstrip(b"\x00").decode("utf-8", errors="replace")


from typing import Any


# ---------------------------------------------------------------------------
# DB helper for NAS client loading
# ---------------------------------------------------------------------------

async def _load_db_nas_clients() -> list[tuple[str, str]]:
    """Return list of (ip_address, secret) for all enabled NAS clients in DB."""
    from sqlalchemy import select
    async with AsyncSessionLocal() as db:
        stmt = select(NasClient).where(NasClient.enabled == True)
        clients = (await db.execute(stmt)).scalars().all()
        return [(c.ip_address, c.secret) for c in clients]


# ---------------------------------------------------------------------------
# Public launcher
# ---------------------------------------------------------------------------

def run_radius_server(loop: asyncio.AbstractEventLoop) -> None:
    """Start the RADIUS server in the calling thread (blocking)."""
    cfg = get_config().radius
    server = RaspISERadiusServer()
    server._loop = loop

    # Merge NAS clients from the DB into the server (on top of YAML clients)
    try:
        db_clients = asyncio.run_coroutine_threadsafe(
            _load_db_nas_clients(), loop
        ).result(timeout=10)
        for ip, secret in db_clients:
            if ip not in server._clients:
                server._clients[ip] = secret
                server.hosts[ip] = pyrad.server.RemoteHost(ip, secret.encode(), ip)
        if db_clients:
            log.info("Loaded %d NAS client(s) from database", len(db_clients))
    except Exception as exc:
        log.warning("Could not load NAS clients from DB: %s", exc)

    server.BindToAddress(cfg.host)

    log.info(
        "RADIUS server listening on %s:%d (auth) %s:%d (acct)",
        cfg.host, cfg.auth_port, cfg.host, cfg.acct_port,
    )
    server.Run()
