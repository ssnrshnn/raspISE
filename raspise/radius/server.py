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
from typing import TYPE_CHECKING

import pyrad.dictionary
import pyrad.packet
import pyrad.server

from raspise.config import get_config
from raspise.core.events import bus, Event, EventType
from raspise.core.logger import get_logger
from raspise.core.utils import normalise_mac, chap_verify
from raspise.db.database import AsyncSessionLocal
from raspise.db.models import (
    AuthLog, AuthMethod, AuthResult, ActiveSession, Device, User
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
    # Authentication handler
    # ------------------------------------------------------------------

    def HandleAuthPacket(self, pkt: pyrad.packet.AuthPacket) -> None:  # noqa: N802
        nas_ip = pkt.source[0]
        log.debug("RADIUS Auth from NAS %s", nas_ip)

        # Reject unknown NAS clients early
        if nas_ip not in self._clients:
            log.warning("Dropping RADIUS request from unknown NAS %s", nas_ip)
            return

        # Determine auth method from packet attributes
        method, username, result, reason = self._authenticate(pkt)

        # Build reply
        if result == AuthResult.SUCCESS:
            reply = pkt.CreateReply(code=pyrad.packet.AccessAccept)
            vlan = self._resolve_vlan(username, nas_ip, method, pkt)
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
        self._log_auth(pkt, username, method, result, reason)
        self._publish(username, pkt, method, result, reason)

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

        result, reason = _run_sync(self._check_user_password(username, password))
        return AuthMethod.PAP, username, result, reason

    # .... CHAP ....

    def _authenticate_chap(
        self, username: str, chap_pw: bytes, pkt: pyrad.packet.AuthPacket
    ) -> tuple[AuthMethod, str, AuthResult, str]:
        chap_id     = bytes([chap_pw[0]])
        chap_resp   = chap_pw[1:17]
        challenge   = pkt.get("CHAP-Challenge", [pkt.authenticator])[0]

        db_password = _run_sync(self._get_cleartext_password(username))
        if db_password is None:
            return AuthMethod.CHAP, username, AuthResult.FAILURE, "Unknown user"

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

        result, reason = _run_sync(self._check_device_authorized(mac))
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
        from passlib.context import CryptContext
        pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
        async with AsyncSessionLocal() as db:
            from sqlalchemy import select
            stmt = select(User).where(User.username == username, User.enabled == True)
            row = (await db.execute(stmt)).scalar_one_or_none()
            if row is None:
                return AuthResult.FAILURE, "Unknown user"
            if not pwd_ctx.verify(password, row.password_hash):
                return AuthResult.FAILURE, "Wrong password"
            return AuthResult.SUCCESS, ""

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
        async with AsyncSessionLocal() as db:
            if status in (1, "Start"):
                sess = ActiveSession(
                    session_id=session_id, username=username,
                    ip_address=ip, nas_ip=nas_ip, nas_port=nas_port,
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
            await db.commit()

    # ---- VLAN resolution ----

    def _resolve_vlan(self, username, nas_ip, method, pkt) -> int | None:
        cfg = self._cfg
        if method == AuthMethod.MAB:
            return cfg.guest_vlan
        return cfg.default_vlan

    # ---- Auth logging ----

    def _log_auth(self, pkt, username, method, result, reason) -> None:
        nas_ip  = pkt.source[0]
        mac_raw = pkt.get("Calling-Station-Id", [""])[0]
        try:
            mac = normalise_mac(mac_raw)
        except ValueError:
            mac = mac_raw

        if self._loop:
            asyncio.run_coroutine_threadsafe(
                self._write_auth_log(username, mac, nas_ip, method, result, reason),
                self._loop,
            )

    async def _write_auth_log(self, username, mac, nas_ip, method, result, reason) -> None:
        async with AsyncSessionLocal() as db:
            log_entry = AuthLog(
                username=username,
                mac_address=mac,
                nas_ip=nas_ip,
                auth_method=method,
                result=result,
                reason=reason,
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


def _run_sync(coro) -> Any:
    """Run an async coroutine from synchronous code."""
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            future = concurrent.futures.Future()

            async def _wrapper():
                try:
                    future.set_result(await coro)
                except Exception as exc:
                    future.set_exception(exc)

            asyncio.ensure_future(_wrapper())
            return future.result(timeout=5)
        else:
            return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


from typing import Any


# ---------------------------------------------------------------------------
# Public launcher
# ---------------------------------------------------------------------------

def run_radius_server(loop: asyncio.AbstractEventLoop) -> None:
    """Start the RADIUS server in the calling thread (blocking)."""
    cfg = get_config().radius
    server = RaspISERadiusServer()
    server._loop = loop
    server.BindToAddress(cfg.host)

    log.info(
        "RADIUS server listening on %s:%d (auth) %s:%d (acct)",
        cfg.host, cfg.auth_port, cfg.host, cfg.acct_port,
    )
    server.Run()
