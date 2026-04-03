"""
RaspISE TACACS+ Server
======================
Pure-Python TACACS+ server implementing RFC 8907.

Packet types supported
-----------------------
  0x01  Authentication  START → REPLY
  0x02  Authorization   REQUEST → RESPONSE
  0x03  Accounting      REQUEST → REPLY

Encryption
----------
  Body XOR with MD5(key || session_id || version || seq_no) pseudo-pad,
  extended in 16-byte blocks.

Authentication methods supported
---------------------------------
  ASCII  — password delivered in CONTINUE packet (typical CLI login)
  PAP    — password in START packet data field
  CHAP   — challenge/response (limited; see _chap_verify)
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import struct
from dataclasses import dataclass
from typing import Any

from raspise.config import get_config
from raspise.core.events import bus, Event, EventType
from raspise.core.logger import get_logger
from raspise.db.database import AsyncSessionLocal
from raspise.db.models import TacacsLog, TacacsPacketType, PolicyAction, User
from raspise.policy.engine import AuthContext, engine as policy_engine

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# TACACS+ Protocol Constants  (RFC 8907)
# ---------------------------------------------------------------------------

TAC_PLUS_MAJOR_VER   = 0xC
TAC_PLUS_MINOR_VER_1 = 0x1
TAC_PLUS_VER         = (TAC_PLUS_MAJOR_VER << 4) | TAC_PLUS_MINOR_VER_1  # 0xC1

TAC_PLUS_AUTHEN  = 0x01
TAC_PLUS_AUTHOR  = 0x02
TAC_PLUS_ACCT    = 0x03

TAC_PLUS_UNENCRYPTED_FLAG = 0x04
TAC_PLUS_SINGLE_CONNECT   = 0x04

# Authentication status
TAC_PLUS_AUTHEN_STATUS_PASS    = 0x01
TAC_PLUS_AUTHEN_STATUS_FAIL    = 0x02
TAC_PLUS_AUTHEN_STATUS_GETDATA = 0x03
TAC_PLUS_AUTHEN_STATUS_GETUSER = 0x04
TAC_PLUS_AUTHEN_STATUS_GETPASS = 0x05
TAC_PLUS_AUTHEN_STATUS_RESTART = 0x06
TAC_PLUS_AUTHEN_STATUS_ERROR   = 0x07
TAC_PLUS_AUTHEN_STATUS_FOLLOW  = 0x21

# Authentication action
TAC_PLUS_AUTHEN_LOGIN  = 0x01
TAC_PLUS_AUTHEN_CHPASS = 0x02
TAC_PLUS_AUTHEN_SENDPASS = 0x03
TAC_PLUS_AUTHEN_SENDAUTH = 0x04

# Authentication type
TAC_PLUS_AUTHEN_TYPE_ASCII = 0x01
TAC_PLUS_AUTHEN_TYPE_PAP   = 0x02
TAC_PLUS_AUTHEN_TYPE_CHAP  = 0x03
TAC_PLUS_AUTHEN_TYPE_MSCHAP = 0x05

# Authorization status
TAC_PLUS_AUTHOR_STATUS_PASS_ADD  = 0x01
TAC_PLUS_AUTHOR_STATUS_PASS_REPL = 0x02
TAC_PLUS_AUTHOR_STATUS_FAIL      = 0x10
TAC_PLUS_AUTHOR_STATUS_ERROR     = 0x11

# Accounting
TAC_PLUS_ACCT_STATUS_SUCCESS = 0x01
TAC_PLUS_ACCT_STATUS_ERROR   = 0x02
TAC_PLUS_ACCT_FLAG_START     = 0x02
TAC_PLUS_ACCT_FLAG_STOP      = 0x04
TAC_PLUS_ACCT_FLAG_WATCHDOG  = 0x08

HEADER_LEN = 12


# ---------------------------------------------------------------------------
# Packet encode / decode
# ---------------------------------------------------------------------------

def _md5_pad(key: bytes, session_id: int, version: int, seq_no: int, length: int) -> bytes:
    """Build the pseudo-random pad for body encryption (RFC 8907 §4.5)."""
    pad = b""
    prev = b""
    sid  = struct.pack("!I", session_id)
    while len(pad) < length:
        prev = hashlib.md5(key + sid + bytes([version, seq_no]) + prev).digest()
        pad += prev
    return pad[:length]


def _crypt(body: bytes, key: bytes, session_id: int, version: int, seq_no: int) -> bytes:
    pad = _md5_pad(key, session_id, version, seq_no, len(body))
    return bytes(a ^ b for a, b in zip(body, pad))


@dataclass
class TacacsHeader:
    version:    int
    pkt_type:   int
    seq_no:     int
    flags:      int
    session_id: int
    length:     int

    @classmethod
    def decode(cls, raw: bytes) -> "TacacsHeader":
        version, pkt_type, seq_no, flags = struct.unpack("!BBBB", raw[0:4])
        session_id, length = struct.unpack("!II", raw[4:12])
        return cls(version, pkt_type, seq_no, flags, session_id, length)

    def encode(self) -> bytes:
        return struct.pack(
            "!BBBBII",
            self.version, self.pkt_type, self.seq_no,
            self.flags, self.session_id, self.length,
        )


def _parse_av_pairs(data: bytes) -> list[str]:
    """Parse length-prefixed AV-pair list."""
    pairs: list[str] = []
    offset = 0
    while offset < len(data):
        ln = data[offset]
        offset += 1
        if offset + ln > len(data):
            break  # truncated pair — stop parsing
        pairs.append(data[offset:offset + ln].decode("utf-8", errors="replace"))
        offset += ln
    return pairs


def _encode_av_pairs(pairs: list[str]) -> bytes:
    buf = bytearray()
    for p in pairs:
        enc = p.encode()
        buf.append(len(enc))
        buf.extend(enc)
    return bytes(buf)


# ---------------------------------------------------------------------------
# Per-connection session handler
# ---------------------------------------------------------------------------

class TacacsSession:
    """Handles one TCP connection (one or more TACACS+ packets)."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        key: bytes,
        allowed_clients: set[str],
    ) -> None:
        self._reader   = reader
        self._writer   = writer
        self._key      = key
        self._allowed  = allowed_clients
        self._peer_ip  = writer.get_extra_info("peername", ("?", 0))[0]
        # Per-connection ASCII auth state for multi-round exchanges
        self._ascii_state: dict = {}

    async def handle(self) -> None:
        if self._allowed and self._peer_ip not in self._allowed:
            log.warning("TACACS+ connection from unauthorised host %s — closing", self._peer_ip)
            self._writer.close()
            return

        try:
            while True:
                await self._handle_one_packet()
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        except Exception as exc:
            log.exception("TACACS+ session error: %s", exc)
        finally:
            self._writer.close()

    async def _handle_one_packet(self) -> None:
        raw_hdr = await self._reader.readexactly(HEADER_LEN)
        hdr     = TacacsHeader.decode(raw_hdr)
        raw_body = await self._reader.readexactly(hdr.length)

        # Decrypt unless UNENCRYPTED flag is set (should not happen in prod)
        if not (hdr.flags & TAC_PLUS_UNENCRYPTED_FLAG):
            body = _crypt(raw_body, self._key, hdr.session_id, hdr.version, hdr.seq_no)
        else:
            body = raw_body

        if hdr.pkt_type == TAC_PLUS_AUTHEN:
            await self._handle_authen(hdr, body)
        elif hdr.pkt_type == TAC_PLUS_AUTHOR:
            await self._handle_author(hdr, body)
        elif hdr.pkt_type == TAC_PLUS_ACCT:
            await self._handle_acct(hdr, body)
        else:
            log.warning("Unknown TACACS+ packet type 0x%02x from %s", hdr.pkt_type, self._peer_ip)

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    async def _handle_authen(self, hdr: TacacsHeader, body: bytes) -> None:
        if hdr.seq_no == 1:
            await self._handle_authen_start(hdr, body)
        else:
            # CONTINUE packets in a multi-round exchange (ASCII login)
            await self._handle_authen_continue(hdr, body)

    async def _handle_authen_start(self, hdr: TacacsHeader, body: bytes) -> None:
        if len(body) < 8:
            await self._send_authen_reply(hdr, TAC_PLUS_AUTHEN_STATUS_ERROR, "Bad packet")
            return

        action, priv_lvl, authen_type, authen_svc = struct.unpack("!BBBB", body[0:4])
        user_len, port_len, rem_addr_len, data_len = struct.unpack("!BBBB", body[4:8])

        expected = 8 + user_len + port_len + rem_addr_len + data_len
        if expected > len(body):
            log.warning("TACACS+ AUTHEN START: body too short (need %d, got %d) from %s", expected, len(body), self._peer_ip)
            await self._send_authen_reply(hdr, TAC_PLUS_AUTHEN_STATUS_ERROR, "Malformed packet")
            return

        offset = 8
        username  = body[offset:offset + user_len].decode("utf-8", errors="replace"); offset += user_len
        port      = body[offset:offset + port_len].decode("utf-8", errors="replace"); offset += port_len
        rem_addr  = body[offset:offset + rem_addr_len].decode("utf-8", errors="replace"); offset += rem_addr_len
        data      = body[offset:offset + data_len]; offset += data_len

        log.debug("TACACS+ AUTHEN START user=%r type=0x%02x from %s", username, authen_type, self._peer_ip)

        if authen_type == TAC_PLUS_AUTHEN_TYPE_PAP:
            password = data.decode("utf-8", errors="replace")
            if await _verify_user(username, password):
                await self._log_tacacs(TacacsPacketType.AUTHEN, username, rem_addr, "LOGIN", "PASS")
                await self._send_authen_reply(hdr, TAC_PLUS_AUTHEN_STATUS_PASS, "Authentication successful")
            else:
                await self._log_tacacs(TacacsPacketType.AUTHEN, username, rem_addr, "LOGIN", "FAIL")
                await self._send_authen_reply(hdr, TAC_PLUS_AUTHEN_STATUS_FAIL, "Authentication failed")

        elif authen_type == TAC_PLUS_AUTHEN_TYPE_ASCII:
            # Reset any prior ASCII state for this connection
            if not username:
                # Ask for username first
                self._ascii_state = {"step": "getuser", "rem": rem_addr}
                await self._send_authen_reply(
                    hdr, TAC_PLUS_AUTHEN_STATUS_GETUSER, "Username: ", no_echo=False
                )
            else:
                # Username already present in START — ask for password
                self._ascii_state = {"step": "getpass", "username": username, "rem": rem_addr}
                await self._send_authen_reply(
                    hdr, TAC_PLUS_AUTHEN_STATUS_GETPASS, "Password: ", no_echo=True
                )
        else:
            await self._send_authen_reply(hdr, TAC_PLUS_AUTHEN_STATUS_ERROR, "Unsupported auth type")

    async def _handle_authen_continue(self, hdr: TacacsHeader, body: bytes) -> None:
        """Handle ASCII multi-round CONTINUE packets (RFC 8907 §4.3)."""
        # CONTINUE body: user_msg_len (2B), data_len (2B), flags (1B), user_msg, data
        if len(body) < 5:
            await self._send_authen_reply(hdr, TAC_PLUS_AUTHEN_STATUS_FAIL, "Bad CONTINUE packet")
            return

        user_msg_len, data_len = struct.unpack("!HH", body[0:4])
        if 5 + user_msg_len + data_len > len(body):
            log.warning("TACACS+ CONTINUE: body too short from %s", self._peer_ip)
            await self._send_authen_reply(hdr, TAC_PLUS_AUTHEN_STATUS_FAIL, "Malformed CONTINUE")
            return
        # flags = body[4]  (abort flag etc. — not checked here)
        offset   = 5
        user_msg = body[offset:offset + user_msg_len].decode("utf-8", errors="replace")

        state = self._ascii_state
        if not state:
            await self._send_authen_reply(hdr, TAC_PLUS_AUTHEN_STATUS_FAIL, "Unexpected CONTINUE")
            return

        if state.get("step") == "getuser":
            username = user_msg.strip()
            if not username:
                await self._send_authen_reply(hdr, TAC_PLUS_AUTHEN_STATUS_FAIL, "Empty username")
                self._ascii_state = {}
                return
            self._ascii_state = {"step": "getpass", "username": username, "rem": state.get("rem", "")}
            await self._send_authen_reply(hdr, TAC_PLUS_AUTHEN_STATUS_GETPASS, "Password: ", no_echo=True)

        elif state.get("step") == "getpass":
            username = state["username"]
            password = user_msg
            rem      = state.get("rem", "")
            self._ascii_state = {}   # clear state regardless of outcome

            if await _verify_user(username, password):
                await self._log_tacacs(TacacsPacketType.AUTHEN, username, rem, "LOGIN", "PASS")
                await self._send_authen_reply(hdr, TAC_PLUS_AUTHEN_STATUS_PASS, "Authentication successful")
            else:
                await self._log_tacacs(TacacsPacketType.AUTHEN, username, rem, "LOGIN", "FAIL")
                await self._send_authen_reply(hdr, TAC_PLUS_AUTHEN_STATUS_FAIL, "Authentication failed")

        else:
            self._ascii_state = {}
            await self._send_authen_reply(hdr, TAC_PLUS_AUTHEN_STATUS_FAIL, "Unknown auth state")

    async def _send_authen_reply(
        self,
        req_hdr: TacacsHeader,
        status: int,
        msg: str,
        *,
        no_echo: bool = False,
    ) -> None:
        msg_b   = msg.encode()
        flags   = 0x01 if no_echo else 0x00
        body    = struct.pack("!BBHH", status, flags, len(msg_b), 0) + msg_b
        await self._send_reply(req_hdr, TAC_PLUS_AUTHEN, body)

    # ------------------------------------------------------------------
    # Authorization
    # ------------------------------------------------------------------

    async def _handle_author(self, hdr: TacacsHeader, body: bytes) -> None:
        if len(body) < 8:
            await self._send_author_reply(hdr, TAC_PLUS_AUTHOR_STATUS_ERROR, [])
            return

        authen_method, priv_lvl, authen_type, authen_svc = struct.unpack("!BBBB", body[0:4])
        user_len, port_len, rem_addr_len, arg_cnt       = struct.unpack("!BBBB", body[4:8])

        offset = 8
        if offset + arg_cnt > len(body):
            log.warning("TACACS+ AUTHOR: body too short for arg lengths from %s", self._peer_ip)
            await self._send_author_reply(hdr, TAC_PLUS_AUTHOR_STATUS_ERROR, [])
            return
        arg_lengths = list(body[offset:offset + arg_cnt]); offset += arg_cnt
        expected = offset + user_len + port_len + rem_addr_len + sum(arg_lengths)
        if expected > len(body):
            log.warning("TACACS+ AUTHOR: body too short (need %d, got %d) from %s", expected, len(body), self._peer_ip)
            await self._send_author_reply(hdr, TAC_PLUS_AUTHOR_STATUS_ERROR, [])
            return
        username = body[offset:offset + user_len].decode("utf-8", errors="replace"); offset += user_len
        port     = body[offset:offset + port_len].decode("utf-8", errors="replace"); offset += port_len
        rem_addr = body[offset:offset + rem_addr_len].decode("utf-8", errors="replace"); offset += rem_addr_len

        args: list[str] = []
        for ln in arg_lengths:
            args.append(body[offset:offset + ln].decode("utf-8", errors="replace"))
            offset += ln

        log.debug("TACACS+ AUTHOR user=%r args=%r from %s", username, args, self._peer_ip)

        # Simple authorization: allow all commands for known users that have priv 15
        command = next((a.split("=", 1)[1] for a in args if a.startswith("cmd=")), "")
        allowed = await _is_user_authorized(username, priv_lvl, command, nas_ip=self._peer_ip)

        result_str = "PASS" if allowed else "FAIL"
        await self._log_tacacs(TacacsPacketType.AUTHOR, username, rem_addr, command, result_str, priv_lvl)

        if allowed:
            await self._send_author_reply(hdr, TAC_PLUS_AUTHOR_STATUS_PASS_ADD, args)
        else:
            await self._send_author_reply(hdr, TAC_PLUS_AUTHOR_STATUS_FAIL, [])

    async def _send_author_reply(
        self, req_hdr: TacacsHeader, status: int, av_pairs: list[str]
    ) -> None:
        av_data = _encode_av_pairs(av_pairs)
        body = struct.pack(
            "!BBHH",
            status, len(av_pairs),
            0,        # server_msg_len
            0,        # data_len
        ) + av_data
        await self._send_reply(req_hdr, TAC_PLUS_AUTHOR, body)

    # ------------------------------------------------------------------
    # Accounting
    # ------------------------------------------------------------------

    async def _handle_acct(self, hdr: TacacsHeader, body: bytes) -> None:
        if len(body) < 9:
            await self._send_acct_reply(hdr, TAC_PLUS_ACCT_STATUS_ERROR)
            return

        flags, authen_method, priv_lvl, authen_type, authen_svc = struct.unpack("!BBBBB", body[0:5])
        user_len, port_len, rem_addr_len, arg_cnt                = struct.unpack("!BBBB", body[5:9])

        offset = 9
        if offset + arg_cnt > len(body):
            log.warning("TACACS+ ACCT: body too short for arg lengths from %s", self._peer_ip)
            await self._send_acct_reply(hdr, TAC_PLUS_ACCT_STATUS_ERROR)
            return
        arg_lengths = list(body[offset:offset + arg_cnt]); offset += arg_cnt
        expected = offset + user_len + port_len + rem_addr_len + sum(arg_lengths)
        if expected > len(body):
            log.warning("TACACS+ ACCT: body too short (need %d, got %d) from %s", expected, len(body), self._peer_ip)
            await self._send_acct_reply(hdr, TAC_PLUS_ACCT_STATUS_ERROR)
            return
        username = body[offset:offset + user_len].decode("utf-8", errors="replace"); offset += user_len
        port     = body[offset:offset + port_len].decode("utf-8", errors="replace"); offset += port_len
        rem_addr = body[offset:offset + rem_addr_len].decode("utf-8", errors="replace"); offset += rem_addr_len

        args: list[str] = []
        for ln in arg_lengths:
            args.append(body[offset:offset + ln].decode("utf-8", errors="replace"))
            offset += ln

        command = next((a.split("=", 1)[1] for a in args if a.startswith("cmd=")), "")
        log.debug("TACACS+ ACCT user=%r flags=0x%02x cmd=%r", username, flags, command)
        await self._log_tacacs(TacacsPacketType.ACCTING, username, rem_addr, command, "LOGGED", priv_lvl)
        await self._send_acct_reply(hdr, TAC_PLUS_ACCT_STATUS_SUCCESS)

    async def _send_acct_reply(self, req_hdr: TacacsHeader, status: int) -> None:
        body = struct.pack("!HHB", 0, 0, status)   # server_msg_len=0, data_len=0, status
        await self._send_reply(req_hdr, TAC_PLUS_ACCT, body)

    # ------------------------------------------------------------------
    # Common send helper
    # ------------------------------------------------------------------

    async def _send_reply(self, req_hdr: TacacsHeader, pkt_type: int, body: bytes) -> None:
        seq_no = req_hdr.seq_no + 1
        flags  = 0                                    # encrypted
        encrypted_body = _crypt(body, self._key, req_hdr.session_id, req_hdr.version, seq_no)

        hdr = TacacsHeader(
            version    = req_hdr.version,
            pkt_type   = pkt_type,
            seq_no     = seq_no,
            flags      = flags,
            session_id = req_hdr.session_id,
            length     = len(encrypted_body),
        )
        self._writer.write(hdr.encode() + encrypted_body)
        await self._writer.drain()

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    async def _log_tacacs(
        self, pkt_type: TacacsPacketType, username: str,
        remote_ip: str, command: str, result: str,
        priv_lvl: int = 1,
    ) -> None:
        async with AsyncSessionLocal() as db:
            entry = TacacsLog(
                packet_type=pkt_type,
                username=username,
                remote_ip=remote_ip or self._peer_ip,
                command=command,
                privilege_level=priv_lvl,
                result=result,
            )
            db.add(entry)
            await db.commit()

        bus.publish_sync(Event(EventType.TACACS_AUTH, data={
            "username": username, "remote_ip": remote_ip or self._peer_ip,
            "command": command, "result": result,
        }))


# ---------------------------------------------------------------------------
# DB-backed auth helpers
# ---------------------------------------------------------------------------

async def _verify_user(username: str, password: str) -> bool:
    import bcrypt
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        stmt = select(User).where(User.username == username, User.enabled == True)
        user = (await db.execute(stmt)).scalar_one_or_none()
        if user is None:
            return False
        return bcrypt.checkpw(password.encode(), user.password_hash.encode())


async def _is_user_authorized(username: str, priv_lvl: int, command: str, nas_ip: str = "") -> bool:
    """
    Authorize a TACACS+ command request.

    1. Confirm the user exists and is enabled.
    2. Run the policy engine — the same policies that govern RADIUS also apply here.
    3. Fall back to group-based heuristic only when no policies match (DENY is default).
    """
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload
    async with AsyncSessionLocal() as db:
        stmt = (
            select(User)
            .options(selectinload(User.group))
            .where(User.username == username, User.enabled == True)
        )
        user = (await db.execute(stmt)).scalar_one_or_none()
        if user is None:
            return False

        group_name = user.group.name if user.group else ""

        ctx = AuthContext(
            username=username,
            nas_ip=nas_ip,
            auth_method="TACACS",
            group_name=group_name,
        )
        decision = await policy_engine.evaluate(ctx, db)

    if decision.action == PolicyAction.PERMIT:
        return True
    if decision.action == PolicyAction.DENY:
        return False
    # GUEST action — allow read-only show commands only
    return command.strip().lower().startswith("show")


# ---------------------------------------------------------------------------
# Server entry point
# ---------------------------------------------------------------------------

async def run_tacacs_server() -> None:
    cfg = get_config().tacacs
    default_key = cfg.key.encode()
    # Build per-client key map: IP → key bytes
    client_keys: dict[str, bytes] = {}
    for c in cfg.clients:
        client_keys[c.address] = c.key.encode()
    allowed = set(client_keys.keys()) if cfg.clients else set()

    async def _client_cb(reader, writer):
        peer_ip = writer.get_extra_info("peername", ("?", 0))[0]
        # Use per-client key if configured, otherwise fall back to global key
        key = client_keys.get(peer_ip, default_key)
        sess = TacacsSession(reader, writer, key, allowed)
        await sess.handle()

    server = await asyncio.start_server(_client_cb, cfg.host, cfg.port)
    log.info("TACACS+ server listening on %s:%d", cfg.host, cfg.port)
    async with server:
        await server.serve_forever()
