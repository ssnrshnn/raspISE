"""
RADIUS Change of Authorization (CoA) & Disconnect
==================================================
Implements RFC 5176 Disconnect-Request packets.

The NAS (switch/AP) listens on UDP port 3799 (standard CoA port).
We send a Disconnect-Request containing Acct-Session-Id + User-Name
so the NAS can identify and terminate the session.
"""
from __future__ import annotations

import hashlib
import os
import struct
from typing import Any

from raspise.core.logger import get_logger

log = get_logger(__name__)

# RADIUS packet codes (RFC 5176)
DISCONNECT_REQUEST = 40
DISCONNECT_ACK     = 41
DISCONNECT_NAK     = 42
COA_REQUEST        = 43
COA_ACK            = 44
COA_NAK            = 45

# Standard CoA/DM port
COA_PORT = 3799

# Common attribute type numbers (RFC 2865 / 5176)
ATTR_USER_NAME       = 1
ATTR_NAS_IP_ADDRESS  = 4
ATTR_ACCT_SESSION_ID = 44
ATTR_EVENT_TIMESTAMP = 55
ATTR_NAS_PORT        = 5


def _encode_attribute(attr_type: int, value: bytes) -> bytes:
    """Encode a single RADIUS attribute as type-length-value."""
    length = 2 + len(value)
    return struct.pack("!BB", attr_type, length) + value


def _build_disconnect_request(
    session_id: str,
    nas_ip: str,
    username: str = "",
    secret: str = "",
) -> bytes:
    """Build a raw RADIUS Disconnect-Request packet (code 40).

    Returns the complete UDP payload ready to send to the NAS on port 3799.
    """
    # Build attribute list
    attrs = bytearray()
    attrs += _encode_attribute(ATTR_ACCT_SESSION_ID, session_id.encode("ascii"))

    if nas_ip:
        import socket
        try:
            packed_ip = socket.inet_aton(nas_ip)
            attrs += _encode_attribute(ATTR_NAS_IP_ADDRESS, packed_ip)
        except OSError:
            pass

    if username:
        attrs += _encode_attribute(ATTR_USER_NAME, username.encode("utf-8"))

    # Packet: code(1) + identifier(1) + length(2) + authenticator(16) + attributes
    identifier = os.urandom(1)[0]
    length = 20 + len(attrs)

    # First pass: authenticator = 16 zero bytes for MD5 calculation
    header = struct.pack("!BBH", DISCONNECT_REQUEST, identifier, length)
    zero_auth = b"\x00" * 16
    raw = header + zero_auth + bytes(attrs)

    # Authenticator = MD5(packet with zero auth + secret)
    authenticator = hashlib.md5(raw + secret.encode("utf-8")).digest()

    # Reassemble with real authenticator
    return header + authenticator + bytes(attrs)


async def send_disconnect_request(
    nas_ip: str,
    session_id: str,
    username: str = "",
    secret: str = "",
    port: int = COA_PORT,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Send a RADIUS Disconnect-Request to a NAS and wait for the response.

    Returns a dict with:
      - ``success``: True if Disconnect-ACK received
      - ``code``: response packet code (41=ACK, 42=NAK) or 0 on timeout
      - ``message``: human-readable result description
    """
    import asyncio
    import socket

    packet = _build_disconnect_request(session_id, nas_ip, username, secret)

    loop = asyncio.get_running_loop()

    # Create a one-shot UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)

    try:
        await loop.sock_sendto(sock, packet, (nas_ip, port))
        log.info(
            "Disconnect-Request sent to NAS %s:%d session=%s user=%s",
            nas_ip, port, session_id, username,
        )

        # Wait for response with timeout
        try:
            data = await asyncio.wait_for(
                loop.sock_recv(sock, 4096),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            log.warning("Disconnect-Request to %s timed out after %.1fs", nas_ip, timeout)
            return {"success": False, "code": 0, "message": f"Timeout — NAS {nas_ip} did not respond"}

        if len(data) < 20:
            return {"success": False, "code": 0, "message": "Invalid response (too short)"}

        resp_code = data[0]
        if resp_code == DISCONNECT_ACK:
            log.info("Disconnect-ACK from NAS %s for session %s", nas_ip, session_id)
            return {"success": True, "code": DISCONNECT_ACK, "message": "Session disconnected successfully"}
        elif resp_code == DISCONNECT_NAK:
            log.warning("Disconnect-NAK from NAS %s for session %s", nas_ip, session_id)
            return {"success": False, "code": DISCONNECT_NAK, "message": "NAS rejected disconnect request"}
        else:
            log.warning("Unexpected RADIUS response code %d from NAS %s", resp_code, nas_ip)
            return {"success": False, "code": resp_code, "message": f"Unexpected response code {resp_code}"}

    except OSError as exc:
        log.error("Failed to send Disconnect-Request to %s: %s", nas_ip, exc)
        return {"success": False, "code": 0, "message": f"Network error: {exc}"}
    finally:
        sock.close()


async def disconnect_session(
    session_id: str,
    nas_ip: str,
    acct_session_id: str,
    username: str,
    nas_secret: str,
) -> dict[str, Any]:
    """High-level helper: look up the NAS secret and send Disconnect-Request."""
    if not nas_secret:
        return {
            "success": False, "code": 0,
            "message": f"No shared secret found for NAS {nas_ip} — cannot send CoA",
        }

    return await send_disconnect_request(
        nas_ip=nas_ip,
        session_id=acct_session_id,
        username=username,
        secret=nas_secret,
    )
