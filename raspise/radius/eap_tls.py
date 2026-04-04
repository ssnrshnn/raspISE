"""
EAP-TLS state machine for RADIUS
=================================
Implements EAP-TLS (RFC 5216) certificate-based authentication inside
RADIUS Access-Request / Access-Challenge exchanges.

How it works
------------
1. Client sends **EAP-Identity** inside a RADIUS Access-Request.
2. Server replies with **EAP-TLS Start** inside an Access-Challenge.
3. Client sends **TLS ClientHello** (may be fragmented over multiple
   RADIUS round-trips).
4. Server drives a real OpenSSL handshake via a memory BIO pair,
   returning **TLS ServerHello / Certificate / CertificateRequest** etc.
5. The client presents its certificate; OpenSSL verifies it against the
   configured CA bundle.
6. On success → Access-Accept + optional VLAN attributes.
   On failure → Access-Reject.

Session state
-------------
Each in-flight handshake is tracked by `(NAS-IP, username)` in a dict
that maps to an `_EapTlsSession` object.  A background task expires
stale sessions after *SESSION_TIMEOUT_S* seconds.

EAP framing
-----------
Multiple ``EAP-Message`` attributes (type 79, up to 253 bytes each)
carry a single EAP packet.  The ``State`` attribute (type 24) links
RADIUS round-trips belonging to the same EAP conversation.
"""
from __future__ import annotations

import os
import ssl
import struct
import secrets
import threading
import time
from dataclasses import dataclass, field

from raspise.core.logger import get_logger

log = get_logger(__name__)

# EAP codes
EAP_REQUEST  = 1
EAP_RESPONSE = 2
EAP_SUCCESS  = 3
EAP_FAILURE  = 4

# EAP types
EAP_TYPE_IDENTITY = 1
EAP_TYPE_NAK      = 3
EAP_TYPE_TLS      = 13

# EAP-TLS flag bits
TLS_FLAG_LENGTH    = 0x80  # L — TLS-Message-Length field included
TLS_FLAG_MORE      = 0x40  # M — more fragments follow
TLS_FLAG_START     = 0x20  # S — this is the TLS-Start message
TLS_FLAG_RESERVED  = 0x1F  # must be zero

# Limits
MAX_EAP_FRAGMENT   = 1024   # bytes per EAP-TLS payload fragment
SESSION_TIMEOUT_S  = 30     # stale handshake timeout


# ---------------------------------------------------------------------------
# Session tracking
# ---------------------------------------------------------------------------

@dataclass
class _EapTlsSession:
    """State for one in-flight EAP-TLS handshake."""
    eap_id: int = 0
    state_token: bytes = field(default_factory=lambda: secrets.token_bytes(16))
    incoming_buf: bytearray = field(default_factory=bytearray)
    outgoing_buf: bytes = b""
    outgoing_offset: int = 0
    ssl_object: ssl.SSLObject | None = None
    in_bio: ssl.MemoryBIO = field(default_factory=ssl.MemoryBIO)
    out_bio: ssl.MemoryBIO = field(default_factory=ssl.MemoryBIO)
    handshake_done: bool = False
    pending_accept: bool = False  # TLS done, waiting for client ACK
    peer_cn: str = ""
    created: float = field(default_factory=time.monotonic)


_sessions: dict[tuple[str, str], _EapTlsSession] = {}
_sessions_lock = threading.Lock()


def _get_session(nas_ip: str, username: str) -> _EapTlsSession | None:
    with _sessions_lock:
        return _sessions.get((nas_ip, username))


def _set_session(nas_ip: str, username: str, sess: _EapTlsSession) -> None:
    with _sessions_lock:
        _sessions[(nas_ip, username)] = sess


def _del_session(nas_ip: str, username: str) -> None:
    with _sessions_lock:
        _sessions.pop((nas_ip, username), None)


def cleanup_stale_sessions() -> int:
    """Remove sessions older than SESSION_TIMEOUT_S.  Returns count removed."""
    now = time.monotonic()
    to_remove = []
    with _sessions_lock:
        for key, sess in _sessions.items():
            if now - sess.created > SESSION_TIMEOUT_S:
                to_remove.append(key)
        for key in to_remove:
            del _sessions[key]
    return len(to_remove)


# ---------------------------------------------------------------------------
# SSL context factory
# ---------------------------------------------------------------------------

_ssl_ctx: ssl.SSLContext | None = None
_ssl_ctx_lock = threading.Lock()


def _build_ssl_context(
    ca_cert: str,
    server_cert: str,
    server_key: str,
) -> ssl.SSLContext:
    """Build a server-side TLS context for EAP-TLS."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(ca_cert)
    ctx.load_cert_chain(certfile=server_cert, keyfile=server_key)
    return ctx


def get_ssl_context(ca_cert: str, server_cert: str, server_key: str) -> ssl.SSLContext:
    """Cached SSLContext — rebuilt only once per process."""
    global _ssl_ctx
    with _ssl_ctx_lock:
        if _ssl_ctx is None:
            _ssl_ctx = _build_ssl_context(ca_cert, server_cert, server_key)
        return _ssl_ctx


# ---------------------------------------------------------------------------
# EAP packet helpers
# ---------------------------------------------------------------------------

def parse_eap(data: bytes) -> tuple[int, int, int, bytes]:
    """Parse an EAP packet → (code, identifier, eap_type, type_data).

    For Success/Failure packets eap_type=0 and type_data=b''.
    """
    if len(data) < 4:
        raise ValueError("EAP packet too short")
    code, ident, length = struct.unpack("!BBH", data[:4])
    payload = data[4:length]
    if code in (EAP_SUCCESS, EAP_FAILURE) or not payload:
        return code, ident, 0, b""
    eap_type = payload[0]
    return code, ident, eap_type, payload[1:]


def build_eap(code: int, ident: int, eap_type: int = 0, type_data: bytes = b"") -> bytes:
    """Build a raw EAP packet."""
    if code in (EAP_SUCCESS, EAP_FAILURE):
        pkt = struct.pack("!BBH", code, ident, 4)
        return pkt
    body = bytes([eap_type]) + type_data
    length = 4 + len(body)
    return struct.pack("!BBH", code, ident, length) + body


def fragment_eap_messages(eap_packet: bytes) -> list[bytes]:
    """Split one EAP packet into ≤253-byte chunks for RADIUS EAP-Message AVPs."""
    chunks = []
    for i in range(0, len(eap_packet), 253):
        chunks.append(eap_packet[i:i + 253])
    return chunks


def reassemble_eap_messages(attrs: list[bytes]) -> bytes:
    """Concatenate multiple RADIUS EAP-Message attributes into one EAP packet."""
    return b"".join(attrs)


# ---------------------------------------------------------------------------
# EAP-TLS processing
# ---------------------------------------------------------------------------

def handle_eap_tls(
    nas_ip: str,
    username: str,
    eap_messages: list[bytes],
    state_attr: bytes | None,
    ca_cert: str,
    server_cert: str,
    server_key: str,
) -> tuple[str, list[bytes], bytes | None, str]:
    """Process an EAP-TLS exchange.

    Parameters
    ----------
    nas_ip       : NAS IP address (for session keying)
    username     : EAP Identity (User-Name)
    eap_messages : list of raw EAP-Message attribute values
    state_attr   : RADIUS State attribute (or None for first packet)
    ca_cert      : path to CA certificate PEM
    server_cert  : path to server certificate PEM
    server_key   : path to server private key PEM

    Returns
    -------
    (action, eap_reply_chunks, new_state, peer_cn)
      action : "challenge" | "accept" | "reject"
      eap_reply_chunks : list of ≤253-byte chunks for EAP-Message attrs
      new_state : RADIUS State attr for next round (None if finished)
      peer_cn : Common Name from client cert (empty until handshake done)
    """
    raw_eap = reassemble_eap_messages(eap_messages)
    try:
        code, ident, eap_type, type_data = parse_eap(raw_eap)
    except ValueError as exc:
        log.warning("Invalid EAP packet from NAS %s: %s", nas_ip, exc)
        return "reject", fragment_eap_messages(build_eap(EAP_FAILURE, 0)), None, ""

    # Step 1: EAP-Identity response → send EAP-TLS Start
    if eap_type == EAP_TYPE_IDENTITY:
        sess = _EapTlsSession(eap_id=ident + 1)
        _set_session(nas_ip, username, sess)
        # EAP-Request / TLS with Start flag
        tls_start = bytes([TLS_FLAG_START])
        eap_pkt = build_eap(EAP_REQUEST, sess.eap_id, EAP_TYPE_TLS, tls_start)
        return "challenge", fragment_eap_messages(eap_pkt), sess.state_token, ""

    # Step 2+: EAP-TLS data
    if eap_type == EAP_TYPE_TLS:
        sess = _get_session(nas_ip, username)
        if sess is None:
            log.warning("EAP-TLS: no session for %s@%s", username, nas_ip)
            eap_fail = build_eap(EAP_FAILURE, ident)
            return "reject", fragment_eap_messages(eap_fail), None, ""

        return _process_tls_data(nas_ip, username, sess, ident, type_data,
                                 ca_cert, server_cert, server_key)

    # NAK (client doesn't support TLS) or unknown type → reject
    if eap_type == EAP_TYPE_NAK:
        log.info("EAP-TLS: client NAK (doesn't support EAP-TLS) for %s", username)
    else:
        log.info("EAP-TLS: unsupported EAP type %d from %s", eap_type, username)
    _del_session(nas_ip, username)
    eap_fail = build_eap(EAP_FAILURE, ident)
    return "reject", fragment_eap_messages(eap_fail), None, ""


def _process_tls_data(
    nas_ip: str,
    username: str,
    sess: _EapTlsSession,
    ident: int,
    type_data: bytes,
    ca_cert: str,
    server_cert: str,
    server_key: str,
) -> tuple[str, list[bytes], bytes | None, str]:
    """Drive the OpenSSL handshake with incoming TLS data."""

    # Client ACK after we sent the TLS Finished data — complete the exchange
    if sess.pending_accept:
        peer_cn = sess.peer_cn
        _del_session(nas_ip, username)
        success = build_eap(EAP_SUCCESS, (ident + 1) & 0xFF)
        return "accept", fragment_eap_messages(success), None, peer_cn

    # Parse EAP-TLS flags
    if not type_data:
        _del_session(nas_ip, username)
        return "reject", fragment_eap_messages(build_eap(EAP_FAILURE, ident)), None, ""

    flags = type_data[0]
    offset = 1

    # If L flag set, 4-byte TLS message length follows
    if flags & TLS_FLAG_LENGTH:
        if len(type_data) < 5:
            _del_session(nas_ip, username)
            return "reject", fragment_eap_messages(build_eap(EAP_FAILURE, ident)), None, ""
        offset = 5

    tls_data = type_data[offset:]

    # Accumulate fragments
    sess.incoming_buf.extend(tls_data)

    # If M flag set, more fragments coming — send empty ACK
    if flags & TLS_FLAG_MORE:
        sess.eap_id = (ident + 1) & 0xFF
        ack = build_eap(EAP_REQUEST, sess.eap_id, EAP_TYPE_TLS, b"\x00")
        return "challenge", fragment_eap_messages(ack), sess.state_token, ""

    # All fragments received — feed into OpenSSL
    tls_input = bytes(sess.incoming_buf)
    sess.incoming_buf.clear()

    # Lazy-init SSL object
    if sess.ssl_object is None:
        ctx = get_ssl_context(ca_cert, server_cert, server_key)
        sess.ssl_object = ctx.wrap_bio(
            sess.in_bio, sess.out_bio, server_side=True
        )

    # Feed client data into the incoming BIO
    sess.in_bio.write(tls_input)

    # Drive handshake
    try:
        sess.ssl_object.do_handshake()
        sess.handshake_done = True
    except ssl.SSLWantReadError:
        # Handshake needs more data from client — send what OpenSSL produced
        pass
    except ssl.SSLError as exc:
        log.info("EAP-TLS handshake failed for %s@%s: %s", username, nas_ip, exc)
        _del_session(nas_ip, username)
        eap_fail = build_eap(EAP_FAILURE, ident)
        return "reject", fragment_eap_messages(eap_fail), None, ""

    # Read whatever OpenSSL wants to send back
    out_data = sess.out_bio.read()

    if sess.handshake_done:
        # Extract CN from peer certificate
        peer_cn = ""
        peer_cert = sess.ssl_object.getpeercert()
        if peer_cert:
            for rdn in peer_cert.get("subject", ()):
                for attr_type, value in rdn:
                    if attr_type == "commonName":
                        peer_cn = value
                        break
        sess.peer_cn = peer_cn

        if out_data:
            # Server has TLS Finished data to send — deliver it as a
            # challenge and wait for the client's empty ACK before
            # sending EAP-Success in the next round-trip.
            sess.pending_accept = True
            sess.eap_id = (ident + 1) & 0xFF
            eap_pkt = _build_tls_fragment(sess.eap_id, out_data, len(out_data))
            return "challenge", fragment_eap_messages(eap_pkt), sess.state_token, ""

        # No remaining TLS data — send EAP-Success immediately
        _del_session(nas_ip, username)
        success = build_eap(EAP_SUCCESS, (ident + 1) & 0xFF)
        return "accept", fragment_eap_messages(success), None, peer_cn

    # Handshake in progress — fragment and send as EAP-Request/TLS
    if out_data:
        sess.outgoing_buf = out_data
        sess.outgoing_offset = 0
        return _send_next_fragment(nas_ip, username, sess, ident)

    # OpenSSL produced nothing — shouldn't happen, but ACK to keep going
    sess.eap_id = (ident + 1) & 0xFF
    ack = build_eap(EAP_REQUEST, sess.eap_id, EAP_TYPE_TLS, b"\x00")
    return "challenge", fragment_eap_messages(ack), sess.state_token, ""


def _send_next_fragment(
    nas_ip: str,
    username: str,
    sess: _EapTlsSession,
    ident: int,
) -> tuple[str, list[bytes], bytes | None, str]:
    """Send the next chunk of the outgoing TLS buffer."""
    data = sess.outgoing_buf
    offset = sess.outgoing_offset
    remaining = len(data) - offset
    chunk_size = min(remaining, MAX_EAP_FRAGMENT)
    chunk = data[offset:offset + chunk_size]
    sess.outgoing_offset = offset + chunk_size

    sess.eap_id = (ident + 1) & 0xFF
    eap_pkt = _build_tls_fragment(
        sess.eap_id, chunk,
        total_length=len(data) if offset == 0 else 0,
        more=(sess.outgoing_offset < len(data)),
    )
    return "challenge", fragment_eap_messages(eap_pkt), sess.state_token, ""


def _build_tls_fragment(
    eap_id: int,
    tls_data: bytes,
    total_length: int = 0,
    more: bool = False,
) -> bytes:
    """Build an EAP-Request/TLS packet with proper flags and optional length."""
    flags = 0
    extra = b""
    if total_length > 0:
        flags |= TLS_FLAG_LENGTH
        extra = struct.pack("!I", total_length)
    if more:
        flags |= TLS_FLAG_MORE
    type_data = bytes([flags]) + extra + tls_data
    return build_eap(EAP_REQUEST, eap_id, EAP_TYPE_TLS, type_data)
