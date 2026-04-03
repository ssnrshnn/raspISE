"""Tests for TACACS+ packet encode/decode and encryption primitives."""
from __future__ import annotations

import struct

import pytest

from raspise.tacacs.server import (
    HEADER_LEN,
    TAC_PLUS_AUTHEN,
    TAC_PLUS_UNENCRYPTED_FLAG,
    TAC_PLUS_VER,
    TacacsHeader,
    _crypt,
    _encode_av_pairs,
    _md5_pad,
    _parse_av_pairs,
)


# ---------------------------------------------------------------------------
# TacacsHeader encode / decode round-trip
# ---------------------------------------------------------------------------

class TestTacacsHeader:
    def test_encode_decode_roundtrip(self):
        hdr = TacacsHeader(
            version=TAC_PLUS_VER,
            pkt_type=TAC_PLUS_AUTHEN,
            seq_no=1,
            flags=0,
            session_id=0xDEADBEEF,
            length=42,
        )
        raw = hdr.encode()
        assert len(raw) == HEADER_LEN

        decoded = TacacsHeader.decode(raw)
        assert decoded.version == hdr.version
        assert decoded.pkt_type == hdr.pkt_type
        assert decoded.seq_no == hdr.seq_no
        assert decoded.flags == hdr.flags
        assert decoded.session_id == hdr.session_id
        assert decoded.length == hdr.length

    def test_unencrypted_flag(self):
        hdr = TacacsHeader(TAC_PLUS_VER, TAC_PLUS_AUTHEN, 1, TAC_PLUS_UNENCRYPTED_FLAG, 1, 0)
        raw = hdr.encode()
        decoded = TacacsHeader.decode(raw)
        assert decoded.flags & TAC_PLUS_UNENCRYPTED_FLAG


# ---------------------------------------------------------------------------
# MD5 pad generation
# ---------------------------------------------------------------------------

class TestMd5Pad:
    def test_correct_length(self):
        pad = _md5_pad(b"secret", 0x12345678, TAC_PLUS_VER, 1, 100)
        assert len(pad) == 100

    def test_deterministic(self):
        a = _md5_pad(b"key", 1, TAC_PLUS_VER, 1, 32)
        b = _md5_pad(b"key", 1, TAC_PLUS_VER, 1, 32)
        assert a == b

    def test_different_keys_differ(self):
        a = _md5_pad(b"key1", 1, TAC_PLUS_VER, 1, 32)
        b = _md5_pad(b"key2", 1, TAC_PLUS_VER, 1, 32)
        assert a != b


# ---------------------------------------------------------------------------
# Body encryption / decryption round-trip
# ---------------------------------------------------------------------------

class TestCrypt:
    def test_encrypt_decrypt_roundtrip(self):
        key = b"tacacs_secret"
        session_id = 0xCAFEBABE
        body = b"Hello, TACACS+ world! This is a test payload."

        encrypted = _crypt(body, key, session_id, TAC_PLUS_VER, 1)
        assert encrypted != body  # must be altered

        decrypted = _crypt(encrypted, key, session_id, TAC_PLUS_VER, 1)
        assert decrypted == body

    def test_wrong_key_produces_garbage(self):
        key = b"correct"
        bad_key = b"wrong"
        session_id = 1
        body = b"secret data"

        encrypted = _crypt(body, key, session_id, TAC_PLUS_VER, 1)
        decrypted = _crypt(encrypted, bad_key, session_id, TAC_PLUS_VER, 1)
        assert decrypted != body

    def test_empty_body(self):
        result = _crypt(b"", b"key", 1, TAC_PLUS_VER, 1)
        assert result == b""


# ---------------------------------------------------------------------------
# AV-pair encode / parse round-trip
# ---------------------------------------------------------------------------

class TestAvPairs:
    def test_roundtrip(self):
        pairs = ["service=shell", "cmd=show", "cmd-arg=version"]
        encoded = _encode_av_pairs(pairs)
        parsed = _parse_av_pairs(encoded)
        assert parsed == pairs

    def test_empty_list(self):
        encoded = _encode_av_pairs([])
        assert encoded == b""
        parsed = _parse_av_pairs(encoded)
        assert parsed == []

    def test_single_pair(self):
        encoded = _encode_av_pairs(["priv-lvl=15"])
        parsed = _parse_av_pairs(encoded)
        assert parsed == ["priv-lvl=15"]

    def test_truncated_data(self):
        """Truncated input should return whatever pairs were fully read."""
        encoded = _encode_av_pairs(["a=1", "b=2"])
        truncated = encoded[: len(encoded) - 1]
        parsed = _parse_av_pairs(truncated)
        # Should at least have the first pair
        assert "a=1" in parsed
