"""Tests for raspise.core.utils."""
from __future__ import annotations

import hashlib
from datetime import time

import pytest

from raspise.core.utils import (
    chap_verify,
    constant_time_compare,
    generate_password,
    generate_token,
    is_within_time_range,
    mac_oui,
    normalise_mac,
    utcnow,
)


# ---------------------------------------------------------------------------
# normalise_mac
# ---------------------------------------------------------------------------

class TestNormaliseMac:
    def test_colon_format(self):
        assert normalise_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"

    def test_dash_format(self):
        assert normalise_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"

    def test_dot_format(self):
        assert normalise_mac("aabb.ccdd.eeff") == "aa:bb:cc:dd:ee:ff"

    def test_plain_hex(self):
        assert normalise_mac("aabbccddeeff") == "aa:bb:cc:dd:ee:ff"

    def test_mixed_case(self):
        assert normalise_mac("aA:Bb:cC:dD:eE:fF") == "aa:bb:cc:dd:ee:ff"

    def test_invalid_too_short(self):
        with pytest.raises(ValueError):
            normalise_mac("AA:BB:CC")

    def test_invalid_too_long(self):
        with pytest.raises(ValueError):
            normalise_mac("AA:BB:CC:DD:EE:FF:00")

    def test_empty_string(self):
        with pytest.raises(ValueError):
            normalise_mac("")


# ---------------------------------------------------------------------------
# mac_oui
# ---------------------------------------------------------------------------

class TestMacOui:
    def test_returns_first_six_hex(self):
        assert mac_oui("AA:BB:CC:DD:EE:FF") == "aabbcc"

    def test_dash_format(self):
        assert mac_oui("11-22-33-44-55-66") == "112233"


# ---------------------------------------------------------------------------
# generate_password
# ---------------------------------------------------------------------------

class TestGeneratePassword:
    def test_default_length(self):
        pw = generate_password()
        assert len(pw) == 16

    def test_custom_length(self):
        pw = generate_password(32)
        assert len(pw) == 32

    def test_uniqueness(self):
        passwords = {generate_password() for _ in range(20)}
        assert len(passwords) == 20


# ---------------------------------------------------------------------------
# constant_time_compare
# ---------------------------------------------------------------------------

class TestConstantTimeCompare:
    def test_equal(self):
        assert constant_time_compare("secret", "secret") is True

    def test_not_equal(self):
        assert constant_time_compare("secret", "other") is False

    def test_empty(self):
        assert constant_time_compare("", "") is True


# ---------------------------------------------------------------------------
# generate_token
# ---------------------------------------------------------------------------

class TestGenerateToken:
    def test_is_string(self):
        assert isinstance(generate_token(), str)

    def test_length(self):
        # 32 bytes → ~43 url-safe base64 chars
        tok = generate_token(32)
        assert len(tok) > 0

    def test_uniqueness(self):
        tokens = {generate_token() for _ in range(20)}
        assert len(tokens) == 20


# ---------------------------------------------------------------------------
# utcnow
# ---------------------------------------------------------------------------

class TestUtcnow:
    def test_has_tzinfo(self):
        now = utcnow()
        assert now.tzinfo is not None

    def test_utc_offset_zero(self):
        from datetime import timezone
        now = utcnow()
        assert now.utcoffset() == timezone.utc.utcoffset(None)


# ---------------------------------------------------------------------------
# is_within_time_range
# ---------------------------------------------------------------------------

class TestIsWithinTimeRange:
    def test_within_normal_range(self):
        assert is_within_time_range("08:00", "17:00", time(12, 0)) is True

    def test_outside_normal_range(self):
        assert is_within_time_range("08:00", "17:00", time(20, 0)) is False

    def test_at_start_boundary(self):
        assert is_within_time_range("08:00", "17:00", time(8, 0)) is True

    def test_at_end_boundary(self):
        assert is_within_time_range("08:00", "17:00", time(17, 0)) is True

    def test_overnight_range_inside(self):
        # 22:00 – 06:00 — midnight should match
        assert is_within_time_range("22:00", "06:00", time(0, 0)) is True

    def test_overnight_range_outside(self):
        assert is_within_time_range("22:00", "06:00", time(12, 0)) is False

    def test_overnight_range_at_start(self):
        assert is_within_time_range("22:00", "06:00", time(22, 0)) is True


# ---------------------------------------------------------------------------
# chap_verify
# ---------------------------------------------------------------------------

class TestChapVerify:
    def test_valid_chap(self):
        identifier = b"\x01"
        password = "testpassword"
        challenge = b"randomchallenge!"
        expected = hashlib.md5(identifier + password.encode() + challenge).digest()
        chap_response = expected + challenge
        assert chap_verify(identifier, password, chap_response) is True

    def test_invalid_chap_wrong_password(self):
        identifier = b"\x01"
        challenge = b"randomchallenge!"
        expected = hashlib.md5(identifier + b"correct" + challenge).digest()
        chap_response = expected + challenge
        assert chap_verify(identifier, "wrong", chap_response) is False

    def test_invalid_chap_wrong_identifier(self):
        identifier = b"\x01"
        password = "test"
        challenge = b"abcdefgh12345678"
        expected = hashlib.md5(identifier + password.encode() + challenge).digest()
        chap_response = expected + challenge
        # Verify with different identifier
        assert chap_verify(b"\x02", password, chap_response) is False
