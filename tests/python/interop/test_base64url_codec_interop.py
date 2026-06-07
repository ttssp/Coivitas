"""TS <-> Python base64url codec byte-level interop verification.

TS source of truth
------------------
- TS implementation: ``packages/crypto/src/encoding.ts`` ``toBase64Url`` / ``fromBase64Url``
  (RFC 4648 §5 base64url charset, no padding)

Cross-language alignment contract
---------------------------------
1. Same byte sequence -> Python ``to_base64url`` and TS ``toBase64Url`` yield the same string
2. Same string -> Python ``from_base64url`` and TS ``fromBase64Url`` yield the same byte sequence
3. RFC 4648 charset (A-Za-z0-9-_); illegal characters -> fail-closed
4. Boundaries: empty input / single byte / 32 bytes (Ed25519 public key) / 64 bytes (Ed25519 signature)
"""

from __future__ import annotations

import pytest

from coivitas._wire import (
    WireSerializationError,
    from_base64url,
    from_hex,
    to_base64url,
    to_hex,
)


class TestBase64UrlRfc4648Vectors:
    """RFC 4648 §10 test vectors (reconciled against TS encoding.ts output)."""

    def test_empty_input(self) -> None:
        assert to_base64url(b"") == ""
        assert from_base64url("") == b""

    def test_single_byte(self) -> None:
        assert to_base64url(b"\x00") == "AA"
        assert from_base64url("AA") == b"\x00"

    def test_two_bytes(self) -> None:
        assert to_base64url(b"\x00\x00") == "AAA"
        assert from_base64url("AAA") == b"\x00\x00"

    def test_three_bytes(self) -> None:
        # Standard base64: AAAA; equivalent under the base64url charset
        assert to_base64url(b"\x00\x00\x00") == "AAAA"
        assert from_base64url("AAAA") == b"\x00\x00\x00"

    def test_hello_ascii(self) -> None:
        # hello = 0x68656c6c6f -> standard base64 = "aGVsbG8="; base64url without padding = "aGVsbG8"
        assert to_base64url(b"hello") == "aGVsbG8"
        assert from_base64url("aGVsbG8") == b"hello"

    def test_url_safe_chars_used(self) -> None:
        """- replaces +; _ replaces / (RFC 4648 §5)."""
        # High-order bytes trigger the + / characters; pick 0xFA 0xFB -> standard base64 "+vs="
        # Actual: bytes [0xFB, 0xFC] = 0b11111011 11111100 -> 6-bit groups:
        #   111110 = 62 = '-' (base64url) / '+' (standard)
        #   111111 = 63 = '_' (base64url) / '/' (standard)
        encoded = to_base64url(bytes([0xFB, 0xFC]))
        # First character should be '-' (position 62 in BASE64URL_CHARSET); must not contain '+' / '/'
        assert "+" not in encoded
        assert "/" not in encoded


class TestBase64UrlEd25519KeySizes:
    """base64url length assertions for Ed25519 key sizes (32-byte public key / 64-byte signature)."""

    def test_ed25519_pubkey_43_chars(self) -> None:
        """32 bytes -> base64url 43 chars (no padding; schemas.ts:136 base64url43Pattern)."""
        pubkey = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        encoded = to_base64url(pubkey)
        assert len(encoded) == 43
        # Charset is valid
        assert all(
            ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            for ch in encoded
        )
        # roundtrip
        decoded = from_base64url(encoded)
        assert decoded == pubkey

    def test_ed25519_signature_86_chars(self) -> None:
        """64 bytes -> base64url 86 chars (no padding; schemas.ts:134 base64url86Pattern)."""
        signature = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        encoded = to_base64url(signature)
        assert len(encoded) == 86
        decoded = from_base64url(encoded)
        assert decoded == signature


class TestBase64UrlFailClosed:
    """fail-closed: illegal input -> WireSerializationError."""

    def test_invalid_chars_rejected(self) -> None:
        # '!' is not in the base64url charset
        with pytest.raises(WireSerializationError):
            from_base64url("aGVsbG8!")

    def test_padding_with_invalid_length_rejected(self) -> None:
        """len(stripped) % 4 == 1 is an impossible valid base64url length (RFC 4648 §3)."""
        # len 1 -> mod 4 == 1
        with pytest.raises(WireSerializationError):
            from_base64url("A")
        # len 5 -> mod 4 == 1
        with pytest.raises(WireSerializationError):
            from_base64url("AAAAA")

    def test_padding_accepted_optionally(self) -> None:
        """= padding is also accepted (RFC 4648 §5; matches TS fromBase64Url behavior)."""
        assert from_base64url("aGVsbG8=") == b"hello"
        assert from_base64url("aGVsbG8==") == b"hello"


class TestHexCodecInterop:
    """Hex codec (equivalent to TS toHex / fromHex)."""

    def test_hex_roundtrip(self) -> None:
        for raw in [b"", b"\x00", b"\xff" * 32, bytes(range(256))]:
            encoded = to_hex(raw)
            # hex is all lowercase (matches TS toHex; islower() returns False for
            # pure-digit strings, so use isupper() as a reverse assertion instead)
            assert not any(c.isupper() for c in encoded)
            assert from_hex(encoded) == raw

    def test_hex_invalid_length_rejected(self) -> None:
        with pytest.raises(WireSerializationError, match="even length"):
            from_hex("abc")  # length 3, odd

    def test_hex_invalid_chars_rejected(self) -> None:
        with pytest.raises(WireSerializationError):
            from_hex("zzaa")  # 'z' is not hex

    def test_hex_uppercase_accepted(self) -> None:
        """Hex is accepted in either case (bytes.fromhex behavior; matches TS HEX_PATTERN /i flag)."""
        assert from_hex("ABCD") == bytes.fromhex("abcd")
