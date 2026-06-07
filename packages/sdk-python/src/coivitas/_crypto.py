"""Internal crypto wrapper (optional crypto backend).

Design principles
--------
1. Consumes wire format only; does not define protocol-level key structures.
2. Backend choice: the Ed25519 implementation from the ``cryptography`` library (one of the recommended options;
   used in FIPS-compliant scenarios); ``pynacl`` is also an optional backend, installed at the
   user's discretion (pyproject.toml installs cryptography by default).
3. fail-closed: signature verification failure → return False (no exception raised); malformed input → CryptoError.

Anchors
----
- ``packages/crypto/src/signing.ts`` ``verify(publicKey, message, signature)``
- security dependency list (cryptography >= 42.0)
- ``tests/fixtures/conformance/identity/crypto-signing.json`` RFC 8032 test vectors
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from coivitas._wire import from_base64url, from_hex


class CryptoError(Exception):
    """Error from the Python SDK crypto wrapper layer.

    Aligned in responsibility with TS ``CryptoError`` (malformed input format / backend unavailable);
    a verification business failure still returns False (does not raise CryptoError; consistent with TS behavior).
    """


def _decode_key_or_signature(value: str | bytes) -> bytes:
    """Support both hex and base64url string encodings (consistent with the schemas.ts tri-state coexistence strategy).

    - bytes are returned as-is;
    - str tries hex first (consistent with the TS detectEncoding strategy that favors hex),
      then falls back to base64url;
    - if both fail → CryptoError.
    """
    if isinstance(
        value, (bytes, bytearray, memoryview)
    ):  # pyright: ignore[reportUnnecessaryIsInstance]
        return bytes(value)
    if not isinstance(value, str):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise CryptoError(f"key/signature must be str or bytes, got {type(value).__name__}")
    if len(value) == 0:
        raise CryptoError("empty key/signature")

    # hex first (consistent with TS detectEncoding)
    if len(value) % 2 == 0 and all(ch in "0123456789abcdefABCDEF" for ch in value):
        try:
            return from_hex(value)
        except Exception:  # noqa: BLE001
            pass

    try:
        return from_base64url(value)
    except Exception as exc:
        raise CryptoError(f"failed to decode key/signature as hex or base64url: {value!r}") from exc


def verify_ed25519(
    public_key: str | bytes,
    message: bytes,
    signature: str | bytes,
) -> bool:
    """Ed25519 signature verification (interop verification contract).

    - public_key: 32 bytes (hex or base64url string)
    - message: raw byte sequence
    - signature: 64 bytes (hex or base64url string)

    Behaves consistently with TS ``verify(publicKey, message, signature)``:
    - verification passes → True
    - verification fails (including signature tampering / public-key mismatch) → False
    - malformed input format (public key length ≠ 32 bytes, signature length ≠ 64 bytes) → CryptoError
    """
    pk_bytes = _decode_key_or_signature(public_key)
    sig_bytes = _decode_key_or_signature(signature)

    if not isinstance(
        message, (bytes, bytearray, memoryview)
    ):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise CryptoError(f"message must be bytes-like, got {type(message).__name__}")
    message = bytes(message)

    if len(pk_bytes) != 32:
        raise CryptoError(f"Ed25519 public key must be 32 bytes, got {len(pk_bytes)}")
    if len(sig_bytes) != 64:
        raise CryptoError(f"Ed25519 signature must be 64 bytes, got {len(sig_bytes)}")

    # Lazy import: other parts of the SDK (e.g. conformance tests) remain usable when the user has not installed cryptography
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError as exc:  # pragma: no cover - dep missing
        raise CryptoError(
            "cryptography backend not available; install via "
            "`pip install coivitas[crypto]` or "
            "`pip install cryptography>=42`"
        ) from exc

    try:
        verifier = Ed25519PublicKey.from_public_bytes(pk_bytes)
        verifier.verify(sig_bytes, message)
        return True
    except InvalidSignature:
        return False
    except ValueError as exc:
        # Invalid public-key bytes (e.g. not a curve point)
        raise CryptoError(f"Ed25519 public key invalid: {exc}") from exc


if TYPE_CHECKING:
    # Import for the type checker only (avoids a hard runtime dependency on cryptography)
    pass


__all__ = [
    "CryptoError",
    "verify_ed25519",
]
