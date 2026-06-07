"""Wire format serialization / deserialization.

Design principles
--------
1. **base64url (RFC 4648 §5, no padding)**: byte-level identical to TS ``packages/crypto/src/encoding.ts``'s
   ``toBase64Url`` / ``fromBase64Url``; on the Python side, ``base64.urlsafe_b64encode``
   with padding stripped suffices (equivalent behavior; a prerequisite for byte-level parity).
2. **RFC 8785 JCS canonicalize**: a pure-Python implementation, byte-level identical to the TS-side
   ``canonicalize`` npm package. Key RFC 8785 constraints:
   - **object keys sorted by UTF-16 code unit** (RFC 8785 §3.2.3; consistent with the JS
     ``Array.sort()`` default behavior); implemented as ``utf-16-be``
     byte-order sorting, which **no longer** relies on Python's default codepoint ordering — a supplementary-plane
     character (U+10000+) whose surrogate-pair first byte is 0xD8XX must sort before a high-codepoint BMP
     character (such as U+FFFD).
   - **numbers output equivalently to ECMA-262 §7.1.12.1 ToString(Number)**;
     Python ``repr()`` is not used (``repr`` produces ``"1e-06"`` for ``1e-6``, whereas the
     ECMA rule mandates the fixed-point form ``"0.000001"``); see ``_format_number`` for the correct implementation.
   - strings use standard JSON escaping (``ensure_ascii=False``, escaping only control chars / quotes / backslashes);
   - ``undefined`` / ``Infinity`` / ``NaN`` / functions / circular references are unsupported;
   - arrays retain input order (no sorting).
3. **fail-closed serialization check**: equivalent to TS ``assertSerializable``;
   on encountering bytes / set / functions etc. → ``WireSerializationError``.

Anchors
----
- ``packages/crypto/src/canonicalization.ts`` ``canonicalize()``
- ``packages/crypto/src/encoding.ts`` ``toBase64Url`` / ``fromBase64Url``
- ECMA-262 §7.1.12.1 ToString(Number) (the authoritative implementation in JS engines such as V8 / SpiderMonkey)
- RFC 8785 §3.2.2.3 (explicitly points to ECMAScript Number-to-String)
"""

from __future__ import annotations

import base64
import json
import math
from typing import Any

from coivitas._brands import _check_base64url


class WireSerializationError(ValueError):
    """Fail-closed exception for wire format serialization failure."""


# JS Number safe integer boundary (IEEE-754 double precision).
# Integers beyond ±(2^53 - 1) lose precision under JS Number floating-point representation
# (e.g. 9007199254740993 → 9007199254740992), making the cross-language canonical JSON byte
# sequence diverge → signature verification failure. Python int is arbitrary-precision, so it must be actively rejected.
_JS_SAFE_INTEGER_MAX = 2**53 - 1  # 9007199254740991
_JS_SAFE_INTEGER_MIN = -(2**53 - 1)  # -9007199254740991


def _check_js_safe_integer(value: int) -> int:
    """Reject integers outside the JS Number safe range (a prerequisite constraint for byte-level interop).

    fail-closed: out of range → ``WireSerializationError``. bool is a subclass of int, so it must be
    short-circuited before calling (the ``_assert_serializable`` / ``_format_number`` entry points already branch on it).
    """
    if value > _JS_SAFE_INTEGER_MAX or value < _JS_SAFE_INTEGER_MIN:
        raise WireSerializationError(
            f"integer {value} exceeds JS safe range "
            f"[-(2^53-1), 2^53-1]; use string encoding for "
            f"arbitrary-precision values"
        )
    return value


# ─── base64url (RFC 4648, no padding) ─────────────────────────────


def to_base64url(data: bytes) -> str:
    """bytes → base64url string (no padding; equivalent to TS toBase64Url)."""
    if not isinstance(
        data, (bytes, bytearray, memoryview)
    ):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise TypeError(f"to_base64url requires bytes-like input, got {type(data).__name__}")
    if len(data) == 0:
        return ""
    return base64.urlsafe_b64encode(bytes(data)).rstrip(b"=").decode("ascii")


def from_base64url(value: str) -> bytes:
    """base64url string → bytes (1:1 with TS fromBase64Url; strict 0-2 padding).

    Aligned with the TS ``packages/crypto/src/encoding.ts`` literal
    ``BASE64URL_PATTERN = /^[A-Za-z0-9_-]*={0,2}$/`` —
    trailing ``=`` must be 0-2; 3+ padding (such as ``"AA==="``) is rejected.
    A lenient ``rstrip("=")`` would leniently accept pathological inputs like ``"AA==="`` / ``"AA===="``
    on the Python side while the TS side rejects them → byte-level interop drift.

    fail-closed: illegal characters / padding out of bounds / invalid length (mod 4 == 1) →
    ``WireSerializationError``.
    """
    if not isinstance(value, str):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise TypeError(f"from_base64url requires str input, got {type(value).__name__}")
    if len(value) == 0:
        return b""

    # strict pattern validation (including the padding upper bound), 1:1 with the TS BASE64URL_PATTERN literal
    try:
        _check_base64url(value)
    except ValueError as exc:
        raise WireSerializationError(f"Invalid base64url string: {exc}; input={value!r}") from exc

    # Validate length after stripping padding
    stripped = value.rstrip("=")
    if len(stripped) % 4 == 1:
        raise WireSerializationError(
            f"Invalid base64url string: impossible length "
            f"(length mod 4 must not be 1); input={value!r}"
        )

    # Python urlsafe_b64decode requires padding; pad the = characters back
    padded = stripped + "=" * ((4 - len(stripped) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:  # binascii.Error etc.
        raise WireSerializationError(f"base64url decode failed: {exc}; input={value!r}") from exc


_BASE64URL_CHARSET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


# ─── hex (equivalent to TS toHex / fromHex) ────────────────────────────────


def to_hex(data: bytes) -> str:
    """bytes → lowercase hex string."""
    return bytes(data).hex()


def from_hex(value: str) -> bytes:
    """hex string → bytes; even length + only [0-9a-fA-F]."""
    if not isinstance(value, str):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise TypeError(f"from_hex requires str input, got {type(value).__name__}")
    if len(value) == 0:
        return b""
    if len(value) % 2 != 0:
        raise WireSerializationError(f"Hex string must have even length; got len={len(value)}")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise WireSerializationError(f"Invalid hex string: {exc}; input={value!r}") from exc


# ─── RFC 8785 JCS canonicalize (equivalent to TS canonicalize) ─────────────


def canonicalize(value: Any) -> str:
    """RFC 8785 JSON Canonicalization Scheme.

    Byte-level identical to TS ``packages/crypto/src/canonicalization.ts``;
    fail-closed: bytes / set / functions / NaN / Infinity / circular references → raise.
    """
    _assert_serializable(value, set(), "$")
    return _canonicalize_inner(value)


def _assert_serializable(value: Any, seen: set[int], path: str) -> None:
    """Equivalent to TS assertSerializable; fail-closed defense."""
    if value is None:
        return
    if isinstance(value, bool):
        return
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise WireSerializationError(f"Non-finite number at {path}: {value!r}")
        # bool is a subclass of int (True/False are always in the safe range, but that dedicated path is
        # already handled in _format_number; here we only guard the int path); bool branches off earlier upstream.
        if isinstance(value, int) and not isinstance(value, bool):
            try:
                _check_js_safe_integer(value)
            except WireSerializationError as exc:
                raise WireSerializationError(f"Non-safe integer at {path}: {exc}") from exc
        return
    if isinstance(value, str):
        return

    obj_id = id(value)
    if obj_id in seen:
        raise WireSerializationError(f"Circular reference detected at {path}")

    if isinstance(value, list):
        seen.add(obj_id)
        for index, entry in enumerate(value):
            _assert_serializable(entry, seen, f"{path}[{index}]")
        seen.discard(obj_id)
        return
    if isinstance(value, dict):
        seen.add(obj_id)
        for key, entry in value.items():
            if not isinstance(key, str):
                raise WireSerializationError(f"Non-string key at {path}: {key!r}")
            sub_path = f"{path}.{key}" if path else key
            _assert_serializable(entry, seen, sub_path)
        seen.discard(obj_id)
        return

    # tuple / set / bytes / functions / custom objects → fail-closed
    raise WireSerializationError(f"Unsupported value at {path}: type={type(value).__name__}")


def _canonicalize_inner(value: Any) -> str:
    """RFC 8785 critical-path recursion."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return _format_number(value)
    if isinstance(value, float):
        return _format_number(value)
    if isinstance(value, str):
        # Standard JSON escaping; ensure_ascii=False preserves non-ASCII
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(_canonicalize_inner(item) for item in value) + "]"
    if isinstance(value, dict):
        # RFC 8785: keys sorted in UTF-16 code-unit order
        # Python str sorts by codepoint by default, which for supplementary-plane characters
        # (U+10000+) is the reverse of the UTF-16 surrogate-pair order — for example:
        #   "𐀀"(U+10000) in UTF-16 is [0xD800, 0xDC00]
        #   "�"(U+FFFD) in UTF-16 is [0xFFFD]
        # by codepoint: U+10000 > U+FFFD ("𐀀" comes later)
        # by UTF-16 code unit: 0xD800 < 0xFFFD ("𐀀" comes first; the JS Array.sort behavior)
        # Solution: use the utf-16-be encoded byte order as the key, equivalent to the JS default order.
        sorted_keys = sorted(value.keys(), key=_utf16_sort_key)
        return (
            "{"
            + ",".join(
                json.dumps(key, ensure_ascii=False, separators=(",", ":"))
                + ":"
                + _canonicalize_inner(value[key])
                for key in sorted_keys
            )
            + "}"
        )
    # Unreachable (_assert_serializable already fail-closed)
    raise WireSerializationError(f"unexpected value type in canonicalize: {type(value).__name__}")


def _utf16_sort_key(key: str) -> bytes:
    """RFC 8785 §3.2.3 UTF-16 code-unit lexicographic sort key.

    Implementation strategy
    --------
    Encode the string in ``utf-16-be`` big-endian byte order: each UTF-16 code unit
    (16 bit) maps to 2 bytes, high byte first; Python ``bytes`` compares lexicographically
    by byte by default, equivalent to lexicographic comparison over the code-unit array.

    Boundaries
    ----
    - BMP characters (U+0000..U+FFFF): single code unit, 2 bytes
    - supplementary characters (U+10000+): a UTF-16 surrogate pair (high 0xD8XX..0xDBXX
      + low 0xDCXX..0xDFXX), 4 bytes total; the first byte 0xD8 < 0xFF, so they sort
      **before** high-BMP characters (such as U+FFFD = 0xFF 0xFD) — this is the JS Array.sort default behavior.

    Anchor: RFC 8785 §3.2.3; the TS ``canonicalize`` npm package internally uses the JS default sort.
    """
    return key.encode("utf-16-be")


def _format_number(value: float | int) -> str:
    """RFC 8785 §3.2.2 + ECMA-262 §7.1.12.1 ToString(Number) number formatting.

    Using Python ``repr()`` directly produces ``"1e-06"`` for ``1e-6``,
    whereas the ECMA-262 rule mandates ``"0.000001"`` (fixed-point). This function implements the
    ECMA-262 §7.1.12.1 algorithm strictly.

    Algorithm (ECMA-262 §7.1.12.1)
    -------------------------
    Given a number m > 0 (sign handling is done in the outer layer), find (n, k, s) such that:
    - k is the fewest integer digits that make ``s × 10^(n−k)`` IEEE-754 round-trip equal to m
    - 1 ≤ s ≤ 10^k - 1 (no leading or trailing zeros)
    - n is the base-10 exponent (satisfying ``s × 10^(n−k) = m``)

    Three format branches based on (n, k):
    1. ``k ≤ n ≤ 21``: fixed-point ``ssss0..0`` (k digits of s + (n−k) zeros)
    2. ``0 < n ≤ 21``: fixed-point ``sss.ssss`` (first n digits + ``.`` + last k−n digits)
    3. ``−6 < n ≤ 0``: fixed-point ``0.000ss`` (``0.`` + (−n) zeros + k digits)
    4. otherwise: scientific notation ``sss.ssse±N`` (with ``+``/``-`` sign; N=n−1)

    Special values
    ------
    - 0 / -0 → ``"0"`` (ECMA step 2)
    - NaN / ±Inf → raise ``WireSerializationError`` (not allowed by JCS)
    - integer floats (``1.0``) → k=1, n=1, takes branch 1 (``"1"``, no decimal point)

    Python-equivalent implementation
    ---------------
    Python 3.1+ ``repr(float)`` already uses the Grisu/dtoa algorithm, producing the IEEE-754 round-trip
    shortest representation — the same source as V8/SpiderMonkey; parsing (digits, exp10) out of repr
    yields (n, k, s), which is then reformatted per the branches above.
    """
    if isinstance(value, bool):
        # bool is a subclass of int, so short-circuit first
        return "true" if value else "false"
    if isinstance(value, int):
        # Double defense: _assert_serializable already rejects; this guards the path that calls
        # _format_number directly (e.g. after a future refactor) and might skip the guard
        _check_js_safe_integer(value)
        return str(value)
    # float path
    if math.isnan(value) or math.isinf(value):
        raise WireSerializationError(f"Non-finite number: {value!r}")
    # ECMA-262 step 2: ±0 → "0" (including -0.0)
    if value == 0.0:
        return "0"

    # Obtain the IEEE-754 shortest round-trippable representation (equivalent to V8/SpiderMonkey)
    repr_str = repr(value)
    return _ecma_format_from_repr(repr_str)


def _ecma_format_from_repr(repr_str: str) -> str:
    """Reformat per ECMA-262 §7.1.12.1 based on Python ``repr(float)`` output.

    ``repr_str`` looks like ``"-1.5"`` / ``"1e-07"`` / ``"1e+21"`` / ``"100.0"``.
    Parse → (digits, exp10) → (n, k, s) → output per the ECMA branches.
    """
    # Handle the sign
    negative = repr_str.startswith("-")
    body = repr_str[1:] if negative else repr_str
    sign_prefix = "-" if negative else ""

    # Python repr contains "e" (scientific) or a plain decimal; parse uniformly into mantissa + decimal exponent
    if "e" in body or "E" in body:
        mantissa_str, exp_str = body.replace("E", "e").split("e", 1)
        exp_part = int(exp_str)
    else:
        mantissa_str = body
        exp_part = 0

    if "." in mantissa_str:
        int_part, frac_part = mantissa_str.split(".", 1)
    else:
        int_part = mantissa_str
        frac_part = ""

    # Assemble the full decimal digit string: value = ±(int_part + frac_part) × 10^(exp_part − len(frac_part))
    raw_digits = (int_part + frac_part).lstrip("0")
    if raw_digits == "":
        # All zeros (unreachable — 0.0 is already short-circuited upstream; fallback)
        return "0"

    # Strip trailing zeros → s_digits (shortest significant digits); adjust the exponent accordingly
    s_digits = raw_digits.rstrip("0")
    trailing_zeros = len(raw_digits) - len(s_digits)
    if s_digits == "":
        return "0"
    k = len(s_digits)
    # value = s_digits × 10^(exp_part − len(frac_part) + trailing_zeros)
    exp10 = exp_part - len(frac_part) + trailing_zeros

    # ECMA-262 uses (n, k, s): value = s × 10^(n−k) → n = exp10 + k
    n = exp10 + k

    # Branch 1: k ≤ n ≤ 21 (s followed by (n−k) zeros)
    if k <= n <= 21:
        return sign_prefix + s_digits + "0" * (n - k)

    # Branch 2: 0 < n ≤ 21 and n < k (first n digits + "." + remaining k−n digits)
    if 0 < n <= 21:
        return sign_prefix + s_digits[:n] + "." + s_digits[n:]

    # Branch 3: −6 < n ≤ 0 ("0." + (−n) zeros + k digits)
    if -6 < n <= 0:
        return sign_prefix + "0." + "0" * (-n) + s_digits

    # Branch 4: scientific notation, N = n − 1, with an explicit ``+``/``-`` sign
    exponent = n - 1
    exp_sign = "+" if exponent >= 0 else "-"
    exp_abs = abs(exponent)
    if k == 1:
        # Single significant digit → "se+N" (no decimal point)
        return sign_prefix + s_digits + "e" + exp_sign + str(exp_abs)
    return sign_prefix + s_digits[0] + "." + s_digits[1:] + "e" + exp_sign + str(exp_abs)


# ─── envelope wire helpers ───────────────────────────────────────────


def envelope_to_wire(envelope: dict[str, Any]) -> bytes:
    """envelope dict → wire format byte sequence (RFC 8785 + UTF-8).

    Equivalent to the byte sequence output by TS ``canonicalize`` after ``buildEnvelope``.
    """
    return canonicalize(envelope).encode("utf-8")


def envelope_from_wire(payload: bytes) -> dict[str, Any]:
    """wire format byte sequence → envelope dict (standard JSON parsing).

    fail-closed: not a dict / parse failure → WireSerializationError.
    """
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise WireSerializationError(
            f"envelope wire payload is not valid UTF-8 JSON: {exc}"
        ) from exc
    if not isinstance(decoded, dict):
        raise WireSerializationError(
            f"envelope wire payload must decode to object, got {type(decoded).__name__}"
        )
    return decoded


__all__ = [
    "WireSerializationError",
    "to_base64url",
    "from_base64url",
    "to_hex",
    "from_hex",
    "canonicalize",
    "envelope_to_wire",
    "envelope_from_wire",
]
