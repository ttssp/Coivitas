"""Runtime validators for Brand types.

Design principles
--------
- Every Brand type goes through the ``Annotated[str, AfterValidator(_check_*)]`` path
- Pattern literals are aligned 1:1 with ``packages/types/src/schemas.ts`` (manually synced during the scaffolding phase;
  planned to be auto-synced by ``scripts/sync-brand-patterns.ts``)
- fail-closed: on a pattern mismatch → raise ValueError directly; pydantic chains it into a ValidationError
- bypassing via cast is forbidden (the Python adaptation does not permit skipping runtime validation)

Anchors
----
schemas.ts:125 didPattern
schemas.ts:127 didKeyPattern
schemas.ts:128 didAgentPattern
schemas.ts:129 hex64Pattern
schemas.ts:130 hex128Pattern
schemas.ts:134 base64url86Pattern
schemas.ts:136 base64url43Pattern
schemas.ts:137 timestampPattern
schemas.ts:139 uuidV4Pattern
schemas.ts:143 capabilityTokenIdPattern
schemas.ts:145 recordIdPattern
"""

from __future__ import annotations

import re

# ─── Pattern literals (manually synced from schemas.ts; the CI gate is taken over by the sync script) ─
# Note: Python raw-string syntax r"..."; maps one-to-one to the TS literal ASCII
_DID_PATTERN = re.compile(r"^did:[a-z][a-z0-9-]*:[a-zA-Z0-9._%-]+(?::[a-zA-Z0-9._%-]+)*$")
_DID_KEY_PATTERN = re.compile(r"^did:key:[a-zA-Z0-9._%-]+(?::[a-zA-Z0-9._%-]+)*$")
_DID_AGENT_PATTERN = re.compile(r"^did:agent:[a-f0-9]{40}$")
_HEX64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_HEX128_PATTERN = re.compile(r"^[0-9a-f]{128}$")
_BASE64URL_43_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_BASE64URL_86_PATTERN = re.compile(r"^[A-Za-z0-9_-]{86}$")
_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
_UUID_V4_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_CAP_TOKEN_ID_PATTERN = re.compile(
    r"^urn:cap:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-" r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_RECORD_ID_PATTERN = re.compile(
    r"^rec-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-" r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
# base64url strict pattern (1:1 with TS packages/crypto/src/encoding.ts:10
# ``BASE64URL_PATTERN = /^[A-Za-z0-9_-]*={0,2}$/``); padding 0-2, body ``*`` (including the empty string).
_BASE64URL_STRICT_PATTERN = re.compile(r"^[A-Za-z0-9_-]*={0,2}$")


def _ensure_str(value: object, field_name: str) -> str:
    """Type guard shared by every validator entry point; raises directly on a non-str."""
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string, got {type(value).__name__}")
    return value


# ─── Brand validator functions (pydantic AfterValidator entry points) ─────────────
# Naming rule: _check_<brand>; return value = the original validated string
# On failure → ValueError (pydantic wraps it into a ValidationError automatically)


def _check_did(value: str) -> str:
    """Validate the DID literal format (schemas.ts:125 didPattern)."""
    s = _ensure_str(value, "DID")
    if not _DID_PATTERN.match(s):
        raise ValueError(f"invalid DID format: {s!r}")
    return s


def _check_did_key(value: str) -> str:
    """Validate the did:key literal format (schemas.ts:127 didKeyPattern)."""
    s = _ensure_str(value, "DidKey")
    if not _DID_KEY_PATTERN.match(s):
        raise ValueError(f"invalid did:key format: {s!r}")
    return s


def _check_did_agent(value: str) -> str:
    """Validate the did:agent:<40-hex> literal format (schemas.ts:128 didAgentPattern)."""
    s = _ensure_str(value, "DidAgent")
    if not _DID_AGENT_PATTERN.match(s):
        raise ValueError(f"invalid did:agent format: {s!r}")
    return s


def _check_timestamp(value: str) -> str:
    """Validate an ISO 8601 millisecond UTC timestamp (schemas.ts:137 timestampPattern)."""
    s = _ensure_str(value, "Timestamp")
    if not _TIMESTAMP_PATTERN.match(s):
        raise ValueError(f"invalid timestamp format: {s!r}")
    return s


def _check_signature(value: str) -> str:
    """Validate the signature encoding (hex128 OR base64url86; schemas.ts:130/134).

    Backward-compatible tri-state coexistence: v0.1.0/v0.2.0 hex; v0.3.0 base64url.
    """
    s = _ensure_str(value, "Signature")
    if not (_HEX128_PATTERN.match(s) or _BASE64URL_86_PATTERN.match(s)):
        raise ValueError(f"invalid signature encoding: {s!r}")
    return s


def _check_public_key(value: str) -> str:
    """Validate the public key encoding (hex64 OR base64url43; schemas.ts:129/136)."""
    s = _ensure_str(value, "PublicKey")
    if not (_HEX64_PATTERN.match(s) or _BASE64URL_43_PATTERN.match(s)):
        raise ValueError(f"invalid public key encoding: {s!r}")
    return s


def _check_hash(value: str) -> str:
    """Validate the hash encoding (hex64 OR base64url43; schemas.ts:129/136)."""
    s = _ensure_str(value, "Hash")
    if not (_HEX64_PATTERN.match(s) or _BASE64URL_43_PATTERN.match(s)):
        raise ValueError(f"invalid hash encoding: {s!r}")
    return s


def _check_cap_token_id(value: str) -> str:
    """Validate the capability token URN (schemas.ts:143 capabilityTokenIdPattern)."""
    s = _ensure_str(value, "CapabilityTokenId")
    if not _CAP_TOKEN_ID_PATTERN.match(s):
        raise ValueError(f"invalid capability token id: {s!r}")
    return s


def _check_record_id(value: str) -> str:
    """Validate the record id (rec- prefix OR uuidV4; schemas.ts:145)."""
    s = _ensure_str(value, "RecordId")
    if not (_RECORD_ID_PATTERN.match(s) or _UUID_V4_PATTERN.match(s)):
        raise ValueError(f"invalid record id: {s!r}")
    return s


def _check_base64url(value: str) -> str:
    """Validate the base64url literal format (TS encoding.ts:10 BASE64URL_PATTERN).

    Strict padding validation: 0-2 trailing ``=``; body only ``[A-Za-z0-9_-]``.
    Aligned 1:1 with the TS ``fromBase64Url`` regex literal, preventing byte-level interop
    drift where 3+ padding such as ``"AA==="`` is leniently accepted on the Python side but rejected on the TS side.
    """
    s = _ensure_str(value, "Base64Url")
    if not _BASE64URL_STRICT_PATTERN.fullmatch(s):
        raise ValueError(
            f"invalid base64url: trailing padding must be 0-2 '=' chars, "
            f"alphabet must be [A-Za-z0-9_-]; got {s!r}"
        )
    return s


__all__ = [
    "_check_did",
    "_check_did_key",
    "_check_did_agent",
    "_check_timestamp",
    "_check_signature",
    "_check_public_key",
    "_check_hash",
    "_check_cap_token_id",
    "_check_record_id",
    "_check_base64url",
]
