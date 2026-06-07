"""hcc v0.2 L0 type definitions.

Version anchor: hccVersion == "2.0.0"

Design principles
-----------------
- ChainIdentity: an RFC 8785 JCS serializable TypedDict (exactly corresponds to the TS ChainIdentity interface)
- ChainIdentityJcs: a brand newtype, constructible only by the canonicalize_chain_identity() factory
- HashChainEntry: pydantic BaseModel strict (8 fields; 1:1 with TS HashChainEntry)
- HccErrorCode: StrEnum (8 members; literally aligned with TS HccErrorCode)
- fail-closed: there is no legal path to construct ChainIdentityJcs outside the factory
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import NotRequired, TypedDict

from pydantic import BaseModel, ConfigDict, field_validator

# ─── hcc protocol version constant ──────────────────────────────────────────────────
HCC_VERSION: str = "2.0.0"

# ─── HccErrorCode (8 members, literally aligned with the TS HccErrorCode enum) ─────────────
HCC_SENTINEL_HASH: str = "0" * 64  # 64 zero characters; genesis previousHash


class HccErrorCode(StrEnum):
    """hcc v0.2 error code enum.

    Each member is exactly aligned with TS HccErrorCode; the Python side uses it as the code field when raising.
    """

    HCC_SCHEMA_VIOLATION = "HCC_SCHEMA_VIOLATION"
    # genesis condition violated: chainPosition != 0 or previousHash != sentinel
    HCC_GENESIS_INVARIANT_VIOLATION = "HCC_GENESIS_INVARIANT_VIOLATION"
    # non-genesis condition violated: previousHash == sentinel but chainPosition > 0
    HCC_CONTINUATION_INVARIANT_VIOLATION = "HCC_CONTINUATION_INVARIANT_VIOLATION"
    # canonicalPayloadHash recomputation differs from the stored value (preimage tampered)
    HCC_HASH_MISMATCH = "HCC_HASH_MISMATCH"
    # chainPosition monotonic-increase violated
    HCC_CHAIN_POSITION_NOT_MONOTONIC = "HCC_CHAIN_POSITION_NOT_MONOTONIC"
    # previousHash linkage broken
    HCC_LINK_BROKEN = "HCC_LINK_BROKEN"
    # chainIdentity field tampered (recompute differs from stored JCS)
    HCC_CHAIN_IDENTITY_TAMPERED = "HCC_CHAIN_IDENTITY_TAMPERED"
    # hccVersion is not "2.0.0"
    HCC_VERSION_MISMATCH = "HCC_VERSION_MISMATCH"


class HccError(Exception):
    """hcc v0.2 structured error.

    Attributes
    ----------
    code : HccErrorCode — error classification
    message : str       — human-readable description
    """

    def __init__(self, code: HccErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __repr__(self) -> str:
        return f"HccError(code={self.code!r}, message={self.message!r})"


# ─── ChainIdentity (3-field TypedDict; safe for RFC 8785 JCS serialization) ──────────
class ChainIdentity(TypedDict):
    """Chain identity (the three-field set that enters the hash preimage).

    Fields (1:1 with the TS ChainIdentity interface):
      chainNamespace  — required; namespace string (e.g. "tenant:prod:audit")
      tenantId        — optional; tenant identifier
      auditClass      — optional; audit classification identifier

    JCS rules (RFC 8785):
      - fields ordered by ascending Unicode code point (JCS fixed)
      - include only non-undefined fields (TS: strip undefined values -> Python: only include present keys)
      - final serialized result = bytes (UTF-8), used for the preimage concat
    """

    chainNamespace: str
    tenantId: NotRequired[str]
    auditClass: NotRequired[str]


# ─── ChainIdentityJcs (brand newtype; constructible only by the factory function) ──────────────
class ChainIdentityJcs(bytes):
    """The JCS RFC 8785 canonical serialization of a ChainIdentity (brand newtype).

    Design:
      - inherits bytes, immutable
      - private construction; producible only via the canonicalize_chain_identity() factory (fail-closed)
      - directly comparing two ChainIdentityJcs instances == byte-level equivalence check
    """

    # Factory-construction marker (prevents bypassing the factory from outside)
    _FACTORY_SENTINEL: object = object()

    def __new__(cls, data: bytes, *, _sentinel: object | None = None) -> "ChainIdentityJcs":
        # Only a caller holding _FACTORY_SENTINEL may construct (brand guard)
        if _sentinel is not cls._FACTORY_SENTINEL:
            raise TypeError(
                "ChainIdentityJcs must be constructed via canonicalize_chain_identity(). "
                "Direct construction is forbidden (brand guard)."
            )
        instance = super().__new__(cls, data)
        return instance


# ─── HashChainEntry (8-field pydantic BaseModel; L0 data model) ───────────
class HashChainEntry(BaseModel):
    """A single hash chain entry (hcc v0.2).

    8 fields (exactly aligned with the TS HashChainEntry interface):
      entryId              — entry unique ID (UUID v4 or RecordId format)
      canonicalPayload     — JCS-canonicalized payload JSON string (RFC 8785)
      canonicalPayloadHash — SHA-256(UTF8(canonicalPayload) || UTF8(chainIdentityJcs)) lowercase hex 64
      previousHash         — predecessor entry's canonicalPayloadHash (genesis = 64 zero characters)
      chainPosition        — position within the chain (0 = genesis)
      chainIdentity        — chain identity (chainNamespace + tenantId? + auditClass?)
      timestamp            — entry write time (ISO 8601 UTC)
      hccVersion           — must be "2.0.0"
    """

    model_config = ConfigDict(strict=True, populate_by_name=True, extra="forbid")

    entryId: str
    canonicalPayload: str           # added (TS L194): JCS-canonicalized payload JSON string
    canonicalPayloadHash: str
    previousHash: str
    chainPosition: int
    chainIdentity: dict[str, str]   # ChainIdentity fields stored as a dict (safe for JSON round-trip)
    timestamp: str                  # added (TS L211): ISO 8601 UTC
    hccVersion: str

    @field_validator("chainPosition")
    @classmethod
    def _validate_chain_position(cls, v: int) -> int:
        # chain position is non-negative
        if v < 0:
            raise ValueError(f"chainPosition must be >= 0, got {v}")
        return v

    @field_validator("previousHash", "canonicalPayloadHash")
    @classmethod
    def _validate_hex64(cls, v: str) -> str:
        # 64-char lowercase hex (SHA-256 output format)
        if not re.fullmatch(r"[0-9a-f]{64}", v):
            raise ValueError(f"expected 64-char lowercase hex, got {v!r}")
        return v

    @field_validator("hccVersion")
    @classmethod
    def _validate_hcc_version(cls, v: str) -> str:
        # the hcc v0.2 protocol version is fixed at "2.0.0"
        if v != HCC_VERSION:
            raise ValueError(f"hccVersion must be {HCC_VERSION!r}, got {v!r}")
        return v

    @field_validator("chainIdentity")
    @classmethod
    def _validate_chain_identity(cls, v: dict[str, str]) -> dict[str, str]:
        # chainNamespace is a required field
        if "chainNamespace" not in v:
            raise ValueError("chainIdentity.chainNamespace is required")
        # only the 3 known fields are allowed
        allowed = {"chainNamespace", "tenantId", "auditClass"}
        unknown = set(v.keys()) - allowed
        if unknown:
            raise ValueError(f"chainIdentity has unknown fields: {unknown}")
        return v

    @field_validator("timestamp")
    @classmethod
    def _validate_timestamp(cls, v: str) -> str:
        # simple ISO 8601 UTC format validation (ending in YYYY-MM-DDTHH:MM:SS...+00:00 or ...Z)
        # allowed: 2026-05-24T00:00:00+00:00 / 2026-05-24T00:00:00Z / 2026-05-24T00:00:00.123456+00:00
        if not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", v):
            raise ValueError(f"timestamp must be ISO 8601 format, got {v!r}")
        return v


__all__ = [
    "HCC_VERSION",
    "HCC_SENTINEL_HASH",
    "HccErrorCode",
    "HccError",
    "ChainIdentity",
    "ChainIdentityJcs",
    "HashChainEntry",
]
