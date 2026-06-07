"""audit-share v0.3 L0 type definitions


Added (v0.3 relative to v0.2)
-------------------
- AuditShareVerifierRequiredError: AUDIT_SHARE_VERIFIER_REQUIRED
- AuditShareBoundaryCheckError: AUDIT_SHARE_BOUNDARY_CHECK_FAILED
- AuditShareChainIdentityTamperedError: AUDIT_SHARE_CHAIN_IDENTITY_TAMPERED
- AuditShareV3VerifyOptions: includes the verified_transport_ctx field (consumed by sdk v0.2)
- AuditShareV3Result: includes the verifier_metadata field (VerifiedTransportContext metadata)
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict


# ─── AuditShareErrorCode (including the 3 items added in v0.3) ────────────────────────────
class AuditShareErrorCode(StrEnum):
    """audit-share v0.3 error code enum (aligned with the TS AuditShareErrorCode literals)."""

    # ── inherited from v0.1/v0.2 ──────────────────────────────────────────────
    AUDIT_SHARE_SCHEMA_VIOLATION = "AUDIT_SHARE_SCHEMA_VIOLATION"
    AUDIT_SHARE_SIGNATURE_INVALID = "AUDIT_SHARE_SIGNATURE_INVALID"
    AUDIT_SHARE_RECORD_NOT_FOUND = "AUDIT_SHARE_RECORD_NOT_FOUND"
    AUDIT_SHARE_PERMISSION_DENIED = "AUDIT_SHARE_PERMISSION_DENIED"
    AUDIT_SHARE_TIMESTAMP_OUT_OF_RANGE = "AUDIT_SHARE_TIMESTAMP_OUT_OF_RANGE"

    # ── added in v0.3 ─────────────────────────────────────────────────────
    # Step 0 failure: VerifiedTransportContext missing (the caller did not provide an sdk v0.2 verifier)
    AUDIT_SHARE_VERIFIER_REQUIRED = "AUDIT_SHARE_VERIFIER_REQUIRED"
    # Step 0 boundary check failure (DID not in the trust set / certificate expired / cross-check inconsistent)
    AUDIT_SHARE_BOUNDARY_CHECK_FAILED = "AUDIT_SHARE_BOUNDARY_CHECK_FAILED"
    # Step 10 hcc v0.2 chainIdentity tampered
    AUDIT_SHARE_CHAIN_IDENTITY_TAMPERED = "AUDIT_SHARE_CHAIN_IDENTITY_TAMPERED"


class AuditShareError(Exception):
    """audit-share v0.3 structured error.

    Attributes
    ----
    code    : AuditShareErrorCode — error category
    message : str                 — human-readable description
    """

    def __init__(self, code: AuditShareErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __repr__(self) -> str:
        return f"AuditShareError(code={self.code!r}, message={self.message!r})"


# ─── AuditShareV3VerifyOptions (raw evidence + trusted config)
class AuditShareV3VerifyOptions(BaseModel):
    """audit-share v0.3 verification parameters (aligned with the TS AuditShareV3VerifyOptions interface).

    Trust-boundary design
    -----------------------------------
    Old-design flaw: verified_transport_ctx was supplied by the caller (the caller, outside the boundary, would
      call verify_*_and_derive_did itself to build a context and pass it in). The caller could construct a
      fresh context matching requester_did without actually proving mTLS/JWT/OAuth2 → bypassing the Step 0 cryptographic guarantee.

    New design (aligned with TS): audit-share invokes the verifier factory internally.
    - raw_transport_evidence: the artifact to be verified (dict; kind + cert/jwt/access_token) — request-controlled
    - trusted_verifier_config: trust anchors are supplied by trusted deployment configuration:
      no longer placed in options (options is request-controlled), but made a separate function parameter of
      verify_audit_request_v03 (splitting trustedVerifierConfig out of options). Otherwise the caller could still
      inject self-controlled trust anchors (CA/JWKS/introspection) via options → reproducing the original trust-boundary bug in the Python binding.

    Inherited from v0.2
    -----------
    record_ids: list of record IDs to verify
    requester_did: the requester's DID
    timestamp_window_seconds: time-window tolerance
    """

    model_config = ConfigDict(strict=False, populate_by_name=True, extra="forbid")

    # v0.3 required: the artifact to be verified (kind + cert/jwt/access_token) — request-controlled
    # Note: trusted_verifier_config is not here — it is deployment config, injected as a separate function parameter
    raw_transport_evidence: dict[str, Any]

    # Inherited from v0.2
    record_ids: list[str]
    requester_did: str
    timestamp_window_seconds: float = 300.0

    # hcc v0.2 verification options (Step 10 added in v0.3)
    # chain_payload_bytes has been removed (payload now lives in entry.canonicalPayload; the new hcc v0.2 API)
    chain_entries: list[Any] = []  # list[HashChainEntry]; an empty list skips Step 10


# ─── AuditShareV3Result (verifier_metadata field added in v0.3) ────────────
class AuditShareV3Result(BaseModel):
    """audit-share v0.3 verification result (aligned with the TS AuditShareV3Result interface).

    Added in v0.3
    ---------
    verifier_metadata: dict — a metadata snapshot of the VerifiedTransportContext
      contains verifierKind + verifiedAt + sdkVersion (no DID; for logging/auditing)

    Inherited from v0.2
    -----------
    success: bool
    verified_record_ids: list[str]
    errors: list[dict]
    """

    model_config = ConfigDict(strict=False, populate_by_name=True, extra="forbid")

    success: bool
    verified_record_ids: list[str] = []
    errors: list[dict[str, str]] = []
    # Added in v0.3: verifier metadata (for the audit log)
    verifier_metadata: dict[str, str] = {}


__all__ = [
    "AuditShareErrorCode",
    "AuditShareError",
    "AuditShareV3VerifyOptions",
    "AuditShareV3Result",
]
