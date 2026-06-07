"""sdk v0.2 L0 type definitions.

Version anchor: sdkVersion == "2.0.0"

Design principles
-----------------
- TrustedSettlerDid: a brand newtype, producible only by the 3 verifier factories
- VerifiedTransportContext: pydantic BaseModel strict (5 fields; 1:1 with TS)
- SdkErrorCode: StrEnum (5 members)
- fail-closed: any verifier failure -> SdkError; no stub default success
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict

# ─── sdk version constant ───────────────────────────────────────────────────────
SDK_VERSION: str = "2.0.0"


# ─── SdkErrorCode (5 members, literally aligned with TS SdkErrorCode) ──────────────────
class SdkErrorCode(StrEnum):
    """sdk v0.2 error code enum.

    Each member is exactly aligned with TS SdkErrorCode.
    """

    # mTLS certificate chain verification failed
    SDK_MTLS_VERIFY_FAILED = "SDK_MTLS_VERIFY_FAILED"
    # JWT signature/exp/iss/aud verification failed
    SDK_JWT_VERIFY_FAILED = "SDK_JWT_VERIFY_FAILED"
    # OAuth2 introspection failed or token inactive
    SDK_OAUTH2_VERIFY_FAILED = "SDK_OAUTH2_VERIFY_FAILED"
    # DID cross-check mapping inconsistent
    SDK_MAPPING_MISMATCH = "SDK_MAPPING_MISMATCH"
    # schema field missing or wrong type
    SDK_SCHEMA_VIOLATION = "SDK_SCHEMA_VIOLATION"


class SdkError(Exception):
    """sdk v0.2 structured error.

    Attributes
    ----------
    code : SdkErrorCode — error classification
    message : str       — human-readable description
    """

    def __init__(self, code: SdkErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __repr__(self) -> str:
        return f"SdkError(code={self.code!r}, message={self.message!r})"


# ─── TrustedSettlerDid brand newtype (constructible only by the factory functions) ──────────────
class TrustedSettlerDid(str):
    """A cryptographically verified settler DID brand newtype.

    Design
    ------
    - inherits str, immutable
    - private construction; producible only via the 3 verifier factory functions (brand guard)
    - carries verifierKind metadata (used to construct VerifiedTransportContext)

    brand guard:
      raw cast / __new__ bypassing the factory is not allowed;
      any external TrustedSettlerDid(value) call -> TypeError
    """

    _FACTORY_SENTINEL: object = object()

    def __new__(cls, value: str, *, _sentinel: object | None = None) -> "TrustedSettlerDid":
        if _sentinel is not cls._FACTORY_SENTINEL:
            raise TypeError(
                "TrustedSettlerDid must be constructed via verify_mtls_and_derive_did(), "
                "verify_jwt_and_derive_did(), or verify_oauth2_and_derive_did(). "
                "Direct construction is forbidden (brand guard)."
            )
        return super().__new__(cls, value)


# ─── VerifierKind (3 kinds; aligned with the TS VerifierKind literal union) ────────
VerifierKind = Literal["mtls", "jwt", "oauth2"]


# ─── VerifiedTransportContext (5-field pydantic BaseModel) ──────────────
class VerifiedTransportContext(BaseModel):
    """A cryptographically verified transport context (sdk v0.2).

    5 fields (exactly aligned with the TS VerifiedTransportContext interface):
      trustedDid      — the verifier-verified TrustedSettlerDid
      verifierKind    — verification method ("mtls" | "jwt" | "oauth2")
      verifiedSubject — the verified subject (DID URI string; from cert CN / JWT sub / OAuth2 client_id)
      verifiedAt      — verification time (ISO 8601 UTC datetime)
      sdkVersion      — must be "2.0.0"

    Construction path
    -----------------
    Constructible only internally by the verifier factory functions (includes TrustedSettlerDid brand validation).
    """

    model_config = ConfigDict(strict=False, populate_by_name=True, extra="forbid")

    # TrustedSettlerDid is a str subclass; pydantic serializes it as str
    trustedDid: str
    verifierKind: str  # Literal["mtls", "jwt", "oauth2"]
    verifiedSubject: str
    verifiedAt: datetime
    sdkVersion: str = SDK_VERSION

    def is_fresh(self, max_age_seconds: float = 300.0) -> bool:
        """Check whether verifiedAt is within max_age_seconds (default 5 minutes).

        Args:
            max_age_seconds: the maximum allowed age (seconds)

        Returns:
            bool — True = fresh; False = expired
        """
        from datetime import timezone

        now = datetime.now(tz=timezone.utc)
        verified_at = (
            self.verifiedAt
            if self.verifiedAt.tzinfo is not None
            else self.verifiedAt.replace(tzinfo=timezone.utc)
        )
        age = (now - verified_at).total_seconds()
        return age <= max_age_seconds


__all__ = [
    "SDK_VERSION",
    "SdkErrorCode",
    "SdkError",
    "TrustedSettlerDid",
    "VerifierKind",
    "VerifiedTransportContext",
]
