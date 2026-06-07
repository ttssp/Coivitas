"""audit-share v0.3 unit tests (pytest).

Coverage: Step 0-10 full-path verification (real consumption of sdk v0.2 + hcc v0.2)

Test naming convention: should_<expected behavior>_when_<condition>

API design
----------------------
The verified context is not passed in directly by the caller, to eliminate the attack surface (a caller fabricating a verified
context to bypass cryptographic verification).
API:
  - options only contains request-controllable raw_transport_evidence + record_ids, etc.
  - trusted_verifier_config is a separate function parameter of verify_audit_request_v03 (injected by the deployment side)
  - within the audit-share boundary, invoke the verify_*_and_derive_did factory -> real cryptographic derivation
These tests mock out the verifier factory (simulating "already successfully verified within the boundary"), focusing on audit-share's own
Step 0b-0d boundary + Step 1-10 logic; the factory's real behavior is covered separately by test_sdk_v02.py.

HashChainEntry field conventions
--------------------------------------
- the chain_payload_bytes parameter has been removed (payload is stored in entry.canonicalPayload)
- _make_valid_chain() uses HashChainEntry fields (canonicalPayload + timestamp)
- the first argument of concat_preimage is a str (the JCS-canonicalized payload string)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from coivitas.audit_share import (
    AuditShareError,
    AuditShareErrorCode,
    AuditShareV3VerifyOptions,
    verify_audit_request_v03,
)
from coivitas.hash_chain_canonicalize import (
    HCC_SENTINEL_HASH,
    HCC_VERSION,
    HashChainEntry,
    canonicalize_chain_identity,
    compute_canonical_payload_hash_hex,
    concat_preimage,
)
from coivitas.sdk import SDK_VERSION, VerifiedTransportContext

# verifier factory module path (patch target — takes effect at the import site inside verify.py)
_VERIFY_MOD = "coivitas.sdk.verifiers"

_DEFAULT_DID = "did:key:zQ3shmTestDid001"


# ─── test helpers ────────────────────────────────────────────────
def _make_fresh_vtx(
    did: str = _DEFAULT_DID,
    kind: str = "mtls",
) -> VerifiedTransportContext:
    """Construct a fresh VerifiedTransportContext (simulating the factory return value)."""
    return VerifiedTransportContext(
        trustedDid=did,
        verifierKind=kind,
        verifiedSubject=did,
        verifiedAt=datetime.now(tz=timezone.utc),
        sdkVersion=SDK_VERSION,
    )


def _make_stale_vtx(did: str = _DEFAULT_DID) -> VerifiedTransportContext:
    """Construct a stale VerifiedTransportContext (verifiedAt 400 seconds ago)."""
    return VerifiedTransportContext(
        trustedDid=did,
        verifierKind="mtls",
        verifiedSubject=did,
        verifiedAt=datetime.now(tz=timezone.utc) - timedelta(seconds=400),
        sdkVersion=SDK_VERSION,
    )


def _mtls_evidence() -> dict:
    """Request-controllable mtls raw evidence."""
    return {"kind": "mtls", "client_cert": "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----"}


def _mtls_config(did: str = _DEFAULT_DID) -> dict:
    """Deployment-side-injected mtls trusted config (the trust anchor)."""
    return {
        "kind": "mtls",
        "trusted_ca_pem": "-----BEGIN CERTIFICATE-----\nMOCK_CA\n-----END CERTIFICATE-----",
        "expected_did": did,
    }


def _make_options(
    did: str = _DEFAULT_DID,
    record_ids: list[str] | None = None,
    chain_entries: list | None = None,
) -> AuditShareV3VerifyOptions:
    """Construct AuditShareV3VerifyOptions (only request-controllable fields).
    payload is stored in entry.canonicalPayload (no chain_payload_bytes parameter).
    """
    return AuditShareV3VerifyOptions(
        raw_transport_evidence=_mtls_evidence(),
        record_ids=record_ids
        if record_ids is not None
        else ["rec-00000000-0000-1000-8000-000000000001"],
        requester_did=did,
        chain_entries=chain_entries if chain_entries is not None else [],
    )


def _patch_factory(vtx: VerifiedTransportContext):
    """Patch the mtls verifier factory to return the given vtx (simulating successful verification within the boundary)."""
    return patch(f"{_VERIFY_MOD}.verify_mtls_and_derive_did", return_value=vtx)


# ─── Step 0 tests: boundary checks ──────────────────────────────────────
class TestAuditShareV03Step0:
    """Step 0: raw evidence + trusted config boundary + factory-produced vtx boundary checks."""

    def should_raise_verifier_required_when_evidence_missing(self) -> None:
        """Step 0a: empty raw_transport_evidence -> AUDIT_SHARE_VERIFIER_REQUIRED (fail-closed)."""
        options = AuditShareV3VerifyOptions(
            raw_transport_evidence={},
            record_ids=["rec-00000000-0000-1000-8000-000000000001"],
            requester_did=_DEFAULT_DID,
        )
        with pytest.raises(AuditShareError) as exc_info:
            verify_audit_request_v03(options, _mtls_config())
        assert exc_info.value.code == AuditShareErrorCode.AUDIT_SHARE_VERIFIER_REQUIRED

    def should_raise_verifier_required_when_config_missing(self) -> None:
        """Step 0a: empty trusted_verifier_config -> AUDIT_SHARE_VERIFIER_REQUIRED (the trust anchor is mandatory)."""
        options = _make_options()
        with pytest.raises(AuditShareError) as exc_info:
            verify_audit_request_v03(options, {})
        assert exc_info.value.code == AuditShareErrorCode.AUDIT_SHARE_VERIFIER_REQUIRED

    def should_raise_verifier_required_when_kind_mismatch(self) -> None:
        """Step 0a: evidence.kind != config.kind -> AUDIT_SHARE_VERIFIER_REQUIRED."""
        options = _make_options()  # evidence.kind = mtls
        jwt_config = {
            "kind": "jwt",
            "jwks_uri_or_pem": "{}",
            "expected_issuer": "iss",
            "expected_audience": "aud",
            "expected_did": _DEFAULT_DID,
        }
        with pytest.raises(AuditShareError) as exc_info:
            verify_audit_request_v03(options, jwt_config)
        assert exc_info.value.code == AuditShareErrorCode.AUDIT_SHARE_VERIFIER_REQUIRED

    def should_raise_boundary_failed_when_vtx_stale(self) -> None:
        """Step 0b: factory-produced vtx is stale -> AUDIT_SHARE_BOUNDARY_CHECK_FAILED."""
        did = "did:key:zQ3shmStale001"
        options = _make_options(did=did)
        with _patch_factory(_make_stale_vtx(did)):
            with pytest.raises(AuditShareError) as exc_info:
                verify_audit_request_v03(options, _mtls_config(did))
        assert exc_info.value.code == AuditShareErrorCode.AUDIT_SHARE_BOUNDARY_CHECK_FAILED

    def should_raise_boundary_failed_when_requester_did_mismatch(self) -> None:
        """Step 0d: requester_did != factory-derived trustedDid -> AUDIT_SHARE_BOUNDARY_CHECK_FAILED."""
        # factory-derived trustedDid = trusted001; but request requester_did = different
        options = _make_options(did="did:key:zQ3shmDifferent")
        with _patch_factory(_make_fresh_vtx("did:key:zQ3shmTrusted001")):
            with pytest.raises(AuditShareError) as exc_info:
                verify_audit_request_v03(options, _mtls_config("did:key:zQ3shmTrusted001"))
        assert exc_info.value.code == AuditShareErrorCode.AUDIT_SHARE_BOUNDARY_CHECK_FAILED

    def should_raise_boundary_failed_when_unsupported_verifier_kind(self) -> None:
        """Step 0c: factory-produced vtx.verifierKind not in the allowed set -> AUDIT_SHARE_BOUNDARY_CHECK_FAILED."""
        did = "did:key:zQ3shmBadKind001"
        options = _make_options(did=did)
        bad_vtx = VerifiedTransportContext(
            trustedDid=did,
            verifierKind="unknown_kind",
            verifiedSubject=did,
            verifiedAt=datetime.now(tz=timezone.utc),
            sdkVersion=SDK_VERSION,
        )
        with _patch_factory(bad_vtx):
            with pytest.raises(AuditShareError) as exc_info:
                verify_audit_request_v03(options, _mtls_config(did))
        assert exc_info.value.code == AuditShareErrorCode.AUDIT_SHARE_BOUNDARY_CHECK_FAILED


# ─── Step 1-9 tests: basic schema validation ────────────────────────────
class TestAuditShareV03Steps1to9:
    """Steps 1-9: schema + DID format + record_ids second-line defense."""

    def should_raise_schema_violation_when_record_ids_empty(self) -> None:
        """Step 1: empty record_ids -> AUDIT_SHARE_SCHEMA_VIOLATION."""
        options = _make_options(record_ids=[])
        with _patch_factory(_make_fresh_vtx()):
            with pytest.raises(AuditShareError) as exc_info:
                verify_audit_request_v03(options, _mtls_config())
        assert exc_info.value.code == AuditShareErrorCode.AUDIT_SHARE_SCHEMA_VIOLATION

    def should_raise_schema_violation_when_requester_did_invalid(self) -> None:
        """Step 2: invalid requester_did format -> AUDIT_SHARE_SCHEMA_VIOLATION."""
        # the factory-derived trustedDid must match requester_did to pass Step 0d,
        # so mock a vtx with trustedDid = "not-a-did" (to test Step 2 DID format).
        bad_vtx = VerifiedTransportContext(
            trustedDid="not-a-did",
            verifierKind="mtls",
            verifiedSubject="not-a-did",
            verifiedAt=datetime.now(tz=timezone.utc),
            sdkVersion=SDK_VERSION,
        )
        options = _make_options(did="not-a-did")
        with _patch_factory(bad_vtx):
            with pytest.raises(AuditShareError) as exc_info:
                verify_audit_request_v03(options, _mtls_config("not-a-did"))
        assert exc_info.value.code == AuditShareErrorCode.AUDIT_SHARE_SCHEMA_VIOLATION

    def should_raise_schema_violation_when_record_id_invalid(self) -> None:
        """Step 3: invalid record_id format -> AUDIT_SHARE_SCHEMA_VIOLATION."""
        options = _make_options(record_ids=["bad-id-format"])
        with _patch_factory(_make_fresh_vtx()):
            with pytest.raises(AuditShareError) as exc_info:
                verify_audit_request_v03(options, _mtls_config())
        assert exc_info.value.code == AuditShareErrorCode.AUDIT_SHARE_SCHEMA_VIOLATION

    def should_succeed_when_all_required_fields_valid(self) -> None:
        """all fields valid -> success=True + verifier_metadata contains verifierKind."""
        options = _make_options()
        with _patch_factory(_make_fresh_vtx()):
            result = verify_audit_request_v03(options, _mtls_config())

        assert result.success is True
        assert "rec-00000000-0000-1000-8000-000000000001" in result.verified_record_ids
        assert result.verifier_metadata["verifierKind"] == "mtls"
        assert result.verifier_metadata["sdkVersion"] == SDK_VERSION


# ─── Step 10 tests: hcc v0.2 chain verify ────────────────────────
class TestAuditShareV03Step10:
    """Step 10: real consumption of hcc v0.2 verifyHashChain.

    payload is stored in entry.canonicalPayload, chain_payload_bytes is not passed separately.
    _make_valid_chain() uses the HashChainEntry 8-field schema:
      - canonicalPayload: the JCS-canonicalized payload JSON string (str type)
      - timestamp: ISO 8601 UTC string
    """

    def _make_valid_chain(self, length: int = 2) -> list[HashChainEntry]:
        """Construct a valid hash chain (length entries).

        The first argument of concat_preimage is a str (the JCS-canonicalized payload string).
        payload is stored in entry.canonicalPayload as a JSON string.
        """
        from coivitas.hash_chain_canonicalize.types import ChainIdentity

        identity: ChainIdentity = {"chainNamespace": "audit:test"}
        identity_jcs = canonicalize_chain_identity(identity)

        entries: list[HashChainEntry] = []
        prev_hash = HCC_SENTINEL_HASH
        timestamp = "2026-05-24T00:00:00+00:00"

        for i in range(length):
            # payload is a JSON string (JCS-canonicalized; this simple JSON object is already canonical)
            canonical_payload = f'{{"index":{i},"type":"audit_log"}}'
            preimage = concat_preimage(canonical_payload, identity_jcs)
            hash_val = compute_canonical_payload_hash_hex(preimage)

            entry = HashChainEntry(
                entryId=f"rec-00000000-0000-1000-8000-{i:012d}",
                chainPosition=i,
                previousHash=prev_hash,
                canonicalPayload=canonical_payload,
                canonicalPayloadHash=hash_val,
                hccVersion=HCC_VERSION,
                chainIdentity={"chainNamespace": "audit:test"},
                timestamp=timestamp,
            )
            entries.append(entry)
            prev_hash = hash_val

        return entries

    def should_pass_when_chain_valid(self) -> None:
        """Step 10: valid hash chain + matching checkpoint -> success=True."""
        chain_entries = self._make_valid_chain(2)
        options = _make_options(chain_entries=chain_entries)
        with _patch_factory(_make_fresh_vtx()):
            result = verify_audit_request_v03(
                options, _mtls_config(), {"expected_entry_count": 2}
            )
        assert result.success is True

    def should_skip_step10_when_chain_entries_empty(self) -> None:
        """when chain_entries=[], Step 10 is skipped -> success=True (normal path; an empty chain has no checkpoint requirement)."""
        options = _make_options()
        with _patch_factory(_make_fresh_vtx()):
            result = verify_audit_request_v03(options, _mtls_config())
        assert result.success is True

    def should_raise_schema_violation_when_checkpoint_missing_for_nonempty_chain(
        self,
    ) -> None:
        """a non-empty chain without a tail anchor checkpoint -> fail-closed (truncation protection)."""
        chain_entries = self._make_valid_chain(2)
        options = _make_options(chain_entries=chain_entries)
        with _patch_factory(_make_fresh_vtx()):
            with pytest.raises(AuditShareError) as exc_info:
                # no trusted_checkpoint (defaults to None) -> a non-empty chain should fail-closed
                verify_audit_request_v03(options, _mtls_config())
        assert exc_info.value.code == AuditShareErrorCode.AUDIT_SHARE_SCHEMA_VIOLATION

    def should_raise_schema_violation_when_chain_tail_truncated(self) -> None:
        """checkpoint expected_entry_count mismatch (tail truncation) -> fail-closed."""
        # real chain has 2 entries, but only the prefix 1 entry is passed + checkpoint expects 2 -> truncation detected
        chain_entries = self._make_valid_chain(2)
        truncated_entries = chain_entries[:1]
        options = _make_options(chain_entries=truncated_entries)
        with _patch_factory(_make_fresh_vtx()):
            with pytest.raises(AuditShareError) as exc_info:
                verify_audit_request_v03(
                    options, _mtls_config(), {"expected_entry_count": 2}
                )
        assert exc_info.value.code == AuditShareErrorCode.AUDIT_SHARE_SCHEMA_VIOLATION

    def should_raise_chain_identity_tampered_when_canonical_payload_hash_mismatch(self) -> None:
        """Step 10: entry.canonicalPayload tampered -> hash mismatch -> AUDIT_SHARE_CHAIN_IDENTITY_TAMPERED.

        Directly tamper with the entry.canonicalPayload field (payload is stored inside the entry) to trigger the hash mismatch.
        """
        chain_entries = self._make_valid_chain(1)
        # tamper with canonicalPayload: the hash no longer matches the original preimage
        original_entry = chain_entries[0]
        tampered_entry = HashChainEntry(
            entryId=original_entry.entryId,
            chainPosition=original_entry.chainPosition,
            previousHash=original_entry.previousHash,
            canonicalPayload='{"index":0,"type":"TAMPERED"}',  # tampered content
            canonicalPayloadHash=original_entry.canonicalPayloadHash,  # old hash unchanged
            hccVersion=original_entry.hccVersion,
            chainIdentity=original_entry.chainIdentity,
            timestamp=original_entry.timestamp,
        )
        options = _make_options(chain_entries=[tampered_entry])
        with _patch_factory(_make_fresh_vtx()):
            with pytest.raises(AuditShareError) as exc_info:
                verify_audit_request_v03(
                    options, _mtls_config(), {"expected_entry_count": 1}
                )
        assert exc_info.value.code == AuditShareErrorCode.AUDIT_SHARE_CHAIN_IDENTITY_TAMPERED


# ─── full happy path ──────────────────────────────────────────────
class TestAuditShareV03HappyPath:
    """full happy path: sdk v0.2 factory + hcc v0.2 pass together."""

    def should_return_full_result_when_all_checks_pass(self) -> None:
        """full verification PASS: returns an AuditShareV3Result containing all metadata.

        Uses the HashChainEntry 8-field schema (canonicalPayload + timestamp).
        The first argument of concat_preimage is a str (the JCS-canonicalized payload string).
        """
        from coivitas.hash_chain_canonicalize.types import ChainIdentity

        did = "did:key:zQ3shmHappyPath001"

        identity: ChainIdentity = {"chainNamespace": "happy:path"}
        identity_jcs = canonicalize_chain_identity(identity)
        # payload is stored in entry.canonicalPayload as a canonical JSON string
        canonical_payload = '{"action":"happy_path_audit","subject":"agent-001"}'
        preimage = concat_preimage(canonical_payload, identity_jcs)
        hash_val = compute_canonical_payload_hash_hex(preimage)

        entry = HashChainEntry(
            entryId="rec-00000000-0000-1000-8000-000000000001",
            chainPosition=0,
            previousHash=HCC_SENTINEL_HASH,
            canonicalPayload=canonical_payload,
            canonicalPayloadHash=hash_val,
            hccVersion=HCC_VERSION,
            chainIdentity={"chainNamespace": "happy:path"},
            timestamp="2026-05-24T00:00:00+00:00",
        )

        options = _make_options(
            did=did,
            chain_entries=[entry],
        )

        with _patch_factory(_make_fresh_vtx(did)):
            result = verify_audit_request_v03(
                options, _mtls_config(did), {"expected_entry_count": 1}
            )

        assert result.success is True
        assert result.verified_record_ids == ["rec-00000000-0000-1000-8000-000000000001"]
        assert result.verifier_metadata["verifierKind"] == "mtls"
        assert result.verifier_metadata["sdkVersion"] == SDK_VERSION
        assert len(result.errors) == 0


class TestTrustedCheckpointVerify:
    """trusted_checkpoint real-path verify.

    audit-share verify.py passes trusted_checkpoint through
    to verify_hash_chain — defending against chain rewrite (same length, same tail position, but rewritten content).
    """

    def _make_valid_chain(self, length: int = 2) -> list[HashChainEntry]:
        """helper: construct a valid hash chain (reuses the TestAuditShareV03Step10 pattern)."""
        from coivitas.hash_chain_canonicalize.types import ChainIdentity

        identity: ChainIdentity = {"chainNamespace": "audit:test"}
        identity_jcs = canonicalize_chain_identity(identity)

        entries: list[HashChainEntry] = []
        prev_hash = HCC_SENTINEL_HASH
        timestamp = "2026-05-24T00:00:00+00:00"

        for i in range(length):
            canonical_payload = f'{{"index":{i},"type":"audit_log"}}'
            preimage = concat_preimage(canonical_payload, identity_jcs)
            hash_val = compute_canonical_payload_hash_hex(preimage)
            entry = HashChainEntry(
                entryId=f"rec-00000000-0000-1000-8000-{i:012d}",
                chainPosition=i,
                previousHash=prev_hash,
                canonicalPayload=canonical_payload,
                canonicalPayloadHash=hash_val,
                hccVersion=HCC_VERSION,
                chainIdentity={"chainNamespace": "audit:test"},
                timestamp=timestamp,
            )
            entries.append(entry)
            prev_hash = hash_val

        return entries

    def should_pass_when_expected_last_hash_matches(self) -> None:
        """trusted_checkpoint containing expected_last_canonical_payload_hash, real path -> PASS."""
        chain_entries = self._make_valid_chain(2)
        options = _make_options(chain_entries=chain_entries)
        expected_last_hash = chain_entries[-1].canonicalPayloadHash
        with _patch_factory(_make_fresh_vtx()):
            result = verify_audit_request_v03(
                options,
                _mtls_config(),
                {"expected_last_canonical_payload_hash": expected_last_hash},
            )
        assert result.success is True

    def should_raise_chain_identity_tampered_when_expected_last_hash_mismatches(self) -> None:
        """trusted_checkpoint expected_last_canonical_payload_hash mismatch ->
        chain rewrite truly detected -> AUDIT_SHARE_CHAIN_IDENTITY_TAMPERED.

        Defends against chain rewrite (entry content rewritten + previousHash re-linked;
        same length, same tail position -> not caught by the count + position tail anchor; caught by the expected_last_hash anchor).
        """
        chain_entries = self._make_valid_chain(2)
        options = _make_options(chain_entries=chain_entries)
        wrong_hash = "f" * 64
        with _patch_factory(_make_fresh_vtx()):
            with pytest.raises(AuditShareError) as exc_info:
                verify_audit_request_v03(
                    options,
                    _mtls_config(),
                    {"expected_last_canonical_payload_hash": wrong_hash},
                )
        # verify_hash_chain trusted_checkpoint mismatch -> HCC_SCHEMA_VIOLATION
        # -> audit-share maps it -> AUDIT_SHARE_SCHEMA_VIOLATION (other hcc errors -> SCHEMA_VIOLATION)
        assert exc_info.value.code == AuditShareErrorCode.AUDIT_SHARE_SCHEMA_VIOLATION
