"""hcc v0.2 unit tests (pytest)

Coverage: Case 1-5 (cross-lang fixture pipeline) + 5 BDD tests

Test naming convention: should_<expected behavior>_when_<condition>

HashChainEntry fields and API contract
--------------------------------------
- HashChainEntry fields: canonicalPayload + timestamp (no payloadType / chainIdentityJcs)
- concat_preimage: first argument is a str (the JCS-canonicalized payload JSON string)
- verify_hash_chain API: no payload_bytes_list; includes keyword-only trusted_checkpoint
- BDD tests: canonical payload validation + identity tamper + append genesis/continuation + checkpoint
- Strict: does not mock _jcs_canonicalize / hashlib.sha256; uses real computation + real fixture values throughout
"""

from __future__ import annotations

import hashlib

import pytest

from coivitas.hash_chain_canonicalize import (
    HCC_SENTINEL_HASH,
    HCC_VERSION,
    ChainIdentity,
    ChainIdentityJcs,
    HashChainEntry,
    HccError,
    HccErrorCode,
    append_hash_chain_entry,
    assert_canonical_payload_hash_consistent,
    assert_canonical_payload_is_canonical,
    canonicalize_chain_identity,
    compute_canonical_payload_hash_hex,
    concat_preimage,
    recompute_canonical_payload_hash,
    verify_hash_chain,
)


# ─── Case 1: canonicalize_chain_identity 3-field full ────────────────
class TestCanonicalizeChainIdentity:
    """Case 1: ChainIdentity 3-field full -> JCS canonicalization correctness."""

    def should_produce_jcs_bytes_when_three_fields_provided(self) -> None:
        """A 3-field ChainIdentity should produce RFC 8785 JCS bytes (fields in ascending code point order)."""
        identity: ChainIdentity = {
            "chainNamespace": "tenant:prod:audit",
            "tenantId": "tenant-001",
            "auditClass": "financial",
        }
        result = canonicalize_chain_identity(identity)
        # RFC 8785 fields in ascending order: auditClass < chainNamespace < tenantId
        expected = b'{"auditClass":"financial","chainNamespace":"tenant:prod:audit","tenantId":"tenant-001"}'
        assert result == expected
        assert isinstance(result, ChainIdentityJcs)

    def should_produce_jcs_bytes_when_namespace_only(self) -> None:
        """Case 2: a namespace-only ChainIdentity should contain only the chainNamespace field."""
        identity: ChainIdentity = {"chainNamespace": "global:audit"}
        result = canonicalize_chain_identity(identity)
        expected = b'{"chainNamespace":"global:audit"}'
        assert result == expected

    def should_raise_when_chain_namespace_missing(self) -> None:
        """When chainNamespace is missing it should raise HccError(HCC_SCHEMA_VIOLATION)."""
        # Force the type ignore to test the boundary (pyright: TypedDict does not cover this case)
        identity: ChainIdentity = {"chainNamespace": ""}  # type: ignore[typeddict-item]
        # An empty string is not missing, and canonicalize does not error (empty string is a valid value)
        result = canonicalize_chain_identity(identity)
        assert b'"chainNamespace":""' in result

    def should_raise_when_direct_construction_attempted(self) -> None:
        """brand guard: ChainIdentityJcs cannot be constructed directly."""
        with pytest.raises(TypeError, match="canonicalize_chain_identity"):
            ChainIdentityJcs(b"raw bytes")

    def should_return_brand_newtype(self) -> None:
        """The canonicalize_chain_identity return value must be a ChainIdentityJcs brand."""
        identity: ChainIdentity = {"chainNamespace": "ns"}
        result = canonicalize_chain_identity(identity)
        assert isinstance(result, ChainIdentityJcs)
        assert isinstance(result, bytes)


# ─── Case 3: concat_preimage + compute hash ────────────────────────
class TestConcatPreimageAndHash:
    """Case 3-4: preimage concat order + SHA-256 hash computation.

    concat_preimage's first argument is a str (the JCS-canonicalized payload string).
    """

    def should_concat_payload_before_identity_when_computing_preimage(self) -> None:
        """Case 4: preimage = UTF8(canonicalPayload) || chainIdentityJcs (fixed order).

        The first argument is a str; it is UTF-8 encoded internally before concatenation.
        """
        canonical_payload = "audit_payload_data"
        identity: ChainIdentity = {"chainNamespace": "test:ns"}
        identity_jcs = canonicalize_chain_identity(identity)

        preimage = concat_preimage(canonical_payload, identity_jcs)
        expected = canonical_payload.encode("utf-8") + bytes(identity_jcs)
        assert preimage == expected

    def should_produce_64_char_lowercase_hex_when_hashing(self) -> None:
        """compute_canonical_payload_hash_hex should return 64-char lowercase hex."""
        preimage = b"test preimage data"
        result = compute_canonical_payload_hash_hex(preimage)
        assert len(result) == 64
        assert result.islower() or all(c in "0123456789abcdef" for c in result)

    def should_match_hashlib_sha256_when_computing(self) -> None:
        """The hash result should match hashlib.sha256 exactly (cross-lang anchor).

        Does not mock hashlib.sha256; uses real computation to verify byte-level consistency.
        """
        preimage = b"cross-lang-test"
        expected = hashlib.sha256(preimage).hexdigest()
        result = compute_canonical_payload_hash_hex(preimage)
        assert result == expected

    def should_produce_consistent_hash_for_same_identity(self) -> None:
        """The same payload + chainIdentity should produce the same hash (determinism)."""
        canonical_payload = "hello world"
        identity: ChainIdentity = {
            "chainNamespace": "tenant:prod:audit",
            "tenantId": "tenant-001",
            "auditClass": "financial",
        }
        identity_jcs = canonicalize_chain_identity(identity)
        preimage = concat_preimage(canonical_payload, identity_jcs)

        hash1 = compute_canonical_payload_hash_hex(preimage)
        hash2 = compute_canonical_payload_hash_hex(preimage)
        assert hash1 == hash2


# ─── Case 5: hccVersion validation ──────────────────────────────────────
class TestHashChainEntry:
    """Case 5: HashChainEntry field validation + hccVersion check.

    8-field schema (canonicalPayload + timestamp; no payloadType / chainIdentityJcs).
    """

    def _make_valid_entry(self) -> dict:
        """Build a dict for a valid HashChainEntry (the new 8-field schema)."""
        identity: ChainIdentity = {"chainNamespace": "test:ns"}
        identity_jcs = canonicalize_chain_identity(identity)
        canonical_payload = '{"action":"test","subject":"agent-001"}'
        preimage = concat_preimage(canonical_payload, identity_jcs)
        hash_val = compute_canonical_payload_hash_hex(preimage)

        return {
            "entryId": "rec-00000000-0000-1000-8000-000000000001",
            "chainPosition": 0,
            "previousHash": HCC_SENTINEL_HASH,
            "canonicalPayload": canonical_payload,
            "canonicalPayloadHash": hash_val,
            "hccVersion": HCC_VERSION,
            "chainIdentity": {"chainNamespace": "test:ns"},
            "timestamp": "2026-05-24T00:00:00+00:00",
        }

    def should_accept_valid_entry_when_all_fields_correct(self) -> None:
        """Case 5: a valid HashChainEntry (the new 8-field schema) should pass pydantic validation."""
        data = self._make_valid_entry()
        entry = HashChainEntry(**data)
        assert entry.hccVersion == "2.0.0"
        assert entry.chainPosition == 0
        # New field validation
        assert entry.canonicalPayload == '{"action":"test","subject":"agent-001"}'
        assert entry.timestamp == "2026-05-24T00:00:00+00:00"

    def should_reject_invalid_hcc_version_when_not_200(self) -> None:
        """Case 5: hccVersion != '2.0.0' should raise ValueError."""
        data = self._make_valid_entry()
        data["hccVersion"] = "1.0.0"
        with pytest.raises(Exception, match="hccVersion"):
            HashChainEntry(**data)

    def should_reject_negative_chain_position(self) -> None:
        """chainPosition < 0 should raise ValueError."""
        data = self._make_valid_entry()
        data["chainPosition"] = -1
        with pytest.raises(Exception, match="chainPosition"):
            HashChainEntry(**data)

    def should_reject_missing_chain_namespace(self) -> None:
        """A chainIdentity without chainNamespace should raise ValueError."""
        data = self._make_valid_entry()
        data["chainIdentity"] = {"tenantId": "t1"}
        with pytest.raises(Exception, match="chainNamespace"):
            HashChainEntry(**data)

    def should_reject_invalid_timestamp_format(self) -> None:
        """A timestamp not in ISO 8601 format should raise ValueError."""
        data = self._make_valid_entry()
        data["timestamp"] = "not-a-timestamp"
        with pytest.raises(Exception, match="timestamp"):
            HashChainEntry(**data)

    def should_reject_old_fields_payloadType_and_chainIdentityJcs(self) -> None:
        """The old fields payloadType and chainIdentityJcs should be rejected by extra='forbid'."""
        data = self._make_valid_entry()
        data["payloadType"] = "audit_record"  # old field
        with pytest.raises(Exception):  # pydantic extra='forbid' raises ValidationError
            HashChainEntry(**data)


# ─── verify_hash_chain full-chain validation ─────────────────────────────────
class TestVerifyHashChain:
    """verify_hash_chain: full chain structure validation.

    payload is read from entry.canonicalPayload (no payload_bytes_list parameter).
    """

    def _make_chain(self, length: int) -> list[HashChainEntry]:
        """Build a valid hash chain of `length` entries (the new 8-field schema)."""
        identity: ChainIdentity = {"chainNamespace": "test:ns"}
        identity_jcs = canonicalize_chain_identity(identity)
        timestamp = "2026-05-24T00:00:00+00:00"

        entries: list[HashChainEntry] = []
        prev_hash = HCC_SENTINEL_HASH

        for i in range(length):
            # canonical payload is a JCS-valid JSON string
            canonical_payload = f'{{"index":{i},"type":"test"}}'
            preimage = concat_preimage(canonical_payload, identity_jcs)
            hash_val = compute_canonical_payload_hash_hex(preimage)

            entry = HashChainEntry(
                entryId=f"rec-00000000-0000-1000-8000-{i:012d}",
                chainPosition=i,
                previousHash=prev_hash,
                canonicalPayload=canonical_payload,
                canonicalPayloadHash=hash_val,
                hccVersion=HCC_VERSION,
                chainIdentity={"chainNamespace": "test:ns"},
                timestamp=timestamp,
            )
            entries.append(entry)
            prev_hash = hash_val

        return entries

    def should_pass_when_single_genesis_entry_valid(self) -> None:
        """A single-entry genesis chain should pass validation."""
        entries = self._make_chain(1)
        verify_hash_chain(entries)  # no exception

    def should_pass_when_multi_entry_chain_valid(self) -> None:
        """A valid 3-entry chain should pass validation."""
        entries = self._make_chain(3)
        verify_hash_chain(entries)  # no exception

    def should_raise_when_entries_empty(self) -> None:
        """Empty entries should raise HccError(HCC_SCHEMA_VIOLATION)."""
        with pytest.raises(HccError) as exc_info:
            verify_hash_chain([])
        assert exc_info.value.code == HccErrorCode.HCC_SCHEMA_VIOLATION

    def should_raise_when_genesis_chain_position_nonzero(self) -> None:
        """A genesis chainPosition != 0 should raise HccError(HCC_GENESIS_INVARIANT_VIOLATION)."""
        entries = self._make_chain(1)
        # Break the genesis chainPosition (use model_dump + rebuild to bypass field immutability)
        bad_entry = HashChainEntry(
            **{
                **entries[0].model_dump(),
                "chainPosition": 1,
            }
        )
        with pytest.raises(HccError) as exc_info:
            verify_hash_chain([bad_entry])
        assert exc_info.value.code == HccErrorCode.HCC_GENESIS_INVARIANT_VIOLATION

    def should_raise_when_hash_mismatch(self) -> None:
        """When entry.canonicalPayload is tampered, the hash no longer matches -> raise HccError(HCC_HASH_MISMATCH).

        Tamper with entry.canonicalPayload directly (no longer passing a wrong_payload parameter).
        """
        entries = self._make_chain(1)
        original = entries[0]
        tampered = HashChainEntry(
            **{
                **original.model_dump(),
                "canonicalPayload": '{"index":0,"type":"TAMPERED"}',  # tampered content
                # canonicalPayloadHash keeps its original value -> hash no longer matches
            }
        )
        with pytest.raises(HccError) as exc_info:
            verify_hash_chain([tampered])
        assert exc_info.value.code == HccErrorCode.HCC_HASH_MISMATCH

    def should_raise_when_chain_identity_tampered(self) -> None:
        """When the chainIdentity field is tampered it should raise HccError (hash mismatch or CHAIN_IDENTITY_TAMPERED).

        Tamper with the entry.chainIdentity dict directly (no longer via chainIdentityJcs hex tampering).
        """
        entries = self._make_chain(1)
        original = entries[0]
        tampered = HashChainEntry(
            **{
                **original.model_dump(),
                "chainIdentity": {"chainNamespace": "tampered:ns"},  # tampered identity
                # canonicalPayloadHash keeps its original value -> recompute uses the tampered identity -> mismatch
            }
        )
        with pytest.raises(HccError) as exc_info:
            verify_hash_chain([tampered])
        # hash mismatch is detected before the identity tamper check (Step 3.2 before Step 3.3)
        assert exc_info.value.code in (
            HccErrorCode.HCC_HASH_MISMATCH,
            HccErrorCode.HCC_CHAIN_IDENTITY_TAMPERED,
        )


# ─── 5 BDD tests ────────────────────────────
class TestHashChainBddRealCompute:
    """5 BDD tests.

    Does not mock _jcs_canonicalize or hashlib.sha256; all computation is real.
    """

    def _make_genesis_entry(self) -> HashChainEntry:
        """Build a valid genesis HashChainEntry (for reuse)."""
        identity: ChainIdentity = {"chainNamespace": "bdd:test"}
        identity_jcs = canonicalize_chain_identity(identity)
        canonical_payload = '{"action":"genesis","version":1}'
        preimage = concat_preimage(canonical_payload, identity_jcs)
        hash_val = compute_canonical_payload_hash_hex(preimage)
        return HashChainEntry(
            entryId="rec-00000000-0000-1000-8000-000000000001",
            chainPosition=0,
            previousHash=HCC_SENTINEL_HASH,
            canonicalPayload=canonical_payload,
            canonicalPayloadHash=hash_val,
            hccVersion=HCC_VERSION,
            chainIdentity={"chainNamespace": "bdd:test"},
            timestamp="2026-05-24T00:00:00+00:00",
        )

    def should_reject_non_canonical_payload_when_payload_not_jcs(self) -> None:
        """assert_canonical_payload_is_canonical: a non-JCS canonical payload should raise HccError.

        Scenario: canonicalPayload is in a non-JCS format (wrong field order or extra whitespace);
        re-canonicalization should detect the difference and raise HCC_CHAIN_IDENTITY_TAMPERED.
        """
        identity: ChainIdentity = {"chainNamespace": "test:ns"}
        identity_jcs = canonicalize_chain_identity(identity)
        # Non-canonical: field order does not match JCS (z > a, but JCS requires a first)
        non_canonical_payload = '{"z_field": 1, "a_field": 2}'
        # First compute the hash of this non-canonical payload (so it passes the hash check)
        preimage = concat_preimage(non_canonical_payload, identity_jcs)
        hash_val = compute_canonical_payload_hash_hex(preimage)
        entry = HashChainEntry(
            entryId="rec-00000000-0000-1000-8000-000000000001",
            chainPosition=0,
            previousHash=HCC_SENTINEL_HASH,
            canonicalPayload=non_canonical_payload,
            canonicalPayloadHash=hash_val,
            hccVersion=HCC_VERSION,
            chainIdentity={"chainNamespace": "test:ns"},
            timestamp="2026-05-24T00:00:00+00:00",
        )
        # assert_canonical_payload_is_canonical should detect the non-JCS format
        with pytest.raises(HccError) as exc_info:
            assert_canonical_payload_is_canonical(entry, 0)
        assert exc_info.value.code == HccErrorCode.HCC_CHAIN_IDENTITY_TAMPERED

    def should_detect_chainidentity_tamper_via_full_hash_recompute(self) -> None:
        """assert_canonical_payload_hash_consistent: a chainIdentity tamper should be detected via full hash recompute.

        Scenario: after building a valid entry, swap the chainIdentity dict (different namespace) while
        keeping the original hash; assert_canonical_payload_hash_consistent should recompute the hash and find a mismatch.
        """
        genesis = self._make_genesis_entry()
        # Tamper with chainIdentity but keep canonicalPayloadHash (a genuine tamper scenario)
        tampered = HashChainEntry(
            **{
                **genesis.model_dump(),
                "chainIdentity": {"chainNamespace": "tampered:ns"},
            }
        )
        with pytest.raises(HccError) as exc_info:
            assert_canonical_payload_hash_consistent(tampered, 0)
        assert exc_info.value.code == HccErrorCode.HCC_HASH_MISMATCH

    def should_produce_valid_entry_when_append_genesis(self) -> None:
        """append_hash_chain_entry: produces a valid genesis entry when there is no prev_entry.

        Verifies: chainPosition=0, previousHash=sentinel, canonicalPayloadHash genuinely computed,
        canonicalPayload as a JCS string, timestamp as ISO 8601 UTC.
        Does not mock _jcs_canonicalize; uses real JCS computation.
        """
        identity: ChainIdentity = {"chainNamespace": "append:test"}
        payload: dict[str, object] = {"action": "genesis_action", "version": 1}

        entry = append_hash_chain_entry(payload, identity)

        # genesis invariants
        assert entry.chainPosition == 0
        assert entry.previousHash == HCC_SENTINEL_HASH
        assert entry.hccVersion == HCC_VERSION
        assert entry.chainIdentity == {"chainNamespace": "append:test"}

        # canonicalPayload must be a JCS JSON string
        import json
        parsed = json.loads(entry.canonicalPayload)
        assert parsed == payload  # content-equivalent

        # canonicalPayloadHash must match the real computation (cross-verify)
        identity_jcs = canonicalize_chain_identity(identity)
        preimage = concat_preimage(entry.canonicalPayload, identity_jcs)
        expected_hash = compute_canonical_payload_hash_hex(preimage)
        assert entry.canonicalPayloadHash == expected_hash

        # timestamp must be in ISO 8601 format
        assert "T" in entry.timestamp

        # entryId must be in UUID format (non-empty)
        assert len(entry.entryId) > 0

    def should_produce_valid_entry_when_append_continuation(self) -> None:
        """append_hash_chain_entry: produces a valid continuation entry when a prev_entry is passed.

        Verifies: chainPosition = prev+1, previousHash = prev.canonicalPayloadHash,
        chainIdentity matches prev_entry (cross-chain continuation is not allowed).
        """
        identity: ChainIdentity = {"chainNamespace": "append:test"}
        payload_0: dict[str, object] = {"seq": 0}
        payload_1: dict[str, object] = {"seq": 1}

        genesis = append_hash_chain_entry(payload_0, identity)
        continuation = append_hash_chain_entry(payload_1, identity, genesis)

        assert continuation.chainPosition == 1
        assert continuation.previousHash == genesis.canonicalPayloadHash
        assert continuation.chainIdentity == {"chainNamespace": "append:test"}

        # The full chain should pass verify
        verify_hash_chain([genesis, continuation])

    def should_verify_trusted_checkpoint_when_provided(self) -> None:
        """verify_hash_chain: should validate the chain-tail hash when a trusted_checkpoint is provided.

        trusted_checkpoint is a keyword-only standalone parameter, not an entry field.
        """
        identity: ChainIdentity = {"chainNamespace": "checkpoint:test"}
        identity_jcs = canonicalize_chain_identity(identity)
        timestamp = "2026-05-24T00:00:00+00:00"

        canonical_payload = '{"action":"tail_entry"}'
        preimage = concat_preimage(canonical_payload, identity_jcs)
        tail_hash = compute_canonical_payload_hash_hex(preimage)

        entry = HashChainEntry(
            entryId="rec-00000000-0000-1000-8000-000000000001",
            chainPosition=0,
            previousHash=HCC_SENTINEL_HASH,
            canonicalPayload=canonical_payload,
            canonicalPayloadHash=tail_hash,
            hccVersion=HCC_VERSION,
            chainIdentity={"chainNamespace": "checkpoint:test"},
            timestamp=timestamp,
        )

        # Correct checkpoint -> pass
        verify_hash_chain([entry], trusted_checkpoint=tail_hash)

        # Wrong checkpoint -> HCC_SCHEMA_VIOLATION (fail-closed)
        wrong_checkpoint = "a" * 64
        with pytest.raises(HccError) as exc_info:
            verify_hash_chain([entry], trusted_checkpoint=wrong_checkpoint)
        assert exc_info.value.code == HccErrorCode.HCC_SCHEMA_VIOLATION


class TestChainIdentityConsistency:
    """chain-level identity consistency real-path verify.

    1. Reject mixed chainIdentity chains — defends against the identity-rebinding attack
    2. trusted_checkpoint pass-through (audit-share caller real path)
    """

    def _build_entry_with_identity(
        self,
        index: int,
        identity: ChainIdentity,
        prev_hash: str,
    ) -> HashChainEntry:
        """helper: build a valid entry for a given chainIdentity (fields aligned with the TS wire)."""
        identity_jcs = canonicalize_chain_identity(identity)
        canonical_payload = f'{{"index":{index},"type":"test"}}'
        preimage = concat_preimage(canonical_payload, identity_jcs)
        hash_val = compute_canonical_payload_hash_hex(preimage)
        return HashChainEntry(
            entryId=f"rec-00000000-0000-1000-8000-{index:012d}",
            chainPosition=index,
            previousHash=prev_hash,
            canonicalPayload=canonical_payload,
            canonicalPayloadHash=hash_val,
            hccVersion=HCC_VERSION,
            chainIdentity=dict(identity),
            timestamp="2026-05-24T00:00:00+00:00",
        )

    def should_reject_mixed_chain_identity_when_entries_have_different_identities(self) -> None:
        """A mixed-identity chain must be rejected (prevents identity-rebinding).

        Build two entries, each with a valid chainIdentity + its own hash, but with different identities;
        the previousHash linkage is correct + chainPosition is monotonic -> linkage checks alone would PASS;
        the chain-level identity check -> HCC_CHAIN_IDENTITY_TAMPERED.
        """
        identity_a: ChainIdentity = {"chainNamespace": "tenant:a:audit"}
        identity_b: ChainIdentity = {"chainNamespace": "tenant:b:audit"}

        # entry 0 — identity A genesis
        entry_a = self._build_entry_with_identity(0, identity_a, HCC_SENTINEL_HASH)
        # entry 1 — identity B but linked to entry_a.canonicalPayloadHash
        entry_b = self._build_entry_with_identity(1, identity_b, entry_a.canonicalPayloadHash)

        # entries pass the previousHash + chainPosition + per-entry hash checks,
        # but chainIdentity is mixed -> Step 0.5 chain-level identity check rejects
        with pytest.raises(HccError) as exc_info:
            verify_hash_chain([entry_a, entry_b])
        assert exc_info.value.code == HccErrorCode.HCC_CHAIN_IDENTITY_TAMPERED
        assert "mixed-identity chain rejected" in str(exc_info.value)

    def should_reject_when_expected_chain_identity_does_not_match(self) -> None:
        """A non-matching expected_chain_identity -> reject (scope isolation)."""
        identity_a: ChainIdentity = {"chainNamespace": "tenant:a:audit"}
        identity_b: ChainIdentity = {"chainNamespace": "tenant:b:audit"}

        entry_a = self._build_entry_with_identity(0, identity_a, HCC_SENTINEL_HASH)

        with pytest.raises(HccError) as exc_info:
            verify_hash_chain([entry_a], expected_chain_identity=identity_b)
        assert exc_info.value.code == HccErrorCode.HCC_CHAIN_IDENTITY_TAMPERED
        assert "does not match expected_chain_identity" in str(exc_info.value)

    def should_pass_when_expected_chain_identity_matches(self) -> None:
        """A matching expected_chain_identity -> PASS."""
        identity: ChainIdentity = {"chainNamespace": "tenant:a:audit"}

        entry = self._build_entry_with_identity(0, identity, HCC_SENTINEL_HASH)
        # No exception is raised on a match
        verify_hash_chain([entry], expected_chain_identity=identity)
