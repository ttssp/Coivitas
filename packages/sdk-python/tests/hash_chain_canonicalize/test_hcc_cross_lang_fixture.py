"""cross-lang HCC fixture consumer (TS Producer -> Python Consumer)

Roles
-----
TS HCC v0.2 (packages/types + packages/crypto/hash-chain-canonicalize)
is the authoritative producer of cross-lang golden bytes; this file is the
Python-side consumer test.
fixture path: tests/fixtures/cross-lang/hcc-vectors.json
generation command: pnpm --filter @coivitas/sdk hcc:fixtures:regenerate

Anti self-equal principle
-------------------------
The expected value must be read from the fixture JSON; computing and asserting
the same expected value within one test is not allowed.
Correct form::
    expected_hash = vector["expected_canonical_payload_hash_per_position"][i]  # from fixture
    actual_hash = compute_canonical_payload_hash_hex(preimage)                  # Python recompute
    assert actual_hash == expected_hash

cross-lang anchor coverage
--------------------------
1. JCS canonicalize (TS canonicalize npm <-> Python jcs/stdlib fallback): RFC 8785 byte-level
2. preimage concat order (canonicalPayloadBytes || chainIdentityJcsBytes)
3. SHA-256 hash byte-level (TS @noble/hashes <-> Python hashlib)
4. recursive hash linkage (previousHash linkage across entries)
5. NEGATIVE: mixed-identity reject (V6) + tampered hash reject (V7)

Test naming convention: should_<expected behavior>_when_<condition>
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from coivitas.hash_chain_canonicalize import (
    ChainIdentity,
    HashChainEntry,
    HccError,
    HccErrorCode,
    canonicalize_chain_identity,
    compute_canonical_payload_hash_hex,
    concat_preimage,
    recompute_canonical_payload_hash,
    verify_hash_chain,
)


# ─── Path constants (packages/sdk-python/tests/hash_chain_canonicalize/ -> 4 levels up = REPO_ROOT) ──

_REPO_ROOT = Path(__file__).resolve().parents[4]
_FIXTURE_PATH = _REPO_ROOT / "tests" / "fixtures" / "cross-lang" / "hcc-vectors.json"


# ─── Fixture loading helpers ──────────────────────────────────────────────────────


def _load_fixture() -> dict[str, Any]:
    """Load hcc-vectors.json. If it does not exist, point to the generator."""
    if not _FIXTURE_PATH.exists():
        raise FileNotFoundError(
            f"hcc-vectors.json missing at {_FIXTURE_PATH}; "
            "run 'pnpm --filter @coivitas/sdk hcc:fixtures:regenerate' first"
        )
    with _FIXTURE_PATH.open("r", encoding="utf-8") as f:
        data: dict[str, Any] = json.load(f)
    return data


def _build_chain_identity(d: dict[str, str]) -> ChainIdentity:
    """Build a ChainIdentity TypedDict from the fixture JSON chainIdentity dict (present fields only)."""
    identity: ChainIdentity = {"chainNamespace": d["chainNamespace"]}
    if "tenantId" in d:
        identity["tenantId"] = d["tenantId"]
    if "auditClass" in d:
        identity["auditClass"] = d["auditClass"]
    return identity


def _entries_from_vector(vector: dict[str, Any]) -> list[HashChainEntry]:
    """Build a list of HashChainEntry pydantic instances from fixture vector["entries"]."""
    return [HashChainEntry.model_validate(e) for e in vector["entries"]]


# ─── TestHashChainFixtureConsumer ──────────────────────────────────────────


class TestHashChainFixtureConsumer:
    """Python HCC v0.2 consumes the TS fixture to verify cross-lang byte-level consistency (PASS vectors V1-V5).

    All expected values are read from the fixture JSON; Python only recomputes and asserts.
    """

    def test_should_load_version_v0_2_when_hcc_fixture_is_read(self) -> None:
        """should load version v0.2 when hcc fixture is read."""
        fixture = _load_fixture()
        assert fixture["version"] == "v0.2"
        assert fixture["hcc_version"] == "2.0.0"

    def test_should_contain_seven_vectors_when_hcc_fixture_is_loaded(self) -> None:
        """should contain 7 vectors (V1-V5 PASS + V6/V7 NEGATIVE) when fixture is loaded."""
        fixture = _load_fixture()
        assert len(fixture["vectors"]) == 7
        ids = [v["id"] for v in fixture["vectors"]]
        assert "V1-genesis-only" in ids
        assert "V2-three-entry-chain" in ids
        assert "V3-five-entry-chain" in ids
        assert "V4-unicode-emoji-payload" in ids
        assert "V5-multi-field-identity" in ids
        assert "V6-NEGATIVE-mixed-identity" in ids
        assert "V7-NEGATIVE-tampered-hash" in ids

    def test_should_match_ts_concat_preimage_byte_exact_for_all_pass_vectors(self) -> None:
        """should match TS concat_preimage bytes for all PASS vectors V1-V5 (byte-exact)."""
        fixture = _load_fixture()
        failures: list[str] = []
        for v in fixture["vectors"]:
            if v["expected_verify_outcome"] != "PASS":
                continue
            identity = _build_chain_identity(v["chainIdentity"])
            identity_jcs = canonicalize_chain_identity(identity)
            for i, entry_dict in enumerate(v["entries"]):
                entry = HashChainEntry.model_validate(entry_dict)
                # Python recomputes the preimage
                preimage = concat_preimage(entry.canonicalPayload, identity_jcs)
                # expected comes from the fixture (TS-produced); Python does not recompute expected
                expected_hex: str = v["expected_concat_preimage_hex_per_position"][i]
                actual_hex = preimage.hex()
                if actual_hex != expected_hex:
                    failures.append(
                        f"  {v['id']} entry[{i}]:\n"
                        f"    expected={expected_hex!r}\n"
                        f"    actual  ={actual_hex!r}"
                    )
        assert not failures, (
            f"Python concat_preimage diverged from TS for {len(failures)} entry/vectors:\n"
            + "\n".join(failures)
        )

    def test_should_match_ts_canonical_payload_hash_byte_exact_for_all_pass_vectors(
        self,
    ) -> None:
        """should match TS canonical_payload_hash for all PASS vectors V1-V5 (byte-exact)."""
        fixture = _load_fixture()
        failures: list[str] = []
        for v in fixture["vectors"]:
            if v["expected_verify_outcome"] != "PASS":
                continue
            identity = _build_chain_identity(v["chainIdentity"])
            identity_jcs = canonicalize_chain_identity(identity)
            for i, entry_dict in enumerate(v["entries"]):
                entry = HashChainEntry.model_validate(entry_dict)
                preimage = concat_preimage(entry.canonicalPayload, identity_jcs)
                actual_hash = compute_canonical_payload_hash_hex(preimage)
                # expected comes from the fixture (TS-produced)
                expected_hash: str = v["expected_canonical_payload_hash_per_position"][i]
                if actual_hash != expected_hash:
                    failures.append(
                        f"  {v['id']} entry[{i}]:\n"
                        f"    expected={expected_hash!r}\n"
                        f"    actual  ={actual_hash!r}"
                    )
                # In a PASS vector, the stored canonicalPayloadHash should equal the recomputed value
                if entry.canonicalPayloadHash != expected_hash:
                    failures.append(
                        f"  {v['id']} entry[{i}] stored vs expected:\n"
                        f"    stored  ={entry.canonicalPayloadHash!r}\n"
                        f"    expected={expected_hash!r}"
                    )
        assert not failures, (
            f"Python canonical_payload_hash diverged from TS for {len(failures)} entry/vectors:\n"
            + "\n".join(failures)
        )

    def test_should_pass_verify_hash_chain_for_all_pass_vectors(self) -> None:
        """should pass verify_hash_chain for all PASS vectors V1-V5 (full chain consistency)."""
        fixture = _load_fixture()
        failures: list[str] = []
        for v in fixture["vectors"]:
            if v["expected_verify_outcome"] != "PASS":
                continue
            entries = _entries_from_vector(v)
            expected_identity = _build_chain_identity(v["chainIdentity"])
            try:
                # Run verify_hash_chain — chain-level identity + recursive hash linkage + per-entry hash check
                verify_hash_chain(entries, expected_chain_identity=expected_identity)
            except HccError as exc:
                failures.append(
                    f"  {v['id']}: verify_hash_chain raised HccError "
                    f"code={exc.code.value} message={exc.message!r}"
                )
        assert not failures, (
            f"verify_hash_chain unexpectedly rejected {len(failures)} PASS vector(s):\n"
            + "\n".join(failures)
        )

    def test_should_pass_trusted_checkpoint_when_using_expected_final_hash(self) -> None:
        """should pass trusted_checkpoint when checkpoint == expected_final_hash for V1-V5."""
        fixture = _load_fixture()
        failures: list[str] = []
        for v in fixture["vectors"]:
            if v["expected_verify_outcome"] != "PASS":
                continue
            entries = _entries_from_vector(v)
            expected_identity = _build_chain_identity(v["chainIdentity"])
            checkpoint: str = v["expected_final_hash"]
            try:
                verify_hash_chain(
                    entries,
                    trusted_checkpoint=checkpoint,
                    expected_chain_identity=expected_identity,
                )
            except HccError as exc:
                failures.append(
                    f"  {v['id']}: trusted_checkpoint verify raised "
                    f"code={exc.code.value} message={exc.message!r}"
                )
        assert not failures, (
            f"trusted_checkpoint verify failed for {len(failures)} PASS vector(s):\n"
            + "\n".join(failures)
        )

    def test_should_reject_mixed_identity_chain_when_consuming_v6_negative(self) -> None:
        """should reject mixed-identity chain when consuming V6 NEGATIVE vector.

        V6: entry[1].chainIdentity is replaced with a different tenant; Python
        verify_hash_chain must raise HCC_CHAIN_IDENTITY_TAMPERED via the chain-level
        identity consistency check.
        """
        fixture = _load_fixture()
        v6 = next(v for v in fixture["vectors"] if v["id"] == "V6-NEGATIVE-mixed-identity")
        assert v6["expected_verify_outcome"] == "REJECT"
        assert v6["expected_reject_error_code"] == "HCC_CHAIN_IDENTITY_TAMPERED"

        entries = _entries_from_vector(v6)
        # Pass no expected_chain_identity — even without a scope guard, V6 must still be
        # rejected by the chain-level identity consistency check (entry[0] vs entry[1]
        # have different chainIdentity).
        with pytest.raises(HccError) as exc_info:
            verify_hash_chain(entries)
        assert exc_info.value.code == HccErrorCode.HCC_CHAIN_IDENTITY_TAMPERED
        # Error message substring check (defined literally in the fixture)
        expected_substring: str = v6["expected_reject_error_substring"]
        assert expected_substring in exc_info.value.message, (
            f"V6 expected error message containing {expected_substring!r}, "
            f"got: {exc_info.value.message!r}"
        )

    def test_should_reject_v6_with_scope_isolation_when_expected_identity_provided(
        self,
    ) -> None:
        """should reject V6 with scope isolation when expected_chain_identity provided.

        V6 entry[0].chainIdentity = audit-A/tenant-A; if the caller passes
        expected_chain_identity = audit-A, entry[1] (audit-B) triggers a mixed-identity reject;
        if it passes expected_chain_identity = audit-B, entry[0] (audit-A) triggers a scope isolation reject.
        """
        fixture = _load_fixture()
        v6 = next(v for v in fixture["vectors"] if v["id"] == "V6-NEGATIVE-mixed-identity")
        entries = _entries_from_vector(v6)
        # Pass audit-A scope expected: entry[0] match, entry[1] mismatch (mixed)
        expected_a = _build_chain_identity(v6["chainIdentity"])  # audit-A
        with pytest.raises(HccError) as exc_a:
            verify_hash_chain(entries, expected_chain_identity=expected_a)
        assert exc_a.value.code == HccErrorCode.HCC_CHAIN_IDENTITY_TAMPERED

        # Pass audit-B scope expected: entry[0] (audit-A) mismatch immediately
        expected_b: ChainIdentity = {
            "chainNamespace": "audit-B",
            "tenantId": "tenant-B",
            "auditClass": "L1",
        }
        with pytest.raises(HccError) as exc_b:
            verify_hash_chain(entries, expected_chain_identity=expected_b)
        assert exc_b.value.code == HccErrorCode.HCC_CHAIN_IDENTITY_TAMPERED

    def test_should_reject_tampered_hash_when_consuming_v7_negative(self) -> None:
        """should reject tampered hash when consuming V7 NEGATIVE vector.

        V7: the last entry[2].canonicalPayloadHash has 1 character flipped (stored != recompute);
        Python verify_hash_chain raises HCC_HASH_MISMATCH via assert_canonical_payload_hash_consistent.
        """
        fixture = _load_fixture()
        v7 = next(v for v in fixture["vectors"] if v["id"] == "V7-NEGATIVE-tampered-hash")
        assert v7["expected_verify_outcome"] == "REJECT"
        assert v7["expected_reject_error_code"] == "HCC_HASH_MISMATCH"

        entries = _entries_from_vector(v7)
        expected_identity = _build_chain_identity(v7["chainIdentity"])

        with pytest.raises(HccError) as exc_info:
            verify_hash_chain(entries, expected_chain_identity=expected_identity)
        # V7 has a single chainIdentity, so the identity check passes; the hash recompute check fails.
        # Step 2 (chainPosition + previousHash linkage) could fire first — but entry[2].previousHash
        # points to entry[1].canonicalPayloadHash (valid), and tampering entry[2].canonicalPayloadHash
        # does not affect the previousHash linkage (the chain stops at entry[2]); so the Step 3 hash
        # recompute is the first failure point.
        assert exc_info.value.code == HccErrorCode.HCC_HASH_MISMATCH
        expected_substring: str = v7["expected_reject_error_substring"]
        assert expected_substring in exc_info.value.message, (
            f"V7 expected error message containing {expected_substring!r}, "
            f"got: {exc_info.value.message!r}"
        )

    def test_should_compute_preimage_hex_byte_exact_for_v7_pristine_value(self) -> None:
        """should compute preimage hex byte-exact for V7 pristine value.

        V7 entry[2].canonicalPayloadHash is the tampered (flipped) value; but
        expected_canonical_payload_hash_per_position[2] is the original (pre-tamper) value.
        The Python recompute should equal the pre-tamper value (a preimage->hash algorithm-correctness anchor).
        """
        fixture = _load_fixture()
        v7 = next(v for v in fixture["vectors"] if v["id"] == "V7-NEGATIVE-tampered-hash")
        identity = _build_chain_identity(v7["chainIdentity"])
        identity_jcs = canonicalize_chain_identity(identity)
        # Take the last entry
        last_idx = len(v7["entries"]) - 1
        last_entry = HashChainEntry.model_validate(v7["entries"][last_idx])
        preimage = concat_preimage(last_entry.canonicalPayload, identity_jcs)
        actual_hex = preimage.hex()
        # expected_concat_preimage_hex comes from the fixture
        expected_hex: str = v7["expected_concat_preimage_hex_per_position"][last_idx]
        assert actual_hex == expected_hex
        # The recomputed hash should equal the fixture pre-tamper expected (the "correct value" apart from entries[2].canonicalPayloadHash)
        actual_hash = compute_canonical_payload_hash_hex(preimage)
        expected_hash: str = v7["expected_canonical_payload_hash_per_position"][last_idx]
        assert actual_hash == expected_hash
        # Verify stored (post-tamper) != expected (pre-tamper)
        assert last_entry.canonicalPayloadHash != expected_hash, (
            "V7 stored canonicalPayloadHash should differ from pre-tamper expected"
        )
        # And the difference is exactly 1 character (flipped tamper_last_hash_char_index=0)
        diff_count = sum(
            1
            for a, b in zip(last_entry.canonicalPayloadHash, expected_hash, strict=True)
            if a != b
        )
        assert diff_count == 1, (
            f"V7 expected 1-char diff between stored and pre-tamper hash, "
            f"got {diff_count} diffs"
        )

    def test_should_recompute_canonical_payload_hash_byte_exact_for_all_pass_entries(
        self,
    ) -> None:
        """should recompute canonical_payload_hash byte-exact via recompute_canonical_payload_hash.

        Covers the recompute_canonical_payload_hash() helper's same-source algorithm path
        (canonicalize_chain_identity -> concat_preimage -> compute_canonical_payload_hash_hex).
        Cross-validated bidirectionally with the V7 recompute path.
        """
        fixture = _load_fixture()
        failures: list[str] = []
        for v in fixture["vectors"]:
            if v["expected_verify_outcome"] != "PASS":
                continue
            for i, entry_dict in enumerate(v["entries"]):
                entry = HashChainEntry.model_validate(entry_dict)
                actual = recompute_canonical_payload_hash(entry)
                expected: str = v["expected_canonical_payload_hash_per_position"][i]
                if actual != expected:
                    failures.append(
                        f"  {v['id']} entry[{i}]: actual={actual!r}, expected={expected!r}"
                    )
        assert not failures, (
            f"recompute_canonical_payload_hash diverged from TS for {len(failures)} entry/vectors:\n"
            + "\n".join(failures)
        )

    def test_should_handle_unicode_emoji_payload_when_consuming_v4(self) -> None:
        """should handle Unicode CJK + emoji canonicalPayload when consuming V4.

        In V4, canonicalPayload contains CJK + emoji; verify that Python JCS (jcs/stdlib fallback)
        and the TS canonicalize npm are byte-level consistent in UTF-8 + field code-point ordering.
        """
        fixture = _load_fixture()
        v4 = next(v for v in fixture["vectors"] if v["id"] == "V4-unicode-emoji-payload")
        identity = _build_chain_identity(v4["chainIdentity"])
        identity_jcs = canonicalize_chain_identity(identity)
        # Recompute and assert byte-exact for every entry
        for i, entry_dict in enumerate(v4["entries"]):
            entry = HashChainEntry.model_validate(entry_dict)
            # canonicalPayload contains CJK + emoji characters — must UTF-8 encode correctly
            preimage = concat_preimage(entry.canonicalPayload, identity_jcs)
            expected_hex: str = v4["expected_concat_preimage_hex_per_position"][i]
            assert preimage.hex() == expected_hex, (
                f"V4 entry[{i}] preimage mismatch (Unicode UTF-8 cross-lang divergence?)"
            )
            actual_hash = compute_canonical_payload_hash_hex(preimage)
            expected_hash: str = v4["expected_canonical_payload_hash_per_position"][i]
            assert actual_hash == expected_hash

    def test_should_verify_recursive_hash_linkage_when_consuming_multi_entry_chains(
        self,
    ) -> None:
        """should verify previousHash recursive linkage for V2/V3/V4/V5 multi-entry chains."""
        fixture = _load_fixture()
        failures: list[str] = []
        for v in fixture["vectors"]:
            if v["expected_verify_outcome"] != "PASS":
                continue
            entries = _entries_from_vector(v)
            if len(entries) < 2:
                continue  # skip V1 (single entry)
            # Each entry[i].previousHash must equal entry[i-1].canonicalPayloadHash
            for i in range(1, len(entries)):
                prev_hash_field = entries[i].previousHash
                prev_canonical_hash = entries[i - 1].canonicalPayloadHash
                if prev_hash_field != prev_canonical_hash:
                    failures.append(
                        f"  {v['id']} entry[{i}].previousHash={prev_hash_field!r} != "
                        f"entries[{i-1}].canonicalPayloadHash={prev_canonical_hash!r}"
                    )
            # genesis entry[0].previousHash must be 64 zeros
            if entries[0].previousHash != "0" * 64:
                failures.append(
                    f"  {v['id']} entry[0].previousHash != 64-zero sentinel: "
                    f"{entries[0].previousHash!r}"
                )
        assert not failures, (
            f"recursive hash linkage broken for {len(failures)} entry/vectors:\n"
            + "\n".join(failures)
        )
