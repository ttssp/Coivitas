"""Authorization conformance fixtures.

TS counterpart
--------------
- Shared fixtures: the 4 files ``tests/fixtures/conformance/authorization/*.json``:
  - ``capability-token-fixtures.json`` (valid/invalid shape)
  - ``policy-engine-vectors.json`` (vectors[] shape)
  - ``runtime-guard-vectors.json`` (vectors[] shape)
  - ``scope-evaluator-vectors.json`` (vectors[] shape)

Cross-language alignment contract
---------------------------------
- ``capability-token-fixtures.json``: in valid samples ``id`` must pass ``_check_cap_token_id``
- ``vectors[]`` shape: every vector must contain ``id`` + ``expected`` anchors (no drift allowed)
- valid count > 0 for all vector files (silent-skip guard)
"""

from __future__ import annotations

import pytest

from coivitas._brands import (
    _check_cap_token_id,
    _check_did,
    _check_timestamp,
)
from ._fixture_loader import collect_samples, load_fixture


# ─── capability-token-fixtures.json (valid/invalid) ─────────────────


class TestCapabilityTokenAuthorizationFixtures:
    """authorization/capability-token-fixtures.json valid/invalid."""

    def test_valid_tokens_brand_pattern_passes(self) -> None:
        fixture = load_fixture("authorization/capability-token-fixtures.json")
        valid_samples = collect_samples(fixture, "valid")
        assert len(valid_samples) > 0, "silent skip guard"

        for sample in valid_samples:
            data = sample["data"]
            sample_id = sample.get("id", "<unnamed>")
            token_id = data["id"]
            assert _check_cap_token_id(token_id) == token_id, sample_id

            # issuerDid / principalDid / issuedTo must pass _check_did
            for did_field in ("issuerDid", "principalDid", "issuedTo"):
                value = data.get(did_field)
                if value is not None:
                    assert isinstance(value, str)
                    assert _check_did(value) == value, sample_id

            # issuedAt must pass _check_timestamp (if present)
            issued_at = data.get("issuedAt")
            if issued_at is not None:
                assert _check_timestamp(issued_at) == issued_at, sample_id

    def test_invalid_tokens_have_reason_anchor(self) -> None:
        fixture = load_fixture("authorization/capability-token-fixtures.json")
        invalid_samples = collect_samples(fixture, "invalid")
        assert len(invalid_samples) > 0
        for sample in invalid_samples:
            assert "id" in sample or "description" in sample


# ─── vectors[] shape files (policy / runtime-guard / scope-evaluator) ─────


VECTOR_FIXTURE_FILES = [
    "authorization/policy-engine-vectors.json",
    "authorization/runtime-guard-vectors.json",
    "authorization/scope-evaluator-vectors.json",
]


class TestAuthorizationVectorFixtures:
    """vectors[] shape: every vector must contain id + expected anchors."""

    @pytest.mark.parametrize("filename", VECTOR_FIXTURE_FILES)
    def test_vectors_present_and_have_id_expected(self, filename: str) -> None:
        fixture = load_fixture(filename)
        vectors = fixture.get("vectors")
        assert isinstance(vectors, list), f"{filename} missing vectors[]"
        assert len(vectors) > 0, f"{filename} silent-skip guard: vectors must be non-empty"

        for index, vector in enumerate(vectors):
            assert isinstance(vector, dict), f"{filename}[{index}] not dict"
            # Each vector contains an id anchor (fixture-author contract; same source as the TS tests)
            assert "id" in vector, (
                f"{filename}[{index}] missing 'id' anchor: {vector}"
            )
            # Contains an expected field (behavioral expectation; consistent with the TS test)
            assert "expected" in vector, (
                f"{filename}[{index}] missing 'expected' anchor: {vector}"
            )

    def test_scope_evaluator_vectors_have_scope_and_params(self) -> None:
        """scope-evaluator-vectors.json specific: every vector contains scope + params."""
        fixture = load_fixture("authorization/scope-evaluator-vectors.json")
        vectors = fixture["vectors"]
        for vector in vectors:
            # scope-evaluator's vector shape (aligned with the ts/policy/scope-evaluator input)
            assert "scope" in vector, f"{vector.get('id')} missing scope"
            assert "params" in vector, f"{vector.get('id')} missing params"
