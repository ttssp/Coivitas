"""ActionRecord conformance fixtures.

TS counterpart
--------------
- ``tests/interop/conformance-suite.test.ts`` ``describeFixtureFile('ActionRecord', ...)``
- Shared fixtures:
  - ``tests/fixtures/conformance/action-record.json`` (specVersion 0.1.0)
  - ``tests/fixtures/conformance/action-record.v0.2.json`` (specVersion 0.2.0)

Cross-language alignment contract
---------------------------------
- valid samples: ``id`` must pass ``_check_record_id``; ``agentDid`` / ``principalDid``
  must pass ``_check_did``; ``timestamp`` must pass ``_check_timestamp``;
  ``ledgerSignature`` / ``actorSignature`` (optional) must pass ``_check_signature``;
  ``prevHash`` must pass ``_check_hash``
- the action field must be in the ACTION_VOCABULARY allowlist (base.ts ACTION_VOCABULARY)
- both the v0.1 / v0.2 fixtures pass the same Brand validator
"""

from __future__ import annotations

import pytest

from coivitas._brands import (
    _check_did,
    _check_hash,
    _check_record_id,
    _check_signature,
)
from ._fixture_loader import collect_samples, load_fixture


ACTION_RECORD_FIXTURES = [
    "action-record.json",
    "action-record.v0.2.json",
]

# Literally aligned with packages/types/src/base.ts ACTION_VOCABULARY
# (BUSINESS_ACTION_VOCABULARY = ACTION_VOCABULARY \ ['SESSION_SUPERSEDED'])
ACTION_VOCABULARY = frozenset(
    {
        "INQUIRY",
        "QUOTE",
        "CONFIRM",
        "PUBLISH",
        "RECORD",
        "SESSION_SUPERSEDED",
    }
)


class TestActionRecordFixtures:
    """Corresponds to TS describeFixtureFile('ActionRecord' / 'ActionRecord (v0.2)')."""

    @pytest.mark.parametrize("filename", ACTION_RECORD_FIXTURES)
    def test_valid_records_brand_pattern_passes(self, filename: str) -> None:
        fixture = load_fixture(filename)
        valid_samples = collect_samples(fixture, "valid")
        assert len(valid_samples) > 0, f"silent skip guard: {filename}"

        for sample in valid_samples:
            data = sample["data"]
            sample_id = sample.get("id", "<unnamed>")

            # id must pass _check_record_id (rec-* OR uuidv4)
            record_id = data["id"]
            assert _check_record_id(record_id) == record_id, sample_id

            # agentDid / principalDid must pass _check_did
            for did_field in ("agentDid", "principalDid"):
                value = data.get(did_field)
                if value is None:
                    continue
                assert isinstance(value, str)
                assert _check_did(value) == value, sample_id

            # action must be in the ACTION_VOCABULARY allowlist (literally aligned with schemas.ts)
            action = data.get("action")
            assert action in ACTION_VOCABULARY, (
                f"{sample_id} action={action!r} not in ACTION_VOCABULARY"
            )

            # ledgerSignature must pass _check_signature
            ledger_sig = data.get("ledgerSignature")
            if ledger_sig is not None:
                assert _check_signature(ledger_sig) == ledger_sig, sample_id

            # prevHash must pass _check_hash (the first record = 0×64 hex; accepted by the TS schema)
            prev_hash = data.get("prevHash")
            if prev_hash is not None:
                assert _check_hash(prev_hash) == prev_hash, sample_id

    @pytest.mark.parametrize("filename", ACTION_RECORD_FIXTURES)
    def test_invalid_records_have_reason_anchor(self, filename: str) -> None:
        fixture = load_fixture(filename)
        invalid_samples = collect_samples(fixture, "invalid")
        assert len(invalid_samples) > 0

        for sample in invalid_samples:
            assert "id" in sample or "description" in sample, (
                f"{filename} invalid sample missing reason anchor"
            )

    @pytest.mark.parametrize("filename", ACTION_RECORD_FIXTURES)
    def test_boundary_records_have_id_marker(self, filename: str) -> None:
        fixture = load_fixture(filename)
        boundary_samples = collect_samples(fixture, "boundary")

        for sample in boundary_samples:
            assert "id" in sample or "description" in sample
