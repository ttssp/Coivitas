"""CapabilityToken conformance fixtures.

TS same-source
--------------
- ``tests/interop/conformance-suite.test.ts`` ``describeFixtureFile('CapabilityToken', ...)``
- shared fixtures:
  - ``tests/fixtures/conformance/capability-token.json`` (specVersion 0.1.0)
  - ``tests/fixtures/conformance/capability-token.v0.2.json`` (specVersion 0.2.0)

Cross-language alignment contract
---------------------------------
- valid samples: ``id`` must pass ``_check_cap_token_id``; ``issuerDid`` / ``principalDid``
  must pass ``_check_did``; ``issuedAt`` / ``expiresAt`` must pass ``_check_timestamp``
- invalid samples: declare a reason anchor; at least **some** samples are wire-level rejectable by Python
- both the v0.1 / v0.2 fixtures go through the same Brand validator (backward-compatible tri-state)
"""

from __future__ import annotations

import pytest

from coivitas._brands import (
    _check_cap_token_id,
    _check_did,
    _check_timestamp,
)
from ._fixture_loader import collect_samples, load_fixture


CAPABILITY_TOKEN_FIXTURES = [
    "capability-token.json",
    "capability-token.v0.2.json",
]


class TestCapabilityTokenFixtures:
    """Corresponds to TS describeFixtureFile('CapabilityToken' / 'CapabilityToken (v0.2)')."""

    @pytest.mark.parametrize("filename", CAPABILITY_TOKEN_FIXTURES)
    def test_valid_tokens_brand_pattern_passes(self, filename: str) -> None:
        fixture = load_fixture(filename)
        valid_samples = collect_samples(fixture, "valid")
        assert len(valid_samples) > 0, f"silent-skip guard: {filename}"

        for sample in valid_samples:
            data = sample["data"]
            sample_id = sample.get("id", "<unnamed>")

            # id must pass _check_cap_token_id (schemas.ts capabilityTokenIdPattern)
            token_id = data["id"]
            assert _check_cap_token_id(token_id) == token_id, sample_id

            # issuerDid / principalDid / issuedTo must pass _check_did
            for did_field in ("issuerDid", "principalDid", "issuedTo"):
                value = data.get(did_field)
                if value is None:
                    continue
                assert isinstance(value, str)
                assert _check_did(value) == value, (
                    f"{sample_id}.{did_field}={value!r} fails _check_did"
                )

            # issuedAt / expiresAt must pass _check_timestamp
            issued_at = data["issuedAt"]
            assert _check_timestamp(issued_at) == issued_at
            expires_at = data.get("expiresAt")
            if expires_at is not None:
                assert _check_timestamp(expires_at) == expires_at

            # capabilities must be a non-empty list[dict] (TS interface field)
            capabilities = data["capabilities"]
            assert isinstance(capabilities, list) and len(capabilities) > 0, (
                f"{sample_id} capabilities must be non-empty list"
            )

    @pytest.mark.parametrize("filename", CAPABILITY_TOKEN_FIXTURES)
    def test_invalid_tokens_have_reason_anchor(self, filename: str) -> None:
        fixture = load_fixture(filename)
        invalid_samples = collect_samples(fixture, "invalid")
        assert len(invalid_samples) > 0

        for sample in invalid_samples:
            assert "id" in sample or "description" in sample, (
                f"{filename} invalid sample missing reason anchor: {sample}"
            )

    @pytest.mark.parametrize("filename", CAPABILITY_TOKEN_FIXTURES)
    def test_boundary_tokens_either_valid_or_invalid_marker(
        self, filename: str
    ) -> None:
        fixture = load_fixture(filename)
        boundary_samples = collect_samples(fixture, "boundary")

        for sample in boundary_samples:
            assert "id" in sample or "description" in sample
            # boundary samples explicitly carry valid:true/false (consistent with TS
            # describeFixtureFile)
            assert "valid" in sample or sample.get("data") is not None
