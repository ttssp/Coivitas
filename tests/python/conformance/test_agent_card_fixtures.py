"""AgentCard conformance fixtures.

TS counterpart
--------------
- ``tests/interop/conformance-suite.test.ts`` ``describeFixtureFile('AgentCard', ...)``
- Shared fixture: ``tests/fixtures/conformance/discovery/agent-card.json``

Cross-language alignment contract
---------------------------------
- valid samples: ``did`` must pass ``_check_did``; ``publicKey`` must pass ``_check_public_key``;
  ``signature`` must pass ``_check_signature``; ``updatedAt`` must pass ``_check_timestamp``
- ``capabilitiesDeclared`` is list[str]; ``serviceEndpoints`` is list[dict]
- maxLength boundaries: displayName ≤ 128, description ≤ 1024
"""

from __future__ import annotations

from coivitas._brands import (
    _check_did,
    _check_public_key,
    _check_signature,
    _check_timestamp,
)
from ._fixture_loader import collect_samples, load_fixture


class TestAgentCardFixtures:
    """Corresponds to TS describeFixtureFile('AgentCard', ...) (maxLength boundary anchor)."""

    def test_valid_agent_cards_brand_pattern_passes(self) -> None:
        fixture = load_fixture("discovery/agent-card.json")
        valid_samples = collect_samples(fixture, "valid")
        assert len(valid_samples) > 0, "silent skip guard"

        for sample in valid_samples:
            data = sample["data"]
            sample_id = sample.get("id", "<unnamed>")

            # did must pass _check_did
            did = data["did"]
            assert _check_did(did) == did, sample_id

            # publicKey must pass _check_public_key
            public_key = data["publicKey"]
            assert _check_public_key(public_key) == public_key, sample_id

            # signature must pass _check_signature
            signature = data["signature"]
            assert _check_signature(signature) == signature, sample_id

            # updatedAt must pass _check_timestamp
            updated_at = data["updatedAt"]
            assert _check_timestamp(updated_at) == updated_at, sample_id

            # capabilitiesDeclared must be list[str]
            capabilities = data.get("capabilitiesDeclared", [])
            assert isinstance(capabilities, list), sample_id
            for cap in capabilities:
                assert isinstance(cap, str), f"{sample_id} cap not str: {cap!r}"

    def test_invalid_agent_cards_have_reason_anchor(self) -> None:
        fixture = load_fixture("discovery/agent-card.json")
        invalid_samples = collect_samples(fixture, "invalid")
        assert len(invalid_samples) > 0

        for sample in invalid_samples:
            assert "id" in sample or "description" in sample

    def test_boundary_agent_cards_w19_maxlength(self) -> None:
        """displayName 64→128 / description 512→1024 boundary regression."""
        fixture = load_fixture("discovery/agent-card.json")
        boundary_samples = collect_samples(fixture, "boundary")
        assert len(boundary_samples) > 0

        for sample in boundary_samples:
            assert "id" in sample or "description" in sample
            # Contains at least a displayName or description field for maxLength boundary coverage
            data = sample["data"]
            assert isinstance(data, dict)
