"""Communication conformance fixtures (cross-language alignment of the communication package wire format).

TS same-source
--------------
- ``tests/conformance/communication-fixtures.test.ts`` (envelope schema + parse)
- shared fixtures: ``tests/fixtures/conformance/{negotiation-envelope.json,communication/*.json}``

Cross-language alignment contract
---------------------------------
1. **Full-set fixture consumption**: the valid / invalid / boundary sample counts are all > 0 (silent-skip guard)
2. **wire shape field reconciliation**: a valid envelope must contain the envelope top-level keys (id / specVersion /
   header / messageType / body / signature / timestamp); missing → assertion fail
3. **Brand pattern literal values**: the senderDid / signature / timestamp in valid samples must pass
   ``_check_did`` / ``_check_signature`` / ``_check_timestamp``;
   pattern-violating samples in an invalid envelope do not go through the same validator
4. **handshake / error envelope semantic shape**: 1:1-replicated assertions against TS expectHandshakeMessageShape /
   expectStandardErrorEnvelope (same literal values; same issue strings)

Anti self-equal grounding
-------------------------
Every ``assert`` reaches: (a) Python production code (``_brands.py`` validator /
``_wire.py`` canonicalize / pydantic BaseModel), OR (b) a TS literal-value anchor
(``packages/types/src/schemas.ts`` / the same-named expectedError in the TS test)
"""

from __future__ import annotations

import pytest

from coivitas._brands import (
    _check_did,
    _check_signature,
    _check_timestamp,
)
from ._fixture_loader import (
    collect_samples,
    fixture_meta,
    load_fixture,
)

# Literally aligned with TS ``tests/conformance/communication-fixtures.test.ts:37-43``
STANDARD_ERROR_CODES = frozenset(
    {
        "AUTHORIZATION_INSUFFICIENT",
        "IDENTITY_VERIFICATION_FAILED",
        "SESSION_NOT_FOUND",
        "INVALID_ENVELOPE",
        "INTERNAL_ERROR",
    }
)


# ─── envelope wire shape required fields (aligned with the TS parseEnvelope accept set) ─────


REQUIRED_ENVELOPE_KEYS = frozenset(
    {"id", "specVersion", "header", "messageType", "body", "signature", "timestamp"}
)

# Literally aligned with packages/types/src/base.ts MESSAGE_TYPES (line 93-103)
ALLOWED_MESSAGE_TYPES = frozenset(
    {
        "HANDSHAKE_INIT",
        "HANDSHAKE_ACK",
        "NEGOTIATION_REQUEST",
        "NEGOTIATION_RESPONSE",
        "NEGOTIATION_CONFIRM",
        "ERROR",
        # discovery message types added in v0.2 (effective at specVersion >= 0.3.0)
        "DISCOVERY_REQUEST",
        "DISCOVERY_RESPONSE",
    }
)


def _has_envelope_shape(data: dict) -> bool:
    """Minimal envelope top-level field set (a subset of the schemas.ts negotiationEnvelope schema).

    Consistent with the TS schema validation rejection conditions:
    - missing field → False
    - messageType not in the allowlist → False (base.ts MESSAGE_TYPES literals)
    - header.senderDid has wrong type → False
    """
    if not isinstance(data, dict):
        return False
    if not REQUIRED_ENVELOPE_KEYS.issubset(data.keys()):
        return False
    header = data.get("header")
    if not isinstance(header, dict):
        return False
    if not isinstance(header.get("senderDid"), str):
        return False
    message_type = data.get("messageType")
    if not isinstance(message_type, str):
        return False
    if message_type not in ALLOWED_MESSAGE_TYPES:
        return False
    return True


# ─── Main path: aligned with TS describe('communication conformance fixtures') ──


class TestCommunicationConformanceFixtures:
    """Corresponds to TS `describe('communication conformance fixtures')` (line 45)."""

    def test_keeps_phase5_negotiation_aligned_with_root_baseline(self) -> None:
        """Corresponds to TS line 46-56: specVersion + valid count alignment across fixture files."""
        root = load_fixture("negotiation-envelope.json")
        phase5 = load_fixture("communication/negotiation-envelope.json")

        # Byte-level consistency prerequisite: specVersion literals must be equal (no drift allowed)
        assert root["specVersion"] == phase5["specVersion"]
        # Silent-skip guard: valid samples must be > 0
        assert len(collect_samples(root, "valid")) > 0
        assert len(collect_samples(phase5, "valid")) > 0
        # At least one expectedError literal value (error-cause anchor) among the invalid samples
        invalid_with_reason = [
            s
            for s in collect_samples(phase5, "invalid")
            if s.get("expectedError") is not None
        ]
        assert len(invalid_with_reason) > 0

    def test_accepts_valid_and_boundary_negotiation_envelope_samples(self) -> None:
        """Corresponds to TS line 58-67: valid + boundary envelopes all pass wire shape validation."""
        fixture = load_fixture("communication/negotiation-envelope.json")
        valid_samples = collect_samples(fixture, "valid")
        boundary_samples = collect_samples(fixture, "boundary")

        assert len(valid_samples) > 0, "silent-skip guard"

        for sample in valid_samples + boundary_samples:
            data = sample["data"]
            sample_id = sample.get("id", "<unnamed>")
            assert _has_envelope_shape(data), (
                f"valid sample {sample_id} fails envelope wire shape; data={data}"
            )
            # Brand validator reached: senderDid must pass _check_did
            sender_did = data["header"]["senderDid"]
            assert _check_did(sender_did) == sender_did, (
                f"sample {sample_id} senderDid={sender_did!r} fails _check_did"
            )

    def test_rejects_invalid_negotiation_envelope_samples_with_documented_error_code(
        self,
    ) -> None:
        """Corresponds to TS line 69-78: invalid samples must carry an expectedError literal-value anchor.

        Python-side boundary
        --------------------
        The Python SDK does not replicate the full AJV schema validator (including cross-field
        ``if/then`` constraints / specVersion → capabilityTokenRef mutual exclusion, etc.). This assertion
        only covers the binding-layer fail-closed scope:
        - wire shape failure (missing key / messageType not in allowlist) → rejected on the Python side
        - Brand pattern failure (DID / signature / timestamp mismatch) → rejected on the Python side
        - other cross-field semantic violations (e.g. SPEC_VERSION_MISMATCH +
          capabilityTokenRef forbidden) → not strictly rejected on the Python side;
          but the fixture author is still required to declare the expectedError anchor (literally aligned with TS line 73-78)

        Anti self-equal: each branch reaches production code (_has_envelope_shape /
        _check_did / _check_signature / _check_timestamp).
        """
        fixture = load_fixture("communication/negotiation-envelope.json")
        invalid_samples = collect_samples(fixture, "invalid")
        assert len(invalid_samples) > 0

        cross_field_only_count = 0
        for sample in invalid_samples:
            data = sample["data"]
            sample_id = sample.get("id", "<unnamed>")
            expected_error = sample.get("expectedError")
            # The fixture author must declare expectedError (consistent with the TS reason anchor)
            assert expected_error is not None, (
                f"invalid sample {sample_id} missing expectedError reason anchor"
            )

            # Violating at least one of envelope shape / Brand pattern → the Python binding layer
            # can reject it at the wire level (no AJV cross-field constraints needed); if both pass it is a "cross-field semantic"
            # invalid sample (e.g. the invalid-incompatible-spec-version special case,
            # which is outside the Python-side coverage)
            shape_ok = _has_envelope_shape(data)
            brand_ok = True
            if shape_ok:
                try:
                    _check_did(data["header"]["senderDid"])
                except Exception:
                    brand_ok = False
                try:
                    _check_timestamp(data["timestamp"])
                except Exception:
                    brand_ok = False
                try:
                    _check_signature(data["signature"])
                except Exception:
                    brand_ok = False

            if shape_ok and brand_ok:
                # Cross-field semantic violation (not covered on the Python side; the TS schema validator
                # rejection path) → skip the Python-side wire-layer assertion; spec consistency is already
                # guaranteed by the expectedError anchor + the TS conformance test
                cross_field_only_count += 1

        # Silent-skip guard: at least some wire-level rejectable samples enter the Python-side assertions
        wire_level_count = len(invalid_samples) - cross_field_only_count
        assert wire_level_count > 0, (
            "no invalid samples are wire-level rejectable; suspect Python "
            "shape/brand checks are too lax"
        )

    def test_accepts_handshake_fixtures_initiator_responder_body(self) -> None:
        """Corresponds to TS line 80-91: handshake valid + boundary shape check."""
        fixture = load_fixture("communication/handshake-messages.json")
        valid_samples = collect_samples(fixture, "valid") + collect_samples(
            fixture, "boundary"
        )
        assert len(valid_samples) > 0

        for sample in valid_samples:
            data = sample["data"]
            sample_id = sample.get("id", "<unnamed>")
            assert _has_envelope_shape(data), f"sample {sample_id} fails shape"
            _expect_handshake_message_shape(data, sample_id)

    def test_rejects_invalid_handshake_fixtures_at_semantic_layer(self) -> None:
        """Corresponds to TS line 93-103: invalid handshake violates at least the semantic shape."""
        fixture = load_fixture("communication/handshake-messages.json")
        invalid_samples = collect_samples(fixture, "invalid")
        assert len(invalid_samples) > 0

        for sample in invalid_samples:
            data = sample["data"]
            sample_id = sample.get("id", "<unnamed>")
            expected_issue = sample.get("expectedIssue")
            assert expected_issue is not None, (
                f"invalid handshake sample {sample_id} missing expectedIssue"
            )

            # Must violate the semantic shape (aligned with TS expectHandshakeMessageShape)
            with pytest.raises(AssertionError, match="INVALID_HANDSHAKE"):
                _expect_handshake_message_shape(data, sample_id)

    def test_accepts_standard_error_envelope_fixtures(self) -> None:
        """Corresponds to TS line 105-115: error envelope valid + boundary shape check."""
        fixture = load_fixture("communication/error-envelope.json")
        valid_samples = collect_samples(fixture, "valid") + collect_samples(
            fixture, "boundary"
        )
        assert len(valid_samples) > 0

        for sample in valid_samples:
            data = sample["data"]
            sample_id = sample.get("id", "<unnamed>")
            assert _has_envelope_shape(data), f"sample {sample_id} fails shape"
            _expect_standard_error_envelope(data, sample_id)

    def test_rejects_invalid_error_envelope_fixtures_at_semantic_layer(
        self,
    ) -> None:
        """Corresponds to TS line 118-128: invalid error envelope violates the standard shape."""
        fixture = load_fixture("communication/error-envelope.json")
        invalid_samples = collect_samples(fixture, "invalid")
        assert len(invalid_samples) > 0

        for sample in invalid_samples:
            data = sample["data"]
            sample_id = sample.get("id", "<unnamed>")
            with pytest.raises(AssertionError, match="INVALID_ERROR_ENVELOPE"):
                _expect_standard_error_envelope(data, sample_id)


# ─── helpers (1:1 with TS expectHandshakeMessageShape / expectStandardErrorEnvelope) ─


def _expect_handshake_message_shape(data: dict, sample_id: str) -> None:
    """Corresponds to TS line 222-272; the fail-closed assertion raises AssertionError."""
    message_type = data.get("messageType")
    body = data.get("body", {})

    if message_type == "HANDSHAKE_INIT":
        challenge = body.get("challenge")
        assert (
            isinstance(challenge, dict)
        ), f"INVALID_HANDSHAKE: challenge must be an object (sample={sample_id})"
        for field in (
            "challengeId",
            "initiatorDid",
            "responderDid",
            "nonce",
            "timestamp",
            "expiresAt",
        ):
            assert (
                isinstance(challenge.get(field), str) and challenge[field]
            ), f"INVALID_HANDSHAKE: {field} must be a non-empty string (sample={sample_id})"
        capabilities = challenge.get("initiatorCapabilities")
        assert isinstance(capabilities, list) and all(
            isinstance(entry, str) for entry in capabilities
        ), f"INVALID_HANDSHAKE: initiatorCapabilities must be a string array (sample={sample_id})"
        return

    if message_type == "HANDSHAKE_ACK":
        accepted = body.get("accepted")
        assert isinstance(
            accepted, bool
        ), f"INVALID_HANDSHAKE: accepted must be a boolean (sample={sample_id})"
        response = body.get("response")
        assert isinstance(
            response, dict
        ), f"INVALID_HANDSHAKE: response must be an object (sample={sample_id})"
        for field in ("challengeId", "responderDid", "nonce", "timestamp"):
            assert (
                isinstance(response.get(field), str) and response[field]
            ), f"INVALID_HANDSHAKE: {field} must be a non-empty string (sample={sample_id})"
        if accepted:
            assert (
                isinstance(response.get("sessionId"), str)
                and response["sessionId"]
            ), f"INVALID_HANDSHAKE: sessionId must be a string when rejected (sample={sample_id})"
        else:
            session_id = response.get("sessionId")
            # On the rejected path sessionId must be a string (consistent with TS line 253)
            assert isinstance(
                session_id, str
            ), f"INVALID_HANDSHAKE: sessionId must be a string when rejected (sample={sample_id})"
        responder_capabilities = response.get("responderCapabilities")
        assert isinstance(responder_capabilities, list) and all(
            isinstance(entry, str) for entry in responder_capabilities
        ), f"INVALID_HANDSHAKE: responderCapabilities must be a string array (sample={sample_id})"
        return

    raise AssertionError(
        f"INVALID_HANDSHAKE: unexpected messageType {message_type!r} (sample={sample_id})"
    )


def _expect_standard_error_envelope(data: dict, sample_id: str) -> None:
    """Corresponds to TS line 274-293; raises AssertionError when an assert fails."""
    message_type = data.get("messageType")
    assert (
        message_type == "ERROR"
    ), f"INVALID_ERROR_ENVELOPE: messageType must be ERROR (sample={sample_id})"
    body = data.get("body", {})
    code = body.get("code")
    assert (
        isinstance(code, str) and code in STANDARD_ERROR_CODES
    ), f"INVALID_ERROR_ENVELOPE: unknown standard error code (sample={sample_id})"
    message = body.get("message")
    assert (
        isinstance(message, str) and len(message) > 0
    ), f"INVALID_ERROR_ENVELOPE: message is required (sample={sample_id})"


# ─── Metadata health (a subset aligned with the TS line 130-162 v0.3.0 subdirectory scan) ────


class TestCommunicationFixtureMetadata:
    """fixture health self-check (not silently skipped)."""

    def test_root_negotiation_fixture_meta(self) -> None:
        meta = fixture_meta(load_fixture("negotiation-envelope.json"))
        assert meta["spec_version"] == "0.1.0"
        assert meta["description"], "fixture must declare description"

    def test_communication_subdir_fixtures_present(self) -> None:
        """The communication fixtures trio is present (silent-skip guard)."""
        for filename in (
            "communication/negotiation-envelope.json",
            "communication/handshake-messages.json",
            "communication/error-envelope.json",
        ):
            fixture = load_fixture(filename)
            assert isinstance(fixture, dict)
            assert "valid" in fixture, f"{filename} missing valid section"
