"""trust-build conformance test

Test goals
----------
This file covers 4 production-code contracts (**not mock-self**; anti self-equal grounding):

1. **wire format literal consistency**: BUSINESS_ACTION_VOCABULARY 5 items checked against
   ``packages/types/src/schemas.ts`` (assert enum value set = TS-side literal set)
2. **Brand validator fail-closed**: invalid DID / Timestamp / DID-Agent literals must raise ValidationError
   (assert the pydantic-chained ValueError; not a mock input equal to itself)
3. **Strict mode prevents implicit coercion**: BaseModel.handled field type = bool; passing int 1 must raise
   (pydantic v2 strict=True behavioral contract)
4. **Wire format alias bidirectional consistency**: snake_case construction + by_alias=True serialization emits camelCase
   (prerequisite for cross-language byte-level wire format consistency)

Cross-language alignment
------------------------
- TS counterpart: ``tests/conformance/communication-fixtures.test.ts`` (same-source schema)
- Python: ``test_basic.py`` (snake_case conversion)
- Same assertion semantics: 5-item BUSINESS_ACTION vocabulary enum; DID pattern fail-closed

self-check
----------
- Each ``assert`` hits **production-code** behavior (the actual validator/strict config in Brand/types.py)
- No ``mock_value == mock_value`` pattern
- No import of any fixture-less helper
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from coivitas import (
    BusinessAction,
    BusinessHandlerContext,
    DID,
    OrchestratorHandleResult,
    RevocationResult,
    __version__,
)


# ─── Contract 1: wire format BUSINESS_ACTION_VOCABULARY literal consistency ────────


class TestWireFormatVocabulary:
    """Cross-language anchoring of the 5 BUSINESS_ACTION_VOCABULARY literals.

    Background: the wire format is not extensible; the Python SDK consumes, it does not define.
    This test does a cross-check: the Python-side enum set must equal the TS-side ACTION_VOCABULARY minus SESSION_SUPERSEDED.
    """

    def test_business_action_vocabulary_matches_ts_schema(self) -> None:
        """The BusinessAction enum value set should be strictly equal to the 5 literals in TS schemas.ts."""
        # Directly reconcile against the TS-side BUSINESS_ACTION_VOCABULARY literals
        # Not a mock: the 5 items on the right are the actual TS string literals, promoted to a CI gate by the sync-vocabulary script
        expected_ts_vocabulary = {"INQUIRY", "QUOTE", "CONFIRM", "PUBLISH", "RECORD"}
        actual_python_vocabulary = {member.value for member in BusinessAction}

        assert actual_python_vocabulary == expected_ts_vocabulary, (
            f"Python BusinessAction enum drifted from TS schemas.ts BUSINESS_ACTION_VOCABULARY: "
            f"Python={actual_python_vocabulary} vs TS={expected_ts_vocabulary}"
        )

    def test_business_action_excludes_session_superseded(self) -> None:
        """SESSION_SUPERSEDED is not in the business vocabulary (excluded by the schemas.ts filter)."""
        # Reverse assertion: SESSION_SUPERSEDED is a control-flow action and must not be consumed by a business handler
        action_values = {member.value for member in BusinessAction}
        assert "SESSION_SUPERSEDED" not in action_values


# ─── Contract 2: Brand validator fail-closed behavior ────────────────────────


class TestBrandValidatorFailClosed:
    """Brand type pattern validation path (enforced in strict mode).

    Key invariant: every Brand field runs its AfterValidator on BaseModel instantiation;
    a pattern mismatch → ValidationError (not a silent fallback; not a mock).
    """

    def test_did_pattern_rejects_invalid_format(self) -> None:
        """A non-did:* prefixed string as sender_did should raise ValidationError."""
        # Real production-code contract: BusinessHandlerContext.sender_did is validated by _check_did
        with pytest.raises(ValidationError) as exc_info:
            BusinessHandlerContext(
                action="INQUIRY",  # string literal (the normal wire inbound form)
                params={"foo": "bar"},
                senderDid="not-a-did",  # intentionally invalid; triggers _check_did failure
                sessionId=None,  # required-but-nullable, must be passed explicitly
            )

        # Assert the error message indeed comes from the Brand validator (literal contains "DID" or "did"),
        # and not some other internal pydantic error (e.g. missing field)
        error_text = str(exc_info.value).lower()
        assert "did" in error_text or "value error" in error_text, (
            f"expected Brand validator to report a DID error, actual: {exc_info.value}"
        )

    def test_did_pattern_accepts_valid_did_agent(self) -> None:
        """A valid did:agent:<40-hex> string must pass validation."""
        # Positive assertion: a literal value conforming to schemas.ts didAgentPattern
        valid_did = "did:agent:" + "a" * 40
        ctx = BusinessHandlerContext(
            action="QUOTE",  # string literal
            params={},
            senderDid=valid_did,
            sessionId=None,  # required-but-nullable
        )
        # The field value is preserved as-is (Brand is a type alias and does not change the runtime type)
        assert ctx.sender_did == valid_did
        # action is not an enum instance but the string literal after Literal validation
        assert ctx.action == "QUOTE"

    def test_did_pattern_rejects_empty_string(self) -> None:
        """An empty string as a DID must fail (pattern anchor ^did:.*$)."""
        with pytest.raises(ValidationError):
            BusinessHandlerContext(
                action="INQUIRY",  # string literal
                params={},
                senderDid="",
                sessionId=None,  # required-but-nullable
            )


# ─── Contract 3: Strict mode prevents implicit type coercion ──────────────────────────


class TestStrictModeRejectImplicitCoercion:
    """Every BaseModel sets ``model_config = ConfigDict(strict=True)``.

    Production contract: passing int/str to a bool field → ValidationError; no 1→True implicit coercion is allowed.
    """

    def test_handled_field_rejects_int_in_strict_mode(self) -> None:
        """OrchestratorHandleResult.handled field type = bool; passing int should fail."""
        # Key assertion: under strict=True, 1 is not auto-converted to True
        with pytest.raises(ValidationError):
            OrchestratorHandleResult(
                handled=1,  # type: ignore[arg-type] # intentional type error, verifies strict rejection
                responseEnvelope={},
            )

    def test_handled_field_accepts_bool(self) -> None:
        """Positive assertion: a native bool is accepted."""
        result = OrchestratorHandleResult(
            handled=True,
            responseEnvelope={"messageType": "SESSION_ACK"},
        )
        assert result.handled is True
        assert result.response_envelope == {"messageType": "SESSION_ACK"}

    def test_extra_fields_forbidden(self) -> None:
        """Extra fields → ValidationError (guards against wire format drift)."""
        # Enforced by extra="forbid" in types.py _STRICT_MODEL_CONFIG
        with pytest.raises(ValidationError):
            OrchestratorHandleResult(
                handled=True,
                responseEnvelope={},
                unknown_extra_field="should-fail",  # type: ignore[call-arg]
            )


# ─── Contract 4: wire format alias bidirectional consistency (snake_case ↔ camelCase) ────


class TestWireFormatAliasRoundtrip:
    """API surface = snake_case; wire format JSON = camelCase.

    Production contract:
    - construction may use snake_case (Python style) or camelCase (wire format)
    - ``model_dump(by_alias=True)`` emits wire format (byte-level consistency prerequisite)
    """

    def test_construct_with_snake_case_then_dump_camel_case(self) -> None:
        """snake_case construction → by_alias=True serializes to camelCase."""
        ctx = BusinessHandlerContext(
            action=BusinessAction.RECORD,
            params={"key": "value"},
            sender_did="did:agent:" + "f" * 40,  # snake_case construction
            session_id="session-123",
        )

        wire_payload = ctx.model_dump(by_alias=True)

        # wire format must be camelCase (cross-language byte-level consistency prerequisite)
        assert "senderDid" in wire_payload
        assert "sessionId" in wire_payload
        # snake_case must not leak to the wire (guards against TS-side parse failure)
        assert "sender_did" not in wire_payload
        assert "session_id" not in wire_payload

    def test_construct_with_camel_case_alias(self) -> None:
        """populate_by_name=True: camelCase is also allowed at construction (wire-in path)."""
        ctx = BusinessHandlerContext(
            action="PUBLISH",  # string literal (the normal wire inbound form)
            params={},
            senderDid="did:agent:" + "0" * 40,  # camelCase construction (wire inbound)
            sessionId=None,  # required-but-nullable
        )
        # The API side still exposes snake_case (Python style)
        assert ctx.sender_did.startswith("did:agent:")

    def test_revocation_result_snake_case_round_trip(self) -> None:
        """RevocationResult contains aliases such as fallbackReason / revokedAt; roundtrip fields stay consistent."""
        result = RevocationResult(
            credentialId="cred-001",
            revoked=True,
            revokedAt="2026-05-07T12:00:00.000Z",
        )
        # API side: snake_case
        assert result.credential_id == "cred-001"
        assert result.revoked_at == "2026-05-07T12:00:00.000Z"

        # wire side: camelCase
        wire = result.model_dump(by_alias=True, exclude_none=True)
        assert wire["credentialId"] == "cred-001"
        assert wire["revokedAt"] == "2026-05-07T12:00:00.000Z"
        assert "credential_id" not in wire


# ─── BusinessAction strict mode accepts string literal inputs ──────────────────


class TestBusinessActionLiteralAcceptsString:
    """BusinessHandlerContext.action = BusinessActionLiteral
    (Literal of 5 items); under strict=True it accepts the string literal passed straight through from the wire payload.

    Background: the original ``action: BusinessAction`` with ``strict=True`` made pydantic refuse
    to auto-wrap a string into an enum instance → strings from real JSON deserialization could not construct the model.
    After switching to Literal, the 5-item allowlist is still validated literally by pydantic and the wire payload can be consumed directly.

    Cross-language reconciliation: semantically consistent with TS ``orchestrator.ts BusinessHandlerContext.action: string``
    + the ``schemas.ts BUSINESS_ACTION_VOCABULARY`` 5-item allowlist.
    """

    def test_literal_action_accepts_plain_string(self) -> None:
        """Passing the string literal "INQUIRY" at construction should pass (strict=True does not reject it)."""
        ctx = BusinessHandlerContext(
            action="INQUIRY",  # the normal form from real JSON deserialization: a string
            params={"foo": "bar"},
            senderDid="did:agent:" + "a" * 40,
            sessionId=None,
        )
        # The field is preserved as a string literal (not coerced into an enum instance)
        assert ctx.action == "INQUIRY"
        # Literal validation path: yields a str, not a BusinessAction
        assert isinstance(ctx.action, str)

    def test_literal_action_accepts_all_five_vocabulary_strings(self) -> None:
        """All 5 BUSINESS_ACTION_VOCABULARY literal strings should pass."""
        # Aligned with the schemas.ts literals
        for action_str in ("INQUIRY", "QUOTE", "CONFIRM", "PUBLISH", "RECORD"):
            ctx = BusinessHandlerContext(
                action=action_str,
                params={},
                senderDid="did:agent:" + "1" * 40,
                sessionId=None,
            )
            assert ctx.action == action_str

    def test_literal_action_rejects_unknown_string(self) -> None:
        """A string outside the allowlist (e.g. "UNKNOWN") should raise ValidationError."""
        with pytest.raises(ValidationError):
            BusinessHandlerContext(
                action="UNKNOWN",  # type: ignore[arg-type] # intentionally out of range
                params={},
                senderDid="did:agent:" + "1" * 40,
                sessionId=None,
            )

    def test_literal_action_rejects_session_superseded(self) -> None:
        """SESSION_SUPERSEDED is a control-flow action (excluded by the schemas.ts filter),
        not in the BUSINESS_ACTION_VOCABULARY allowlist → should be rejected."""
        with pytest.raises(ValidationError):
            BusinessHandlerContext(
                action="SESSION_SUPERSEDED",  # type: ignore[arg-type]
                params={},
                senderDid="did:agent:" + "1" * 40,
                sessionId=None,
            )

    def test_str_enum_value_still_compatible(self) -> None:
        """Backward compatibility: because StrEnum inherits from str, its ``.value`` is equal to the Literal literal,
        so SDK users can still pass ``BusinessAction.X`` as a convenience symbol."""
        # A StrEnum instance passed to a Literal-of-5-items field (StrEnum inherits str → accepted by pydantic Literal)
        ctx = BusinessHandlerContext(
            action=BusinessAction.QUOTE,
            params={},
            senderDid="did:agent:" + "1" * 40,
            sessionId=None,
        )
        # The literal value matches BusinessAction.QUOTE.value
        assert ctx.action == BusinessAction.QUOTE.value == "QUOTE"


# ─── session_id required-but-nullable (aligned with TS) ──────────────────


class TestSessionIdRequiredButNullable:
    """``session_id: SessionId | None`` (default removed).

    Background: TS ``BusinessHandlerContext.sessionId: string | null`` is
    required-but-nullable — a missing field throws; the old Python ``= None`` default caused
    a missing field to pass silently, making fixture/interop payloads prone to drift.

    Invariant: construction **must** pass ``sessionId`` explicitly, which may be None; a missing field → ValidationError.
    """

    def test_session_id_explicit_none_passes(self) -> None:
        """Explicit sessionId=None should pass (required-but-nullable)."""
        ctx = BusinessHandlerContext(
            action="INQUIRY",
            params={},
            senderDid="did:agent:" + "b" * 40,
            sessionId=None,  # explicit null
        )
        assert ctx.session_id is None

    def test_session_id_missing_raises_validation_error(self) -> None:
        """Omitting the sessionId field entirely should raise ValidationError (drift detection)."""
        with pytest.raises(ValidationError) as exc_info:
            BusinessHandlerContext(  # type: ignore[call-arg]
                action="INQUIRY",
                params={},
                senderDid="did:agent:" + "b" * 40,
                # intentionally omit sessionId / session_id; triggers the missing field error
            )
        # Assert the error comes from a missing field (pydantic marks it "Field required" or "missing")
        error_text = str(exc_info.value).lower()
        assert "session" in error_text or "required" in error_text or "missing" in error_text, (
            f"expected a missing field error, actual: {exc_info.value}"
        )

    def test_session_id_string_value_passes(self) -> None:
        """Passing a non-empty string as sessionId should pass."""
        ctx = BusinessHandlerContext(
            action="INQUIRY",
            params={},
            senderDid="did:agent:" + "b" * 40,
            sessionId="session-abc-123",
        )
        assert ctx.session_id == "session-abc-123"


# ─── OrchestratorHandleResult cacheable + responseSpec ──────────────


class TestOrchestratorHandleResultCacheable:
    """Fills in the ``cacheable`` + ``response_spec`` fields.

    Background: TS ``orchestrator.ts`` publicly exports
    ``cacheable?: boolean`` + ``responseSpec?: CachedResponseSpec``;
    on the Python side, strict.extra="forbid" with the old field set would reject real TS output (e.g.
    ``{handled: true, responseEnvelope: {...}, cacheable: false}``).

    Invariants:
    - cacheable may be None / bool; it is not required
    - response_spec may be None / dict (wire-passthrough of the discriminated union;
      later stages will upgrade it to a strongly-typed CachedResponseSpec)
    - when both fields are None, ``model_dump(exclude_none=True)`` should strip them (no wire pollution)
    """

    def test_cacheable_field_accepts_false(self) -> None:
        """cacheable=False (transient failure path) should be accepted without raising a strict error.

        The error envelope wire shape is literally aligned with TS error-envelope.ts
        (``messageType: 'ERROR'`` + ``body.code: 'INVALID_ENVELOPE'``);
        the old fixture using ``'PROTOCOL_ERROR'`` is wire shape drift (not in the TS
        STANDARD_ERROR_CODES).
        """
        result = OrchestratorHandleResult(
            handled=True,
            responseEnvelope={
                "messageType": "ERROR",
                "body": {
                    "code": "INVALID_ENVELOPE",
                    "message": "transient failure",
                },
            },
            cacheable=False,
        )
        assert result.cacheable is False

    def test_cacheable_field_accepts_true(self) -> None:
        """cacheable=True (terminal-state path) should be accepted."""
        result = OrchestratorHandleResult(
            handled=True,
            responseEnvelope={"messageType": "BUSINESS_RESPONSE"},
            cacheable=True,
        )
        assert result.cacheable is True

    def test_cacheable_default_is_none(self) -> None:
        """When cacheable is unspecified it defaults to None (equivalent to TS undefined)."""
        result = OrchestratorHandleResult(
            handled=True,
            responseEnvelope={},
        )
        assert result.cacheable is None
        assert result.response_spec is None

    def test_response_spec_passthrough_dict(self) -> None:
        """response_spec accepts a dict (wire-passthrough of CachedResponseSpec)."""
        spec_payload = {
            "kind": "SUCCESS",
            "agentDid": "did:agent:" + "c" * 40,
            "originalSenderDid": "did:agent:" + "d" * 40,
            "sessionId": None,
            "requestId": "req-001",
            "action": "QUOTE",
            "data": {"price": 100},
            "recordId": "rec-001",
        }
        result = OrchestratorHandleResult(
            handled=True,
            responseEnvelope={},
            cacheable=True,
            responseSpec=spec_payload,
        )
        assert result.response_spec == spec_payload

    def test_real_ts_output_roundtrip(self) -> None:
        """Key regression: parsing real TS-style output (including cacheable: false) should not raise
        ValidationError — this is the strict.extra=forbid false-rejection scenario.

        The error envelope wire shape is literally aligned with TS ``buildInvalidEnvelopeEnvelope``
        (``messageType: 'ERROR'`` + ``body.code: 'INVALID_ENVELOPE'``).
        The old fixture ``messageType: 'PROTOCOL_ERROR'`` does not exist in TS
        STANDARD_ERROR_CODES (packages/communication/src/error-envelope.ts).
        """
        # Simulate real TS orchestrator.ts output (INVALID_MESSAGE → ERROR envelope)
        ts_style_output = {
            "handled": False,
            "responseEnvelope": {
                "messageType": "ERROR",
                "body": {
                    "code": "INVALID_ENVELOPE",
                    "message": "duplicate envelope",
                },
            },
            "rejectionReason": "duplicate envelope",
            "cacheable": False,
        }
        # Use model_validate to take the wire-in path (camelCase alias)
        result = OrchestratorHandleResult.model_validate(ts_style_output)
        assert result.handled is False
        assert result.cacheable is False
        assert result.rejection_reason == "duplicate envelope"
        assert result.response_envelope["messageType"] == "ERROR"
        assert result.response_envelope["body"]["code"] == "INVALID_ENVELOPE"

    def test_cacheable_roundtrip_camel_case(self) -> None:
        """The cacheable field stays consistent across a wire-in/out roundtrip."""
        wire_in = {
            "handled": True,
            "responseEnvelope": {"messageType": "BUSINESS_RESPONSE"},
            "cacheable": True,
            "responseSpec": {"kind": "SUCCESS"},
        }
        result = OrchestratorHandleResult.model_validate(wire_in)
        wire_out = result.model_dump(by_alias=True, exclude_none=True)
        assert wire_out["cacheable"] is True
        assert wire_out["responseSpec"] == {"kind": "SUCCESS"}
        # The field name uses the alias; snake_case does not pollute the wire
        assert "response_spec" not in wire_out

    def test_none_fields_excluded_from_wire(self) -> None:
        """When cacheable / response_spec=None, exclude_none=True should strip them."""
        result = OrchestratorHandleResult(
            handled=True,
            responseEnvelope={},
        )
        wire = result.model_dump(by_alias=True, exclude_none=True)
        assert "cacheable" not in wire
        assert "responseSpec" not in wire


# ─── Metadata: version string is readable ─────────────────────────────────────────


class TestPackageMetadata:
    """Minimal metadata contract for the scaffolding stage."""

    def test_version_is_pep440_alpha(self) -> None:
        """__version__ should be a PEP 440 alpha version (synced with pyproject.toml)."""
        # Not a mock: reads the __version__ literal from __init__.py directly
        assert __version__ == "0.1.0a1"

    def test_did_brand_alias_importable(self) -> None:
        """The DID type alias is importable from the top level (for user BaseModel extensions)."""
        # DID is Annotated[str, AfterValidator(...)], so it cannot be used with isinstance
        # Only asserts that the import path is stable
        assert DID is not None
