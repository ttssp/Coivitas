"""Orchestrator + OrchestratorConfig boundaries (public API #2 + 22 config fields).

Anti self-equal
---------------
Every assert touches the ``Orchestrator.__init__`` / ``OrchestratorConfig``
BaseModel production code; it is not a mock.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from coivitas import (
    BusinessHandlerContext,
    Orchestrator,
    OrchestratorConfig,
    OrchestratorHandleResult,
)

# sentinel object distinguishing "missing" from "explicitly None" in test fixture
_MISSING = object()


# --- Helpers: minimal config (matches TS: only 6 required fields needed) ---


class _NoopBusinessHandler:
    """A Test Double compatible with the BusinessHandler Protocol."""

    async def __call__(self, context: BusinessHandlerContext) -> dict:
        return {"status": "SUCCESS", "echoed_action": context.action}


class _NoopPolicyEngine:
    """Duck-type compatible with PolicyEngine.executeWithPolicy (placeholder)."""

    async def execute_with_policy(self, *args, **kwargs):
        return {"approved": True}


class _NoopTransport:
    """Compatible with the Transport Protocol (placeholder)."""

    async def send(self, *args, **kwargs):
        return None


class _NoopPolicyRecorder:
    async def record(self, *args, **kwargs):
        return "rec-test"


def _minimal_config() -> OrchestratorConfig:
    """Aligned with the 6 required fields."""
    return OrchestratorConfig(
        agentDid="did:agent:" + "a" * 40,
        agentPrivateKey="ed25519-stub",
        principalDid="did:agent:" + "b" * 40,
        policyEngine=_NoopPolicyEngine(),
        transport=_NoopTransport(),
        businessHandler=_NoopBusinessHandler(),
        policyRecorder=_NoopPolicyRecorder(),
    )


# --- OrchestratorConfig 22-field construction ---


class TestOrchestratorConfigRequiredFields:
    """6 required fields; missing any one raises ValidationError."""

    def test_minimal_required_fields_construct_ok(self) -> None:
        config = _minimal_config()
        assert config.agent_did == "did:agent:" + "a" * 40
        assert config.principal_did == "did:agent:" + "b" * 40
        # Both snake_case access and camelCase alias work
        assert config.policy_recorder is not None

    def test_missing_policy_recorder_raises(self) -> None:
        """``policy_recorder`` is required (no default)."""
        with pytest.raises(ValidationError, match="policy_?[Rr]ecorder"):
            OrchestratorConfig(  # type: ignore[call-arg]
                agentDid="did:agent:" + "a" * 40,
                agentPrivateKey="stub",
                principalDid="did:agent:" + "b" * 40,
                policyEngine=_NoopPolicyEngine(),
                transport=_NoopTransport(),
                businessHandler=_NoopBusinessHandler(),
                # policyRecorder deliberately omitted; consistent with the required-field contract
            )

    def test_missing_agent_did_raises(self) -> None:
        with pytest.raises(ValidationError, match="agent_?[Dd]id"):
            OrchestratorConfig(  # type: ignore[call-arg]
                agentPrivateKey="stub",
                principalDid="did:agent:" + "b" * 40,
                policyEngine=_NoopPolicyEngine(),
                transport=_NoopTransport(),
                businessHandler=_NoopBusinessHandler(),
                policyRecorder=_NoopPolicyRecorder(),
            )

    def test_invalid_did_brand_pattern_raises(self) -> None:
        """Brand validator pattern fail-closed."""
        with pytest.raises(ValidationError):
            OrchestratorConfig(
                agentDid="not-a-did",  # type: ignore[arg-type]
                agentPrivateKey="stub",
                principalDid="did:agent:" + "b" * 40,
                policyEngine=_NoopPolicyEngine(),
                transport=_NoopTransport(),
                businessHandler=_NoopBusinessHandler(),
                policyRecorder=_NoopPolicyRecorder(),
            )

    def test_extra_field_forbidden(self) -> None:
        """strict + extra=forbid (guards against wire format drift)."""
        with pytest.raises(ValidationError, match="[Ee]xtra"):
            OrchestratorConfig(  # type: ignore[call-arg]
                agentDid="did:agent:" + "a" * 40,
                agentPrivateKey="stub",
                principalDid="did:agent:" + "b" * 40,
                policyEngine=_NoopPolicyEngine(),
                transport=_NoopTransport(),
                businessHandler=_NoopBusinessHandler(),
                policyRecorder=_NoopPolicyRecorder(),
                unknown_field="should-fail",
            )


class TestOrchestratorConfigPhase2DependencyChecks:
    """Reconciled against the dependency constraint in orchestrator.ts:170:

    When ``token_store`` is injected, ``delegation_chain_validator`` /
    ``revocation_checker`` / ``resolve_agent_document`` / ``policy_recorder``
    are all required. Orchestrator.__init__ is fail-closed at construction time.
    """

    def test_token_store_without_dependencies_raises(self) -> None:
        config = _minimal_config()
        config = config.model_copy(update={"token_store": object()})  # injected but missing dependencies
        with pytest.raises(ValueError, match="token_store"):
            Orchestrator(config)

    def test_token_store_with_all_dependencies_ok(self) -> None:
        config = _minimal_config()
        config = config.model_copy(
            update={
                "token_store": object(),
                "delegation_chain_validator": object(),
                "revocation_checker": (lambda token_id: None),
                "resolve_agent_document": object(),
            }
        )
        orch = Orchestrator(config)
        assert orch is not None

    def test_federated_resolver_and_resolve_public_key_mutually_exclusive(self) -> None:
        """Mutually exclusive ports fail-closed (cf. orchestrator.ts:94)."""
        config = _minimal_config()
        config = config.model_copy(
            update={
                "federated_resolver": object(),
                "resolve_public_key": (lambda did: None),
            }
        )
        with pytest.raises(ValueError, match="mutually exclusive"):
            Orchestrator(config)


# --- Orchestrator.handle_envelope (#2 main entry point) ---


class TestOrchestratorHandleEnvelope:
    """handle_envelope async method behavioral contract (public API #2 + #12)."""

    @pytest.mark.asyncio
    async def test_valid_envelope_dispatches_to_business_handler(self) -> None:
        orch = Orchestrator(_minimal_config())
        result = await orch.handle_envelope(
            {
                "id": "env-1",
                "specVersion": "0.1.0",
                "header": {
                    "senderDid": "did:agent:" + "a" * 40,
                    "recipientDid": "did:agent:" + "b" * 40,
                    "sessionId": None,
                },
                "messageType": "NEGOTIATION_REQUEST",
                "body": {"action": "INQUIRY", "params": {"item": "x"}},
                "timestamp": "2026-05-07T12:00:00.000Z",
            }
        )
        assert isinstance(result, OrchestratorHandleResult)
        assert result.handled is True
        assert result.cacheable is True
        # business_handler returns echoed_action -> embedded in response_envelope.body
        assert result.response_envelope["body"]["echoed_action"] == "INQUIRY"

    @pytest.mark.asyncio
    async def test_invalid_envelope_message_type_returns_protocol_error(
        self,
    ) -> None:
        """messageType empty string / missing -> INVALID_ENVELOPE wire shape.

        The error-response wire shape is literally aligned with TS
        ``buildInvalidEnvelopeEnvelope`` -- ``messageType: 'ERROR'`` + ``body:
        {code: 'INVALID_ENVELOPE', message: ...}``. The early Python-invented
        ``messageType: 'PROTOCOL_ERROR'`` is wire shape drift (not in TS
        STANDARD_ERROR_CODES).
        """
        orch = Orchestrator(_minimal_config())
        result = await orch.handle_envelope(
            {
                "id": "env-1",
                "specVersion": "0.1.0",
                "header": {
                    "senderDid": "did:agent:" + "a" * 40,
                    "recipientDid": "did:agent:" + "b" * 40,
                    "sessionId": None,
                },
                "messageType": "",  # empty string
                "body": {},
                "timestamp": "2026-05-07T12:00:00.000Z",
            }
        )
        assert result.handled is False
        # Literally aligned with TS error-envelope.ts
        assert result.response_envelope["messageType"] == "ERROR"
        assert result.response_envelope["body"]["code"] == "INVALID_ENVELOPE"
        assert "invalid_envelope_message_type" in (result.rejection_reason or "")
        assert result.cacheable is False

    @pytest.mark.asyncio
    async def test_non_dict_envelope_raises(self) -> None:
        orch = Orchestrator(_minimal_config())
        with pytest.raises(TypeError, match="dict"):
            await orch.handle_envelope("not-a-dict")  # type: ignore[arg-type]

    @pytest.mark.asyncio
    async def test_invalid_action_returns_protocol_error(self) -> None:
        orch = Orchestrator(_minimal_config())
        result = await orch.handle_envelope(
            {
                "id": "env-1",
                "specVersion": "0.1.0",
                "header": {
                    "senderDid": "did:agent:" + "a" * 40,
                    "recipientDid": "did:agent:" + "b" * 40,
                    "sessionId": None,
                },
                "messageType": "NEGOTIATION_REQUEST",
                "body": {"action": "UNKNOWN_ACTION", "params": {}},  # not on the allowlist
                "timestamp": "2026-05-07T12:00:00.000Z",
            }
        )
        # business_context BaseModel validation rejects (Literal allowlist)
        assert result.handled is False
        assert "business_context_invalid" in (result.rejection_reason or "")

    @pytest.mark.asyncio
    async def test_business_handler_exception_caught(self) -> None:
        """handler raises -> returns the INTERNAL_ERROR wire shape; does not let the exception bubble to the main path.

        The error-response wire shape is literally aligned with TS
        ``buildInternalErrorEnvelope`` -- ``messageType: 'ERROR'`` + ``body.code:
        'INTERNAL_ERROR'``.
        """

        class _FailingHandler:
            async def __call__(self, ctx):
                raise RuntimeError("handler explodes")

        config = _minimal_config()
        config = config.model_copy(update={"business_handler": _FailingHandler()})
        orch = Orchestrator(config)

        result = await orch.handle_envelope(
            {
                "id": "env-1",
                "specVersion": "0.1.0",
                "header": {
                    "senderDid": "did:agent:" + "a" * 40,
                    "recipientDid": "did:agent:" + "b" * 40,
                    "sessionId": None,
                },
                "messageType": "NEGOTIATION_REQUEST",
                "body": {"action": "INQUIRY", "params": {}},
                "timestamp": "2026-05-07T12:00:00.000Z",
            }
        )
        assert result.handled is False
        # handler raises -> INTERNAL_ERROR path (literally aligned with TS)
        assert result.response_envelope["messageType"] == "ERROR"
        assert result.response_envelope["body"]["code"] == "INTERNAL_ERROR"
        assert "business_handler_error" in (result.rejection_reason or "")
        assert "handler explodes" in (result.rejection_reason or "")


# --- MessageType strict ---


class TestOrchestratorProductionSafetyGateR2HIGH1:
    """handle_envelope production-safety gate fail-closed.

    handle_envelope does not verify signatures / capability / idempotency, but as a
    public API export, a user might wire it into a server -> a forged envelope
    reaches business_handler.
    Constraint: an envelope containing production-only fields (signature /
    capabilityToken / idempotencyKey) is fail-closed directly.
    """

    @pytest.mark.asyncio
    async def test_envelope_with_signature_field_rejected(self) -> None:
        """envelope containing a signature field -> fail-closed (binding-layer does not verify signatures)."""
        orch = Orchestrator(_minimal_config())
        result = await orch.handle_envelope(
            {
                "id": "env-1",
                "specVersion": "0.1.0",
                "header": {
                    "senderDid": "did:agent:" + "a" * 40,
                    "recipientDid": "did:agent:" + "b" * 40,
                    "sessionId": None,
                },
                "messageType": "NEGOTIATION_REQUEST",
                "body": {"action": "INQUIRY", "params": {}},
                "signature": "0" * 128,  # production-only field
                "timestamp": "2026-05-07T12:00:00.000Z",
            }
        )
        assert result.handled is False
        assert result.response_envelope["messageType"] == "ERROR"
        assert "production_field_in_binding_layer" in (result.rejection_reason or "")
        assert "signature" in (result.rejection_reason or "")

    @pytest.mark.asyncio
    async def test_envelope_with_capability_token_field_rejected(self) -> None:
        """envelope containing a capabilityToken field -> fail-closed."""
        orch = Orchestrator(_minimal_config())
        result = await orch.handle_envelope(
            {
                "id": "env-1",
                "specVersion": "0.1.0",
                "header": {
                    "senderDid": "did:agent:" + "a" * 40,
                    "recipientDid": "did:agent:" + "b" * 40,
                    "sessionId": None,
                },
                "messageType": "NEGOTIATION_REQUEST",
                "body": {"action": "INQUIRY", "params": {}},
                "capabilityToken": {"id": "urn:cap:test"},
                "timestamp": "2026-05-07T12:00:00.000Z",
            }
        )
        assert result.handled is False
        assert "capabilityToken" in (result.rejection_reason or "")

    @pytest.mark.asyncio
    async def test_envelope_with_idempotency_key_field_rejected(self) -> None:
        """envelope containing an idempotencyKey field -> fail-closed."""
        orch = Orchestrator(_minimal_config())
        result = await orch.handle_envelope(
            {
                "id": "env-1",
                "specVersion": "0.1.0",
                "header": {
                    "senderDid": "did:agent:" + "a" * 40,
                    "recipientDid": "did:agent:" + "b" * 40,
                    "sessionId": None,
                },
                "messageType": "NEGOTIATION_REQUEST",
                "body": {"action": "INQUIRY", "params": {}},
                "idempotencyKey": "key-001",
                "timestamp": "2026-05-07T12:00:00.000Z",
            }
        )
        assert result.handled is False
        assert "idempotencyKey" in (result.rejection_reason or "")

    @pytest.mark.asyncio
    async def test_envelope_without_production_fields_succeeds(self) -> None:
        """envelope without production-only fields -> handled normally (binding-layer mode)."""
        orch = Orchestrator(_minimal_config())
        result = await orch.handle_envelope(
            {
                "id": "env-1",
                "specVersion": "0.1.0",
                "header": {
                    "senderDid": "did:agent:" + "a" * 40,
                    "recipientDid": "did:agent:" + "b" * 40,
                    "sessionId": None,
                },
                "messageType": "NEGOTIATION_REQUEST",
                "body": {"action": "INQUIRY", "params": {}},
                "timestamp": "2026-05-07T12:00:00.000Z",
            }
        )
        assert result.handled is True


class TestOrchestratorMessageTypeStrictR3F1:
    """messageType not in {NEGOTIATION_REQUEST, NEGOTIATION_CONFIRM} ->
    INVALID_MESSAGE error response; literally aligned with TS ``orchestrator.ts:2387-2394``.

    The early Python side, when messageType was ``ERROR`` / ``SESSION_ACK`` /
    other off-allowlist values, **silently fell through to business_handler** and
    returned a synthetic ``NEGOTIATION_RESPONSE`` -- a protocol contract drift.
    """

    @staticmethod
    def _make_envelope(message_type: str) -> dict:
        return {
            "id": "env-1",
            "specVersion": "0.1.0",
            "header": {
                "senderDid": "did:agent:" + "a" * 40,
                "recipientDid": "did:agent:" + "b" * 40,
                "sessionId": None,
            },
            "messageType": message_type,
            "body": {"action": "INQUIRY", "params": {}},
            "timestamp": "2026-05-07T12:00:00.000Z",
        }

    @pytest.mark.asyncio
    async def test_error_message_type_rejected_with_invalid_message(self) -> None:
        """messageType=ERROR -> INVALID_MESSAGE, does not fall through to business_handler."""
        orch = Orchestrator(_minimal_config())
        result = await orch.handle_envelope(self._make_envelope("ERROR"))
        assert result.handled is False
        assert result.response_envelope["messageType"] == "ERROR"
        assert result.response_envelope["body"]["code"] == "INVALID_ENVELOPE"
        assert "INVALID_MESSAGE" in (result.rejection_reason or "")
        assert "ERROR" in (result.rejection_reason or "")
        assert result.cacheable is False

    @pytest.mark.asyncio
    async def test_session_ack_message_type_rejected_with_invalid_message(
        self,
    ) -> None:
        """messageType=SESSION_ACK -> INVALID_MESSAGE, does not fall through to business_handler."""
        orch = Orchestrator(_minimal_config())
        result = await orch.handle_envelope(self._make_envelope("SESSION_ACK"))
        assert result.handled is False
        assert result.response_envelope["messageType"] == "ERROR"
        assert result.response_envelope["body"]["code"] == "INVALID_ENVELOPE"
        assert "INVALID_MESSAGE" in (result.rejection_reason or "")
        assert "SESSION_ACK" in (result.rejection_reason or "")

    @pytest.mark.asyncio
    async def test_arbitrary_unknown_message_type_rejected(self) -> None:
        """messageType=arbitrary string -> INVALID_MESSAGE. fail-closed to guard against typo drift."""
        orch = Orchestrator(_minimal_config())
        result = await orch.handle_envelope(self._make_envelope("NEGOTIATION_RESPONSE"))
        # NEGOTIATION_RESPONSE is the response direction; it should not appear as a handle_envelope arg (the receive path)
        # Matches TS extractActionPayload: only accepts REQUEST / CONFIRM
        assert result.handled is False
        assert result.response_envelope["body"]["code"] == "INVALID_ENVELOPE"

    @pytest.mark.asyncio
    async def test_negotiation_request_still_dispatches(self) -> None:
        """Positive: messageType=NEGOTIATION_REQUEST -> goes to business_handler (not blocked by messageType validation)."""
        orch = Orchestrator(_minimal_config())
        result = await orch.handle_envelope(self._make_envelope("NEGOTIATION_REQUEST"))
        assert result.handled is True
        assert result.response_envelope["messageType"] == "NEGOTIATION_RESPONSE"

    @pytest.mark.asyncio
    async def test_negotiation_confirm_still_dispatches(self) -> None:
        """Positive: messageType=NEGOTIATION_CONFIRM -> goes to business_handler."""
        orch = Orchestrator(_minimal_config())
        result = await orch.handle_envelope(self._make_envelope("NEGOTIATION_CONFIRM"))
        assert result.handled is True
        assert result.response_envelope["messageType"] == "NEGOTIATION_RESPONSE"


# --- params not a dict -> INVALID_MESSAGE ---


class TestOrchestratorParamsStrictR3F2:
    """``body.params`` not a dict -> INVALID_MESSAGE; literally aligned with TS
    ``orchestrator.ts:2408-2412``.

    The early Python side silently substituted ``params = {}`` -> a tampering
    attack surface (an attacker could make params missing / a list / a string, and
    the binding would still dispatch normally).
    """

    @staticmethod
    def _make_envelope(params) -> dict:
        body = {"action": "INQUIRY"}
        if params is not _MISSING:
            body["params"] = params
        return {
            "id": "env-1",
            "specVersion": "0.1.0",
            "header": {
                "senderDid": "did:agent:" + "a" * 40,
                "recipientDid": "did:agent:" + "b" * 40,
                "sessionId": None,
            },
            "messageType": "NEGOTIATION_REQUEST",
            "body": body,
            "timestamp": "2026-05-07T12:00:00.000Z",
        }

    @pytest.mark.asyncio
    async def test_params_missing_rejected(self) -> None:
        orch = Orchestrator(_minimal_config())
        result = await orch.handle_envelope(self._make_envelope(_MISSING))
        assert result.handled is False
        assert result.response_envelope["body"]["code"] == "INVALID_ENVELOPE"
        assert "INVALID_MESSAGE" in (result.rejection_reason or "")

    @pytest.mark.asyncio
    async def test_params_as_list_rejected(self) -> None:
        """params is a list -> INVALID_MESSAGE (matches the TS Array.isArray check)."""
        orch = Orchestrator(_minimal_config())
        result = await orch.handle_envelope(self._make_envelope([1, 2, 3]))
        assert result.handled is False
        assert result.response_envelope["body"]["code"] == "INVALID_ENVELOPE"
        assert "INVALID_MESSAGE" in (result.rejection_reason or "")

    @pytest.mark.asyncio
    async def test_params_as_string_rejected(self) -> None:
        """params is a str -> INVALID_MESSAGE."""
        orch = Orchestrator(_minimal_config())
        result = await orch.handle_envelope(self._make_envelope("not-a-dict"))
        assert result.handled is False
        assert result.response_envelope["body"]["code"] == "INVALID_ENVELOPE"

    @pytest.mark.asyncio
    async def test_params_as_none_rejected(self) -> None:
        """params explicitly None -> INVALID_MESSAGE (matches the TS ``!params`` falsy check)."""
        orch = Orchestrator(_minimal_config())
        result = await orch.handle_envelope(self._make_envelope(None))
        assert result.handled is False
        assert result.response_envelope["body"]["code"] == "INVALID_ENVELOPE"

    @pytest.mark.asyncio
    async def test_params_as_int_rejected(self) -> None:
        """params is an int -> INVALID_MESSAGE."""
        orch = Orchestrator(_minimal_config())
        result = await orch.handle_envelope(self._make_envelope(42))
        assert result.handled is False
        assert result.response_envelope["body"]["code"] == "INVALID_ENVELOPE"

    @pytest.mark.asyncio
    async def test_params_as_empty_dict_accepted(self) -> None:
        """Positive: params={} is valid -> goes to business_handler."""
        orch = Orchestrator(_minimal_config())
        result = await orch.handle_envelope(self._make_envelope({}))
        assert result.handled is True


# --- EnvelopeHeader pydantic schema fail-closed ---


class TestOrchestratorHeaderSchemaR3FixF1:
    """The handle_envelope entry point applies EnvelopeHeader pydantic schema
    validation to envelope.header; literally 1:1 with TS
    ``packages/types/src/schemas.ts:636-650`` +
    ``packages/types/src/communication.ts:43-53``.

    The early Python only fetched fields via ``header.get(...)``, letting a missing
    recipientDid / injected extra field pass silently -> byte-level interop drift /
    wire shape drift.
    """

    @staticmethod
    def _envelope_with_header(header: dict) -> dict:
        return {
            "id": "env-1",
            "specVersion": "0.1.0",
            "header": header,
            "messageType": "NEGOTIATION_REQUEST",
            "body": {"action": "INQUIRY", "params": {}},
            "timestamp": "2026-05-07T12:00:00.000Z",
        }

    @pytest.mark.asyncio
    async def test_missing_recipient_did_rejected(self) -> None:
        """recipientDid missing -> INVALID_ENVELOPE (schemas.ts:648 required)."""
        orch = Orchestrator(_minimal_config())
        result = await orch.handle_envelope(
            self._envelope_with_header(
                {
                    "senderDid": "did:agent:" + "a" * 40,
                    # recipientDid deliberately missing
                    "sessionId": None,
                }
            )
        )
        assert result.handled is False
        assert result.response_envelope["body"]["code"] == "INVALID_ENVELOPE"
        assert "header schema violation" in (result.rejection_reason or "")
        assert "recipientDid" in (result.rejection_reason or "") or "recipient_did" in (
            result.rejection_reason or ""
        )

    @pytest.mark.asyncio
    async def test_missing_session_id_key_rejected(self) -> None:
        """sessionId key missing -> INVALID_ENVELOPE. null vs missing differ:
        null is valid (schemas.ts:642 anyOf null); missing is rejected.
        """
        orch = Orchestrator(_minimal_config())
        result = await orch.handle_envelope(
            self._envelope_with_header(
                {
                    "senderDid": "did:agent:" + "a" * 40,
                    "recipientDid": "did:agent:" + "b" * 40,
                    # sessionId deliberately missing (different from sessionId=None)
                }
            )
        )
        assert result.handled is False
        assert result.response_envelope["body"]["code"] == "INVALID_ENVELOPE"
        assert "header schema violation" in (result.rejection_reason or "")

    @pytest.mark.asyncio
    async def test_session_id_null_accepted(self) -> None:
        """sessionId=null is valid (schemas.ts:642 anyOf [string, null]) -> normal path."""
        orch = Orchestrator(_minimal_config())
        result = await orch.handle_envelope(
            self._envelope_with_header(
                {
                    "senderDid": "did:agent:" + "a" * 40,
                    "recipientDid": "did:agent:" + "b" * 40,
                    "sessionId": None,
                }
            )
        )
        assert result.handled is True

    @pytest.mark.asyncio
    async def test_extra_unknown_field_rejected(self) -> None:
        """An extra unknown field (e.g. attackerInjected: 1) -> INVALID_ENVELOPE
        (schemas.ts:649 additionalProperties: false / pydantic extra='forbid').
        """
        orch = Orchestrator(_minimal_config())
        result = await orch.handle_envelope(
            self._envelope_with_header(
                {
                    "senderDid": "did:agent:" + "a" * 40,
                    "recipientDid": "did:agent:" + "b" * 40,
                    "sessionId": None,
                    "attackerInjected": 1,  # attack-injected field
                }
            )
        )
        assert result.handled is False
        assert result.response_envelope["body"]["code"] == "INVALID_ENVELOPE"
        assert "header schema violation" in (result.rejection_reason or "")

    @pytest.mark.asyncio
    async def test_invalid_recipient_did_brand_rejected(self) -> None:
        """recipientDid is not a DID brand -> INVALID_ENVELOPE."""
        orch = Orchestrator(_minimal_config())
        result = await orch.handle_envelope(
            self._envelope_with_header(
                {
                    "senderDid": "did:agent:" + "a" * 40,
                    "recipientDid": "not-a-did",
                    "sessionId": None,
                }
            )
        )
        assert result.handled is False
        assert result.response_envelope["body"]["code"] == "INVALID_ENVELOPE"
        assert "header schema violation" in (result.rejection_reason or "")

    @pytest.mark.asyncio
    async def test_happy_path_full_header_dispatches(self) -> None:
        """A complete valid header (with optional sessionId / sequenceNumber) -> handled normally."""
        orch = Orchestrator(_minimal_config())
        result = await orch.handle_envelope(
            self._envelope_with_header(
                {
                    "senderDid": "did:agent:" + "a" * 40,
                    "recipientDid": "did:agent:" + "b" * 40,
                    "sessionId": "abc-123",
                    "sequenceNumber": 0,
                }
            )
        )
        assert result.handled is True


# --- response_envelope NegotiationEnvelope complete wire shape ---


class TestOrchestratorResponseEnvelopeShapeR3HIGH1:
    """response_envelope must contain the complete NegotiationEnvelope 7 fields
    (id/specVersion/header/messageType/body/signature/timestamp); literally aligned
    with TS communication.ts:55-63.

    The early Python only returned the 2 fields {messageType, body} -- after
    reading from OrchestratorHandleResult.response_envelope the user could not do
    JCS canonical / forwarding / signature verification (missing id / signature /
    timestamp / header).

    After the fix it produces a complete 7-field wire stub:
    - the signature field is filled with the 'BINDING_LAYER_STUB_NOT_SIGNED' sentinel (fail-closed)
    - the user must strip it before the wire / re-sign in the TS backend
    """

    REQUIRED_NEG_ENVELOPE_FIELDS = {
        "id",
        "specVersion",
        "header",
        "messageType",
        "body",
        "signature",
        "timestamp",
    }

    BINDING_LAYER_STUB = "BINDING_LAYER_STUB_NOT_SIGNED"

    @staticmethod
    def _valid_envelope() -> dict:
        return {
            "id": "env-1",
            "specVersion": "0.1.0",
            "header": {
                "senderDid": "did:agent:" + "a" * 40,
                "recipientDid": "did:agent:" + "b" * 40,
                "sessionId": None,
            },
            "messageType": "NEGOTIATION_REQUEST",
            "body": {"action": "INQUIRY", "params": {"item": "x"}},
            "timestamp": "2026-05-07T12:00:00.000Z",
        }

    @pytest.mark.asyncio
    async def test_success_path_response_has_all_7_fields(self) -> None:
        """Success path -> response_envelope contains the full NegotiationEnvelope 7-field set."""
        orch = Orchestrator(_minimal_config())
        result = await orch.handle_envelope(self._valid_envelope())
        assert result.handled is True
        assert set(result.response_envelope.keys()) >= self.REQUIRED_NEG_ENVELOPE_FIELDS
        assert result.response_envelope["messageType"] == "NEGOTIATION_RESPONSE"
        assert result.response_envelope["signature"] == self.BINDING_LAYER_STUB
        assert result.response_envelope["specVersion"] == "0.1.0"
        # String prefix guard
        assert result.response_envelope["id"].startswith("binding-layer-stub-")

    @pytest.mark.asyncio
    async def test_invalid_envelope_path_response_has_all_7_fields(self) -> None:
        """INVALID_ENVELOPE error response -> likewise contains 7 fields (error-path joint contract)."""
        orch = Orchestrator(_minimal_config())
        result = await orch.handle_envelope(
            {
                "id": "env-1",
                "specVersion": "0.1.0",
                "header": {
                    "senderDid": "did:agent:" + "a" * 40,
                    "recipientDid": "did:agent:" + "b" * 40,
                    "sessionId": None,
                },
                "messageType": "",  # triggers INVALID_ENVELOPE
                "body": {},
                "timestamp": "2026-05-07T12:00:00.000Z",
            }
        )
        assert result.handled is False
        assert set(result.response_envelope.keys()) >= self.REQUIRED_NEG_ENVELOPE_FIELDS
        assert result.response_envelope["messageType"] == "ERROR"
        assert result.response_envelope["body"]["code"] == "INVALID_ENVELOPE"
        assert result.response_envelope["signature"] == self.BINDING_LAYER_STUB

    @pytest.mark.asyncio
    async def test_internal_error_path_response_has_all_7_fields(self) -> None:
        """INTERNAL_ERROR error response -> likewise contains 7 fields."""

        class _FailingHandler:
            async def __call__(self, ctx):
                raise RuntimeError("handler explodes")

        config = _minimal_config()
        config = config.model_copy(update={"business_handler": _FailingHandler()})
        orch = Orchestrator(config)
        result = await orch.handle_envelope(self._valid_envelope())
        assert result.handled is False
        assert set(result.response_envelope.keys()) >= self.REQUIRED_NEG_ENVELOPE_FIELDS
        assert result.response_envelope["messageType"] == "ERROR"
        assert result.response_envelope["body"]["code"] == "INTERNAL_ERROR"
        assert result.response_envelope["signature"] == self.BINDING_LAYER_STUB

    @pytest.mark.asyncio
    async def test_response_header_reverses_sender_recipient(self) -> None:
        """responder mode: response_envelope.header.{senderDid,recipientDid}
        are swapped relative to the source envelope (matches TS responder mode).
        """
        orch = Orchestrator(_minimal_config())
        env = self._valid_envelope()
        result = await orch.handle_envelope(env)
        assert result.handled is True
        # source envelope: sender=a*40, recipient=b*40
        # response envelope: sender=b*40 (was recipient), recipient=a*40 (was sender)
        assert (
            result.response_envelope["header"]["senderDid"]
            == env["header"]["recipientDid"]
        )
        assert (
            result.response_envelope["header"]["recipientDid"]
            == env["header"]["senderDid"]
        )

    @pytest.mark.asyncio
    async def test_response_signature_is_stub_sentinel_not_real(self) -> None:
        """fail-closed: signature is a literal sentinel, must not be a valid hex string."""
        orch = Orchestrator(_minimal_config())
        result = await orch.handle_envelope(self._valid_envelope())
        sig = result.response_envelope["signature"]
        # The sentinel must not be a valid hex signature (to avoid being misread as a real signature on the wire)
        assert sig == self.BINDING_LAYER_STUB
        assert not all(c in "0123456789abcdefABCDEF" for c in sig)
        assert "STUB_NOT_SIGNED" in sig
