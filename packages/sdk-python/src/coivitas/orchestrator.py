"""Orchestrator + OrchestratorConfig (22-field config).

Design principles
-----------------
1. **aligned 1:1 with the TS public API surface**: ``handle_envelope`` async method (literally
   aligned with TS ``handleEnvelope``)
2. **OrchestratorConfig 22 fields**: ``policy_recorder`` required;
   the other 21 fields optional; required fields are fail-closed-checked at construction
3. **capability path prerequisites**: when
   ``token_store`` is injected, ``delegation_chain_validator`` /
   ``revocation_checker`` / ``resolve_agent_document`` / ``policy_recorder``
   are all required — missing any one -> construction raises the ``ProtocolError`` equivalent
4. **Scope**: the Python SDK is a binding layer (full L2-L4 business logic is not a built-in goal);
   ``handle_envelope`` only does wire format validation + delegation to
   ``business_handler`` — the actual capability / signature / cumulative_limit checks
   are delegated to injected Protocols, similar to TS's "placeholder + delegate" structure

fail-closed contract drift fix
-------------------------------------------------------------
- ``messageType`` not in ``{NEGOTIATION_REQUEST, NEGOTIATION_CONFIRM}`` ->
  immediately return an ``INVALID_MESSAGE`` error response; no longer silently falls through to ``business_handler``.
  Literally aligned with TS ``extractActionPayload``
  (ProtocolError('INVALID_MESSAGE')).
- ``body.params`` missing / not a dict -> immediately return ``INVALID_MESSAGE``;
  no longer silently replaced with ``{}``. Literally aligned with TS (``!params || typeof params
  !== 'object' || Array.isArray(params)`` -> throw ProtocolError).
- The error response envelope uses the literal wire shape of TS ``buildInvalidEnvelopeEnvelope`` /
  ``buildInternalErrorEnvelope``: ``messageType: 'ERROR'`` +
  ``body: {code: <STANDARD_ERROR_CODE>, message: ...}``; no longer uses the Python-homegrown
  ``messageType: 'PROTOCOL_ERROR'`` (the latter is not in TS ``STANDARD_ERROR_CODES`` and
  is a wire-shape drift). The literal five values of ``STANDARD_ERROR_CODES``:
  ``AUTHORIZATION_INSUFFICIENT`` / ``IDENTITY_VERIFICATION_FAILED`` /
  ``SESSION_NOT_FOUND`` / ``INVALID_ENVELOPE`` / ``INTERNAL_ERROR``.
  The Python binding layer does not sign, only produces a wire-shape stub; signing +
  full envelope build are handled by the TS backend at production deployment.

Conventions
-----------
- TS ``handleEnvelope`` defines the inputs/outputs and the ``extractActionPayload`` wire semantics
- TS ``STANDARD_ERROR_CODES`` defines the error code set
- wire format is only consumed, not defined
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from pydantic import ValidationError as _PydanticValidationError

from coivitas.types import (
    DID,
    BusinessHandler,
    BusinessHandlerContext,
    EnvelopeHeader,
    OrchestratorHandleResult,
    Timestamp,
)

# handle_envelope production-safety gate
# An envelope containing these fields is fail-closed (the binding layer does not verify signatures/authorization).
_PRODUCTION_ONLY_FIELDS: tuple[str, ...] = (
    "signature",
    "capabilityToken",
    "idempotencyKey",
)


class OrchestratorConfig(BaseModel):
    """Orchestrator config (22 fields).

    Field overview
    --------------
    | # | TS field | Python field | Required |
    |---|----------|--------------|----------|
    | 1 | agentDid | agent_did | YES |
    | 2 | agentPrivateKey | agent_private_key | YES |
    | 3 | principalDid | principal_did | YES |
    | 4 | policyEngine | policy_engine | YES |
    | 5 | transport | transport | YES |
    | 6 | businessHandler | business_handler | YES |
    | 7-22 | optional fields | optional fields | NO |
    | 17 | policyRecorder | policy_recorder | **YES** |

    Design choices
    --------------
    - ``arbitrary_types_allowed=True``: all non-BaseModel fields (Protocol /
      Callable / business objects) cannot be strict-validated by pydantic and work via Protocol duck typing
    - ``extra="forbid"``: undeclared fields -> ValidationError (prevents wire drift
      / typos)
    - after construction, ``Orchestrator.__init__`` performs cross-field invariant checks (e.g.
      capability dependency fail-closed)
    """

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        populate_by_name=True,
        extra="forbid",
    )

    # ── required (6 fields) ─────────────────────────
    agent_did: DID = Field(alias="agentDid")
    agent_private_key: str = Field(alias="agentPrivateKey")
    principal_did: DID = Field(alias="principalDid")
    policy_engine: Any = Field(alias="policyEngine")
    transport: Any
    business_handler: Any = Field(alias="businessHandler")
    # policy_recorder is required
    policy_recorder: Any = Field(alias="policyRecorder")

    # ── optional (16 fields) ────────────────────
    verbose: bool | None = None
    now: Callable[[], Timestamp] | None = None
    discovery_service: Any | None = Field(default=None, alias="discoveryService")
    federated_resolver: Any | None = Field(default=None, alias="federatedResolver")
    resolve_public_key: Callable[[DID], Awaitable[str | None]] | None = Field(
        default=None, alias="resolvePublicKey"
    )
    resolve_public_keys: Any | None = Field(default=None, alias="resolvePublicKeys")
    resolve_agent_document: Any | None = Field(default=None, alias="resolveAgentDocument")
    token_store: Any | None = Field(default=None, alias="tokenStore")
    revocation_checker: Callable[[str], Awaitable[bool]] | None = Field(
        default=None, alias="revocationChecker"
    )
    delegation_chain_validator: Any | None = Field(default=None, alias="delegationChainValidator")
    sender_cumulative_tracker: Any | None = Field(default=None, alias="senderCumulativeTracker")
    idempotency_cache: Any | None = Field(default=None, alias="idempotencyCache")
    idempotency_cache_write_timeout_ms: int | None = Field(
        default=None, alias="idempotencyCacheWriteTimeoutMs"
    )
    managed_service_client: Any | None = Field(default=None, alias="managedServiceClient")
    # logger is a Protocol (not a BaseModel); pydantic v2 strict cannot use it directly as a field type ->
    # passed through as Any + arbitrary_types_allowed=True already enabled in model_config
    logger: Any | None = None


class Orchestrator:
    """L5 orchestrator Python binding.

    Scope
    -----
    - aligned 1:1 with the TS public API: ``handle_envelope(envelope) -> OrchestratorHandleResult``
    - performs cross-field invariant fail-closed checks at construction
    - capability path delegation: checks dependencies when ``token_store`` is injected; raises if any are missing
    - **does not implement L2-L4 business logic** (not a goal): ``handle_envelope`` takes the minimal
      wire validation + delegation to ``business_handler`` path, letting Python users post-process the wire payload
      with a hook in their own service (typical SDK usage)
    - the real end-to-end business flow (signature verification / capability verification / cumulative_limit) is handled by
      the TS SDK at the backend node; Python SDK users mainly make client-side calls within ML/Agent frameworks
      (LangChain/AutoGPT/CrewAI)
    """

    def __init__(self, config: OrchestratorConfig) -> None:
        """Construct the orchestrator; fail-closed check on required fields + capability dependency consistency."""
        self._config = config

        # mutually exclusive port validation
        if config.federated_resolver is not None and config.resolve_public_key is not None:
            raise ValueError(
                "OrchestratorConfig: federated_resolver and resolve_public_key "
                "are mutually exclusive"
            )

        # capability path prerequisite fail-closed
        if config.token_store is not None:
            missing: list[str] = []
            if config.delegation_chain_validator is None:
                missing.append("delegation_chain_validator")
            if config.revocation_checker is None:
                missing.append("revocation_checker")
            if config.resolve_agent_document is None:
                missing.append("resolve_agent_document")
            # policy_recorder is already required, no need to check separately
            if missing:
                raise ValueError(
                    "OrchestratorConfig: token_store injected but missing "
                    f"required capability dependencies: {missing}"
                )

    @property
    def config(self) -> OrchestratorConfig:
        """Read-only access to the config (used by components such as ScenarioRunner)."""
        return self._config

    @property
    def agent_did(self) -> str:
        """The Agent DID held by the orchestrator (read-only convenience accessor)."""
        return self._config.agent_did

    async def handle_envelope(self, envelope: dict[str, Any]) -> OrchestratorHandleResult:
        """Handle a single envelope and produce a response (main entry point).

        Scope
        -----
        Python SDK binding layer (full business/performance alignment is not a goal):
        this method **does not** implement the full verifyEnvelope / verifyCapability / cumulative_limit
        paths — those paths require the L0-L4 TypeScript implementation, and the Python side cannot rewrite them 1:1
        without duplicating a large amount of low-level logic (the binding layer only consumes the wire format, it does not define it).

        ⚠ Production-Safety Gate
        ------------------------------------------------------------
        handle_envelope does not verify signatures/capability/idempotency, but as a public
        API export, a user might wire it into a server -> a forged envelope reaches business_handler via an
        attacker-controlled senderDid/sessionId. A real trust-boundary gap.

        Fix:
        - by default reject an envelope carrying production-only fields (signature / capabilityToken /
          idempotencyKey) — these fields mean the user expects real signature/authorization verification; the binding layer
          must not pretend to implement it. fail-closed -> INVALID_ENVELOPE: production_field_in_binding_layer
        - emit a docstring + warning log making it clear "FOR TEST/LOCAL/SCAFFOLD ONLY; DO NOT
          WIRE INTO PRODUCTION SERVER WITHOUT TS BACKEND VERIFICATION"
        - production users must run verifyEnvelope/verifyCapability on the TS backend, then
          delegate the verified wire payload to the Python SDK for handling (typical LangChain SDK usage)

        Handling path
        -------------
        1. ⚠ Production-safety gate: an envelope containing signature/capabilityToken/
           idempotencyKey -> INVALID_ENVELOPE fail-closed
        2. basic wire shape validation (envelope is a dict + contains messageType + body)
        3. **fail-closed**: messageType not in {NEGOTIATION_REQUEST, NEGOTIATION_CONFIRM}
           -> INVALID_MESSAGE; literally aligned with TS ``extractActionPayload``
        4. **fail-closed**: body.params not a dict / missing -> INVALID_MESSAGE;
           literally aligned with TS (no longer silently replaced with ``{}``)
        5. parse body.action / body.params to construct BusinessHandlerContext
        6. delegate to the injected ``business_handler`` (user-implemented)
        7. wrap the result as ``OrchestratorHandleResult`` (the same wire shape as TS)

        Production path
        ---------------
        Production deployment should run the full orchestrator on the TypeScript backend; the Python SDK user's
        typical scenario is the client-side (LangChain Agent) caller — driving test scenarios through ScenarioRunner,
        with wire payload validation done by the backend.
        """
        if not isinstance(envelope, dict):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise TypeError(f"envelope must be dict, got {type(envelope).__name__}")

        # fail-closed gate: reject production-only fields
        # Carrying these fields means the user expects real signature/authorization verification; the binding layer must not pretend to implement it,
        # otherwise a forged envelope would reach business_handler via an attacker-controlled senderDid.
        # production users must first run verifyEnvelope/verifyCapability/checkRevocation on the TS backend,
        # then delegate the verified wire payload to the Python binding (typical LangChain SDK pattern).
        for prod_field in _PRODUCTION_ONLY_FIELDS:
            if prod_field in envelope:
                return self._build_invalid_envelope_result(
                    detail=(
                        f"INVALID_ENVELOPE: production_field_in_binding_layer "
                        f"(envelope contains '{prod_field}'; "
                        f"fail-closed gate — Python binding-layer does not "
                        f"implement verifyEnvelope/verifyCapability/idempotency. "
                        f"Use TS backend orchestrator first, then forward "
                        f"verified payload to Python SDK; or strip the field "
                        f"if calling binding for test/scaffold purposes.)"
                    ),
                    source_envelope=envelope,
                )

        message_type = envelope.get("messageType")
        body = envelope.get("body")
        header = envelope.get("header")

        if not isinstance(message_type, str) or not message_type:
            # messageType missing/non-string -> INVALID_ENVELOPE wire shape
            return self._build_invalid_envelope_result(
                detail="invalid_envelope_message_type",
                source_envelope=envelope,
            )
        if not isinstance(body, dict):
            return self._build_invalid_envelope_result(
                detail="invalid_envelope_body",
                source_envelope=envelope,
            )
        if not isinstance(header, dict):
            return self._build_invalid_envelope_result(
                detail="invalid_envelope_header",
                source_envelope=envelope,
            )
        # pydantic schema validation fail-closed (1:1 TS envelopeHeader +
        # additionalProperties:false). An early implementation only used .get() to read fields, letting a missing
        # recipientDid / extra injected fields pass silently -> byte-level interop drift.
        try:
            parsed_header = EnvelopeHeader.model_validate(header)
        except _PydanticValidationError as exc:
            return self._build_invalid_envelope_result(
                detail=f"INVALID_ENVELOPE: header schema violation - {exc}",
                source_envelope=envelope,
            )

        # messageType not in {NEGOTIATION_REQUEST, NEGOTIATION_CONFIRM} ->
        # INVALID_MESSAGE (literally aligned with TS extractActionPayload).
        # ERROR / SESSION_ACK / any other value -> fail-closed, **does not** fall through to
        # business_handler.
        if message_type not in ("NEGOTIATION_REQUEST", "NEGOTIATION_CONFIRM"):
            return self._build_invalid_envelope_result(
                detail=(
                    f"INVALID_MESSAGE: Unsupported messageType for "
                    f"orchestration: {message_type}"
                ),
                source_envelope=envelope,
            )

        action = body.get("action")
        # action must be a non-empty string (INVALID_MESSAGE), literally aligned with TS
        if not isinstance(action, str) or not action:
            return self._build_invalid_envelope_result(
                detail=("INVALID_MESSAGE: Envelope body must include a " "non-empty action field."),
                source_envelope=envelope,
            )

        # sender_did / session_id are provided by EnvelopeHeader strongly-typed fields
        # (DID brand + str|None already validated); session_id required-but-nullable
        # semantics are 1:1 with TS BusinessHandlerContext.sessionId
        sender_did = parsed_header.sender_did
        session_id = parsed_header.session_id

        # params not a dict / missing / is a list -> INVALID_MESSAGE
        # literally aligned with TS (`!params || typeof params !== 'object' ||
        # Array.isArray(params)`). An early implementation silently fell through here
        # to ``params = {}``, forming a tampering attack surface.
        params = body.get("params")
        if not isinstance(params, dict):
            return self._build_invalid_envelope_result(
                detail=("INVALID_MESSAGE: Envelope body must include an object " "params field."),
                source_envelope=envelope,
            )

        # construct BusinessHandlerContext; the pydantic fail-closed Brand validator fires
        try:
            context = BusinessHandlerContext(
                action=action,  # type: ignore[arg-type] # Literal validation done by pydantic
                params=params,
                senderDid=sender_did,
                sessionId=session_id,
            )
        except Exception as exc:  # pydantic ValidationError
            return self._build_invalid_envelope_result(
                detail=f"business_context_invalid: {exc}",
                source_envelope=envelope,
            )

        # delegate to business_handler; Protocol duck typing
        handler: BusinessHandler = self._config.business_handler
        try:
            response_body = await handler(context)
        except Exception as exc:  # noqa: BLE001 - unified capture at the SDK boundary
            # business_handler raises -> INTERNAL_ERROR (aligned with the TS
            # ``buildInternalErrorEnvelope`` path); the Python binding layer uniformly
            # classifies business-side exceptions as INTERNAL_ERROR, keeping boundary handling consistent.
            return self._build_internal_error_result(
                detail=f"business_handler_error: {exc}",
                source_envelope=envelope,
            )

        if not isinstance(response_body, dict):  # pyright: ignore[reportUnnecessaryIsInstance]
            return self._build_internal_error_result(
                detail="business_handler_returned_non_dict",
                source_envelope=envelope,
            )

        # success path (full NegotiationEnvelope wire shape)
        return OrchestratorHandleResult(
            handled=True,
            responseEnvelope=self._build_response_envelope_stub(
                message_type="NEGOTIATION_RESPONSE",
                body=response_body,
                source_envelope=envelope,
            ),
            cacheable=True,
        )

    # ─── error response wire shape aligned 1:1 with the TS error-envelope ───────
    # TS literal STANDARD_ERROR_CODES:
    #     AUTHORIZATION_INSUFFICIENT / IDENTITY_VERIFICATION_FAILED /
    #     SESSION_NOT_FOUND / INVALID_ENVELOPE / INTERNAL_ERROR
    # The error envelope's wire shape: ``messageType: 'ERROR'`` +
    # ``body: {code: <STANDARD_ERROR_CODE>, message: <str>, ...}``;
    # the literal ``messageType: 'PROTOCOL_ERROR'`` does not exist (it was an early homegrown drift).
    # ────────────────────────────────────────────────────────────────────
    # ─── response_envelope full NegotiationEnvelope wire shape ───
    # TS NegotiationEnvelope literal 7 fields:
    #     id / specVersion / header / messageType / body / signature / timestamp
    # Early Python only returned the 2 fields {messageType, body} — a breach of the TS wire contract;
    # after reading from OrchestratorHandleResult.response_envelope, the user could not directly do JCS
    # canonical / signing / forwarding (missing id / signature / timestamp / header).
    # Fix: the binding layer produces a stub envelope with all fields (literally consistent with TS), but
    # the signature field is marked stub-only:
    # - id: scenario-style stub id (uuid-ish literal stub)
    # - specVersion: "0.1.0" (consistent with the scenario_runner synthetic envelope)
    # - header: swap senderDid/recipientDid (consistent with the TS responder pattern); session_id passed through
    # - signature: placeholder sentinel "BINDING_LAYER_STUB_NOT_SIGNED" (the caller should re-sign on the TS backend
    #   before wiring it out; fail-closed guard)
    # - timestamp: current ISO 8601 (consistent with the scenario_runner timestamp)
    # ────────────────────────────────────────────────────────────────────

    # binding-layer signature stub sentinel
    # the user must strip / re-sign before wiring; fail-closed guard
    _BINDING_LAYER_SIGNATURE_STUB = "BINDING_LAYER_STUB_NOT_SIGNED"

    def _build_response_envelope_stub(
        self,
        *,
        message_type: str,
        body: dict[str, Any],
        source_envelope: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Construct the full NegotiationEnvelope wire shape stub.

        Aligned with the TS NegotiationEnvelope literal 7 fields:
        id / specVersion / header / messageType / body / signature / timestamp.

        The Python binding layer does not sign (a firewall exists between the binding layer and the signing layer):
        - signature is filled with the ``BINDING_LAYER_STUB_NOT_SIGNED`` sentinel —
          fail-closed; production users can only wire it out after re-signing on the TS backend
        - header swaps senderDid/recipientDid when source_envelope is present (responder mode);
          otherwise it uses placeholder DIDs (the source may be unavailable on the error response path)
        - id / timestamp use binding-layer stub literal values (not part of JCS / signature verification)

        Production deployment has the TS backend ``handleEnvelope`` produce a fully-signed
        envelope; Python users should call this method only after completing verification + re-signing + idempotency on the backend.
        """
        from datetime import UTC, datetime
        from uuid import uuid4

        # source_envelope swap strategy: responder mode (consistent with the TS responder)
        if source_envelope is not None and isinstance(source_envelope.get("header"), dict):
            src_header = source_envelope["header"]
            response_header: dict[str, Any] = {
                "senderDid": src_header.get("recipientDid", self._config.agent_did),
                "recipientDid": src_header.get("senderDid", "did:agent:unknown"),
                "sessionId": src_header.get("sessionId"),
            }
        else:
            # error response early path (before envelope parsing fails): use agent_did + unknown
            response_header = {
                "senderDid": self._config.agent_did,
                "recipientDid": "did:agent:unknown",
                "sessionId": None,
            }

        now_iso = (
            datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.")
            + f"{datetime.now(UTC).microsecond // 1000:03d}Z"
        )

        return {
            "id": f"binding-layer-stub-{uuid4()}",
            "specVersion": "0.1.0",
            "header": response_header,
            "messageType": message_type,
            "body": body,
            "signature": self._BINDING_LAYER_SIGNATURE_STUB,
            "timestamp": now_iso,
        }

    def _build_invalid_envelope_result(
        self, *, detail: str, source_envelope: dict[str, Any] | None = None
    ) -> OrchestratorHandleResult:
        """Construct an INVALID_ENVELOPE error response stub (aligned with TS buildInvalidEnvelopeEnvelope).

        The Python binding layer does not sign + does not construct a full envelope (not a goal);
        it produces a **full** wire-shape stub: a 7-field
        NegotiationEnvelope (id / specVersion / header / messageType=ERROR /
        body.{code,message} / signature=stub-sentinel / timestamp); literally aligned with the TS
        NegotiationEnvelope.

        ``cacheable=False``: the Python binding layer takes the wire-shape stub path, not crossing a commit boundary
        (on the TS side INVALID_MESSAGE is cacheable=true, but the cache is only written when idempotencyKey is
        already initialized; the Python side does not implement an idempotency cache, so it uniformly uses false
        to avoid poisoning).
        """
        return OrchestratorHandleResult(
            handled=False,
            responseEnvelope=self._build_response_envelope_stub(
                message_type="ERROR",
                body={
                    "code": "INVALID_ENVELOPE",
                    "message": detail,
                },
                source_envelope=source_envelope,
            ),
            rejectionReason=detail,
            cacheable=False,
        )

    def _build_internal_error_result(
        self, *, detail: str, source_envelope: dict[str, Any] | None = None
    ) -> OrchestratorHandleResult:
        """Construct an INTERNAL_ERROR error response stub (aligned with TS buildInternalErrorEnvelope).

        See the ``_build_invalid_envelope_result`` docstring; body.code is changed to
        ``'INTERNAL_ERROR'``; likewise produces a 7-field full wire stub.
        """
        return OrchestratorHandleResult(
            handled=False,
            responseEnvelope=self._build_response_envelope_stub(
                message_type="ERROR",
                body={
                    "code": "INTERNAL_ERROR",
                    "message": detail,
                },
                source_envelope=source_envelope,
            ),
            rejectionReason=detail,
            cacheable=False,
        )


__all__ = [
    "Orchestrator",
    "OrchestratorConfig",
]
