"""Python SDK type mapping.

Design principles
-----------------
1. **unified Brand path**: all Brand types = ``Annotated[str, AfterValidator(_check_*)]``,
   not ``NewType``.
2. **BaseModel strict mode**: ``model_config = ConfigDict(strict=True)``;
   no implicit type coercion, no ``arbitrary_types_allowed``.
3. **wire format alias**: every snake_case field corresponds to ``Field(alias=<camelCase>)``,
   ``populate_by_name=True`` allows flexibility on the construction side; serialization defaults to ``model_dump(by_alias=True)``.
4. **full scope**: exports all 22 items, aligned 1:1 with the TS side
   (the full Orchestrator / ManagedServiceClient / ScenarioRunner / golden_path family).

Anchors
-------
- ``packages/sdk/src/index.ts`` re-export full set (22 items)
- ``packages/types/src/identity.ts`` AgentIdentityDocument (strongly typed)
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from enum import StrEnum
from typing import Annotated, Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic.functional_validators import AfterValidator

from coivitas._brands import (
    _check_base64url,
    _check_cap_token_id,
    _check_did,
    _check_did_agent,
    _check_did_key,
    _check_hash,
    _check_public_key,
    _check_record_id,
    _check_signature,
    _check_timestamp,
)

# ─── Brand type aliases (unified form) ──────────────────────────
# Note: these are type aliases, not directly constructible (no __init__);
# all validation happens when a BaseModel field is instantiated (pydantic AfterValidator fires automatically)

DID = Annotated[str, AfterValidator(_check_did)]
DidKey = Annotated[str, AfterValidator(_check_did_key)]
DidAgent = Annotated[str, AfterValidator(_check_did_agent)]
Timestamp = Annotated[str, AfterValidator(_check_timestamp)]
Signature = Annotated[str, AfterValidator(_check_signature)]
PublicKey = Annotated[str, AfterValidator(_check_public_key)]
Hash = Annotated[str, AfterValidator(_check_hash)]
CapabilityTokenId = Annotated[str, AfterValidator(_check_cap_token_id)]
RecordId = Annotated[str, AfterValidator(_check_record_id)]
# base64url Brand (1:1 with TS BASE64URL_PATTERN ={0,2} padding;
# byte-level interop; boundary catches at the type layer by default)
Base64Url = Annotated[str, AfterValidator(_check_base64url)]


# ─── Enums───────────────────────────────────────────────


class BusinessAction(StrEnum):
    """Business action vocabulary (schemas.ts:120 BUSINESS_ACTION_VOCABULARY).

    Note: BaseModel fields use ``BusinessActionLiteral`` rather than this StrEnum;
    see the module top-level comment for details.
    """

    INQUIRY = "INQUIRY"
    QUOTE = "QUOTE"
    CONFIRM = "CONFIRM"
    PUBLISH = "PUBLISH"
    RECORD = "RECORD"


BusinessActionLiteral = Literal[
    "INQUIRY",
    "QUOTE",
    "CONFIRM",
    "PUBLISH",
    "RECORD",
]


class ManagedServiceErrorCode(StrEnum):
    """ManagedService error codes."""

    MANAGED_SERVICE_CLIENT_ERROR = "MANAGED_SERVICE_CLIENT_ERROR"
    MANAGED_SERVICE_RATE_LIMITED = "MANAGED_SERVICE_RATE_LIMITED"


class KeyRotationState(StrEnum):
    """Key rotation state (aligned with packages/types/src/types.ts KeyRotationState)."""

    STABLE = "STABLE"
    ROTATING = "ROTATING"
    FROZEN = "FROZEN"


# ─── BaseModel shared config──────────────────────────────────────


_STRICT_MODEL_CONFIG = ConfigDict(
    strict=True,
    populate_by_name=True,
    extra="forbid",
)


# ─── BusinessHandler-related Models──────────────────────────────


class BusinessHandlerContext(BaseModel):
    """Business handler context (the orchestrator BusinessHandler input).

    ``action`` Literal accepts a string; ``session_id`` is required-but-nullable.
    """

    model_config = _STRICT_MODEL_CONFIG

    action: BusinessActionLiteral
    params: dict[str, Any]
    sender_did: DID = Field(alias="senderDid")
    session_id: str | None = Field(alias="sessionId")


# ─── Orchestrator-related Models──────────────────────────────────────


class OrchestratorHandleResult(BaseModel):
    """Orchestrator handle result.

    Includes the ``cacheable`` + ``response_spec`` fields.
    """

    model_config = _STRICT_MODEL_CONFIG

    handled: bool
    response_envelope: dict[str, Any] = Field(alias="responseEnvelope")
    record_id: str | None = Field(default=None, alias="recordId")
    rejection_reason: str | None = Field(default=None, alias="rejectionReason")
    cacheable: bool | None = Field(default=None)
    response_spec: dict[str, Any] | None = Field(default=None, alias="responseSpec")


# ─── Identity-related Models──────────────────────────────────────


class ServiceEndpoint(BaseModel):
    """Service endpoint (aligned 1:1 with packages/types/src/identity.ts:10-14).

    Upgraded from dict[str, Any] to a
    strongly-typed BaseModel + extra=forbid, aligned with the TS schema additionalProperties: false.
    """

    model_config = _STRICT_MODEL_CONFIG

    id: str
    type: str
    url: str


class BindingProof(BaseModel):
    """Binding proof (aligned 1:1 with packages/types/src/identity.ts:16-22).

    Upgraded from dict[str, Any] to a
    strongly-typed BaseModel + extra=forbid + Brand fields.
    principal_did -> refined to DidKey (literal identity.ts:17);
    agent_did -> refined to DidAgent (literally aligned with the TS schemas.ts pattern).
    """

    model_config = _STRICT_MODEL_CONFIG

    # principalDid must be did:key (literal identity.ts:17)
    principal_did: DidKey = Field(alias="principalDid")
    # agentDid must be did:agent (literal identity.ts:18)
    agent_did: DidAgent = Field(alias="agentDid")
    issued_at: Timestamp = Field(alias="issuedAt")
    # expires_at may be null (literal identity.ts:20 Timestamp | null)
    expires_at: Timestamp | None = Field(default=None, alias="expiresAt")
    signature: Signature


class RotationProof(BaseModel):
    """Key rotation proof (aligned 1:1 with packages/types/src/identity.ts:30-38).

    Upgraded from dict[str, Any] to a
    strongly-typed BaseModel + extra=forbid. The triple signature (old/new/principal) is all strictly validated.
    {old,new}_public_key refined with the PublicKey brand; agent_did -> refined to DidAgent.
    """

    model_config = _STRICT_MODEL_CONFIG

    # the public key must pass PublicKey Brand validation (literal identity.ts:31-32)
    old_public_key: PublicKey = Field(alias="oldPublicKey")
    new_public_key: PublicKey = Field(alias="newPublicKey")
    old_key_signature: Signature = Field(alias="oldKeySignature")
    new_key_signature: Signature = Field(alias="newKeySignature")
    principal_signature: Signature = Field(alias="principalSignature")
    # agentDid must be did:agent (literal identity.ts:36)
    agent_did: DidAgent = Field(alias="agentDid")
    rotated_at: Timestamp = Field(alias="rotatedAt")


# capabilities vocabulary (literal identity.ts:89 capabilities?: string[])
# the TS schema schemas.ts literally constrains via BUSINESS_ACTION_VOCABULARY + size + uniqueness;
# here we reuse BusinessActionLiteral (already a 5-item vocabulary) + add a uniqueness check.
CapabilityVocab = Literal[
    "INQUIRY",
    "QUOTE",
    "CONFIRM",
    "PUBLISH",
    "RECORD",
]


class AgentIdentityDocument(BaseModel):
    """Agent identity document (strongly typed).

    Field-aligned 1:1 with the ``packages/types/src/identity.ts:83-99`` AgentIdentityDocument.

    ``ManagedServiceClient.resolve_did`` returns this BaseModel;
    shape + Brand validation is fail-closed at the SDK boundary.

    Trust boundary fail-closed
    ---------------------------------------------
    ``extra="allow"`` is a trust-boundary flaw:
    - accepts a schema-invalid AgentIdentityDocument (e.g. `{"attackerInjected": 1, ...}`)
    - nested ``binding_proof`` / ``rotation_proof`` / ``service_endpoints`` using
      dict[str, Any] skip validation
    - capabilities using list[str] accept arbitrary strings + duplicates

    Therefore this type adopts:
    - ``extra="forbid"`` to block unknown top-level fields, aligned with TS additionalProperties: false
    - binding_proof / rotation_proof / service_endpoints strongly typed (nested BaseModels)

    Brand field refinement
    ----------------------------------
    - id: DID -> refined to DidAgent (literal identity.ts:84)
    - principal_did: DID -> refined to DidKey (literal identity.ts:86)
    - public_key: already PublicKey
    - previous_public_key: str -> refined to the PublicKey brand
    - capabilities: list[str] -> list[CapabilityVocab] + uniqueness invariant
    - rotation_proof + previous_public_key mutual-dependency invariant validator
    """

    model_config = ConfigDict(
        strict=True,
        populate_by_name=True,
        # trust boundary fail-closed, aligned with TS additionalProperties: false
        extra="forbid",
    )

    # id must be did:agent (literal identity.ts:84)
    id: DidAgent
    spec_version: str = Field(alias="specVersion")
    # principalDid must be did:key (literal identity.ts:86)
    principal_did: DidKey = Field(alias="principalDid")
    public_key: PublicKey = Field(alias="publicKey")
    # upgraded from dict[str, Any] to a BindingProof BaseModel
    binding_proof: BindingProof = Field(alias="bindingProof")
    # capabilities vocabulary constraint + uniqueness (model_validator guard)
    capabilities: list[CapabilityVocab] | None = None
    # upgraded from list[dict[str, Any]] to list[ServiceEndpoint]
    service_endpoints: list[ServiceEndpoint] | None = Field(default=None, alias="serviceEndpoints")
    created_at: Timestamp = Field(alias="createdAt")
    updated_at: Timestamp = Field(alias="updatedAt")
    # Versioned extensions (identity.ts:93-98)
    version: int | None = None
    # previous_public_key refined with the PublicKey brand (literal identity.ts:96)
    previous_public_key: PublicKey | None = Field(default=None, alias="previousPublicKey")
    # upgraded from dict[str, Any] to a RotationProof BaseModel
    rotation_proof: RotationProof | None = Field(default=None, alias="rotationProof")

    # invariant: rotation_proof => previous_public_key + capabilities uniqueness
    @model_validator(mode="after")
    def _check_invariants(self) -> AgentIdentityDocument:
        """Cross-field invariant guard.

        1. rotation_proof present -> previous_public_key must be present (TS schema literal contract;
           identity.ts:97-98 comment "required when version > 1" + rotationProof.oldPublicKey
           must equal previousPublicKey)
        2. capabilities must be unique (duplicates like ['INQUIRY', 'INQUIRY'] are not allowed)
        """
        # invariant 1: rotation_proof => previous_public_key
        if self.rotation_proof is not None and self.previous_public_key is None:
            raise ValueError(
                "AgentIdentityDocument invariant violated: "
                "rotation_proof present but previous_public_key missing "
                "(identity.ts:97-98 literal contract: rotationProof requires previousPublicKey)"
            )
        # invariant 2: capabilities uniqueness
        if self.capabilities is not None and len(self.capabilities) != len(set(self.capabilities)):
            raise ValueError(
                "AgentIdentityDocument invariant violated: "
                f"capabilities contains duplicates: {self.capabilities}"
            )
        return self


# ─── ManagedServiceClient-related Models──────────────────────────


class RevocationResult(BaseModel):
    """Credential revocation result."""

    model_config = _STRICT_MODEL_CONFIG

    credential_id: str = Field(alias="credentialId")
    revoked: bool | Literal["unknown"]
    revoked_at: str | None = Field(default=None, alias="revokedAt")
    reason: str | None = None
    fallback_reason: str | None = Field(default=None, alias="fallbackReason")


class ManagedServiceClientConfig(BaseModel):
    """Managed service client config.

    Note: the ``fallback_resolver`` / ``on_fallback`` field types are relaxed to Any,
    because FederatedResolver / Callback are Protocols, not BaseModels;
    pydantic cannot strict-validate Protocol types, but they still work via Protocol duck typing at runtime.
    """

    model_config = ConfigDict(
        # FederatedResolver is a Protocol; pydantic strict mode does not accept arbitrary objects,
        # so arbitrary_types_allowed locally relaxes it (a Protocol exception)
        arbitrary_types_allowed=True,
        populate_by_name=True,
        extra="forbid",
    )

    service_url: str | None = Field(default=None, alias="serviceUrl")
    api_key: str | None = Field(default=None, alias="apiKey")
    timeout_ms: int = Field(default=5000, alias="timeoutMs")
    max_retries: int = Field(default=0, alias="maxRetries")
    fallback_resolver: Any = Field(alias="fallbackResolver")
    on_fallback: Any | None = Field(default=None, alias="onFallback")


# ─── ScenarioRunner-related Models──────────────────────────────


class ScenarioStep(BaseModel):
    """Scenario step."""

    model_config = _STRICT_MODEL_CONFIG

    name: str
    action: str
    params: dict[str, Any]
    expected_result: dict[str, Any] = Field(alias="expectedResult")


class EnvelopeHeader(BaseModel):
    """Envelope header schema (binding-layer fail-closed).

    Aligned 1:1 literally with TS ``packages/types/src/communication.ts:43-53`` ``EnvelopeHeader``
    + the ``packages/types/src/schemas.ts:636-650`` AJV ``envelopeHeader`` schema:

    - ``senderDid``: required; DID brand pattern validation
    - ``recipientDid``: required; DID brand pattern validation (Python did not validate this before)
    - ``sessionId``: required (the key is mandatory); value ``str | None`` (schemas.ts:642 anyOf
      string|null; TS interface literal ``string | null``)
    - ``sequenceNumber``: optional; non-negative integer (schemas.ts:644 ``minimum: 0``)
    - ``capabilityTokenRef``: optional; URN ``urn:cap:<uuid>`` format (capabilityTokenId pattern)

    ``extra='forbid'`` prevents drift: TS schema ``additionalProperties: false``
    (schemas.ts:649); the Python side must reject unknown fields from the same source, otherwise an attacker could inject
    arbitrary header fields (e.g. ``attackerInjected: 1``) that TS rejects but Python silently allows.
    """

    model_config = _STRICT_MODEL_CONFIG

    sender_did: DID = Field(alias="senderDid")
    recipient_did: DID = Field(alias="recipientDid")
    session_id: str | None = Field(alias="sessionId")
    sequence_number: int | None = Field(default=None, alias="sequenceNumber", ge=0)
    capability_token_ref: CapabilityTokenId | None = Field(default=None, alias="capabilityTokenRef")


# ScenarioFile historical alias (backward compatibility; downstream should not depend on this name)
_EnvelopeHeader = EnvelopeHeader


class ScenarioFile(BaseModel):
    """Scenario file.

    Aligned with TS ``ScenarioFile``; one of ``steps`` / ``envelopes`` drives the test.
    """

    model_config = _STRICT_MODEL_CONFIG

    scenario_id: str = Field(alias="scenarioId")
    description: str
    steps: list[ScenarioStep] | None = None
    envelopes: list[dict[str, Any]] | None = None
    expected_outcomes: dict[str, Any] | None = Field(default=None, alias="expectedOutcomes")


class ScenarioStepResult(BaseModel):
    """ScenarioRunResult.step_results[]"""

    model_config = _STRICT_MODEL_CONFIG

    name: str
    passed: bool
    actual_result: dict[str, Any] | None = Field(default=None, alias="actualResult")
    expected_result: dict[str, Any] | None = Field(default=None, alias="expectedResult")
    error: str | None = None


class ScenarioRunResult(BaseModel):
    """Scenario run result."""

    model_config = _STRICT_MODEL_CONFIG

    scenario_id: str = Field(alias="scenarioId")
    passed: bool
    step_results: list[ScenarioStepResult] = Field(alias="stepResults")
    total_duration_ms: float = Field(alias="totalDurationMs")


# ─── GoldenPath-related Models──────────────────────────────────


class GoldenPathOptions(BaseModel):
    """run_golden_path input.

    Note: ``pool`` is a DatabasePool (asyncpg/psycopg3 connection pool). The Python SDK
    is positioned as a binding layer and does not bundle a pool implementation; the user passes in
    an asyncpg.Pool instance / Mock object / None. When ``pool=None``, ``run_golden_path``
    returns all-SKIPPED records (reason literal "postgres_pool_required"), consistent with the
    performance non-alignment declaration + the GoldenPathStepSummary.skipped semantics.
    """

    model_config = ConfigDict(
        arbitrary_types_allowed=True,  # DatabasePool is an arbitrary Protocol
        populate_by_name=True,
        extra="forbid",
    )

    pool: Any = None  # asyncpg.Pool / Mock / None
    identity_registry_url: str | None = Field(default=None, alias="identityRegistryUrl")
    ledger_private_key: str | None = Field(default=None, alias="ledgerPrivateKey")
    governor_public_key: str | None = Field(default=None, alias="governorPublicKey")
    governor_private_key: str | None = Field(default=None, alias="governorPrivateKey")
    verbose: bool = False


class GoldenPathStepSummary(BaseModel):
    """golden-path single-step execution summary (golden-path/runner.ts)."""

    model_config = _STRICT_MODEL_CONFIG

    number: int
    name: str
    duration_ms: float = Field(alias="durationMs")
    passed: bool
    skipped: bool | None = None
    skip_reason: str | None = Field(default=None, alias="skipReason")


class GoldenPathResult(BaseModel):
    """golden-path execution result.

    ⚠ binding-layer success semantics note
    --------------------------------------------------------------
    The Python SDK is a binding layer and does not implement the L0-L4 business paths. When the pool is absent, all steps
    are skipped but ``success=True`` — consistent with the TS behavior contract (TS also only looks at errors, not at
    skipped; a skip does not block subsequent steps). All-skipped + success=True represents a
    **binding-layer step-name conformance PASS**, not a "real E2E PASS".

    To avoid users misreading ``success=True`` as "33/33 real E2E PASS", the
    ``is_real_execution`` computed property is provided for active detection.

    User detection pattern
    ----------------------
    ::

        result = await run_golden_path(options)
        if not result.is_real_execution:
            warn("Python SDK is binding-layer; result.success=True only "
                 "means step-name conformance PASS, not real E2E execution. "
                 "Use TypeScript SDK runGoldenPath() for real E2E.")

    This field does not enter the wire format (a computed property, not part of the default model_dump serialization output);
    it is only for Python callers to actively detect the binding-layer degraded state.
    """

    model_config = _STRICT_MODEL_CONFIG

    success: bool
    steps: list[GoldenPathStepSummary]
    total_duration_ms: float = Field(alias="totalDurationMs")
    core_flow_duration_ms: float = Field(alias="coreFlowDurationMs")
    errors: list[dict[str, Any]]

    @property
    def is_real_execution(self) -> bool:
        """Whether this is a real E2E execution.

        Decision rule (literally aligned with TS behavior):
        - real E2E: **any** step is not skipped (i.e. ``skipped is not True``)
        - binding-layer skip-only: **all** steps have ``skipped=True``

        When ``is_real_execution=False`` and ``success=True`` -> the user should be warned
        "binding-layer step-name conformance PASS, not real E2E PASS";
        production users should use the TypeScript SDK ``runGoldenPath()`` for a real E2E run.

        A computed property, not part of the wire format / not part of the default model_dump serialization output.
        """
        return any(not s.skipped for s in self.steps)


class GoldenPathContext(BaseModel):
    """golden-path execution context (golden-path/context.ts).

    The Python SDK serves only as an internal state container; field-aligned with TS GoldenPathContext to
    the subset "expressible within the Python SDK scope" (pool / injected URLs / keys); L2-L4 state beyond the Python
    binding layer (IdentityRegistry / RuntimeGuard, etc.) is passed through as Any.
    """

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        populate_by_name=True,
        extra="allow",  # context fields added later pass through (wire only consumes)
    )

    pool: Any = None
    identity_registry_url: str | None = Field(default=None, alias="identityRegistryUrl")
    ledger_private_key: str | None = Field(default=None, alias="ledgerPrivateKey")
    governor_public_key: str | None = Field(default=None, alias="governorPublicKey")
    governor_private_key: str | None = Field(default=None, alias="governorPrivateKey")
    verbose: bool = False


# ─── Protocol Interfaces──────────────────────────────────────


class OrchestratorLogger(Protocol):
    """Logger Protocol (orchestrator.ts:309)."""

    def warn(self, message: str) -> None: ...
    def error(self, message: str) -> None: ...
    def info(self, message: str) -> None: ...
    def debug(self, message: str) -> None: ...


class TokenStoreReader(Protocol):
    """Token store Protocol (orchestrator.ts:170)."""

    async def get_token(self, token_id: str) -> dict[str, Any] | None: ...


class BusinessHandler(Protocol):
    """Business handler Protocol."""

    async def __call__(self, context: BusinessHandlerContext) -> dict[str, Any]: ...


class DelegationChainValidator(Protocol):
    """Delegation chain validation Protocol."""

    async def __call__(
        self,
        token: dict[str, Any],
        resolve_public_keys: Callable[[str], Awaitable[Any]],
        is_revoked: Callable[[str], Awaitable[bool]] | None = None,
        now: str | None = None,
        resolve_token: Callable[[str], Awaitable[Any]] | None = None,
    ) -> dict[str, Any]: ...


# ─── public export symbols (kept in sync with __init__.py) ──────────────────────────────


__all__ = [
    # Brand type aliases
    "DID",
    "DidKey",
    "DidAgent",
    "Timestamp",
    "Signature",
    "PublicKey",
    "Hash",
    "CapabilityTokenId",
    "RecordId",
    "Base64Url",
    # Enums + Literals
    "BusinessAction",
    "BusinessActionLiteral",
    "ManagedServiceErrorCode",
    "KeyRotationState",
    # Identity
    "AgentIdentityDocument",
    # Envelope header
    "EnvelopeHeader",
    # BusinessHandler
    "BusinessHandlerContext",
    # Orchestrator
    "OrchestratorHandleResult",
    # ManagedServiceClient
    "RevocationResult",
    "ManagedServiceClientConfig",
    # ScenarioRunner
    "ScenarioStep",
    "ScenarioFile",
    "ScenarioStepResult",
    "ScenarioRunResult",
    # GoldenPath
    "GoldenPathOptions",
    "GoldenPathStepSummary",
    "GoldenPathResult",
    "GoldenPathContext",
    # Protocols
    "OrchestratorLogger",
    "TokenStoreReader",
    "BusinessHandler",
    "DelegationChainValidator",
]
