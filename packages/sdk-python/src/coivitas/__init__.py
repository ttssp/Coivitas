"""Coivitas Python SDK — 1:1 binding for ``@coivitas/sdk`` (TypeScript).

Export surface (all 22 items aligned 1:1 with the TypeScript SDK)
----------------------------------------
- value exports (5 items): ``Orchestrator`` / ``ManagedServiceClient`` /
 ``ManagedServiceError`` / ``run_golden_path`` / ``ScenarioRunner``
- type exports (17 items): ``OrchestratorConfig`` / ``OrchestratorHandleResult`` /
 ``BusinessHandler`` / ``BusinessHandlerContext`` / ``ManagedServiceClientConfig`` /
 ``ManagedServiceErrorCode`` / ``RevocationResult`` / ``DelegationChainValidator`` /
 ``OrchestratorLogger`` / ``TokenStoreReader`` / ``GoldenPathContext`` /
 ``GoldenPathOptions`` / ``GoldenPathResult`` / ``ScenarioFile`` /
 ``ScenarioRunResult`` / ``ScenarioStep`` / ``AgentIdentityDocument``
- Brand type aliases (9 items): ``DID`` / ``DidKey`` / ``DidAgent`` / ``Timestamp`` /
 ``Signature`` / ``PublicKey`` / ``Hash`` / ``CapabilityTokenId`` / ``RecordId``
- not mapped (out of scope): ``buildCliProgram`` / internal transport /
 ``InMemoryResponseIdempotencyCache``

 Guards
-----------------
- package isolation: this package does not depend on any TS module under ``packages/sdk/``
- wire format is consumed only, never defined; BUSINESS_ACTION_VOCABULARY matches the TS side
- Python adaptation: ``typing.cast`` Brand paths are forbidden; every Brand is validated via AfterValidator
"""

from __future__ import annotations

from coivitas.golden_path import run_golden_path
from coivitas.managed_service_client import (
 ManagedServiceClient,
 ManagedServiceError,
)
from coivitas.orchestrator import Orchestrator, OrchestratorConfig
from coivitas.scenario_runner import ScenarioRunner
from coivitas.types import (
 DID,
 AgentIdentityDocument,
 Base64Url,
 BusinessAction,
 BusinessActionLiteral,
 BusinessHandler,
 BusinessHandlerContext,
 CapabilityTokenId,
 DelegationChainValidator,
 DidAgent,
 DidKey,
 EnvelopeHeader,
 GoldenPathContext,
 GoldenPathOptions,
 GoldenPathResult,
 GoldenPathStepSummary,
 Hash,
 KeyRotationState,
 ManagedServiceClientConfig,
 ManagedServiceErrorCode,
 OrchestratorHandleResult,
 OrchestratorLogger,
 PublicKey,
 RecordId,
 RevocationResult,
 ScenarioFile,
 ScenarioRunResult,
 ScenarioStep,
 ScenarioStepResult,
 Signature,
 Timestamp,
 TokenStoreReader,
)

# Version kept in sync with pyproject.toml
__version__ = "0.1.0a1"

# ─── Public API surface (all 22 items) ─────────────────────────
__all__ = [
 # metadata
 "__version__",
 # Brand type aliases (9 items)
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
 # Envelope header (type layer; public surface)
 "EnvelopeHeader",
 #  #2-22 (21 mapped items; #1 buildCliProgram not mapped)
 "Orchestrator", # #2
 "ManagedServiceClient", # #3
 "ManagedServiceError", # #4
 "ManagedServiceClientConfig", # #5
 "RevocationResult", # #7
 "BusinessHandler", # #8 (Protocol)
 "BusinessHandlerContext", # #9
 "DelegationChainValidator", # #10 (Protocol)
 "OrchestratorConfig", # #11
 "OrchestratorHandleResult", # #12
 "OrchestratorLogger", # #13 (Protocol)
 "TokenStoreReader", # #14 (Protocol)
 "run_golden_path", # #15
 "GoldenPathContext", # #16
 "GoldenPathOptions", # #17
 "GoldenPathResult", # #18
 "GoldenPathStepSummary", # #18 subtype
 "ScenarioRunner", # #19
 "ScenarioFile", # #20
 "ScenarioRunResult", # #21
 "ScenarioStep", # #22
 "ScenarioStepResult", # #21 subtype
]
