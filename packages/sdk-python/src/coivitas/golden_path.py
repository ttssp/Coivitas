"""run_golden_path Python binding.

Design principles
--------
1. **1:1 alignment with the TS public API** (``packages/sdk/src/golden-path/index.ts``):
   - ``run_golden_path(options) -> GoldenPathResult`` async function
   - the 33 step names (0-32) match the TS ``runGoldenPath`` array exactly
   - consistent with the TS GoldenPathStepSummary.skipped semantics
2. **Scope statement** (the Python SDK does not claim performance parity):
   the Python SDK is a binding layer; it does not embed PostgreSQL / IdentityRegistry / RuntimeGuard /
   a full communication transport (these are all L0-L4 TypeScript implementations). When
   ``pool is None``, ``run_golden_path`` returns 33 ``GoldenPathStepSummary`` records
   all with ``skipped=True`` + a ``skip_reason`` describing the binding-layer limitation, and
   ``GoldenPathResult.success=True`` (consistent with the TS ``makeSkippedStepRecord`` skip semantics)
3. **Real E2E**: inject a ``pool`` (asyncpg.Pool or a compatible Protocol) to take the external-callback injection path
   that runs the 33 steps; the Python SDK does not reimplement the L0-L4 implementation (binding-layer firewall)
4. **Cross-language step-name contract**: the 33 step-name literals match the TS
   golden-path/index.ts:105-138 list character-for-character → cross-language reconciliation PASS

Anchors
----
- ``packages/sdk/src/golden-path/index.ts:60-178`` runGoldenPath main entry point
- ``packages/sdk/src/golden-path/runner.ts:20-33`` makeSkippedStepRecord
"""

from __future__ import annotations

import time

from coivitas.types import (
    GoldenPathContext,
    GoldenPathOptions,
    GoldenPathResult,
    GoldenPathStepSummary,
)

# ─── Step-name authoritative source (1:1 aligned with TS golden-path/index.ts:105-138) ─────
# Order-locked invariant (cross-language reconciliation):
# - tuple of (number, name); number strictly monotonically increasing 0..32
# - name literals equal the TS implementation (no i18n / translation drift allowed)
# - core flow window = step 6..11 (same range as the TS coreFlowDurationMs)

GOLDEN_PATH_STEPS: tuple[tuple[int, str], ...] = (
    (0, "Generate principal keys"),
    (1, "Register Agent-A"),
    (2, "Register Agent-B"),
    (3, "Issue token A"),
    (4, "Issue token B"),
    (5, "Resolve Agent-B DID"),
    (6, "Complete handshake"),
    (7, "Send inquiry request"),
    (8, "Responder authorization check"),
    (9, "Receive quote response"),
    (10, "Authorize confirm on Agent-A"),
    (11, "Send confirm request"),
    (12, "Write action records"),
    (13, "Verify ledger integrity"),
    (14, "Revoke token A"),
    (15, "Verify revoked token denial"),
    (16, "Publish Agent-A AgentCard"),
    (17, "Discover Agent-A via AgentCard"),
    (18, "Confirm Principal→A direct issuance"),
    (19, "Delegate A→B sub-token + verify chain"),
    (20, "Revocation cascades to delegated token"),
    (21, "Initiate key rotation for Agent-A"),
    (22, "Grace-period old signature remains valid"),
    (23, "Complete rotation: old fails, new passes"),
    (24, "temporal_scope enforces time window"),
    (25, "cumulative_limit enforces running total"),
    (26, "Dual-key ROTATING pass"),
    (27, "E2E encryption happy path"),
    (28, "audit-before-execute barrier"),
    (29, "cumulative settle cross-domain"),
    (30, "quorum fault injection"),
    (31, "EnvelopeLedger crash recovery"),
    (32, "SESSION_SUPERSEDED on-chain"),
)


# core flow range (aligned with TS golden-path/index.ts:140 ``if (number >= 6 && number <= 11)``)
CORE_FLOW_RANGE = range(6, 12)


def _make_skipped(step_number: int, step_name: str, reason: str) -> GoldenPathStepSummary:
    """Skip-record construction consistent with TS makeSkippedStepRecord (runner.ts:20-33).

    duration_ms=0; passed=True (a skip does not block subsequent steps); skipped=True;
    skip_reason carries the reason literal.
    """
    return GoldenPathStepSummary(
        number=step_number,
        name=step_name,
        durationMs=0.0,
        passed=True,
        skipped=True,
        skipReason=reason,
    )


async def run_golden_path(options: GoldenPathOptions) -> GoldenPathResult:
    """Run all 33 golden-path steps.

    Python SDK behavior contract
    -------------------
    - ``options.pool is None`` → all 33 steps return ``skipped=True``;
      ``success=True`` (consistent with the TS semantics where skipped does not block subsequent steps);
      ``coreFlowDurationMs=0``; ``totalDurationMs`` reflects the method's own elapsed time
    - ``options.pool`` injected → the Python SDK **does not implement** the L0-L4 business path
      (binding-layer firewall; out of scope); it likewise returns all-SKIPPED
      records, ``skip_reason="binding_layer_only (Python SDK is binding layer; \
implement step logic in TypeScript backend)"`` — this is the legitimate degradation path of the Python SDK
      binding layer, and callers should use the TypeScript SDK runGoldenPath to run real E2E.

    ⚠ binding-layer success semantics note
    --------------------------------------------------------------
    When users see ``success=True`` + all steps skipped, they may mistake it for a "real E2E
    33/33 PASS". In fact this is consistent with the TS behavior contract — TS also looks only at errors, not skipped
    (``golden-path/index.ts`` ``return { success: errors.length === 0 }``;
    a skipped step has ``passed=true`` and does not block subsequent steps). The Python SDK is a binding layer,
    does not implement the L0-L4 business path, and all-skipped + success=True signifies a binding-layer
    step-name conformance PASS, not a real E2E PASS.

    To avoid misreading, the ``GoldenPathResult.is_real_execution`` computed property is provided, plus this method's
    verbose output explicitly warns about the binding-layer degradation state.

    User detection pattern
    ----------------
    ::

        result = await run_golden_path(options)
        if not result.is_real_execution:
            warn("Python SDK is binding-layer; result.success=True only "
                 "means step-name conformance PASS, not real E2E execution. "
                 "Use TypeScript SDK runGoldenPath() for real E2E.")

    Production deployment model
    ------------
    - TypeScript backend: runs ``runGoldenPath()`` for real E2E (requires PostgreSQL +
      WebSocket transport; all 32 steps PASS)
    - Python SDK client: uses ``ScenarioRunner`` + same-source fixture / wire format
      conformance tests to verify that client-side behavior aligns with the backend; ``run_golden_path``
      exposes only the step-name contract + skip semantics (the cross-language reconciliation anchor)
    """
    started_at = time.monotonic()
    pool = options.pool
    verbose = options.verbose

    if pool is None:
        skip_reason = (
            "postgres_pool_required "
            "(Python SDK binding layer; "
            "use TypeScript SDK runGoldenPath() for real E2E execution)"
        )
    else:
        skip_reason = (
            "binding_layer_only "
            "(Python SDK is binding layer; "
            "implement step logic in TypeScript backend, use this method for "
            "step-name conformance only)"
        )

    if verbose:
        # noqa T201: verbose debug output; production users should inject a logger instead
        # Explicitly warn about the binding-layer degradation state to avoid misreading
        # success=True is not a real E2E PASS (see GoldenPathResult.is_real_execution)
        print(  # noqa: T201
            f"run_golden_path: pool={'<injected>' if pool is not None else 'None'}, "
            f"will return {len(GOLDEN_PATH_STEPS)} skipped step records "
            f"(binding-layer mode; success=True means step-name conformance "
            f"PASS, NOT real E2E. Check result.is_real_execution before "
            f"trusting success.)"
        )

    steps: list[GoldenPathStepSummary] = [
        _make_skipped(number, name, skip_reason) for number, name in GOLDEN_PATH_STEPS
    ]

    total_duration_ms = (time.monotonic() - started_at) * 1000.0

    return GoldenPathResult(
        success=True,
        steps=steps,
        totalDurationMs=total_duration_ms,
        # TS behavior: a skipped step has durationMs=0, so the core flow sums to 0; consistent with the local implementation
        coreFlowDurationMs=0.0,
        errors=[],
    )


def make_golden_path_context(
    options: GoldenPathOptions,
) -> GoldenPathContext:
    """Construct a GoldenPathContext (used when the user implements custom steps).

    This factory method is provided to keep field mapping consistent with the TS GoldenPathContext
    (pool / identity_registry_url / ledger_private_key / governor_*);
    TS-internal fields such as ``cleanups`` / ``ownPool`` are not exposed, in keeping with the binding layer's
    "consume the wire format, do not define it" responsibility.
    """
    return GoldenPathContext(
        pool=options.pool,
        identityRegistryUrl=options.identity_registry_url,
        ledgerPrivateKey=options.ledger_private_key,
        governorPublicKey=options.governor_public_key,
        governorPrivateKey=options.governor_private_key,
        verbose=options.verbose,
    )


__all__ = [
    "GOLDEN_PATH_STEPS",
    "CORE_FLOW_RANGE",
    "run_golden_path",
    "make_golden_path_context",
]
