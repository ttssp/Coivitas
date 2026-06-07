"""golden-path GoldenPathResult invariants (cross-language reconciliation).

TS same-source
--------------
- ``packages/sdk/src/golden-path/index.ts:60-178`` runGoldenPath
- ``packages/sdk/src/golden-path/runner.ts:20-33`` makeSkippedStepRecord

Invariants
----------
1. 33 steps (reconciled against the TS index.ts:105-138 array length)
2. step.number is strictly monotonically increasing 0..32 (consistent with TS; no skipped numbers allowed)
3. ``success=True`` when all steps are skipped/passed (binding-layer degradation)
4. ``errors=[]`` (skip does not write errors; consistent with TS makeSkippedStepRecord)
5. ``total_duration_ms >= 0`` (Python time.monotonic is monotonic)
6. ``core_flow_duration_ms`` = sum of step 6-11 duration_ms; = 0 when skipped
"""

from __future__ import annotations

import pytest

from coivitas import (
    GoldenPathOptions,
    GoldenPathResult,
    GoldenPathStepSummary,
    run_golden_path,
)


class TestGoldenPathResultInvariants:
    """GoldenPathResult reconciled against TS behavior."""

    @pytest.mark.asyncio
    async def test_result_has_33_steps(self) -> None:
        """Reconciled against the TS index.ts:105-138 array length (0..32 = 33 items)."""
        result = await run_golden_path(GoldenPathOptions(pool=None))
        assert (
            len(result.steps) == 33
        ), f"expected 33 steps (0..32), got {len(result.steps)}"

    @pytest.mark.asyncio
    async def test_step_numbers_strictly_monotonic_0_to_32(self) -> None:
        result = await run_golden_path(GoldenPathOptions(pool=None))
        for index, step in enumerate(result.steps):
            assert (
                step.number == index
            ), f"steps[{index}].number={step.number} != {index} (skipped number or drift)"

    @pytest.mark.asyncio
    async def test_success_true_when_all_skipped(self) -> None:
        result = await run_golden_path(GoldenPathOptions(pool=None))
        assert result.success is True
        assert all(s.skipped is True for s in result.steps)
        assert all(s.passed is True for s in result.steps)

    @pytest.mark.asyncio
    async def test_errors_empty_when_all_skipped(self) -> None:
        result = await run_golden_path(GoldenPathOptions(pool=None))
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_total_duration_non_negative(self) -> None:
        result = await run_golden_path(GoldenPathOptions(pool=None))
        # Python time.monotonic() is monotonic; total_duration_ms >= 0
        assert result.total_duration_ms >= 0

    @pytest.mark.asyncio
    async def test_core_flow_duration_zero_when_all_skipped(self) -> None:
        """skip step duration_ms=0 → core_flow_duration_ms=0."""
        result = await run_golden_path(GoldenPathOptions(pool=None))
        assert result.core_flow_duration_ms == 0.0

    @pytest.mark.asyncio
    async def test_each_skipped_step_has_skip_reason(self) -> None:
        """skipped=True → skip_reason must be non-empty (consistent with TS makeSkippedStepRecord)."""
        result = await run_golden_path(GoldenPathOptions(pool=None))
        for step in result.steps:
            if step.skipped:
                assert step.skip_reason is not None
                assert len(step.skip_reason) > 0

    @pytest.mark.asyncio
    async def test_pool_none_skip_reason_distinct_from_pool_injected(self) -> None:
        """The skip_reason for pool=None vs pool=<obj> should differ (for easier diagnosis)."""
        result_none = await run_golden_path(GoldenPathOptions(pool=None))
        result_obj = await run_golden_path(GoldenPathOptions(pool=object()))
        # At least the reason literal differs, so users can distinguish the two degradation paths
        none_reason = result_none.steps[0].skip_reason or ""
        obj_reason = result_obj.steps[0].skip_reason or ""
        assert none_reason != obj_reason, (
            f"skip reasons should differ between pool=None ({none_reason!r}) "
            f"and pool=injected ({obj_reason!r})"
        )
        assert "postgres_pool_required" in none_reason
        assert "binding_layer_only" in obj_reason


class TestGoldenPathResultPydanticShape:
    """GoldenPathResult / GoldenPathStepSummary BaseModel shape validation."""

    @pytest.mark.asyncio
    async def test_result_serializes_with_camel_case_aliases(self) -> None:
        """wire format alias: camelCase output."""
        result = await run_golden_path(GoldenPathOptions(pool=None))
        wire = result.model_dump(by_alias=True)
        # Top-level wire fields are camelCase
        assert "totalDurationMs" in wire
        assert "coreFlowDurationMs" in wire
        # snake_case must not leak
        assert "total_duration_ms" not in wire
        assert "core_flow_duration_ms" not in wire

    @pytest.mark.asyncio
    async def test_step_summary_serializes_with_aliases(self) -> None:
        result = await run_golden_path(GoldenPathOptions(pool=None))
        first = result.steps[0]
        wire = first.model_dump(by_alias=True)
        assert "durationMs" in wire
        assert "skipReason" in wire
        assert "duration_ms" not in wire
        assert "skip_reason" not in wire

    @pytest.mark.asyncio
    async def test_step_summary_constructed_from_camel_case(self) -> None:
        """populate_by_name=True: both camelCase and snake_case are accepted."""
        s = GoldenPathStepSummary(
            number=99,
            name="custom",
            durationMs=42.5,
            passed=True,
            skipped=False,
            skipReason=None,
        )
        assert s.number == 99
        assert s.duration_ms == 42.5


# ─── is_real_execution computed-property guard ────────────────


class TestGoldenPathResultIsRealExecutionR3HIGH2:
    """is_real_execution regression.

    Design conclusion: success=True + all skipped is the established binding-layer degradation semantics;
    the success semantics are not overturned; a new is_real_execution computed property
    lets users actively detect the binding-layer skip-only state.

    Invariants verified:
    1. binding-layer skip-only → is_real_execution=False (success=True is not overturned)
    2. any step not skipped → is_real_execution=True (real E2E entry)
    3. is_real_execution does not participate in wire format serialization (the default model_dump output omits this field)
    """

    @pytest.mark.asyncio
    async def test_skip_only_result_is_real_execution_false(self) -> None:
        """All skipped (binding-layer) → is_real_execution=False;
        success=True is retained (literally aligned with TS errors.length === 0).
        """
        result = await run_golden_path(GoldenPathOptions(pool=None))
        # success=True is not overturned (literally consistent with TS golden-path/index.ts:169)
        assert result.success is True
        # is_real_execution=False because all 33 steps are skipped
        assert result.is_real_execution is False
        assert all(s.skipped for s in result.steps)

    @pytest.mark.asyncio
    async def test_skip_only_with_pool_injected_still_skip_only(self) -> None:
        """An injected pool still takes the binding-layer skip-only path (binding-layer firewall);
        is_real_execution=False.
        """

        # An injected pool still takes the binding-layer skip-only path
        # Only the skip_reason literal differs
        class _DummyPool:
            pass

        result = await run_golden_path(GoldenPathOptions(pool=_DummyPool()))
        assert result.success is True
        assert result.is_real_execution is False
        # A skip_reason different from the pool=None path (binding_layer_only)
        assert all(
            s.skip_reason and "binding_layer_only" in s.skip_reason
            for s in result.steps
        )

    def test_synthetic_real_execution_result_is_real_execution_true(self) -> None:
        """If the caller manually constructs a GoldenPathResult containing real steps (skipped=False) →
        is_real_execution=True. Verifies the computed-property logic is correct, independent of the
        binding-layer implementation path.
        """
        result = GoldenPathResult(
            success=True,
            steps=[
                GoldenPathStepSummary(
                    number=0,
                    name="real-step-0",
                    durationMs=10.5,
                    passed=True,
                    skipped=False,  # real E2E step
                ),
                GoldenPathStepSummary(
                    number=1,
                    name="real-step-1",
                    durationMs=12.3,
                    passed=True,
                    skipped=False,
                ),
            ],
            totalDurationMs=22.8,
            coreFlowDurationMs=0.0,
            errors=[],
        )
        assert result.is_real_execution is True

    def test_synthetic_mixed_result_is_real_execution_true(self) -> None:
        """Mixed steps (some skipped + some real execution) → is_real_execution=True.

        For example under the TS Step 31 DEFER path: 32/33 real-executed + 1 skipped →
        is_real_execution should evaluate to True (a real-execution step triggering = real E2E entry).
        """
        result = GoldenPathResult(
            success=True,
            steps=[
                GoldenPathStepSummary(
                    number=0,
                    name="real",
                    durationMs=10.0,
                    passed=True,
                    skipped=False,
                ),
                GoldenPathStepSummary(
                    number=31,
                    name="DEFER skip",
                    durationMs=0.0,
                    passed=True,
                    skipped=True,
                    skipReason="DEFER to a later release",
                ),
            ],
            totalDurationMs=10.0,
            coreFlowDurationMs=0.0,
            errors=[],
        )
        assert result.is_real_execution is True

    @pytest.mark.asyncio
    async def test_is_real_execution_not_in_wire_format_dump(self) -> None:
        """is_real_execution is a computed property and should not enter wire format serialization.

        This field is only for Python callers to actively detect; it does not participate in cross-language wire alignment.
        """
        result = await run_golden_path(GoldenPathOptions(pool=None))
        wire = result.model_dump(by_alias=True)
        assert "is_real_execution" not in wire
        assert "isRealExecution" not in wire
        # The five fields success / steps / totalDurationMs / coreFlowDurationMs / errors are retained
        assert {
            "success",
            "steps",
            "totalDurationMs",
            "coreFlowDurationMs",
            "errors",
        } <= set(wire.keys())
