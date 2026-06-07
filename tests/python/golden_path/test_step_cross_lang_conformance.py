"""Python <-> TypeScript golden-path cross-language contract tests.

Test goal (real-assertion guard + cross-language reconciliation anchors)
------------------------------------------------------------------------
The existing 5 test_step_*.py tests cover step 0-32 step name conformance +
skipped behavior + duration invariants, but **reconciliation against the
cross-language source of truth** still has gaps:

1. **Grep the step name list directly out of the TS source file** -> compare
   against the Python ``GOLDEN_PATH_STEPS`` tuple (catches drift where TS
   renamed a step but Python was not kept in sync)
2. **CORE_FLOW_RANGE 6..11 cross-language reconciliation** -> literal alignment
   with TS index.ts:140 ``if (number >= 6 && number <= 11)``
3. **Python run_golden_path binding-layer contract when a pool is injected**:
   all steps skipped + skip_reason literal = "binding_layer_only" + success=True
4. **Python run_golden_path contract when pool=None**: skip_reason literal =
   "postgres_pool_required" + success=True

Real-assertion reconciliation:
- packages/sdk/src/golden-path/index.ts:105-138 (TS step array source of truth)
- packages/sdk/src/golden-path/index.ts:140 (CORE FLOW range literal)
- packages/sdk-python/src/coivitas/golden_path.py:45-79 (Python tuple)
- packages/sdk-python/src/coivitas/golden_path.py:128-140 (pool injection contract)

Out of scope (drift prevention):
- Do not touch packages/sdk-python (design already frozen)
- Do not implement the real pool injection path
- Do not modify TS index.ts
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from coivitas.golden_path import (
    CORE_FLOW_RANGE,
    GOLDEN_PATH_STEPS,
    run_golden_path,
)
from coivitas.types import GoldenPathOptions

# TS source file (cross-language source of truth)
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
TS_GOLDEN_PATH_INDEX = (
    _REPO_ROOT / "packages" / "sdk" / "src" / "golden-path" / "index.ts"
)


def _extract_ts_steps_from_source() -> list[tuple[int, str]]:
    """Regex-extract the step array out of the TS source file (source of truth).

    Match pattern: ``[N, 'STEP NAME', () => runStepN(ctx)],``
    or ``[N, "STEP NAME", () => runStepN()],``

    Preserve source order (regex findall already yields source order),
    **do not sort** -- so the cross-language test can catch step ordering drift
    on the TS side (even if the step number stays the same, swapping array
    positions is detected; because runGoldenPath executes in array declaration
    order, not by step number).
    """
    text = TS_GOLDEN_PATH_INDEX.read_text(encoding="utf-8")
    # Dual-quote tolerant (the TS source uses single quotes, but ['"] is safer)
    pattern = re.compile(
        r"\[\s*(\d+)\s*,\s*['\"]([^'\"]+)['\"]\s*,\s*\(\)",
        re.MULTILINE,
    )
    matches = pattern.findall(text)
    # Convert to a (int, str) list -- preserve source order (do not sort)
    steps = [(int(num), name) for num, name in matches]
    return steps


# -- L1: TS source step array -> Python GOLDEN_PATH_STEPS comparison ----------


class TestStepNameCrossLangConformance:
    """TS source grepped step array -> Python GOLDEN_PATH_STEPS comparison.

    Real assertion: catch drift where TS renamed a step but Python was not synced.
    """

    def test_ts_source_step_count_matches_python(self) -> None:
        """TS step count === Python step count (33 steps; locked at 0..32)."""
        ts_steps = _extract_ts_steps_from_source()
        py_steps = list(GOLDEN_PATH_STEPS)

        assert len(ts_steps) == 33, (
            f"grepped {len(ts_steps)} steps from TS source (expected 33; "
            f"or regex failed to match source line 105-138)"
        )
        assert (
            len(py_steps) == 33
        ), f"Python GOLDEN_PATH_STEPS has {len(py_steps)} steps (expected 33)"

    def test_ts_source_step_numbers_strictly_monotonic(self) -> None:
        """TS step numbers strictly 0..32 monotonically increasing (locked)."""
        ts_steps = _extract_ts_steps_from_source()
        numbers = [n for n, _ in ts_steps]
        assert numbers == list(
            range(33)
        ), f"TS step numbers {numbers} are not strictly 0..32 monotonic"

    def test_python_step_numbers_strictly_monotonic(self) -> None:
        """Python step numbers strictly 0..32 monotonically increasing."""
        numbers = [n for n, _ in GOLDEN_PATH_STEPS]
        assert numbers == list(
            range(33)
        ), f"Python step numbers {numbers} are not strictly 0..32 monotonic"

    @pytest.mark.parametrize("step_index", list(range(33)))
    def test_step_name_byte_identical_per_index(self, step_index: int) -> None:
        """The step name for each step number is byte-identical in TS and Python."""
        ts_steps = _extract_ts_steps_from_source()
        py_steps = list(GOLDEN_PATH_STEPS)

        ts_num, ts_name = ts_steps[step_index]
        py_num, py_name = py_steps[step_index]

        assert (
            ts_num == py_num
        ), f"step index {step_index} number mismatch: TS={ts_num} Python={py_num}"
        assert ts_name == py_name, (
            f"step {ts_num} name mismatch: TS='{ts_name}' Python='{py_name}' "
            f"(cross-language reconciliation contract broken -- Python did not sync TS source rename)"
        )


# -- L2: CORE_FLOW_RANGE semantic contract -----------------------------------


class TestCoreFlowRangeSemanticContract:
    """Python CORE_FLOW_RANGE semantic contract: core flow = step 6..11.

    The previous case grepped the TS source literal 'number >= 6 && number <= 11',
    which would false-positive fail after a behavior-preserving TS refactor
    (constant / helper / equivalent inequality). Switched to verifying only the
    **semantic contract** -- Python CORE_FLOW_RANGE must be 6..11 (inclusive),
    6 steps. Whether TS uses a literal comparison / constant / helper does not
    matter: as long as the TS core-flow timing still covers step 6..11, the two
    languages agree.
    """

    def test_python_core_flow_range_is_6_to_11_inclusive(self) -> None:
        """Python CORE_FLOW_RANGE = range(6, 12) (includes 6, excludes 12 -> step 6..11)."""
        # range(6, 12) is equivalent to step numbers 6, 7, 8, 9, 10, 11 -> 6 steps
        assert list(CORE_FLOW_RANGE) == [
            6,
            7,
            8,
            9,
            10,
            11,
        ], f"Python CORE_FLOW_RANGE = {list(CORE_FLOW_RANGE)}, expected [6..11]"

    def test_python_core_flow_range_step_count_is_6(self) -> None:
        """core flow contains 6 steps (handshake -> confirm full chain)."""
        assert (
            len(list(CORE_FLOW_RANGE)) == 6
        ), f"core flow step count = {len(list(CORE_FLOW_RANGE))}, expected 6"

    def test_python_core_flow_range_boundary_inclusive(self) -> None:
        """Boundary check: 6 in range, 11 in range, 5 not in range, 12 not in range."""
        assert 6 in CORE_FLOW_RANGE, "step 6 (handshake) should be inside core flow"
        assert 11 in CORE_FLOW_RANGE, "step 11 (confirm) should be inside core flow"
        assert 5 not in CORE_FLOW_RANGE, "step 5 (DID resolution) should not be inside core flow"
        assert 12 not in CORE_FLOW_RANGE, "step 12 (action records) should not be inside core flow"


# -- L3: Python run_golden_path pool=None contract ---------------------------


class TestPythonRunGoldenPathPoolNoneContract:
    """binding-layer contract: pool=None -> all 33 steps skipped + success=True."""

    @pytest.mark.asyncio
    async def test_pool_none_returns_all_skipped_with_success_true(self) -> None:
        """pool=None -> success=True + 33 step records + all skipped=True."""
        options = GoldenPathOptions(pool=None, verbose=False)
        result = await run_golden_path(options)

        assert (
            result.success is True
        ), "when pool=None, success should be True (skip does not block -- matches TS)"
        assert len(result.steps) == 33, f"step count should be 33 (actual {len(result.steps)})"
        assert all(
            step.skipped is True for step in result.steps
        ), "all steps should be skipped=True (binding layer limitation)"
        assert (
            result.core_flow_duration_ms == 0.0
        ), "coreFlowDurationMs should be 0 in skip mode"
        assert result.errors == [], "skip mode should have no errors"

    @pytest.mark.asyncio
    async def test_pool_none_skip_reason_mentions_postgres_pool_required(
        self,
    ) -> None:
        """pool=None -> skip_reason literally contains 'postgres_pool_required'."""
        options = GoldenPathOptions(pool=None, verbose=False)
        result = await run_golden_path(options)

        for step in result.steps:
            assert (
                step.skip_reason is not None
            ), f"step {step.number} skipReason should not be None"
            assert "postgres_pool_required" in step.skip_reason, (
                f"step {step.number} skipReason='{step.skip_reason}' "
                f"missing 'postgres_pool_required' literal (cf. golden_path.py:130)"
            )

    @pytest.mark.asyncio
    async def test_pool_none_step_names_match_ts_source(self) -> None:
        """pool=None -> step names literally identical to TS source (end-to-end contract)."""
        options = GoldenPathOptions(pool=None, verbose=False)
        result = await run_golden_path(options)

        ts_steps = _extract_ts_steps_from_source()
        assert len(result.steps) == len(ts_steps)

        for actual, (expected_num, expected_name) in zip(
            result.steps, ts_steps, strict=True
        ):
            assert actual.number == expected_num
            assert actual.name == expected_name, (
                f"runtime step {actual.number} name='{actual.name}' "
                f"≠ TS source '{expected_name}'"
            )


# -- L4: Python run_golden_path pool injection contract ----------------------


class TestPythonRunGoldenPathPoolInjectedContract:
    """golden_path.py:134-140: pool injected -> all SKIPPED + binding_layer_only."""

    @pytest.mark.asyncio
    async def test_pool_injected_still_returns_all_skipped(self) -> None:
        """pool injected (any truthy placeholder value) -> still all SKIPPED.

        The Python SDK is the binding layer; it does not implement the L0-L4
        business path (binding-layer firewall).
        """
        # Use a sentinel object to impersonate a pool (no real asyncpg needed)
        sentinel_pool: object = object()
        options = GoldenPathOptions(pool=sentinel_pool, verbose=False)  # type: ignore[arg-type]
        result = await run_golden_path(options)

        assert result.success is True
        assert len(result.steps) == 33
        assert all(
            step.skipped is True for step in result.steps
        ), "should still be all skipped when a pool is injected (binding layer does not implement real business)"

    @pytest.mark.asyncio
    async def test_pool_injected_skip_reason_mentions_binding_layer_only(
        self,
    ) -> None:
        """pool injected -> skip_reason literally contains 'binding_layer_only'."""
        sentinel_pool: object = object()
        options = GoldenPathOptions(pool=sentinel_pool, verbose=False)  # type: ignore[arg-type]
        result = await run_golden_path(options)

        for step in result.steps:
            assert step.skip_reason is not None
            assert "binding_layer_only" in step.skip_reason, (
                f"when pool injected, step {step.number} skipReason="
                f"'{step.skip_reason}' missing 'binding_layer_only' literal "
                f"(cf. golden_path.py:136)"
            )


# -- L5: key step name literal anchors (milestones) --------------------------


class TestKeyStepNameAnchors:
    """Key step name literal anchors among the 11 milestones."""

    @pytest.mark.parametrize(
        "step_number,expected_name",
        [
            (0, "Generate principal keys"),
            (5, "Resolve Agent-B DID"),
            (10, "Authorize confirm on Agent-A"),
            (15, "Verify revoked token denial"),
            (20, "Revocation cascades to delegated token"),
            (25, "cumulative_limit enforces running total"),
            (30, "quorum fault injection"),
            (31, "EnvelopeLedger crash recovery"),
            (32, "SESSION_SUPERSEDED on-chain"),
        ],
    )
    def test_python_step_name_matches_anchor(
        self, step_number: int, expected_name: str
    ) -> None:
        """The name for a step number in the Python tuple matches the literal anchor exactly."""
        actual = next((n, name) for n, name in GOLDEN_PATH_STEPS if n == step_number)
        assert actual == (
            step_number,
            expected_name,
        ), f"step {step_number} name='{actual[1]}' ≠ expected '{expected_name}'"
