"""golden-path Step 0-4 cross-language reconciliation.

TS same-source
--------------
- ``packages/sdk/src/golden-path/index.ts:105-110`` Step 0-4 name definitions
- ``packages/sdk/src/golden-path/steps-0-4.ts`` real business implementation

Cross-language reconciliation contract
--------------------------------------
- Python ``run_golden_path`` does not implement the L0-L4 business logic (binding-layer firewall)
- but it **must** share the step number + step name literals with TS (cross-language reconciliation anchor)
- ``pool=None`` → all SKIPPED; an injected ``pool`` → also SKIPPED (binding-layer degradation semantics)

Anti self-equal
---------------
Every assert reaches the ``GOLDEN_PATH_STEPS`` constant + the ``run_golden_path`` production code;
not a mock equal to itself. The step name literals are the anchor values from TS index.ts:105-110.
"""

from __future__ import annotations

import pytest

from coivitas import (
    GoldenPathOptions,
    GoldenPathStepSummary,
    run_golden_path,
)
from coivitas.golden_path import GOLDEN_PATH_STEPS


# Literally aligned with TS golden-path/index.ts:105-110 (line by line)
EXPECTED_STEPS_0_4 = (
    (0, "Generate principal keys"),
    (1, "Register Agent-A"),
    (2, "Register Agent-B"),
    (3, "Issue token A"),
    (4, "Issue token B"),
)


class TestStep0To4ConformanceWithTypeScript:
    """Step 0-4 step number + step name cross-language literal alignment."""

    def test_step_definitions_match_ts_index(self) -> None:
        """Steps 0..4 in GOLDEN_PATH_STEPS are literally equal to TS golden-path/index.ts."""
        for index, (number, name) in enumerate(EXPECTED_STEPS_0_4):
            actual_number, actual_name = GOLDEN_PATH_STEPS[index]
            assert actual_number == number, f"step {index} number drift"
            assert actual_name == name, (
                f"step {index} name drift: Python={actual_name!r} vs TS={name!r}"
            )


class TestStep0To4SkippedBehavior:
    """When pool=None, steps 0-4 are all skipped."""

    @pytest.mark.asyncio
    async def test_step_0_register_principal_keys_skipped(self) -> None:
        """Step 0: Generate principal keys (TS steps-0-4.ts:20)."""
        result = await run_golden_path(GoldenPathOptions(pool=None))
        step = result.steps[0]
        assert step.number == 0
        assert step.name == "Generate principal keys"
        assert step.skipped is True
        assert step.passed is True  # skip does not block (consistent with TS makeSkippedStepRecord)
        assert step.duration_ms == 0.0
        assert step.skip_reason is not None

    @pytest.mark.asyncio
    async def test_step_1_register_agent_a_skipped(self) -> None:
        result = await run_golden_path(GoldenPathOptions(pool=None))
        step = result.steps[1]
        assert step.number == 1
        assert step.name == "Register Agent-A"
        assert step.skipped is True

    @pytest.mark.asyncio
    async def test_step_2_register_agent_b_skipped(self) -> None:
        result = await run_golden_path(GoldenPathOptions(pool=None))
        step = result.steps[2]
        assert step.number == 2
        assert step.name == "Register Agent-B"
        assert step.skipped is True

    @pytest.mark.asyncio
    async def test_step_3_issue_token_a_skipped(self) -> None:
        result = await run_golden_path(GoldenPathOptions(pool=None))
        step = result.steps[3]
        assert step.number == 3
        assert step.name == "Issue token A"
        assert step.skipped is True

    @pytest.mark.asyncio
    async def test_step_4_issue_token_b_skipped(self) -> None:
        result = await run_golden_path(GoldenPathOptions(pool=None))
        step = result.steps[4]
        assert step.number == 4
        assert step.name == "Issue token B"
        assert step.skipped is True


class TestStep0To4InjectedPoolStillSkipped:
    """Injecting any pool object still takes the binding-layer degradation path."""

    @pytest.mark.asyncio
    async def test_injected_pool_does_not_change_skip_behavior(self) -> None:
        """Behavior is the same as pool=None; only the skip_reason changes (binding_layer_only)."""
        # Any non-None object as the pool (duck-typing)
        fake_pool = object()
        result = await run_golden_path(
            GoldenPathOptions(pool=fake_pool, verbose=False)
        )
        for index in range(5):
            step = result.steps[index]
            assert step.skipped is True
            assert "binding_layer_only" in (step.skip_reason or "")
