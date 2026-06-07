"""golden-path Step 5-15 cross-language reconciliation.

TS source of truth
-------------------
- ``packages/sdk/src/golden-path/index.ts:111-122`` Step 5-15
- core flow window: step 6-11 (same range as TS coreFlowDurationMs)

step 5-15 = business core:
- 5: DID resolution
- 6: handshake
- 7-9: inquiry/quote business request-response
- 10-11: confirm path
- 12: ActionRecord write
- 13: ledger integrity verification
- 14-15: token revocation + denial after revocation
"""

from __future__ import annotations

import pytest

from coivitas import GoldenPathOptions, run_golden_path
from coivitas.golden_path import CORE_FLOW_RANGE, GOLDEN_PATH_STEPS


EXPECTED_STEPS_5_15 = (
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
)


class TestStep5To15ConformanceWithTypeScript:
    """Step 5-15 step number + step name literal cross-language alignment."""

    @pytest.mark.parametrize("number,expected_name", EXPECTED_STEPS_5_15)
    def test_step_definition_matches_ts(self, number: int, expected_name: str) -> None:
        actual_number, actual_name = GOLDEN_PATH_STEPS[number]
        assert actual_number == number
        assert actual_name == expected_name, (
            f"step {number} name drift: Python={actual_name!r} vs TS={expected_name!r}"
        )

    def test_core_flow_range_covers_steps_6_to_11(self) -> None:
        """Literal match with TS index.ts:140 ``if (number >= 6 && number <= 11)``."""
        # Python range(6, 12) covers 6,7,8,9,10,11; excludes 12
        assert list(CORE_FLOW_RANGE) == [6, 7, 8, 9, 10, 11]


class TestStep5To15SkippedBehavior:
    """When pool=None, steps 5-15 are all skipped."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("number,expected_name", EXPECTED_STEPS_5_15)
    async def test_step_skipped_with_correct_name(
        self, number: int, expected_name: str
    ) -> None:
        result = await run_golden_path(GoldenPathOptions(pool=None))
        step = result.steps[number]
        assert step.number == number
        assert step.name == expected_name
        assert step.skipped is True
        assert step.passed is True


class TestCoreFlowDurationWindowSemantic:
    """core_flow_duration_ms = sum of step 6-11 durations (matches TS)."""

    @pytest.mark.asyncio
    async def test_core_flow_duration_zero_when_all_skipped(self) -> None:
        """skipped step duration_ms=0; core flow sum = 0 (matches TS makeSkippedStepRecord)."""
        result = await run_golden_path(GoldenPathOptions(pool=None))
        # core flow window = step 6-11
        core_steps = [
            s for s in result.steps if s.number in CORE_FLOW_RANGE
        ]
        assert len(core_steps) == 6, "core flow must cover step 6,7,8,9,10,11"
        for s in core_steps:
            assert s.duration_ms == 0.0
        assert result.core_flow_duration_ms == 0.0
