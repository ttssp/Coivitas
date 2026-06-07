"""golden-path Step 26-31 cross-language reconciliation.

TS same-source
--------------
- ``packages/sdk/src/golden-path/index.ts:131-138`` Step 26-31
- Step 31 is the EnvelopeLedger crash recovery

step 26-31 = business core:
- 26: dual-key ROTATING
- 27: E2E encryption happy path
- 28: audit-before-execute barrier
- 29: cumulative settle cross-domain
- 30: quorum fault injection
- 31: EnvelopeLedger crash recovery

Note: Step 32 SESSION_SUPERSEDED on-chain is the last item of GOLDEN_PATH_STEPS;
TS index.ts has 33 items total (0..32). This file covers 26-31 + a separate assertion for step 32
(including Step 31 EnvelopeLedger crash recovery).
"""

from __future__ import annotations

import pytest

from coivitas import GoldenPathOptions, run_golden_path
from coivitas.golden_path import GOLDEN_PATH_STEPS


EXPECTED_STEPS_26_32 = (
    (26, "Dual-key ROTATING pass"),
    (27, "E2E encryption happy path"),
    (28, "audit-before-execute barrier"),
    (29, "cumulative settle cross-domain"),
    (30, "quorum fault injection"),
    (31, "EnvelopeLedger crash recovery"),
    (32, "SESSION_SUPERSEDED on-chain"),
)


class TestStep26To32ConformanceWithTypeScript:
    """Step 26-32 step number + step name cross-language literal alignment."""

    @pytest.mark.parametrize("number,expected_name", EXPECTED_STEPS_26_32)
    def test_step_definition_matches_ts(
        self, number: int, expected_name: str
    ) -> None:
        actual_number, actual_name = GOLDEN_PATH_STEPS[number]
        assert actual_number == number
        assert actual_name == expected_name, (
            f"step {number} name drift: Python={actual_name!r} vs TS={expected_name!r}"
        )

    def test_step_31_matches_envelope_ledger_crash_recovery(self) -> None:
        """Step 31 EnvelopeLedger crash recovery."""
        # Implementation scope: Steps 1-31, including Step 31 EnvelopeLedger crash recovery
        step_31 = next(s for s in GOLDEN_PATH_STEPS if s[0] == 31)
        assert step_31 == (31, "EnvelopeLedger crash recovery")


class TestStep26To32SkippedBehavior:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("number,expected_name", EXPECTED_STEPS_26_32)
    async def test_step_skipped_with_correct_name(
        self, number: int, expected_name: str
    ) -> None:
        result = await run_golden_path(GoldenPathOptions(pool=None))
        step = result.steps[number]
        assert step.number == number
        assert step.name == expected_name
        assert step.skipped is True
