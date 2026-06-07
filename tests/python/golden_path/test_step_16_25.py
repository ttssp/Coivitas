"""golden-path Step 16-25 cross-language reconciliation.

TS same-source
--------------
- ``packages/sdk/src/golden-path/index.ts:122-131`` Step 16-25
- step 16-25 = integration: discovery / delegation chain / key rotation / scope expansion

step 16-25 = business core:
- 16-17: AgentCard publication and discovery
- 18-20: 3-level delegation chain (Principal → A → B; revoke cascade)
- 21-23: key rotation (initiate / grace / complete)
- 24-25: scope expansion (temporal_scope / cumulative_limit)
"""

from __future__ import annotations

import pytest

from coivitas import GoldenPathOptions, run_golden_path
from coivitas.golden_path import GOLDEN_PATH_STEPS


EXPECTED_STEPS_16_25 = (
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
)


class TestStep16To25ConformanceWithTypeScript:
    """Step 16-25 step number + step name cross-language literal alignment."""

    @pytest.mark.parametrize("number,expected_name", EXPECTED_STEPS_16_25)
    def test_step_definition_matches_ts(
        self, number: int, expected_name: str
    ) -> None:
        actual_number, actual_name = GOLDEN_PATH_STEPS[number]
        assert actual_number == number
        assert actual_name == expected_name, (
            f"step {number} name drift: Python={actual_name!r} vs TS={expected_name!r}"
        )


class TestStep16To25SkippedBehavior:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("number,expected_name", EXPECTED_STEPS_16_25)
    async def test_step_skipped_with_correct_name(
        self, number: int, expected_name: str
    ) -> None:
        result = await run_golden_path(GoldenPathOptions(pool=None))
        step = result.steps[number]
        assert step.number == number
        assert step.name == expected_name
        assert step.skipped is True
