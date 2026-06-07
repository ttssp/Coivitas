"""ScenarioRunner Python binding.

Design principles
-----------------
1. **aligned 1:1 with the TS public API** (``packages/sdk/src/scenario-runner.ts``):
   - ``__init__(*, orchestrator, verbose=False)`` keyword-only
   - ``run(scenario_file_path)`` async; returns ``ScenarioRunResult``
   - ``run_all(scenario_file_paths)`` async; sequential serial (consistent with TS);
     returns ``list[ScenarioRunResult]``
2. **shared fixtures**: scenario JSON file paths are passed in by the user; same-source fixtures as TS
   drive cross-language alignment
3. **fail-closed parsing**: corrupt JSON / wrong shape -> ScenarioRunResult.passed=False
   + the error field in step_results is populated with the failure cause
"""

from __future__ import annotations

import json
import os
import time
from datetime import UTC
from typing import Any

from coivitas.orchestrator import Orchestrator
from coivitas.types import (
    ScenarioFile,
    ScenarioRunResult,
    ScenarioStep,
    ScenarioStepResult,
)


class ScenarioRunner:
    """Scenario-driven test runner.

    Implementation notes
    ---------------------
    - keyword-only constructor
    - run + run_all dual methods
    - sequential execution (consistent with TS; scenario isolation depends on this order)
    """

    # ── ``*`` forces keyword-only ─────────────────────
    def __init__(
        self,
        *,
        orchestrator: Orchestrator,
        verbose: bool = False,
    ) -> None:
        if not isinstance(
            orchestrator, Orchestrator
        ):  # pyright: ignore[reportUnnecessaryIsInstance]
            # duck-typing compromise: check that the handle_envelope method exists
            # (consistent with the TS Pick<Orchestrator, 'handleEnvelope'> subset type)
            if not hasattr(orchestrator, "handle_envelope"):
                raise TypeError(
                    "orchestrator must have handle_envelope method "
                    "(Orchestrator instance or compatible)"
                )
        self._orchestrator = orchestrator
        self._verbose = verbose

    async def run(self, scenario_file_path: str) -> ScenarioRunResult:
        """Execute a single scenario file (method ``run``)."""
        started_at = time.monotonic()
        scenario = await self._load_scenario(scenario_file_path)
        derived_steps = self._derive_steps(scenario, scenario_file_path)

        step_results: list[ScenarioStepResult] = []
        for step in derived_steps:
            try:
                handle_result = await self._orchestrator.handle_envelope(step["envelope"])
                actual = {
                    "handled": handle_result.handled,
                    "messageType": handle_result.response_envelope.get("messageType"),
                    "body": handle_result.response_envelope.get("body"),
                }
                passed = _matches_expected(actual, step["expected_result"])
                step_results.append(
                    ScenarioStepResult(
                        name=step["name"],
                        passed=passed,
                        actualResult=actual,
                        expectedResult=step["expected_result"],
                        error=(
                            None if passed else _build_diff_message(actual, step["expected_result"])
                        ),
                    )
                )
            except Exception as exc:  # noqa: BLE001 - unified capture at the SDK boundary
                step_results.append(
                    ScenarioStepResult(
                        name=step["name"],
                        passed=False,
                        expectedResult=step["expected_result"],
                        error=str(exc),
                    )
                )

        total_duration_ms = (time.monotonic() - started_at) * 1000.0

        if self._verbose:
            # noqa T201: verbose debug output; production users should inject a logger instead
            print(  # noqa: T201
                f"Scenario {scenario.scenario_id} completed in " f"{total_duration_ms:.0f}ms"
            )

        # fail-closed on empty steps
        # `all([]) === True` would make a 0-step scenario report false-green;
        # changed to: empty step_results -> passed=False + an error explanation (typical scenario: the scenario
        # only contains unsupported envelope messageTypes, so _derive_steps drops all of them)
        if not step_results:
            empty_step_error = ScenarioStepResult(
                name=f"{scenario.scenario_id}:NO_EXECUTABLE_STEPS",
                passed=False,
                expectedResult={
                    "handled": True,
                    "messageType": "NEGOTIATION_RESPONSE",
                    "body": {"status": "SUCCESS"},
                },
                error=(
                    "Scenario yielded zero executable steps "
                    "(typical: all envelopes have unsupported messageType "
                    "outside {NEGOTIATION_REQUEST, NEGOTIATION_CONFIRM}; "
                    "or scenario.steps and scenario.envelopes both empty). "
                    "fail-closed."
                ),
            )
            return ScenarioRunResult(
                scenarioId=scenario.scenario_id,
                passed=False,
                stepResults=[empty_step_error],
                totalDurationMs=total_duration_ms,
            )

        return ScenarioRunResult(
            scenarioId=scenario.scenario_id,
            passed=all(result.passed for result in step_results),
            stepResults=step_results,
            totalDurationMs=total_duration_ms,
        )

    async def run_all(self, scenario_file_paths: list[str]) -> list[ScenarioRunResult]:
        """Execute multiple scenario files sequentially.

        Consistent with TS scenario-runner.ts: ``for ... await``, not parallel;
        scenario isolation depends on this order.
        """
        results: list[ScenarioRunResult] = []
        for path in scenario_file_paths:
            results.append(await self.run(path))
        return results

    async def _load_scenario(self, scenario_file_path: str) -> ScenarioFile:
        """Synchronous read + pydantic parsing; fail-closed shape validation.

        sync read + async wrapper (equivalent to the TS async readFile;
        Python SDK file I/O does not introduce a hard aiofiles dependency; httpx is only recommended)
        """
        with open(scenario_file_path, encoding="utf-8") as f:
            raw = f.read()
        data = json.loads(raw)
        # ScenarioFile pydantic strict mode fail-closed
        return ScenarioFile.model_validate(data)

    def _derive_steps(
        self, scenario: ScenarioFile, scenario_file_path: str
    ) -> list[dict[str, Any]]:
        """Derive the step list from scenario.steps or scenario.envelopes.

        Aligned 1:1 with TS scenario-runner.ts:123-203.
        """
        if scenario.steps:
            return [
                {
                    "name": step.name,
                    "envelope": _make_synthetic_envelope_for_step(step, index),
                    "expected_result": step.expected_result,
                }
                for index, step in enumerate(scenario.steps)
            ]

        # envelopes path
        envelopes = scenario.envelopes or []
        derived: list[dict[str, Any]] = []
        filename = os.path.basename(scenario_file_path)
        valid_message_types = {"NEGOTIATION_REQUEST", "NEGOTIATION_CONFIRM"}

        for index, envelope in enumerate(envelopes):
            if envelope.get("messageType") not in valid_message_types:
                continue

            body = envelope.get("body", {})
            action = _normalize_action(body.get("action"))
            expected_result = {
                "handled": True,
                "messageType": "NEGOTIATION_RESPONSE",
                "body": {"status": "SUCCESS"},
            }

            # do not inject the signature field (the binding layer does not verify signatures;
            # the Orchestrator.handle_envelope production-safety gate rejects an envelope containing
            # signature/capabilityToken/idempotencyKey)
            derived.append(
                {
                    "name": f"{filename}#{index + 1}:{action}",
                    "envelope": {
                        "id": f"scenario-envelope-{index}",
                        "specVersion": "0.1.0",
                        "header": envelope.get("header", {}),
                        "messageType": envelope.get("messageType"),
                        "body": body,
                        "timestamp": _iso_now(),
                    },
                    "expected_result": expected_result,
                }
            )
        return derived


# ─── helpers (not exported) ────────────────────────────────────────────────


def _make_synthetic_envelope_for_step(step: ScenarioStep, index: int) -> dict[str, Any]:
    """Synthetic envelope construction consistent with TS scenario-runner.ts.

    Does not inject the signature field (the binding layer does not verify signatures;
    the Orchestrator.handle_envelope production-safety gate rejects an envelope containing
    signature/capabilityToken/idempotencyKey).
    """
    return {
        "id": f"scenario-step-{index}",
        "specVersion": "0.1.0",
        "header": {
            "senderDid": "did:agent:00112233445566778899aabbccddeeff00112233",
            "recipientDid": "did:agent:1111222233334444555566667777888899990000",
            "sessionId": None,
        },
        "messageType": "NEGOTIATION_REQUEST",
        "body": {
            "action": step.action,
            "params": step.params,
        },
        "timestamp": _iso_now(),
    }


def _normalize_action(value: Any) -> str:
    return value if isinstance(value, str) else "UNKNOWN"


def _matches_expected(actual: dict[str, Any], expected: dict[str, Any]) -> bool:
    """Consistent with TS matchesExpected: recursively compare the dict subset."""
    for key, value in expected.items():
        actual_value = actual.get(key)
        if (
            isinstance(value, dict)
            and not isinstance(value, list)
            and isinstance(actual_value, dict)
        ):
            if not _matches_expected(actual_value, value):
                return False
            continue
        if actual_value != value:
            return False
    return True


def _build_diff_message(actual: Any, expected: Any) -> str:
    return f"expected {json.dumps(expected)} but received {json.dumps(actual)}"


def _iso_now() -> str:
    """Millisecond UTC ISO 8601, consistent with TS new Date().toISOString()."""
    from datetime import datetime

    return (
        datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.")
        + f"{datetime.now(UTC).microsecond // 1000:03d}Z"
    )


__all__ = [
    "ScenarioRunner",
]
