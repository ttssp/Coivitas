"""ScenarioRunner behavioral contract.

Anti self-equal
---------------
Every assertion exercises production code in ``ScenarioRunner.__init__`` /
``run`` / ``run_all`` / ``ScenarioFile.model_validate``; not a mock asserting
equality with itself.
"""

from __future__ import annotations

import json
import os
import tempfile

import pytest

from coivitas import (
    BusinessHandlerContext,
    Orchestrator,
    OrchestratorConfig,
    ScenarioFile,
    ScenarioRunner,
    ScenarioRunResult,
    ScenarioStep,
)


class _EchoBusinessHandler:
    async def __call__(self, ctx: BusinessHandlerContext) -> dict:
        return {"status": "SUCCESS"}


class _NoopPolicyEngine:
    async def execute_with_policy(self, *a, **k):
        return {}


class _NoopTransport:
    async def send(self, *a, **k):
        return None


class _NoopRecorder:
    async def record(self, *a, **k):
        return "rec"


def _make_orchestrator() -> Orchestrator:
    config = OrchestratorConfig(
        agentDid="did:agent:" + "a" * 40,
        agentPrivateKey="stub",
        principalDid="did:agent:" + "b" * 40,
        policyEngine=_NoopPolicyEngine(),
        transport=_NoopTransport(),
        businessHandler=_EchoBusinessHandler(),
        policyRecorder=_NoopRecorder(),
    )
    return Orchestrator(config)


# ─── ScenarioRunner __init__ keyword-only enforce ────


class TestScenarioRunnerKeywordOnlyConstructor:
    def test_keyword_only_orchestrator_required(self) -> None:
        orch = _make_orchestrator()
        # keyword-only path: ok
        runner = ScenarioRunner(orchestrator=orch)
        assert runner is not None

    def test_positional_orchestrator_raises_typeerror(self) -> None:
        """``*`` enforces keyword-only."""
        orch = _make_orchestrator()
        with pytest.raises(TypeError):
            ScenarioRunner(orch)  # type: ignore[misc]

    def test_object_without_handle_envelope_raises(self) -> None:
        """Duck-typing validation: missing handle_envelope method -> TypeError."""
        with pytest.raises(TypeError, match="handle_envelope"):
            ScenarioRunner(orchestrator=object())  # type: ignore[arg-type]

    def test_verbose_default_false(self) -> None:
        orch = _make_orchestrator()
        runner = ScenarioRunner(orchestrator=orch)
        # Internal _verbose field; verify the default value via reflection
        assert runner._verbose is False  # type: ignore[attr-defined]


# ─── ScenarioRunner.run (main path) ───────────────────────


class TestScenarioRunnerRun:
    def _write_scenario_file(self, content: dict) -> str:
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        )
        json.dump(content, tmp)
        tmp.close()
        return tmp.name

    @pytest.mark.asyncio
    async def test_run_with_steps_path_dispatches(self) -> None:
        path = self._write_scenario_file(
            {
                "scenarioId": "test-scenario-1",
                "description": "echo INQUIRY",
                "steps": [
                    {
                        "name": "step-1",
                        "action": "INQUIRY",
                        "params": {"item": "x"},
                        "expectedResult": {
                            "handled": True,
                            "messageType": "NEGOTIATION_RESPONSE",
                        },
                    }
                ],
            }
        )
        try:
            orch = _make_orchestrator()
            runner = ScenarioRunner(orchestrator=orch)
            result = await runner.run(path)
            assert isinstance(result, ScenarioRunResult)
            assert result.scenario_id == "test-scenario-1"
            assert result.passed is True
            assert len(result.step_results) == 1
            assert result.step_results[0].passed is True
            # Matches TS scenario-runner.ts:67-71: actual_result contains handled / messageType / body
            actual = result.step_results[0].actual_result
            assert actual is not None
            assert actual["handled"] is True
            assert actual["messageType"] == "NEGOTIATION_RESPONSE"
        finally:
            os.unlink(path)

    @pytest.mark.asyncio
    async def test_run_with_envelopes_path_filters_negotiation_types(
        self,
    ) -> None:
        """Matches TS scenario-runner.ts:155-160: only NEGOTIATION_REQUEST/CONFIRM enter."""
        path = self._write_scenario_file(
            {
                "scenarioId": "test-scenario-2",
                "description": "envelope-driven",
                "envelopes": [
                    {
                        "messageType": "NEGOTIATION_REQUEST",
                        "header": {
                            "senderDid": "did:agent:" + "a" * 40,
                            "recipientDid": "did:agent:" + "b" * 40,
                            "sessionId": None,
                        },
                        "body": {"action": "PUBLISH", "params": {}},
                    },
                    {
                        "messageType": "NEGOTIATION_RESPONSE",  # should be filtered out
                        "header": {
                            "senderDid": "did:agent:" + "a" * 40,
                            "recipientDid": "did:agent:" + "b" * 40,
                            "sessionId": None,
                        },
                        "body": {"action": "QUOTE", "params": {}},
                    },
                ],
            }
        )
        try:
            orch = _make_orchestrator()
            runner = ScenarioRunner(orchestrator=orch)
            result = await runner.run(path)
            # Only 1 step (NEGOTIATION_REQUEST is kept)
            assert len(result.step_results) == 1
            assert "PUBLISH" in result.step_results[0].name
        finally:
            os.unlink(path)

    @pytest.mark.asyncio
    async def test_run_failed_step_records_diff_message(self) -> None:
        """expected != actual -> step.passed=False + error contains a diff message."""
        path = self._write_scenario_file(
            {
                "scenarioId": "test-fail",
                "description": "expected mismatch",
                "steps": [
                    {
                        "name": "expect-fail",
                        "action": "INQUIRY",
                        "params": {},
                        "expectedResult": {"handled": False},  # intentionally wrong
                    }
                ],
            }
        )
        try:
            orch = _make_orchestrator()
            runner = ScenarioRunner(orchestrator=orch)
            result = await runner.run(path)
            assert result.passed is False
            assert result.step_results[0].passed is False
            assert "expected" in (result.step_results[0].error or "").lower()
        finally:
            os.unlink(path)

    # Regression guard:
    # Before the fix: every envelope has an unsupported messageType -> derived_steps is empty ->
    # all([]) === True -> passed=True false-green
    # After the fix: empty step_results -> automatically inject a NO_EXECUTABLE_STEPS error step + passed=False

    @pytest.mark.asyncio
    async def test_run_with_only_unsupported_envelopes_fails_closed(self) -> None:
        """All envelopes unsupported -> fail-closed.

        Before the fix `all([]) === True` produced a false-positive PASS;
        after the fix it injects a NO_EXECUTABLE_STEPS error step + passed=False.
        """
        path = self._write_scenario_file(
            {
                "scenarioId": "test-empty-after-filter",
                "description": "all envelopes unsupported",
                "envelopes": [
                    {
                        "messageType": "NEGOTIATION_RESPONSE",  # all unsupported
                        "header": {
                            "senderDid": "did:agent:" + "a" * 40,
                            "recipientDid": "did:agent:" + "b" * 40,
                            "sessionId": None,
                        },
                        "body": {"action": "QUOTE", "params": {}},
                    },
                    {
                        "messageType": "ACTION_RECORD",  # also unsupported
                        "header": {
                            "senderDid": "did:agent:" + "a" * 40,
                            "recipientDid": "did:agent:" + "b" * 40,
                            "sessionId": None,
                        },
                        "body": {},
                    },
                ],
            }
        )
        try:
            orch = _make_orchestrator()
            runner = ScenarioRunner(orchestrator=orch)
            result = await runner.run(path)

            # Key fix assertion: fail-closed (passed=False), not a false-green PASS
            assert result.passed is False, (
                "Empty derived steps should fail-closed; "
                "previously `all([]) === True` gave a false-positive PASS"
            )
            # The injected NO_EXECUTABLE_STEPS error step
            assert len(result.step_results) == 1
            error_step = result.step_results[0]
            assert error_step.passed is False
            assert "NO_EXECUTABLE_STEPS" in error_step.name
            assert error_step.error is not None
            assert "zero executable steps" in error_step.error
            assert "fail-closed" in error_step.error
        finally:
            os.unlink(path)


# ─── ScenarioRunner.run_all ─────────────────────


class TestScenarioRunnerRunAll:
    @pytest.mark.asyncio
    async def test_run_all_executes_in_order(self) -> None:
        """Matches TS scenario-runner.ts:113-121: serial execution; input order preserved."""
        files: list[str] = []
        try:
            for i in range(3):
                tmp = tempfile.NamedTemporaryFile(
                    mode="w", suffix=".json", delete=False, encoding="utf-8"
                )
                json.dump(
                    {
                        "scenarioId": f"scenario-{i}",
                        "description": f"test {i}",
                        "steps": [
                            {
                                "name": f"step-{i}",
                                "action": "INQUIRY",
                                "params": {},
                                "expectedResult": {"handled": True},
                            }
                        ],
                    },
                    tmp,
                )
                tmp.close()
                files.append(tmp.name)

            orch = _make_orchestrator()
            runner = ScenarioRunner(orchestrator=orch)
            results = await runner.run_all(files)

            assert len(results) == 3
            for i, result in enumerate(results):
                assert result.scenario_id == f"scenario-{i}"
        finally:
            for f in files:
                if os.path.exists(f):
                    os.unlink(f)

    @pytest.mark.asyncio
    async def test_run_all_empty_list_returns_empty(self) -> None:
        orch = _make_orchestrator()
        runner = ScenarioRunner(orchestrator=orch)
        results = await runner.run_all([])
        assert results == []


# ─── ScenarioFile pydantic strict shape ──────────────


class TestScenarioFileShape:
    def test_minimal_scenario_file_construct(self) -> None:
        sf = ScenarioFile(
            scenarioId="test",
            description="minimal",
        )
        assert sf.scenario_id == "test"
        assert sf.steps is None
        assert sf.envelopes is None

    def test_scenario_file_with_steps(self) -> None:
        sf = ScenarioFile(
            scenarioId="with-steps",
            description="has steps",
            steps=[
                ScenarioStep(
                    name="s1",
                    action="INQUIRY",
                    params={},
                    expectedResult={"handled": True},
                )
            ],
        )
        assert len(sf.steps or []) == 1
