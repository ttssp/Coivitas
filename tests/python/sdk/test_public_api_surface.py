"""Full 22-entry 1:1 public API surface self-check (docs <-> source).

docs <-> source self-check
--------------------------
- Every ts -> python pair listed in the public mapping is importable from the
  ``coivitas`` top level
- ``__all__`` contains all declared exports
- ``__version__`` matches pyproject.toml ``project.version``

Equivalent contract to the CI gate ``pnpm sdk-python:check-mapping``
(fail-fast sentinel): if a new entry is added to the public mapping but the
Python side forgets to export it, this test goes red immediately.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import coivitas


#  Full cross-reference table (22 entries; #1 buildCliProgram is not mapped; 21 mappings remain)
SPEC_2_1_PYTHON_NAMES = (
    # value exports (5 entries; TS index.ts matches spec)
    "Orchestrator",  # #2
    "ManagedServiceClient",  # #3
    "ManagedServiceError",  # #4
    "run_golden_path",  # #15
    "ScenarioRunner",  # #19
    # type exports (16 entries)
    "ManagedServiceClientConfig",  # #5
    "ManagedServiceErrorCode",  # #6
    "RevocationResult",  # #7
    "BusinessHandler",  # #8
    "BusinessHandlerContext",  # #9
    "DelegationChainValidator",  # #10
    "OrchestratorConfig",  # #11
    "OrchestratorHandleResult",  # #12
    "OrchestratorLogger",  # #13
    "TokenStoreReader",  # #14
    "GoldenPathContext",  # #16
    "GoldenPathOptions",  # #17
    "GoldenPathResult",  # #18
    "ScenarioFile",  # #20
    "ScenarioRunResult",  # #21
    "ScenarioStep",  # #22
)


class TestSpec21FullSurface:
    """22-entry public API mapping self-check (docs <-> source anchor)."""

    @pytest.mark.parametrize("name", SPEC_2_1_PYTHON_NAMES)
    def test_each_export_importable_from_top_level(self, name: str) -> None:
        """Each mapped name must be importable from the ``coivitas`` top level."""
        assert hasattr(
            coivitas, name
        ), f"coivitas.{name} not importable"

    def test_all_names_in_dunder_all(self) -> None:
        """``__all__`` must contain all 21 mappings."""
        actual_all = set(coivitas.__all__)
        for name in SPEC_2_1_PYTHON_NAMES:
            assert name in actual_all, f"{name} missing from __all__"

    def test_version_format_pep440_alpha(self) -> None:
        """Validate the alpha version string format."""
        assert re.match(r"^\d+\.\d+\.\d+(a\d+)?$", coivitas.__version__)


class TestBrandTypeAliasesExported:
    """The 9 Brand type aliases are importable from the top level."""

    @pytest.mark.parametrize(
        "name",
        [
            "DID",
            "DidKey",
            "DidAgent",
            "Timestamp",
            "Signature",
            "PublicKey",
            "Hash",
            "CapabilityTokenId",
            "RecordId",
        ],
    )
    def test_brand_alias_importable(self, name: str) -> None:
        assert hasattr(coivitas, name), f"Brand {name} missing from public surface"


class TestEnumsExported:
    """Enums + KeyRotationState (including the ROTATING state) are importable from the top level."""

    def test_business_action_enum(self) -> None:
        from coivitas import BusinessAction

        assert {member.value for member in BusinessAction} == {
            "INQUIRY",
            "QUOTE",
            "CONFIRM",
            "PUBLISH",
            "RECORD",
        }

    def test_managed_service_error_code_enum(self) -> None:
        from coivitas import ManagedServiceErrorCode

        assert {member.value for member in ManagedServiceErrorCode} == {
            "MANAGED_SERVICE_CLIENT_ERROR",
            "MANAGED_SERVICE_RATE_LIMITED",
        }

    def test_key_rotation_state_enum(self) -> None:
        from coivitas import KeyRotationState

        assert {member.value for member in KeyRotationState} == {
            "STABLE",
            "ROTATING",
            "FROZEN",
        }


class TestNonExportedBuildCliProgram:
    """buildCliProgram is **not mapped** to the Python SDK."""

    def test_build_cli_program_not_in_public_api(self) -> None:
        """fail-closed: if someone mistakenly adds buildCliProgram to the Python SDK -> fail."""
        assert not hasattr(
            coivitas, "build_cli_program"
        ), "buildCliProgram must NOT be mapped to Python SDK"
        assert (
            "build_cli_program" not in coivitas.__all__
        ), "build_cli_program should not be in __all__"


class TestVersionSyncWithPyproject:
    """docs <-> source: __version__ stays in sync with pyproject.toml."""

    def test_version_matches_pyproject_toml(self) -> None:
        # Repo root: walk up 4 levels from tests/python/sdk/<file>.py
        repo_root = Path(__file__).resolve().parent.parent.parent.parent
        pyproject = (
            repo_root / "packages" / "sdk-python" / "pyproject.toml"
        )
        assert pyproject.exists(), f"pyproject.toml not at {pyproject}"

        content = pyproject.read_text(encoding="utf-8")
        # Extract [project] version = "..."
        match = re.search(
            r'(?m)^\s*version\s*=\s*"([^"]+)"', content
        )
        assert match is not None, "pyproject.toml missing version"
        pyproject_version = match.group(1)

        assert (
            coivitas.__version__ == pyproject_version
        ), (
            f"version drift: __version__={coivitas.__version__!r} vs "
            f"pyproject.toml version={pyproject_version!r}"
        )
