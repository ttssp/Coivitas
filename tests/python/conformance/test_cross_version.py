"""Cross-version conformance fixtures (v0.3.0 cross-version compatibility matrix).

TS same-source
--------------
- ``tests/conformance/communication-fixtures.test.ts:133-162`` v0.3.0 subdirectory scan
- ``tests/interop/conformance-suite.test.ts:126`` ``describeVersionDirFixtures('v0.3.0')``
- shared fixtures: ``tests/fixtures/conformance/v0.3.0/*.json`` 8 files

Cross-language alignment contract (silent-skip guard)
-----------------------------------------------------
1. **Directory loading**: the v0.3.0 subdirectory has at least 1 .json file
2. **Total sample count**: valid + invalid + cases + matrix sum > 0
3. **schema routing**: each fixture must carry a top-level ``$schema`` or ``schemaId`` declaration,
   or a case must carry its own ``schemaId`` override (a contract equivalent to TS V030_FIXTURE_SCHEMA_REGISTRY;
   does not replicate the full AJV routing)
4. **expectedResult tri-state fail-closed** (consistent with TS conformance-suite.test.ts:275-289)
   PASS / REJECT / FAIL / RUNTIME_DEPENDENT; any other value → fail (silent-acceptance guard)
"""

from __future__ import annotations

import pytest

from ._fixture_loader import collect_samples, iter_fixture_dir


VALID_EXPECTED_RESULTS = frozenset({"PASS", "REJECT", "FAIL", "RUNTIME_DEPENDENT"})


class TestCrossVersionDirectoryScan:
    """Corresponds to TS describeVersionDirFixtures('v0.3.0')."""

    def test_v030_directory_loads_at_least_one_fixture(self) -> None:
        """Corresponds to TS line 139-141 + 143-147: fixture loading + silent-skip guard."""
        loaded_files = list(iter_fixture_dir("v0.3.0"))
        assert len(loaded_files) > 0, "v0.3.0 directory empty (silent skip)"

    def test_v030_aggregates_non_zero_sample_total(self) -> None:
        """v0.3.0 sample aggregate count silent-skip guard."""
        total_samples = 0
        for filename, fixture in iter_fixture_dir("v0.3.0"):
            for category in ("valid", "invalid", "boundary", "cases", "matrix",
                             "cross_version", "encoding_pairs"):
                samples = fixture.get(category, [])
                if isinstance(samples, list):
                    total_samples += len(samples)
        assert total_samples > 0, "v0.3.0 aggregate sample count = 0"

    def test_v030_each_fixture_declares_schema_or_uses_registry(self) -> None:
        """A contract equivalent to TS V030_FIXTURE_SCHEMA_REGISTRY: every fixture must have a schema routing basis."""
        # Consistent with TS conformance-suite.test.ts:51-64 V030_FIXTURE_SCHEMA_REGISTRY
        TS_REGISTRY_FILES = frozenset({
            "dual-key-rotation.v0.3.json",
            "delegation-depth-boundary.v0.3.json",
            "action-vocabulary-supersede.v0.3.json",
            "cross-version.v0.3.json",
            "control-plane-action-isolation.v0.3.json",
        })

        for filename, fixture in iter_fixture_dir("v0.3.0"):
            has_top_level_schema = (
                fixture.get("schemaId") is not None
                or fixture.get("$schema") is not None
            )
            in_registry = filename in TS_REGISTRY_FILES
            # cases/matrix may carry a per-case schemaId override; not required at the top level
            has_per_case_schema = False
            for category in ("cases", "matrix", "valid", "invalid"):
                samples = fixture.get(category, [])
                if isinstance(samples, list):
                    for case in samples:
                        if isinstance(case, dict) and "schemaId" in case:
                            has_per_case_schema = True
                            break
                if has_per_case_schema:
                    break

            # At least one schema routing basis
            assert (
                has_top_level_schema or in_registry or has_per_case_schema
            ), (
                f"{filename} has no schema routing source "
                f"(no top-level schemaId, not in registry, no per-case override)"
            )

    def test_v030_expected_result_tokens_are_well_known(self) -> None:
        """Consistent with the TS conformance-suite.test.ts:275-289 fail-closed:

        expectedResult must be one of PASS / REJECT / FAIL / RUNTIME_DEPENDENT (or absent);
        an unknown token → fail (silent-acceptance guard).
        """
        for filename, fixture in iter_fixture_dir("v0.3.0"):
            for category in ("cases", "matrix", "valid", "invalid"):
                samples = fixture.get(category, [])
                if not isinstance(samples, list):
                    continue
                for case in samples:
                    if not isinstance(case, dict):
                        continue
                    expected_result = case.get("expectedResult")
                    if expected_result is None:
                        continue
                    assert expected_result in VALID_EXPECTED_RESULTS, (
                        f"{filename}/{case.get('id', '<unnamed>')}: "
                        f"unknown expectedResult={expected_result!r}; "
                        f"expected one of {sorted(VALID_EXPECTED_RESULTS)}"
                    )


class TestCrossVersionFixtureSpecificFiles:
    """v0.3.0 key fixture health (literally corresponding to TS V030_FIXTURE_SCHEMA_REGISTRY)."""

    @pytest.mark.parametrize(
        "filename",
        [
            "dual-key-rotation.v0.3.json",
            "delegation-depth-boundary.v0.3.json",
            "action-vocabulary-supersede.v0.3.json",
            "cross-version.v0.3.json",
            "control-plane-action-isolation.v0.3.json",
            "cross-version-intervalidation.v0.3.json",
            "encoding-switch-dual-format.v0.3.json",
            "v030-base64url-field-extensions.v0.3.json",
        ],
    )
    def test_known_v030_fixture_present_and_loadable(self, filename: str) -> None:
        # Aligned with the TS V030_FIXTURE_SCHEMA_REGISTRY + describeVersionDirFixtures list
        files = dict(iter_fixture_dir("v0.3.0"))
        assert filename in files, f"{filename} missing from v0.3.0 directory"
        fixture = files[filename]
        assert isinstance(fixture, dict)
