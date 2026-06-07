"""Fixture loading helper.

Design principles
-----------------
- ``FIXTURE_ROOT`` is anchored at ``tests/fixtures/conformance/`` (the same root as TS
  loadFixtureDir.ts; the single authoritative source)
- ``load_fixture`` returns a dict (equivalent to TS describeFixtureFile + JSON.parse)
- ``iter_fixture_dir`` scans all .json files in a subdirectory (used by v0.3.0 cross-version)
- **Do not** define new fixtures on the Python side (all fixtures use the shared directory as the single source)

Anchors
-------
- ``tests/conformance/loadFixtureDir.ts`` (the TS counterpart; naming/shape aligned)
- ``tests/fixtures/conformance/`` physical layout
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator


# Repo root (worktree root) = the grandparent of the directory containing conftest.py
# This file's path: <repo>/tests/python/conformance/_fixture_loader.py
# fixtures: <repo>/tests/fixtures/conformance/
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
FIXTURE_ROOT = _REPO_ROOT / "tests" / "fixtures" / "conformance"


def load_fixture(relative_path: str) -> dict[str, Any]:
    """Read and parse a single fixture JSON.

    Equivalent to TS ``readFile + JSON.parse``; the shared fixture directory is the single authoritative source.
    """
    fixture_path = FIXTURE_ROOT / relative_path
    if not fixture_path.exists():
        raise FileNotFoundError(
            f"fixture not found: {fixture_path} (relative={relative_path})"
        )
    with fixture_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(
            f"fixture {relative_path} must decode to dict, got {type(data).__name__}"
        )
    return data


def iter_fixture_dir(relative_dir: str) -> Iterator[tuple[str, dict[str, Any]]]:
    """Enumerate all .json fixtures under a subdirectory.

    Consistent with TS loadFixtureDir.ts behavior: only scans direct-child .json files
    (non-recursive); returns an iterator of (basename, parsed_json) tuples.
    """
    dir_path = FIXTURE_ROOT / relative_dir
    if not dir_path.is_dir():
        raise FileNotFoundError(
            f"fixture dir not found: {dir_path} (relative={relative_dir})"
        )
    for child in sorted(dir_path.iterdir()):
        if child.is_file() and child.suffix == ".json":
            with child.open("r", encoding="utf-8") as f:
                data = json.load(f)
            yield child.name, data


def collect_samples(
    fixture: dict[str, Any], category: str
) -> list[dict[str, Any]]:
    """Extract the valid / invalid / boundary / cases / matrix sample arrays from a fixture.

    fail-closed: returns an empty list when the category does not exist (consistent with TS behavior; on the TS side,
    optional chaining ``fixture.valid ?? []``)
    """
    samples = fixture.get(category, [])
    if not isinstance(samples, list):
        raise ValueError(
            f"fixture[{category!r}] must be list, got {type(samples).__name__}"
        )
    return samples


def fixture_meta(fixture: dict[str, Any]) -> dict[str, Any]:
    """Extract the fixture's metadata (specVersion / description / $schema)."""
    return {
        "spec_version": fixture.get("specVersion"),
        "description": fixture.get("description"),
        "schema": fixture.get("$schema"),
    }
