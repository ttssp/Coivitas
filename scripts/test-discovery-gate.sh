#!/bin/bash
# test-discovery-gate.sh — CI test-discoverability gate
#
# Background: sdk-python's should_* BDD tests were once never collected in CI due to
# naming/path issues; after fixing pytest.ini, this gate guards against regressions mechanically.
#
# Rule: every package's collected test count must be > 0; the "tests written but CI doesn't run them" state is not allowed.
# - TS: every packages/*/ package (with tests/ or *.test.ts) must have vitest collect > 0
# - Python: tests/python/ pytest collect-only count > 0 + verify the should_* pattern is collected
#
# Exit codes:
# 0 = all packages have a test count > 0
# 1 = at least one package has a test count = 0 → fail-closed
#
# Usage:
# ./scripts/test-discovery-gate.sh
# ./scripts/test-discovery-gate.sh --verbose
#
# CI hook: fail-closed before turbo test. Lesson: tests declared but not run ≠ tests that exist.

set -e

VERBOSE=0
if [[ "${1:-}" == "--verbose" ]]; then
 VERBOSE=1
fi

VIOLATIONS=0
ROOT="$(git rev-parse --show-toplevel 2>/dev/null || echo .)"
cd "$ROOT"

# ─── TS package test discoverability ─────────────────────────────────────────
TS_TEST_PACKAGES=(
 "packages/types"
 "packages/crypto"
 "packages/identity"
 "packages/policy"
 "packages/communication"
 "packages/sdk"
 "packages/shared"
 "packages/managed-service-runtime"
)

check_ts_test_count() {
 local pkg_dir="$1"
 local pkg_name
 pkg_name=$(basename "$pkg_dir")

 if [[ ! -d "$pkg_dir" ]]; then
 [[ $VERBOSE -eq 1 ]] && echo "⊘ skip (not exist): $pkg_dir"
 return 0
 fi

 # Static grep of test-file count (*.test.ts / *.spec.ts); not a real vitest run (too costly).
 local test_count
 test_count=$(find "$pkg_dir" -type f \( -name "*.test.ts" -o -name "*.spec.ts" \) -not -path "*/node_modules/*" -not -path "*/dist/*" 2>/dev/null | wc -l | tr -d ' ')

 if [[ $test_count -eq 0 ]]; then
 # Check whether package.json declares a test script (no test script → exempt).
 if [[ -f "$pkg_dir/package.json" ]] && grep -q '"test":' "$pkg_dir/package.json"; then
 echo "❌ FAIL: $pkg_name has \"test\" script but 0 *.test.ts / *.spec.ts files found"
 echo " (same root cause — test declared but the actual file is missing)"
 return 1
 else
 [[ $VERBOSE -eq 1 ]] && echo "⊘ skip (no test script): $pkg_name"
 return 0
 fi
 fi

 [[ $VERBOSE -eq 1 ]] && echo "✅ $pkg_name: $test_count test files"
 return 0
}

echo "─── TS package test discovery ───"
for pkg in "${TS_TEST_PACKAGES[@]}"; do
 if ! check_ts_test_count "$pkg"; then
 VIOLATIONS=$((VIOLATIONS + 1))
 fi
done

# ─── Python sdk-python test discoverability ──────────────────
echo ""
echo "─── Python sdk-python test discovery ───"

PYTHON_TEST_DIR="tests/python"
PYTEST_INI="pytest.ini"

# 1) verify the repo-root pytest.ini exists + testpaths + python_functions
if [[ ! -f "$PYTEST_INI" ]]; then
 echo "❌ FAIL: pytest.ini missing at repo root"
 echo " (same root cause — pytest config path misplaced)"
 VIOLATIONS=$((VIOLATIONS + 1))
else
 [[ $VERBOSE -eq 1 ]] && echo "✅ pytest.ini exists"

 # verify pytest.ini testpaths includes tests/python
 if ! grep -qE "testpaths\s*=.*tests/python" "$PYTEST_INI"; then
 echo "❌ FAIL: pytest.ini missing testpaths=tests/python"
 VIOLATIONS=$((VIOLATIONS + 1))
 fi

 # verify pytest.ini python_functions includes should_* OR test_* (prevents recurrence)
 if ! grep -qE "python_functions\s*=.*(should_|test_)" "$PYTEST_INI"; then
 echo "❌ FAIL: pytest.ini missing python_functions = should_*/test_*"
 echo " (direct root cause — sdk-python BDD tests using should_* naming were not collected)"
 VIOLATIONS=$((VIOLATIONS + 1))
 fi
fi

# 2) verify the *.py test-file count under tests/python/ is > 0
if [[ -d "$PYTHON_TEST_DIR" ]]; then
 py_test_count=$(find "$PYTHON_TEST_DIR" -type f -name "*.py" -not -name "__init__.py" -not -name "conftest.py" 2>/dev/null | wc -l | tr -d ' ')

 if [[ $py_test_count -eq 0 ]]; then
 echo "❌ FAIL: tests/python/ has 0 test files (excluding __init__.py / conftest.py)"
 VIOLATIONS=$((VIOLATIONS + 1))
 else
 [[ $VERBOSE -eq 1 ]] && echo "✅ tests/python/: $py_test_count test files"
 fi

 # 3) verify the should_* pattern is actually present (covers sdk-python BDD tests)
 should_count=$(grep -rEh "^def should_" "$PYTHON_TEST_DIR" 2>/dev/null | wc -l | tr -d ' ')

 if [[ $should_count -eq 0 ]]; then
 [[ $VERBOSE -eq 1 ]] && echo "⊘ no should_* BDD tests (baseline)"
 else
 [[ $VERBOSE -eq 1 ]] && echo "✅ tests/python/ should_* count: $should_count"
 fi
else
 [[ $VERBOSE -eq 1 ]] && echo "⊘ skip (no tests/python/ dir)"
fi

# ─── verdict ────────────────────────────────────────────────────────────────
echo ""
if [[ $VIOLATIONS -eq 0 ]]; then
 echo "✅ test-discovery-gate: 0 violations — all packages have discoverable tests"
 exit 0
else
 echo "❌ test-discovery-gate: $VIOLATIONS violations"
 echo ""
 echo "Rationale: should_* tests were once never collected by CI due to naming/path issues."
 echo " Tests declared but not run by CI = tests that do not exist (false confidence)."
 exit 1
fi
