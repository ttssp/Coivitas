#!/usr/bin/env bash
#
# tests/scripts/typecheck-tests.test.sh
#
# Unit tests for scripts/typecheck-tests.sh baseline mode + strict mode.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TESTS_PASSED=0
TESTS_FAILED=0
FAIL_REPORT=""

assert_pass() {
 local label="$1"
 TESTS_PASSED=$((TESTS_PASSED + 1))
 echo " PASS: $label"
}
assert_fail() {
 local label="$1"
 local detail="$2"
 TESTS_FAILED=$((TESTS_FAILED + 1))
 FAIL_REPORT+="FAIL: $label — $detail"$'\n'
 echo " FAIL: $label — $detail"
}

# ----- Test 1: typecheck-tests.sh exists + executable -----
echo "[T1] typecheck-tests.sh exists and is executable"
if [ -x "$REPO_ROOT/scripts/typecheck-tests.sh" ]; then
 assert_pass "typecheck-tests.sh exists + executable"
else
 assert_fail "typecheck-tests.sh missing or not executable" "$REPO_ROOT/scripts/typecheck-tests.sh"
fi

# ----- Test 2: baseline file exists -----
echo "[T2] baseline file exists"
if [ -f "$REPO_ROOT/docs/audits/typecheck-tests-baseline.txt" ]; then
 BASELINE_LINE_COUNT=$(wc -l < "$REPO_ROOT/docs/audits/typecheck-tests-baseline.txt" | tr -d ' ')
 assert_pass "baseline file exists ($BASELINE_LINE_COUNT lines)"
else
 assert_fail "baseline file missing" "$REPO_ROOT/docs/audits/typecheck-tests-baseline.txt"
fi

# ----- Test 3: --help flag works -----
echo "[T3] --help flag prints usage"
if "$REPO_ROOT/scripts/typecheck-tests.sh" --help 2>&1 | grep -q "Usage:"; then
 assert_pass "--help prints usage"
else
 assert_fail "--help does not print usage" "expected 'Usage:' in output"
fi

# ----- Test 4: invalid flag returns exit 2 -----
echo "[T4] unknown flag returns exit 2"
set +e
"$REPO_ROOT/scripts/typecheck-tests.sh" --unknown-flag-xyz >/dev/null 2>&1
EXIT_CODE=$?
set -e
if [ "$EXIT_CODE" -eq 2 ]; then
 assert_pass "unknown flag exits with code 2"
else
 assert_fail "unknown flag wrong exit code" "expected 2 got $EXIT_CODE"
fi

# ----- Test 5: baseline mode with current state PASSes (0 new broken) -----
echo "[T5] baseline mode PASSes when state matches baseline"
set +e
OUTPUT=$("$REPO_ROOT/scripts/typecheck-tests.sh" 2>&1)
EXIT_CODE=$?
set -e
if [ "$EXIT_CODE" -eq 0 ] && echo "$OUTPUT" | grep -q "0 new broken"; then
 assert_pass "baseline mode PASS with 0 new broken"
else
 assert_fail "baseline mode unexpected" "exit=$EXIT_CODE; output last line: $(echo "$OUTPUT" | tail -1)"
fi

# ----- Test 6: script declares strict / baseline / regenerate modes -----
echo "[T6] script supports 3 modes"
SCRIPT_FILE="$REPO_ROOT/scripts/typecheck-tests.sh"
if grep -q '\-\-strict' "$SCRIPT_FILE"; then
 assert_pass "--strict mode declared"
else
 assert_fail "--strict mode missing" "in $SCRIPT_FILE"
fi
if grep -q '\-\-regenerate-baseline' "$SCRIPT_FILE"; then
 assert_pass "--regenerate-baseline mode declared"
else
 assert_fail "--regenerate-baseline mode missing" "in $SCRIPT_FILE"
fi
if grep -q '\-\-baseline=' "$SCRIPT_FILE"; then
 assert_pass "--baseline=PATH mode declared"
else
 assert_fail "--baseline=PATH mode missing" "in $SCRIPT_FILE"
fi

# ----- Test 7: tsconfig.eslint.json includes tests/** -----
echo "[T7] tsconfig.eslint.json covers tests/**"
if grep -q '"./tests/\*\*/\*.ts"' "$REPO_ROOT/tsconfig.eslint.json"; then
 assert_pass "tsconfig.eslint.json includes tests/**"
else
 assert_fail "tsconfig.eslint.json missing tests/**" "include array in $REPO_ROOT/tsconfig.eslint.json"
fi

# ----- Test 10: --tsBuildInfoFile redirect — script does not write into git working tree -----
# Note: tsconfig.eslint.json is a composite project (cannot use --incremental false; triggers TS6379)
# → implemented by redirecting --tsBuildInfoFile to mktemp.
echo "[T10] script redirects tsBuildInfoFile to tmpfs (no git working tree write)"
if grep -q 'tsBuildInfoFile' "$REPO_ROOT/scripts/typecheck-tests.sh" && \
 grep -q 'TSC_BUILDINFO=\$(mktemp' "$REPO_ROOT/scripts/typecheck-tests.sh"; then
 assert_pass "script passes --tsBuildInfoFile to tmpfs"
else
 assert_fail "script missing --tsBuildInfoFile redirect" "tsbuildinfo write into git working tree = read-only env break"
fi

# ----- Test 11: fail-closed on tsc crash -----
echo "[T11] script fail-closed when tsc exits non-zero with no parseable diagnostics"
if grep -q 'TYPECHECK-TESTS TOOL FAILURE' "$REPO_ROOT/scripts/typecheck-tests.sh" && \
 grep -q 'TSC_EXIT.*-ne 0.*CURRENT_COUNT.*-eq 0' "$REPO_ROOT/scripts/typecheck-tests.sh" && \
 grep -q 'exit 2' "$REPO_ROOT/scripts/typecheck-tests.sh"; then
 assert_pass "script fail-closed on tsc crash (exit 2 + TOOL FAILURE message)"
else
 assert_fail "script missing fail-closed guard" "tsc crash → assumed PASS = critical"
fi

# ----- Test 12: normalized baseline diff -----
echo "[T12] script normalizes baseline keys (path|errorCode|message; no line:col)"
if grep -q 'normalize_diag_key' "$REPO_ROOT/scripts/typecheck-tests.sh" && \
 grep -q 'CURRENT_KEYS' "$REPO_ROOT/scripts/typecheck-tests.sh" && \
 grep -q 'BASELINE_KEYS' "$REPO_ROOT/scripts/typecheck-tests.sh"; then
 assert_pass "script normalizes baseline keys via normalize_diag_key"
else
 assert_fail "script missing normalized baseline diff" "a line:col change would trigger a false regression"
fi

# ----- summary -----
echo ""
echo "========================================"
echo "typecheck-tests.test.sh"
echo " PASSED: $TESTS_PASSED"
echo " FAILED: $TESTS_FAILED"
echo "========================================"

if [ "$TESTS_FAILED" -gt 0 ]; then
 echo ""
 echo "$FAIL_REPORT"
 exit 1
fi
exit 0
