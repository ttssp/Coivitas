#!/usr/bin/env bash
#
# typecheck-tests.sh
#
# Purpose: run tsc --noEmit over tests/** + packages/*/tests/** + packages/*/src/**/__tests__/**
# baseline mode: FAIL only on the delta (new broken vs baseline); tolerate known errors in the baseline
# --strict mode: any tsc error is a FAIL
#
# Invocation:
# bash scripts/typecheck-tests.sh # baseline mode (default)
# bash scripts/typecheck-tests.sh --strict # strict mode
# bash scripts/typecheck-tests.sh --regenerate-baseline # regenerate the baseline
#
# Exit codes: 0 = baseline mode 0 new broken or strict mode 0 error / 1 = error / 2 = argument error
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

BASELINE_FILE="docs/audits/typecheck-tests-baseline.txt"
# Use a dedicated tsconfig.tests-only.json that includes only tests.
# Not tsconfig.eslint.json (which also includes packages/*/src + ./*.ts + poc/**, so its name/semantics would not match).
TSCONFIG="tsconfig.tests-only.json"
MODE="baseline"

for arg in "$@"; do
 case "$arg" in
 --strict)
 MODE="strict"
 ;;
 --regenerate-baseline)
 MODE="regenerate"
 ;;
 --baseline=*)
 BASELINE_FILE="${arg#--baseline=}"
 MODE="baseline"
 ;;
 -h|--help)
 cat <<EOF
Usage: bash scripts/typecheck-tests.sh [OPTIONS]

Options:
 --strict strict mode (any tsc error is a FAIL)
 --regenerate-baseline regenerate the baseline file (any post-run difference is accepted as the new baseline)
 --baseline=PATH specify the baseline file path (default ${BASELINE_FILE})
 -h, --help show this help

Exit codes: 0 = PASS / 1 = FAIL / 2 = argument error
EOF
 exit 0
 ;;
 *)
 echo "Unknown option: $arg" >&2
 exit 2
 ;;
 esac
done

# ---------- run tsc ----------
# tsconfig.eslint.json is a composite project (cannot use --incremental false; triggers TS6379)
# → redirect --tsBuildInfoFile to tmpfs to avoid polluting the git working tree and to keep it read-only-safe.
TSC_OUTPUT=$(mktemp "${TMPDIR:-/tmp}/typecheck-tests.XXXXXX")
TSC_BUILDINFO=$(mktemp "${TMPDIR:-/tmp}/typecheck-tests.tsbuildinfo.XXXXXX")
trap 'rm -f "$TSC_OUTPUT" "$TSC_BUILDINFO"' EXIT
echo "[INFO] Running tsc --noEmit -p ${TSCONFIG} (mode: ${MODE}, tsBuildInfoFile=${TSC_BUILDINFO})..."

TSC_EXIT=0
npx tsc --noEmit --tsBuildInfoFile "$TSC_BUILDINFO" -p "$TSCONFIG" > "$TSC_OUTPUT" 2>&1 || TSC_EXIT=$?

# Extract error lines (format: path(line,col): error TSxxxx: message).
# Do not collapse duplicates with sort -u; each raw line is unique (distinguished by line:col).
CURRENT_ERRORS=$(grep -E "error TS[0-9]+" "$TSC_OUTPUT" | sort || true)
if [ -z "$CURRENT_ERRORS" ]; then
 CURRENT_COUNT=0
else
 CURRENT_COUNT=$(printf '%s\n' "$CURRENT_ERRORS" | grep -c "error TS")
fi

# tsc exits non-zero but no diagnostics parsed → fail-closed.
# Prevents a false PASS when npx is missing / Node startup crashes / the compiler errors out.
if [ "$TSC_EXIT" -ne 0 ] && [ "$CURRENT_COUNT" -eq 0 ]; then
 echo "" >&2
 echo "===== TYPECHECK-TESTS TOOL FAILURE =====" >&2
 echo "tsc exited ${TSC_EXIT} but no diagnostics parsed (compiler crash / npx not found?)" >&2
 echo "tsc output:" >&2
 cat "$TSC_OUTPUT" >&2
 echo "========================================" >&2
 exit 2
fi

# Baseline comparison uses a normalized key.
# Dropping (line,col) makes the baseline insensitive to line-number shifts.
# Duplicate occurrences of the same path+code+message are kept (count-based
# diff), not de-duplicated. TS6307 and friends can embed absolute checkout
# paths in their messages, so we normalize any leading "$REPO_ROOT/" plus any
# absolute path pattern to "_ABS_REPO_/" on both sides before comparing, so
# baselines stay portable across checkouts. Baselines are regenerated with
# the same normalization (see regenerate section).
normalize_diag_key() {
 printf '%s\n' "$1" \
 | sed -E "s|^${REPO_ROOT}/||" \
 | sed -E "s|${REPO_ROOT}/|_ABS_REPO_/|g" \
 | sed -E 's|/Users/[^/]+/codes/[^/]+/|_ABS_REPO_/|g' \
 | sed -E 's/^([^(]+)\([0-9]+,[0-9]+\): (error TS[0-9]+): (.*)$/\1|\2|\3/'
}

normalize_diag_lines() {
 local input="$1"
 if [ -z "$input" ]; then
 return
 fi
 printf '%s\n' "$input" | while IFS= read -r line; do
 [ -z "$line" ] && continue
 normalize_diag_key "$line"
 done
}

# ---------- regenerate baseline mode ----------
# Writing the baseline file also runs normalize_diag_lines,
# replacing absolute paths with the _ABS_REPO_/ placeholder so the baseline is stable across checkout / worktree / CI.
if [ "$MODE" = "regenerate" ]; then
 mkdir -p "$(dirname "$BASELINE_FILE")"
 if [ -z "$CURRENT_ERRORS" ]; then
: > "$BASELINE_FILE"
 else
 # The double sed matches normalize_diag_key, but keeps (line,col) and the original message structure (human-readable baseline).
 printf '%s\n' "$CURRENT_ERRORS" \
 | sed -E "s|^${REPO_ROOT}/||" \
 | sed -E "s|${REPO_ROOT}/|_ABS_REPO_/|g" \
 | sed -E 's|/Users/[^/]+/codes/[^/]+/|_ABS_REPO_/|g' \
 > "$BASELINE_FILE"
 fi
 echo "[OK] Regenerated baseline: ${BASELINE_FILE}"
 echo " Captured ${CURRENT_COUNT} errors as baseline (paths normalized to _ABS_REPO_/)"
 exit 0
fi

# ---------- strict mode ----------
if [ "$MODE" = "strict" ]; then
 if [ "$CURRENT_COUNT" -gt 0 ]; then
 echo ""
 echo "===== TYPECHECK-TESTS FAILED (strict mode, ${CURRENT_COUNT} errors) ====="
 echo "$CURRENT_ERRORS" | head -20
 if [ "$CURRENT_COUNT" -gt 20 ]; then
 echo "... ($((CURRENT_COUNT - 20)) more errors omitted)"
 fi
 echo "================================================="
 exit 1
 fi
 echo "[OK] typecheck-tests PASS (strict mode, 0 errors)"
 exit 0
fi

# ---------- baseline mode ----------
if [ ! -f "$BASELINE_FILE" ]; then
 echo "[WARN] Baseline file not found at ${BASELINE_FILE}"
 echo " Run 'bash scripts/typecheck-tests.sh --regenerate-baseline' to create."
 echo " Falling back to strict mode (any error = FAIL)."
 if [ "$CURRENT_COUNT" -gt 0 ]; then
 echo ""
 echo "===== TYPECHECK-TESTS FAILED (no baseline, ${CURRENT_COUNT} errors) ====="
 echo "$CURRENT_ERRORS" | head -20
 echo "================================================="
 exit 1
 fi
 echo "[OK] typecheck-tests PASS (no baseline, 0 errors)"
 exit 0
fi

# Do not collapse duplicates with sort -u; each raw line is kept unique.
BASELINE_ERRORS=$(grep -E "error TS[0-9]+" "$BASELINE_FILE" | sort || true)
if [ -z "$BASELINE_ERRORS" ]; then
 BASELINE_COUNT=0
else
 BASELINE_COUNT=$(printf '%s\n' "$BASELINE_ERRORS" | grep -c "error TS")
fi

# Compare after normalization (line:col removed).
# count-based diff: a normalized key appearing N times counts as N entries.
# Use uniq -c for counts; compare (count, key) tuples.
CURRENT_KEYS_COUNTED=$(normalize_diag_lines "$CURRENT_ERRORS" | sort | uniq -c | awk '{count=$1; $1=""; sub(/^ /,""); print count "|" $0}' || true)
BASELINE_KEYS_COUNTED=$(normalize_diag_lines "$BASELINE_ERRORS" | sort | uniq -c | awk '{count=$1; $1=""; sub(/^ /,""); print count "|" $0}' || true)

# Extract unique normalized keys (without count) for the diff report.
CURRENT_KEYS=$(printf '%s\n' "$CURRENT_KEYS_COUNTED" | awk -F'|' '{$1=""; sub(/^\|/,""); print}' | sort -u || true)
BASELINE_KEYS=$(printf '%s\n' "$BASELINE_KEYS_COUNTED" | awk -F'|' '{$1=""; sub(/^\|/,""); print}' | sort -u || true)

# count-based diff: occurrences of a key in current vs baseline.
# Any key whose current count > baseline count → NEW.
NEW_KEYS_RAW=""
RESOLVED_KEYS_RAW=""
ALL_KEYS=$(printf '%s\n%s\n' "$CURRENT_KEYS" "$BASELINE_KEYS" | sort -u | grep -v "^$" || true)

if [ -n "$ALL_KEYS" ]; then
 # Re-shape COUNTED into an awk-friendly "key TAB count" map.
 CURRENT_MAP=$(printf '%s\n' "$CURRENT_KEYS_COUNTED" | awk -F'|' 'NF>=2 {count=$1; $1=""; sub(/^\|/,""); printf "%s\t%s\n", $0, count}')
 BASELINE_MAP=$(printf '%s\n' "$BASELINE_KEYS_COUNTED" | awk -F'|' 'NF>=2 {count=$1; $1=""; sub(/^\|/,""); printf "%s\t%s\n", $0, count}')
 while IFS= read -r key; do
 [ -z "$key" ] && continue
 # here-string + awk avoids SIGPIPE (awk exit does not cut off the bash printf stream).
 cur_count=$(awk -F'\t' -v k="$key" '$1==k {print $2; exit}' <<< "$CURRENT_MAP")
 base_count=$(awk -F'\t' -v k="$key" '$1==k {print $2; exit}' <<< "$BASELINE_MAP")
 cur_count=${cur_count:-0}
 base_count=${base_count:-0}
 if [ "$cur_count" -gt "$base_count" ]; then
 delta=$((cur_count - base_count))
 NEW_KEYS_RAW+="${delta}× ${key}"$'\n'
 elif [ "$cur_count" -lt "$base_count" ]; then
 delta=$((base_count - cur_count))
 RESOLVED_KEYS_RAW+="${delta}× ${key}"$'\n'
 fi
 done <<< "$ALL_KEYS"
fi

NEW_KEYS="$NEW_KEYS_RAW"
RESOLVED_KEYS="$RESOLVED_KEYS_RAW"

if [ -z "$NEW_KEYS" ]; then
 NEW_COUNT=0
 NEW_ERRORS=""
else
 NEW_COUNT=$(printf '%s' "$NEW_KEYS" | grep -c "×" || echo 0)
 # Look up raw lines for the report (matched by normalized key).
 NEW_ERRORS=$(printf '%s\n' "$CURRENT_ERRORS" | while IFS= read -r raw; do
 [ -z "$raw" ] && continue
 key=$(normalize_diag_key "$raw")
 # Check whether this key is in NEW_KEYS_RAW (any delta count).
 if printf '%s' "$NEW_KEYS" | grep -F " ${key}" > /dev/null 2>&1; then
 printf '%s\n' "$raw"
 fi
 done | sort -u)
fi

if [ -z "$RESOLVED_KEYS" ]; then
 RESOLVED_COUNT=0
else
 RESOLVED_COUNT=$(printf '%s' "$RESOLVED_KEYS" | grep -c "×" || echo 0)
fi

echo "[INFO] baseline=${BASELINE_COUNT} current=${CURRENT_COUNT} new=${NEW_COUNT} resolved=${RESOLVED_COUNT}"

if [ "$RESOLVED_COUNT" -gt 0 ]; then
 echo "[INFO] ${RESOLVED_COUNT} baseline entries no longer broken (run --regenerate-baseline to update)"
fi

if [ "$NEW_COUNT" -gt 0 ]; then
 echo ""
 echo "===== TYPECHECK-TESTS FAILED (baseline mode, ${NEW_COUNT} new errors) ====="
 echo "$NEW_ERRORS" | head -20
 if [ "$NEW_COUNT" -gt 20 ]; then
 echo "... ($((NEW_COUNT - 20)) more new errors omitted)"
 fi
 echo "================================================="
 exit 1
fi

echo "[OK] typecheck-tests PASS (baseline mode, 0 new broken vs ${BASELINE_COUNT}-error baseline)"
exit 0
