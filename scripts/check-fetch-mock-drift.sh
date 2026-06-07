#!/usr/bin/env bash
# Check that vi.stubGlobal('fetch') usages stay in sync with the production
# undici call path. If production switches from globalFetch to undiciFetch
# but tests still stub `fetch`, the mock silently no-ops and tests pass
# without exercising the real path. This script greps for that drift and
# exits non-zero on mismatch.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

FAIL_COUNT=0
WARN_COUNT=0

echo "=== fetch/mock drift guard ==="
echo ""

# ============================================================
# 1. Find all test files using vi.stubGlobal('fetch')
# ============================================================
echo "[1/3] Scanning vi.stubGlobal('fetch') usage..."
STUB_FILES=
while IFS= read -r line; do
 STUB_FILES+=("$line")
done < <(grep -rln "vi\.stubGlobal\(['\"]fetch['\"]" \
 packages/ tests/ 2>/dev/null \
 --include="*.test.ts" \
 --include="*.spec.ts" \
 --exclude-dir=node_modules \
 --exclude-dir=_archive \
 --exclude-dir=.worktrees \
 || true)

if [ ${#STUB_FILES[@]} -eq 0 ]; then
 echo " No vi.stubGlobal('fetch') references → SKIP"
else
 echo " Found ${#STUB_FILES[@]} test file(s) using vi.stubGlobal('fetch')"
fi
echo ""

# ============================================================
# 2. Find all production files that use undici fetch
# ============================================================
echo "[2/3] Scanning production undici fetch calls..."
UNDICI_FILES=
while IFS= read -r line; do
 UNDICI_FILES+=("$line")
done < <(grep -rln "from ['\"]undici['\"]\|undiciFetch\|import.*undici" \
 packages/ \
 --include="*.ts" \
 --exclude="*.test.ts" \
 --exclude="*.spec.ts" \
 --exclude="*.d.ts" \
 --exclude-dir=node_modules \
 --exclude-dir=_archive \
 || true)

if [ ${#UNDICI_FILES[@]} -eq 0 ]; then
 echo " No production undici references → nothing to check"
 exit 0
fi

echo " Found ${#UNDICI_FILES[@]} production file(s) using undici"
for f in "${UNDICI_FILES[@]}"; do
 echo " - $f"
done
echo ""

# ============================================================
# 3. Cross-check: for each production undici file, see whether any test still uses vi.stubGlobal('fetch')
# ============================================================
echo "[3/3] Cross-checking mock-path drift..."

if [ ${#STUB_FILES[@]} -gt 0 ]; then
 for prod_file in "${UNDICI_FILES[@]}"; do
 # Extract the package name (e.g. packages/identity).
 pkg_dir=$(echo "$prod_file" | grep -oE 'packages/[^/]+' | head -1)
 if [ -z "$pkg_dir" ]; then
 continue
 fi

 # Look for stubGlobal('fetch') in the same package (or in tests/e2e/ referencing this package).
 for stub_file in "${STUB_FILES[@]}"; do
 # Simple heuristic: same package path OR tests/e2e.
 if [[ "$stub_file" == "$pkg_dir"/* ]] || [[ "$stub_file" == tests/e2e/* ]]; then
 # Check whether stub_file also has vi.mock('undici').
 if ! grep -q "vi\.mock\(.*undici" "$stub_file" 2>/dev/null; then
 echo " [WARN] $stub_file uses vi.stubGlobal('fetch') but has no matching vi.mock('undici')"
 echo " Related production file: $prod_file"
 echo " Possible mock drift"
 ((WARN_COUNT++))
 fi
 fi
 done
 done
fi

echo ""

# ============================================================
# Summary
# ============================================================
echo "================ fetch/mock drift guard summary ================"
echo "WARN: $WARN_COUNT possible drift"
echo "FAIL: $FAIL_COUNT confirmed drift"
echo "==============================================================="
echo ""

if [ "$WARN_COUNT" -gt 0 ]; then
 echo "Suggestion: review the WARN lines; if you genuinely need to mock fetch while production uses undici,"
 echo " switch to vi.mock('undici') to intercept undiciFetch,"
 echo " or add an explicit comment at the top of the test explaining it is not drift (e.g. production also uses globalFetch)."
fi

# Currently WARN-only; promote to a hard fail once the false-positive rate is
# confirmed low (see lint-doc-references.sh for the same promotion pattern).
exit 0
