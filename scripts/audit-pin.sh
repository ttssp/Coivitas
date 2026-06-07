#!/bin/bash
# audit-pin.sh — manifest exact-pin CI gate
#
# Dependencies are pinned exactly to keep the supply chain reproducible.
#
# Rule: auth/crypto allowlist packages must use an exact `=` pin (no `^` / `~` / `>=` / wildcard).
# Allowlist:
# - TS (package.json): jose, openid-client, @noble/curves, @noble/hashes, @noble/ciphers
# - Python (pyproject.toml): authlib, cryptography, jcs
#
# Exit codes:
# 0 = all allowlist packages use an exact pin
# 1 = at least one allowlist package uses a range pin → fail-closed
#
# Usage:
# ./scripts/audit-pin.sh
# ./scripts/audit-pin.sh --verbose (print each verify line)
#
# CI hook: fail-closed before turbo build.

set -e

VERBOSE=0
if [[ "${1:-}" == "--verbose" ]]; then
 VERBOSE=1
fi

VIOLATIONS=0
ROOT="$(git rev-parse --show-toplevel 2>/dev/null || echo .)"
cd "$ROOT"

# ─── TS allowlist packages (package.json) ─────────────────────────────────────
TS_ALLOWLIST_PKG=("jose" "openid-client" "@noble/curves" "@noble/hashes" "@noble/ciphers")
TS_MANIFESTS=(
 "packages/identity/package.json"
 "packages/communication/package.json"
 "packages/sdk/package.json"
 "packages/crypto/package.json"
 "packages/policy/package.json"
 "packages/types/package.json"
 "packages/shared/package.json"
 # Note: packages/sdk-python/package.json is a pnpm workspace placeholder marker
 # (no dependencies; real package metadata lives in pyproject.toml PEP 621); excluded
 # to avoid a misleading silent PASS during path triage.
)

check_ts_pkg() {
 local pkg="$1"
 local manifest="$2"
 # Match forms like "pkg": "^x.y.z" / "pkg": "~x.y.z" / "pkg": ">=x" / "pkg": "*"
 # Exclude a valid exact pin "pkg": "x.y.z".
 local violation
 violation=$(grep -E "\"$pkg\"\s* \s*\"[\^~><*]" "$manifest" 2>/dev/null || true)
 if [[ -n "$violation" ]]; then
 echo "❌ FAIL: $manifest uses range pin for '$pkg':"
 echo " $violation"
 return 1
 fi
 if [[ $VERBOSE -eq 1 ]]; then
 local exact
 exact=$(grep -E "\"$pkg\"\s* " "$manifest" 2>/dev/null || true)
 if [[ -n "$exact" ]]; then
 echo "✅ $manifest: $exact"
 fi
 fi
 return 0
}

echo "─── TS manifest audit ───"
for manifest in "${TS_MANIFESTS[@]}"; do
 if [[ ! -f "$manifest" ]]; then
 [[ $VERBOSE -eq 1 ]] && echo "⊘ skip (not exist): $manifest"
 continue
 fi
 for pkg in "${TS_ALLOWLIST_PKG[@]}"; do
 if ! check_ts_pkg "$pkg" "$manifest"; then
 VIOLATIONS=$((VIOLATIONS + 1))
 fi
 done
done

# ─── Python allowlist packages (pyproject.toml) ──────────────────────────────
PY_ALLOWLIST_PKG=("authlib" "cryptography" "jcs")
PY_MANIFESTS=(
 "packages/sdk-python/pyproject.toml"
)

check_py_pkg() {
 local pkg="$1"
 local manifest="$2"
 # PEP 508 style: "authlib>=1.3,<2" / "cryptography>=42.0" / "jcs>=0.2,<0.3"
 # exact pin: "authlib==1.6.0" / "cryptography==46.0.3"
 # Match lines containing >= / <= / > / < / ~= / ^ / * but not ==.
 local violation
 violation=$(grep -E "\"$pkg[\^~><*]" "$manifest" 2>/dev/null | grep -v "==" || true)
 if [[ -n "$violation" ]]; then
 echo "❌ FAIL: $manifest uses range pin for '$pkg':"
 echo " $violation"
 return 1
 fi
 if [[ $VERBOSE -eq 1 ]]; then
 local exact
 exact=$(grep -E "\"$pkg" "$manifest" 2>/dev/null || true)
 if [[ -n "$exact" ]]; then
 echo "✅ $manifest: $exact"
 fi
 fi
 return 0
}

echo ""
echo "─── Python manifest audit ───"
for manifest in "${PY_MANIFESTS[@]}"; do
 if [[ ! -f "$manifest" ]]; then
 [[ $VERBOSE -eq 1 ]] && echo "⊘ skip (not exist): $manifest"
 continue
 fi
 for pkg in "${PY_ALLOWLIST_PKG[@]}"; do
 if ! check_py_pkg "$pkg" "$manifest"; then
 VIOLATIONS=$((VIOLATIONS + 1))
 fi
 done
done

# ─── verdict ────────────────────────────────────────────────────────────────
echo ""
if [[ $VIOLATIONS -eq 0 ]]; then
 echo "✅ audit-pin: 0 violations — all allowlist auth/crypto packages use exact pin"
 exit 0
else
 echo "❌ audit-pin: $VIOLATIONS violations — fix manifests before build"
 echo ""
 echo "Rationale: dependencies are pinned exactly to keep the supply chain reproducible."
 echo " Auth/crypto packages must use an exact = pin"
 echo " (prevent supply chain attack via dependency confusion / typo-squatting"
 echo " / malicious version yanking)."
 exit 1
fi
