#!/usr/bin/env bash
#
# lint-doc-references.sh
#
# Walk every markdown file under docs/ (plus root-level markdown such as
# README.md / CONTRIBUTING.md) and verify that referenced files actually
# exist. Any broken reference makes the script exit 1.
#
# Implementation notes:
# - Uses awk (not grep -P) so it runs on macOS BSD grep as well as GNU.
# - Supports a --baseline allowlist so existing broken references can be
#   grandfathered while only flagging new regressions.
# - Scan roots that do not exist are skipped silently.
#
# Invocation: bash scripts/lint-doc-references.sh [OPTIONS]
# Also exposed via `pnpm lint:docs`.
#
# Options:
# --max-broken=N        tolerate N broken refs (backward compat only; prefer --baseline)
# --baseline=<path>     baseline allowlist path; current broken minus baseline = delta
#                       delta == 0 → PASS, delta > 0 → FAIL (new broken refs)
#                       neither this nor --max-broken passed → strict zero-broken to PASS
# --regenerate-baseline print the current broken list (suitable to pipe into a baseline file), then exit 0
#
# Design:
# - Scan *.md and *.markdown under docs/ as source (the files being checked).
# - Check 3 kinds of reference target:
#     1. docs/...md subtree references (relative to repo root)
#     2. /XXX.md / /README.md repo-root canonical files
#     3. repo-root *.md without a leading `/` (e.g. bare README.md; discouraged but allowed)
# - Exclude: references inside fenced code blocks (avoid false positives on example code).
# - Exclude: inline archive aliases (files under _archive/ are allowed even if referenced).
#
# Exit codes: 0 = all references reachable / 1 = at least one broken / 2 = argument error
#
set -euo pipefail

# ---------- self-test: verify required tools are available ----------
# Check awk availability (present on all POSIX systems in theory, but be defensive).
if ! command -v awk >/dev/null 2>&1; then
    echo "FATAL: awk not found in PATH" >&2
    exit 2
fi

# Avoid awk multibyte conversion warnings when processing non-ASCII markdown.
export LC_ALL=C

# ---------- argument parsing ----------
MAX_BROKEN=0
BASELINE_PATH=""
REGENERATE_BASELINE=false
HAS_MAX_BROKEN=false

for arg in "$@"; do
    case "$arg" in
        --max-broken=*)
            MAX_BROKEN="${arg#--max-broken=}"
            HAS_MAX_BROKEN=true
            if ! [[ "$MAX_BROKEN" =~ ^[0-9]+$ ]]; then
                echo "ERROR: --max-broken must be a non-negative integer, got: $MAX_BROKEN" >&2
                exit 2
            fi
            ;;
        --baseline=*)
            BASELINE_PATH="${arg#--baseline=}"
            if [ ! -f "$BASELINE_PATH" ]; then
                echo "ERROR: baseline file not found: $BASELINE_PATH" >&2
                exit 2
            fi
            ;;
        --regenerate-baseline)
            REGENERATE_BASELINE=true
            ;;
        -*)
            echo "Unknown option: $arg" >&2
            exit 2
            ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Whitelist of repo-root canonical markdown files.
# Any /XXX.md reference must hit this list, otherwise it is treated as broken.
ROOT_LEVEL_DOCS=(
    "CHANGELOG.md"
    "CODE_OF_CONDUCT.md"
    "CONTRIBUTING.md"
    "README.md"
    "SECURITY.md"
)

BROKEN_COUNT=0
BROKEN_REPORT=""
# Per-line broken list for baseline diff (normalized form: "src -> ref" or "src -> ref [reason]").
BROKEN_LINES=()

# Extract doc references from a single markdown file (skipping fenced code blocks).
scan_md_for_refs() {
    local file="$1"
    # Use awk to skip ``` fenced code blocks, matching references only in regular body text.
    local body
    body=$(awk '
        BEGIN { in_code = 0 }
        /^```/ { in_code = !in_code; next }
        !in_code { print }
    ' "$file")

    # Pass 1: subtree paths + leading-slash root references (POSIX ERE).
    local pass1
    pass1=$(echo "$body" | \
        grep -oE '(docs/[A-Za-z0-9._/-]+|/[A-Z][A-Za-z0-9._-]+)\.(md|markdown)' || true)

    # Pass 2: bare root references (no path prefix, e.g. README.md / CHANGELOG.md).
    # Pure-awk negative-lookbehind (?<![/a-zA-Z0-9._-]), compatible with macOS BSD grep (no PCRE).
    local pass2
    pass2=$(echo "$body" | awk '
        {
            line = $0
            # Look for each root-level canonical candidate token in turn.
            split("README.md CHANGELOG.md CONTRIBUTING.md SECURITY.md CODE_OF_CONDUCT.md", tokens, " ")
            for (t in tokens) {
                tok = tokens[t]
                offset = 0
                remainder = line
                while ((idx = index(remainder, tok)) > 0) {
                    abs_pos = offset + idx
                    if (abs_pos > 1) {
                        prev_char = substr(line, abs_pos - 1, 1)
                    } else {
                        prev_char = ""
                    }
                    # Negative prefix: the previous char must not be a path char (avoids re-capturing docs/foo.md).
                    if (prev_char == "" || !match(prev_char, /[\/a-zA-Z0-9._-]/)) {
                        print tok
                    }
                    offset = offset + idx + length(tok) - 1
                    remainder = substr(line, offset + 1)
                }
            }
        }
    ' || true)

    # Merge and dedupe.
    { echo "$pass1"; echo "$pass2"; } | grep -v '^$' | sort -u
}

# Resolve a reference to a repo-root-relative path (for the [ -f ] check).
# Input: the raw reference string (may carry a # anchor).
# Output: the corresponding repo-root-relative path; if the form is invalid, a sentinel string.
resolve_ref_to_path() {
    local ref="$1"
    local target="${ref%%#*}" # strip the anchor

    case "$target" in
        /*)
            # Root-level reference: strip the leading `/`, must hit the whitelist.
            local stripped="${target#/}"
            local hit=0
            local whitelisted
            for whitelisted in "${ROOT_LEVEL_DOCS[@]}"; do
                if [ "$stripped" = "$whitelisted" ]; then
                    hit=1
                    break
                fi
            done
            if [ "$hit" -eq 1 ]; then
                echo "$stripped"
            else
                # A non-whitelisted root reference is always treated as broken (misuse even if the file exists).
                echo "__OUT_OF_WHITELIST__:$stripped"
            fi
            ;;
        docs/*)
            echo "$target"
            ;;
        README.md|CHANGELOG.md|CONTRIBUTING.md|SECURITY.md|CODE_OF_CONDUCT.md)
            # bare root reference (no leading path) resolves directly to the repo root
            echo "$target"
            ;;
        *)
            echo "__INVALID_FORM__:$target"
            ;;
    esac
}

# Record one broken reference (single entry point, avoids using `local` at top level).
record_broken() {
    local line="$1"
    BROKEN_COUNT=$((BROKEN_COUNT + 1))
    BROKEN_REPORT+="$line"$'\n'
    BROKEN_LINES+=("$line")
}

# ---------- collect the scan-source list ----------
# Only scan roots that actually exist, so find does not error on a missing directory.
SCAN_ROOTS=()
for root in docs; do
    [ -d "$root" ] && SCAN_ROOTS+=("$root")
done

SRC_FILES=""
if [ "${#SCAN_ROOTS[@]}" -gt 0 ]; then
    SRC_FILES=$(find "${SCAN_ROOTS[@]}" -type f \( -name "*.md" -o -name "*.markdown" \) \
        -not -path "*/_archive/*" 2>/dev/null | sort)
fi

# ---------- main scan loop ----------
while IFS= read -r src; do
    [ -z "$src" ] && continue
    while IFS= read -r ref; do
        [ -z "$ref" ] && continue
        # References inside archive/ are allowed to point at non-existent files.
        case "$ref" in
            *_archive/*) continue ;;
        esac

        resolved=$(resolve_ref_to_path "$ref")

        case "$resolved" in
            __OUT_OF_WHITELIST__:*)
                record_broken "$src -> $ref [root-ref-not-whitelisted:${resolved#__OUT_OF_WHITELIST__:}]"
                ;;
            __INVALID_FORM__:*)
                record_broken "$src -> $ref [invalid-form]"
                ;;
            "")
                : # unreachable; defensive
                ;;
            *)
                if [ ! -f "$resolved" ]; then
                    record_broken "$src -> $ref"
                fi
                ;;
        esac
    done < <(scan_md_for_refs "$src")
done < <(printf '%s\n' "$SRC_FILES")

SCANNED=$(printf '%s\n' "$SRC_FILES" | grep -c -v '^$' || true)

# ---------- --regenerate-baseline mode ----------
if [ "$REGENERATE_BASELINE" = true ]; then
    # Print the current broken list in normalized form, ready to pipe into a baseline file.
    if [ "$BROKEN_COUNT" -gt 0 ]; then
        printf '%s\n' "${BROKEN_LINES[@]}" | sort
    fi
    echo "# regenerated | ${BROKEN_COUNT} broken in ${SCANNED} files" >&2
    exit 0
fi

# ---------- decision logic ----------
if [ "$BROKEN_COUNT" -gt 0 ]; then
    echo "===== BROKEN DOC REFERENCES ($BROKEN_COUNT) ====="
    printf '%s' "$BROKEN_REPORT"
    echo "================================================="

    # --baseline mode: delta-over-baseline decision
    if [ -n "$BASELINE_PATH" ]; then
        CURRENT_SORTED=$(printf '%s\n' "${BROKEN_LINES[@]}" | sort)
        BASELINE_SORTED=$(grep -v '^#' "$BASELINE_PATH" | grep -v '^$' | sort)

        # delta = present now but not in baseline (newly broken)
        DELTA=$(comm -23 <(echo "$CURRENT_SORTED") <(echo "$BASELINE_SORTED"))
        DELTA_COUNT=$(echo "$DELTA" | grep -c -v '^$' || true)

        # resolved = in baseline but not present now (fixed, positive signal)
        RESOLVED=$(comm -13 <(echo "$CURRENT_SORTED") <(echo "$BASELINE_SORTED"))
        RESOLVED_COUNT=$(echo "$RESOLVED" | grep -c -v '^$' || true)

        if [ "$DELTA_COUNT" -gt 0 ]; then
            echo ""
            echo "BASELINE DELTA: ${DELTA_COUNT} new broken (not in baseline):"
            echo "$DELTA" | sed 's/^/  + /'
            echo ""
            if [ "$RESOLVED_COUNT" -gt 0 ]; then
                echo "RESOLVED: ${RESOLVED_COUNT} baseline entries no longer broken (run --regenerate-baseline to update)"
            fi
            echo "BASELINE: FAIL (${DELTA_COUNT} new broken vs baseline ${BASELINE_PATH})"
            exit 1
        else
            if [ "$RESOLVED_COUNT" -gt 0 ]; then
                echo ""
                echo "RESOLVED: ${RESOLVED_COUNT} baseline entries no longer broken (run --regenerate-baseline to update)"
            fi
            echo "BASELINE: PASS (${BROKEN_COUNT} broken, all in baseline; 0 new)"
            echo "scanned ${SCANNED} source files"
            exit 0
        fi
    fi

    # --max-broken backward-compat mode
    if [ "$BROKEN_COUNT" -le "$MAX_BROKEN" ]; then
        echo "THRESHOLD: $BROKEN_COUNT broken <= --max-broken=$MAX_BROKEN -> PASS (legacy threshold)"
        echo "scanned ${SCANNED} source files"
        exit 0
    else
        if [ "$MAX_BROKEN" -gt 0 ]; then
            echo "THRESHOLD: $BROKEN_COUNT broken > --max-broken=$MAX_BROKEN -> FAIL"
        fi
        exit 1
    fi
fi

echo "OK: all doc references reachable (scanned ${SCANNED} source files; docs/ subtree + root canonical whitelist ${ROOT_LEVEL_DOCS[*]})"
