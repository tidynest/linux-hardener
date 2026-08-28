#!/usr/bin/env bash
# =============================================================================
# Unit test: the release-readiness summary's carry-forward
# =============================================================================
# Runs unprivileged in about a second. No containers, no root, no framework.
#
# What it protects. `release-readiness-root.sh` writes one summary.txt per
# invocation, and a --only run used to publish a table containing just that
# suite, overwriting whatever the last full batch recorded. On 2026-08-28 that
# misled three times in one evening: an interrupted --only cross-distro run left
# "Suites: cross-distro / NOTRUN" beside five suites' passing logs, and a
# single-distro GUI re-run replaced a six-distro table with one arch row. Each
# time the conclusion drawn from the summary was the opposite of the truth.
#
# The rows a run did not exercise are carried from the previous summary and
# marked. The load-bearing property is that carrying them must NOT make them
# count: a carried PASS is not evidence, and the exit code still speaks only for
# what this invocation ran.
#
# The functions under test are extracted from the real script rather than
# retyped here, so this cannot pass against a copy that has drifted from it.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="$SCRIPT_DIR/release-readiness-root.sh"
FAILURES=0

pass() { echo "  [PASS] $1"; }
fail() { echo "  [FAIL] $1"; FAILURES=$((FAILURES + 1)); }
check() { [[ "$1" == "$2" ]] && pass "$3" || fail "$3: expected '$2', got '$1'"; }

[[ -f "$TARGET" ]] || { echo "cannot find $TARGET"; exit 2; }

FNS="$(mktemp)"
awk '/^read_previous_summary\(\) \{/,/^\}/' "$TARGET"  > "$FNS"
awk '/^resolve_row\(\) \{/,/^\}/'          "$TARGET" >> "$FNS"
# Two functions, or the extraction silently tested nothing. This is the check
# that stops a rename in the target turning every assertion below vacuous.
found=$(/usr/bin/grep -c '^[a-z_]*() {' "$FNS")
if [[ "$found" -ne 2 ]]; then
    echo "extracted $found function(s), expected 2: read_previous_summary and"
    echo "resolve_row were renamed or reshaped in $TARGET. Fix this test."
    rm -f "$FNS"
    exit 2
fi

RR_DIR="$(mktemp -d)"
SUITE_ORDER=(polkit cross-distro differential package gui rollback)
declare -A SUITE_STATUS SUITE_DETAIL PREV_STATUS PREV_DETAIL
PREV_DATE=""
# shellcheck source=/dev/null
source "$FNS"

echo "Release readiness summary carry-forward"
echo "======================================="

cat > "$RR_DIR/summary.txt" <<'EOF'
Release Readiness Root Batch
============================
Date:    Fri 28 Aug 22:59:46 CEST 2026
Host:    Linux 7.1.9-arch1-2 x86_64
Binary:  hardener 1.5.1 (4a92a9df 2026-08-28)
Suites:  polkit cross-distro differential package gui rollback

Suite          Status   Detail
-----          ------   ------
polkit         PASS     all automated checks passed (3 interactive tests skipped)
cross-distro   PASS     6 distros, booted, apply
differential   PASS     6 distros, booted
package        PASS     6 distros, installed binary applied and rolled back
gui            FAIL     exit 1, see gui.log
rollback       PASS     passed, but at least one arm was not asked
rollback-booted PASS     ssh, service-minimisation and audit divergence arms

Logs: <suite>.log
EOF

read_previous_summary
check "$PREV_DATE" "Fri 28 Aug 22:59:46 CEST 2026" "the previous run's date is read off its own header"
check "${PREV_STATUS[gui]:-}" "FAIL" "a previous FAIL is recovered as a FAIL"
check "${PREV_DETAIL[cross-distro]:-}" "6 distros, booted, apply" "a detail containing spaces survives the parse"
check "${PREV_STATUS[rollback-booted]:-}" "PASS" "the display-only rollback-booted row is recovered"

# The case that started this: sudo release-readiness-root.sh --only gui, passing.
DISPLAY_SUITES=(gui)
SUITE_STATUS[gui]=PASS
SUITE_DETAIL[gui]="6 distros, 171 each"

resolve_row gui
check "$ROW_STATUS" "PASS" "the selected suite reports THIS run's result"
check "$ROW_CARRIED" "false" "the selected suite is not marked carried"
[[ "$ROW_DETAIL" != *carried* ]] \
    && pass "a freshly run row carries no marker" \
    || fail "a freshly run row was marked carried: $ROW_DETAIL"

resolve_row cross-distro
check "$ROW_CARRIED" "true" "an unselected suite is carried rather than dropped"
check "$ROW_STATUS" "PASS" "the carried status is preserved"
[[ "$ROW_DETAIL" == *"[carried from Fri 28 Aug 22:59:46 CEST 2026]"* ]] \
    && pass "the carried row names the run it came from" \
    || fail "the carried marker is missing or undated: $ROW_DETAIL"

# A row carried twice keeps its first origin. Restamping would walk the date
# forward one invocation at a time until a month-old result read as tonight's,
# which is a worse lie than the truncation this mechanism replaced.
PREV_DETAIL[cross-distro]="6 distros, booted, apply [carried from Wed 19 Aug 18:00:00 CEST 2026]"
resolve_row cross-distro
[[ "$ROW_DETAIL" == *"Wed 19 Aug"* && "$ROW_DETAIL" != *"Fri 28 Aug"* ]] \
    && pass "a re-carried row keeps its original date" \
    || fail "the origin date was restamped: $ROW_DETAIL"

# Neither run nor previously recorded. NOTRUN, never an inherited PASS.
unset 'PREV_STATUS[package]'
resolve_row package
check "$ROW_STATUS" "NOTRUN" "a suite with no history at all reads NOTRUN"
check "$ROW_CARRIED" "false" "and is not counted as carried"

rm -rf "$RR_DIR" "$FNS"

echo ""
if [[ $FAILURES -eq 0 ]]; then
    echo "All checks passed."
    exit 0
fi
echo "$FAILURES check(s) failed."
exit 1
