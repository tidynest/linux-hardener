#!/bin/bash
# =============================================================================
# CAPTURE SELF-TEST: cli-walk
# =============================================================================
# Proves the capture machinery works before any walk trusts it. A bug in
# run_recipe that silently wrote empty stdout files would make every future
# walk worthless while looking entirely healthy, and nothing else in this
# harness would catch it.
#
# Usage: ./scripts/test/cli-walk/selftest.sh
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=walk-lib.sh
source "$SCRIPT_DIR/walk-lib.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fails=0
check() {
    local what="$1" want="$2" got="$3"
    if [[ "$want" == "$got" ]]; then
        echo "  ok: $what"
    else
        echo "  FAIL: $what (want '$want', got '$got')"
        fails=$((fails + 1))
    fi
}

walk_init "$TMP"
run_recipe selftest-echo pristine 0 -- /bin/echo hello

d="$TMP/pristine/001-selftest-echo"
check "cmd file exists"    "yes" "$([[ -f $d/cmd ]] && echo yes || echo no)"
check "stdout file exists" "yes" "$([[ -f $d/stdout ]] && echo yes || echo no)"
check "stderr file exists" "yes" "$([[ -f $d/stderr ]] && echo yes || echo no)"
check "exit file exists"   "yes" "$([[ -f $d/exit ]] && echo yes || echo no)"
check "exit is 0"          "0"   "$(cat "$d/exit" 2>/dev/null)"
check "stdout non-empty"   "yes" "$([[ -s $d/stdout ]] && echo yes || echo no)"
check "stdout content"     "hello" "$(cat "$d/stdout" 2>/dev/null)"

# A failing command must be captured, not swallowed, and must not abort us.
run_recipe selftest-false pristine 0 -- /bin/false
check "failure captured"   "1"   "$(cat "$TMP/pristine/002-selftest-false/exit" 2>/dev/null)"

# A blocking command under a timeout must record 124 and survive.
run_recipe selftest-block pristine 1 -- /bin/sleep 30
check "timeout captured"   "124" "$(cat "$TMP/pristine/003-selftest-block/exit" 2>/dev/null)"

# A note containing a literal pipe must be escaped in the markdown table output.
# Without escaping, the pipe would split the row into extra columns, corrupting
# the table. With the fix, escaped pipes appear as \| in the note field.
walk_skip with-pipe-in-reason pristine "something | happened | here"
walk_write_index "test binary"
generated_row=$(grep "with-pipe-in-reason" "$TMP/index.md" 2>/dev/null)
# The note field must contain the escaped pipe sequence \| to preserve rendering.
has_escaped_pipe="$(echo "$generated_row" | grep -q '\\|' && echo yes || echo no)"
check "pipe-in-note escaped" "yes" "$has_escaped_pipe"

if [[ $fails -eq 0 ]]; then
    echo "selftest: all checks passed"
    exit 0
fi
echo "selftest: $fails check(s) failed"
exit 1
