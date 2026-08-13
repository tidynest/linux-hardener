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

# A clap parse error must be called out as a recipe bug rather than left to
# read as ordinary non-zero output. The first real walk lost its whole mutate
# phase to six such rows, each indistinguishable in the index from a genuine
# refusal by the tool.
run_recipe selftest-badargs pristine 0 -- \
    /bin/sh -c "echo \"error: unexpected argument '--nope' found\" >&2; exit 2"
badargs_row="${WALK_ROWS[-1]}"
check "recipe bug flagged"  "yes" \
    "$(grep -q 'RECIPE BUG' <<< "$badargs_row" && echo yes || echo no)"
# And a genuine non-zero exit must NOT be flagged, or the note means nothing.
run_recipe selftest-realfail pristine 0 -- \
    /bin/sh -c "echo 'Error: --ssh is not honoured by this command.' >&2; exit 2"
check "real refusal not flagged" "no" \
    "$(grep -q 'RECIPE BUG' <<< "${WALK_ROWS[-1]}" && echo yes || echo no)"

# A note containing a literal pipe must be escaped in the markdown table output.
# Without escaping, the pipe would split the row into extra columns, corrupting
# the table. With the fix, escaped pipes appear as \| in the note field.
walk_skip with-pipe-in-reason pristine "something | happened | here"
walk_write_index "test binary"
generated_row=$(grep "with-pipe-in-reason" "$TMP/index.md" 2>/dev/null)
# The note field must contain the escaped pipe sequence \| to preserve rendering.
has_escaped_pipe="$(echo "$generated_row" | grep -q '\\|' && echo yes || echo no)"
check "pipe-in-note escaped" "yes" "$has_escaped_pipe"

# The diff pointer must report a real difference and stay silent about one
# that is only a path or a timestamp. Both halves matter: a normaliser too
# aggressive erases the findings it exists to point at, and one too timid
# names every slug on every distribution, which is the same as naming none.
POINTER="$TMP/pointer"
for dist in arch debian; do
    mkdir -p "$POINTER/$dist/pristine/001-same" "$POINTER/$dist/pristine/002-differs"
done
echo "built at 2026-08-13 10:00:00 from /home/one/tree" > "$POINTER/arch/pristine/001-same/stdout"
echo "built at 2026-08-14 23:59:59 from /var/two/other" > "$POINTER/debian/pristine/001-same/stdout"
echo "12 findings" > "$POINTER/arch/pristine/002-differs/stdout"
echo "34 findings" > "$POINTER/debian/pristine/002-differs/stdout"

walk_write_diff_pointer "$POINTER" arch debian
check "pointer names a real difference" "yes" \
    "$(grep -q '002-differs' "$POINTER/diff-pointer.md" && echo yes || echo no)"
check "pointer ignores paths and times" "no" \
    "$(grep -q '001-same' "$POINTER/diff-pointer.md" && echo yes || echo no)"

# An absent capture is reported, never treated as agreement. A distribution
# whose walk died before this slug would otherwise read as matching.
rm -rf "$POINTER/debian/pristine/002-differs"
walk_write_diff_pointer "$POINTER" arch debian
check "pointer flags an absent capture" "yes" \
    "$(grep -q 'debian(absent)' "$POINTER/diff-pointer.md" && echo yes || echo no)"

# An exit code that disagrees is the pointer's headline, and it has to be found
# even where the stdout matches exactly. The two comparisons answer different
# questions: a command can print the same thing on both distributions and still
# have reached a different conclusion about what it managed to do. Built with
# identical stdout on purpose, so this can only pass by reading the exit files.
mkdir -p "$POINTER/arch/pristine/003-exit" "$POINTER/debian/pristine/003-exit"
echo "identical output" > "$POINTER/arch/pristine/003-exit/stdout"
echo "identical output" > "$POINTER/debian/pristine/003-exit/stdout"
echo 0 > "$POINTER/arch/pristine/003-exit/exit"
echo 1 > "$POINTER/debian/pristine/003-exit/exit"
walk_write_diff_pointer "$POINTER" arch debian
check "pointer names an exit-code disagreement" "yes" \
    "$(grep -q 'arch=0 debian=1' "$POINTER/diff-pointer.md" && echo yes || echo no)"

# And agreement must stay unreported. A section that names every slug names
# none, which is the failure the whole rewrite is about.
mkdir -p "$POINTER/arch/pristine/004-agree" "$POINTER/debian/pristine/004-agree"
echo "identical output" > "$POINTER/arch/pristine/004-agree/stdout"
echo "identical output" > "$POINTER/debian/pristine/004-agree/stdout"
echo 0 > "$POINTER/arch/pristine/004-agree/exit"
echo 0 > "$POINTER/debian/pristine/004-agree/exit"
walk_write_diff_pointer "$POINTER" arch debian
check "pointer stays silent where exit codes agree" "no" \
    "$(grep -q '004-agree' "$POINTER/diff-pointer.md" && echo yes || echo no)"

# The added normalisations must blank a checkpoint id and a session UUID, which
# are minted fresh per run and so differ on every distribution every time.
mkdir -p "$POINTER/arch/pristine/005-ids" "$POINTER/debian/pristine/005-ids"
echo "cp_1786650211904_ad3568b1 1896c7b4-8fc3-4b53-b7f1-a4b0a0383b5f done" \
    > "$POINTER/arch/pristine/005-ids/stdout"
echo "cp_1786651070318_218a5a75 3328dbab-63eb-4f65-9f44-f305e8087dbf done" \
    > "$POINTER/debian/pristine/005-ids/stdout"
walk_write_diff_pointer "$POINTER" arch debian
check "pointer ignores checkpoint ids and UUIDs" "no" \
    "$(grep -q '005-ids' "$POINTER/diff-pointer.md" && echo yes || echo no)"

# The WALK PROBLEM comparison must need nothing installed. It was written with
# `cmp`, which the rhel container lacks: the missing command returned 127, the
# `&&` short-circuited, and the one container whose restore phase HAD done
# nothing was the one container that never said so. Running the comparison with
# an empty PATH is the check, because it fails the moment someone reaches for
# an external tool again; asserting only that identical files compare equal
# would have passed on this machine throughout.
SNAP="$TMP/snap"
mkdir -p "$SNAP"
printf 'same\n' > "$SNAP/a"
printf 'same\n' > "$SNAP/b"
printf 'different\n' > "$SNAP/c"
check "identical snapshots compare equal with no PATH" "yes" \
    "$(PATH='' "$BASH" -c '[[ "$(<"$1")" == "$(<"$2")" ]] && echo yes || echo no' _ "$SNAP/a" "$SNAP/b")"
check "differing snapshots compare unequal with no PATH" "no" \
    "$(PATH='' "$BASH" -c '[[ "$(<"$1")" == "$(<"$2")" ]] && echo yes || echo no' _ "$SNAP/a" "$SNAP/c")"

if [[ $fails -eq 0 ]]; then
    echo "selftest: all checks passed"
    exit 0
fi
echo "selftest: $fails check(s) failed"
exit 1
