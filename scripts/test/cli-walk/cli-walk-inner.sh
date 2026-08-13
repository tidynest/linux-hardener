#!/bin/bash
# =============================================================================
# CLI WALK, CONTAINER INNER: Linux Hardener
# =============================================================================
# Runs inside the container, as root, via systemd-nspawn. /project is bound,
# so this sources the same recipes and capture library the host runner uses
# rather than duplicating either.
#
# The ssh tier is NOT run here. Its four recipes are `batch` verbs that target
# a remote over SSH, so they belong outside the container pointing at it, and
# the booted SSH fixture has no /project bound in any case.
#
# Usage (inside container): cli-walk-inner.sh <distro> <tiers-csv>
# =============================================================================

set -uo pipefail

DISTRO="${1:?distro required}"
TIERS="${2:?tiers csv required}"

SCRIPT_DIR="/project/scripts/test/cli-walk"
# shellcheck source=walk-lib.sh
source "$SCRIPT_DIR/walk-lib.sh"
# shellcheck source=recipes.sh
source "$SCRIPT_DIR/recipes.sh"

BIN="/project/target/x86_64-unknown-linux-musl/release/hardener"
[[ -x "$BIN" ]] || BIN="/project/target/release/hardener"
if [[ ! -x "$BIN" ]]; then
    echo "FATAL: no hardener binary inside container"
    exit 1
fi

CAPTURE="/project/test-results/cli-walk/$DISTRO"
rm -rf "$CAPTURE"
walk_init "$CAPTURE"

tier_wanted() { [[ ",$TIERS," == *",$1,"* ]]; }

# Runtime ids, resolved once the first checkpoint and scan exist.
RUNTIME_ID=""
RUNTIME_SESSION=""

# first_id ROWS_KEY ID_KEY -- ARGV...
# Runs the CLI with ARGV, reads its JSON, prints the first row's ID_KEY.
# Prints nothing when there are no rows or the payload cannot be read: at some
# phases no checkpoint or session exists yet, and that is a normal state
# rather than an error. The caller decides what an empty id means.
first_id() {
    local rows_key="$1" id_key="$2"
    shift 2
    [[ "${1:-}" == "--" ]] && shift
    "$BIN" "$@" 2>/dev/null | python3 -c '
import json, sys
rows_key, id_key = sys.argv[1], sys.argv[2]
try:
    d = json.load(sys.stdin)
    rows = d if isinstance(d, list) else d.get(rows_key, [])
    print(rows[0][id_key] if rows else "")
except Exception:
    print("")
' "$rows_key" "$id_key"
}

# Both key names were read out of a real capture rather than assumed, after the
# first walk skipped `history show` and `history export` in EVERY phase,
# including the ones where sessions plainly existed. `history list --format
# json` returns a bare list whose id key is `id`; the guess was `session_id`,
# `first_id` swallowed the KeyError, printed nothing, and the skip reason said
# "no runtime id available at this phase", which was true and told nobody why.
resolve_runtime_ids() {
    RUNTIME_ID="$(first_id checkpoints checkpoint_id -- checkpoint list --format json)"
    RUNTIME_SESSION="$(first_id sessions id -- history list --format json)"
}

# run_phase PHASE KIND
# KIND is "ro" or "mut". Substitutes runtime ids, skipping with a reason where
# one is not yet available.
run_phase() {
    local phase="$1" want_kind="$2" i slug tier kind
    for i in "${!RECIPE_SLUGS[@]}"; do
        slug="${RECIPE_SLUGS[$i]}"
        tier="${RECIPE_TIERS[$i]}"
        kind="${RECIPE_PHASEKIND[$i]}"
        [[ "$kind" == "$want_kind" ]] || continue
        tier_wanted "$tier" || { walk_skip "$slug" "$phase" "tier $tier not available in this run"; continue; }

        local -a argv resolved
        mapfile -t argv <<< "${RECIPE_ARGV[$i]}"
        local j bad=0
        resolved=()
        for j in "${!argv[@]}"; do
            case "${argv[$j]}" in
                RUNTIME_ID)      [[ -n "$RUNTIME_ID" ]] && resolved+=("$RUNTIME_ID") || bad=1 ;;
                RUNTIME_SESSION) [[ -n "$RUNTIME_SESSION" ]] && resolved+=("$RUNTIME_SESSION") || bad=1 ;;
                RUNTIME_OUT)     resolved+=("$CAPTURE/$phase-export.json") ;;
                *)               resolved+=("${argv[$j]}") ;;
            esac
        done
        if [[ $bad -eq 1 ]]; then
            walk_skip "$slug" "$phase" "no runtime id available at this phase"
            continue
        fi
        run_recipe "$slug" "$phase" "${RECIPE_TIMEOUTS[$i]}" -- "$BIN" "${resolved[@]}"
    done
}

resolve_runtime_ids
run_phase pristine ro
run_phase mutate   mut
resolve_runtime_ids
run_phase applied  ro
run_phase restore  mut
resolve_runtime_ids
run_phase restored ro

# The third total check, and it exists because three separate recipe orderings
# have now silently emptied a phase. A walk asserts nothing about the product,
# but a phase that changed nothing is a fact about the WALK, and one no reader
# can see: the rows all look healthy, the exit codes are what they should be,
# and only comparing two snapshots byte for byte says the phase demonstrated
# nothing. The rollback that prompted this reported twenty files restored and
# left the host exactly where it was, because the checkpoint it targeted had
# been taken after the apply rather than before it.
#
# Flags only, and never touches the exit code: the capture is trustworthy, it
# is simply uninformative, and those are different failures.
phase_snapshot() {
    local phase="$1"
    # One glob, because the sequence number in the directory name moves with
    # every recipe added above it and hardcoding one is its own stale reference.
    local match=("$CAPTURE/$phase"/*-scan-text/stdout)
    [[ -f "${match[0]}" ]] && printf '%s' "${match[0]}"
}

# Compared with a bash builtin and NOT with `cmp`, which is the shape this
# check was written to catch, found in the check itself. `cmp` lives in
# diffutils, the rhel container does not install it, and a missing command
# returns 127: the `&&` short-circuited, the `if` was false, and no note was
# written. That container's restore phase HAD done nothing, and its index came
# out clean while debian and ubuntu, which have diffutils, were flagged
# correctly for the identical condition. A guard that reports a problem only on
# hosts equipped to notice it is worse than none, because the silence reads as
# a pass. `$(<file)` needs nothing installed, so there is no absence left to
# handle rather than a handled one. It strips trailing newlines from both sides
# equally, which cannot turn two differing snapshots into a match.
SNAPSHOT_NOTE=""
applied_snap="$(phase_snapshot applied)"
restored_snap="$(phase_snapshot restored)"
pristine_snap="$(phase_snapshot pristine)"
if [[ -n "$applied_snap" && -n "$pristine_snap" ]] &&
    [[ "$(<"$pristine_snap")" == "$(<"$applied_snap")" ]]; then
    SNAPSHOT_NOTE=" | WALK PROBLEM: applied is byte-identical to pristine, so the mutate phase changed nothing"
fi
if [[ -n "$applied_snap" && -n "$restored_snap" ]] &&
    [[ "$(<"$applied_snap")" == "$(<"$restored_snap")" ]]; then
    SNAPSHOT_NOTE="$SNAPSHOT_NOTE | WALK PROBLEM: restored is byte-identical to applied, so the restore phase changed nothing"
fi

STAMP="$($BIN --version 2>&1 | head -1) (binary mtime: $(date -r "$BIN" '+%Y-%m-%d %H:%M'))"
walk_write_index "Binary: $STAMP | distro: $DISTRO | tiers: $TIERS$SNAPSHOT_NOTE"
