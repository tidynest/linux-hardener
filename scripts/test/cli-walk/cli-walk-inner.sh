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

resolve_runtime_ids() {
    RUNTIME_ID="$(first_id checkpoints checkpoint_id -- checkpoint list --format json)"
    RUNTIME_SESSION="$(first_id sessions session_id -- history list --format json)"
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

STAMP="$($BIN --version 2>&1 | head -1) (binary mtime: $(date -r "$BIN" '+%Y-%m-%d %H:%M'))"
walk_write_index "Binary: $STAMP | distro: $DISTRO | tiers: $TIERS"
