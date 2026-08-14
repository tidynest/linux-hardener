#!/bin/bash
# =============================================================================
# CLI WALK, HOST: Linux Hardener
# =============================================================================
# Runs the unprivileged tier against this host and captures everything for a
# reading pass. Read-only: it REFUSES any recipe of another tier.
#
# The refusal is structural, not a property of the current list happening to
# be safe. `apply` on the development host is the one genuinely unrecoverable
# action available here, and a filter that depends on data staying correct is
# not a guard.
#
# Usage: ./scripts/test/cli-walk/cli-walk-host.sh [--bin PATH]
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# shellcheck source=../../lib/common.sh
source "$PROJECT_DIR/scripts/lib/common.sh"
# shellcheck source=walk-lib.sh
source "$SCRIPT_DIR/walk-lib.sh"
# shellcheck source=recipes.sh
source "$SCRIPT_DIR/recipes.sh"

BIN=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --bin) BIN="$2"; shift 2 ;;
        --help) sed -n '2,14p' "$0"; exit 0 ;;
        *) echo "Unknown option: $1"; exit 2 ;;
    esac
done

if [[ -z "$BIN" ]]; then
    TARGET_DIR="$(resolve_target_dir "debug/hardener" "release/hardener")"
    BIN="$TARGET_DIR/debug/hardener"
fi
if [[ ! -x "$BIN" ]]; then
    echo -e "${RED}No hardener binary at $BIN. Build it first:${NC}"
    echo "  cargo build --workspace"
    exit 1
fi

bash "$SCRIPT_DIR/selftest.sh" > /dev/null || {
    echo -e "${RED}Capture self-test failed. Not walking with broken capture.${NC}"
    exit 1
}

CAPTURE="$PROJECT_DIR/test-results/cli-walk/host"
rm -rf "$CAPTURE"
walk_init "$CAPTURE"

echo -e "${CYAN}CLI walk, host, unprivileged tier only${NC}"
echo ""

for i in "${!RECIPE_SLUGS[@]}"; do
    tier="${RECIPE_TIERS[$i]}"
    slug="${RECIPE_SLUGS[$i]}"
    # Membership in the runner's declared tier set rather than a literal, so
    # coverage.sh's picture of what this runner can give cannot drift from what
    # it actually gives.
    if [[ ",$WALK_HOST_TIERS," != *",$tier,"* ]]; then
        continue
    fi
    mapfile -t argv <<< "${RECIPE_ARGV[$i]}"
    if [[ " ${argv[*]} " == *" RUNTIME_"* ]]; then
        walk_skip "$slug" pristine "needs a runtime id; container walk only"
        continue
    fi
    echo "  $slug"
    run_recipe "$slug" pristine "${RECIPE_TIMEOUTS[$i]}" -- "$BIN" "${argv[@]}"
done

STAMP="$($BIN --version 2>&1 | head -1) (binary mtime: $(date -r "$BIN" '+%Y-%m-%d %H:%M'))"
walk_write_index "Binary: $STAMP"

echo ""
echo -e "${GREEN}Capture written to $CAPTURE${NC}"
echo "Read $CAPTURE/index.md first."
