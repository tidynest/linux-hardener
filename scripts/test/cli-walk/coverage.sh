#!/bin/bash
# =============================================================================
# COVERAGE CROSS-CHECK: cli-walk
# =============================================================================
# Walks `hardener --help` recursively and fails if any command or subcommand
# has neither a recipe nor a skip with a stated reason.
#
# Without this, a command added later is silently uncovered and the walk
# reports success on a surface it never touched.
#
# Usage: ./scripts/test/cli-walk/coverage.sh <path-to-hardener>
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=recipes.sh
source "$SCRIPT_DIR/recipes.sh"

BIN="${1:-}"
if [[ -z "$BIN" || ! -x "$BIN" ]]; then
    echo "usage: $0 <path-to-hardener>"
    exit 2
fi

# Collect "family subcommand" pairs plus bare top-level commands.
mapfile -t TOP < <("$BIN" --help 2>&1 |
    sed -n '/^Commands:/,/^Options:/p' |
    sed -nE 's/^  ([a-z][a-z-]*) .*/\1/p')

COMMANDS=()
for cmd in "${TOP[@]}"; do
    # clap emits a `help` subcommand under every family. None is written by
    # this project. Eight boilerplate skips would train a reader to scroll
    # past the skip list, which is where the one real skip would then hide.
    [[ "$cmd" == "help" ]] && continue
    mapfile -t SUBS < <("$BIN" "$cmd" --help 2>&1 |
        sed -n '/^Commands:/,/^Options:/p' |
        sed -nE 's/^  ([a-z][a-z-]*) .*/\1/p')
    if [[ ${#SUBS[@]} -eq 0 ]]; then
        COMMANDS+=("$cmd")
    else
        for sub in "${SUBS[@]}"; do
            [[ "$sub" == "help" ]] && continue
            COMMANDS+=("$cmd $sub")
        done
    fi
done

covered() {
    local target="$1" i argv first second cmd_idx
    # Value-taking global flags are explicit to avoid guessing whether a flag
    # takes a value. Stacking, boolean flags, and new flags all handled by this
    # loop walk.
    local -r value_taking_flags=(--ssh --format -f --config -C)

    for i in "${!RECIPE_SLUGS[@]}"; do
        mapfile -t argv <<< "${RECIPE_ARGV[$i]}"

        # Walk from the start, skipping global flags and consuming one extra
        # token for flags that take a value. Stop at the first non-flag token.
        cmd_idx=0
        while [[ $cmd_idx -lt ${#argv[@]} && "${argv[$cmd_idx]}" == -* ]]; do
            local flag="${argv[$cmd_idx]}"
            local takes_value=0
            for vf in "${value_taking_flags[@]}"; do
                [[ "$flag" == "$vf" ]] && { takes_value=1; break; }
            done
            ((cmd_idx++))
            if [[ $takes_value -eq 1 && $cmd_idx -lt ${#argv[@]} ]]; then
                ((cmd_idx++))
            fi
        done

        first="${argv[$cmd_idx]:-}"
        second="${argv[$((cmd_idx + 1))]:-}"
        [[ "$target" == "$first" ]] && return 0
        [[ "$target" == "$first $second" ]] && return 0
    done
    local s
    for s in "${SKIP_SLUGS[@]}"; do
        [[ "$target" == "$s" ]] && return 0
    done
    return 1
}

missing=()
for c in "${COMMANDS[@]}"; do
    covered "$c" || missing+=("$c")
done

echo "Commands discovered: ${#COMMANDS[@]}"
echo "Recipes registered:  ${#RECIPE_SLUGS[@]}"
if [[ ${#SKIP_SLUGS[@]} -gt 0 ]]; then
    echo "Skipped, with reasons:"
    for i in "${!SKIP_SLUGS[@]}"; do
        echo "  ${SKIP_SLUGS[$i]}: ${SKIP_REASONS[$i]}"
    done
fi

if [[ ${#missing[@]} -gt 0 ]]; then
    echo ""
    echo "UNCOVERED (add a recipe, or a skip with a reason):"
    printf '  %s\n' "${missing[@]}"
    exit 1
fi
echo "All discovered commands are covered."
exit 0
