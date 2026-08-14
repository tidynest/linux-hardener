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

# The tiers some runner can give, padded for substring membership. The set
# itself is composed in recipes.sh beside the per-runner lists, so this file
# cannot come to disagree with them about what "reachable" means.
REACHABLE=" ${WALK_REACHABLE_TIERS//,/ } "
tier_reachable() { [[ "$REACHABLE" == *" $1 "* ]]; }

tier_declared_unreachable() {
    local t
    [[ ${#UNREACHABLE_TIERS[@]} -eq 0 ]] && return 1
    for t in "${UNREACHABLE_TIERS[@]}"; do
        [[ "$t" == "$1" ]] && return 0
    done
    return 1
}

unreachable_reason() {
    local i
    for i in "${!UNREACHABLE_TIERS[@]}"; do
        [[ "${UNREACHABLE_TIERS[$i]}" == "$1" ]] || continue
        printf '%s' "${UNREACHABLE_REASONS[$i]}"
        return
    done
}

# Every tier whose recipes name this command, space separated and deduplicated,
# or nothing at all. This replaces a predicate that returned at the first match:
# knowing a command is covered says nothing useful once the question is whether
# anything can run what covers it.
covering_tiers() {
    local target="$1" i argv first second cmd_idx tiers=" "
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
        if [[ "$target" == "$first" || "$target" == "$first $second" ]]; then
            local t="${RECIPE_TIERS[$i]}"
            [[ "$tiers" == *" $t "* ]] || tiers+="$t "
        fi
    done
    tiers="${tiers# }"
    printf '%s' "${tiers% }"
}

command_skipped() {
    local s
    [[ ${#SKIP_SLUGS[@]} -eq 0 ]] && return 1
    for s in "${SKIP_SLUGS[@]}"; do
        [[ "$1" == "$s" ]] && return 0
    done
    return 1
}

# A tier no runner gives and nobody declared, and a declaration that has gone
# stale, are both this file lying about what it measured. Neither is tolerated,
# because the whole defect being fixed here was a report that overstated.
bad_tiers=()
for i in "${!RECIPE_TIERS[@]}"; do
    t="${RECIPE_TIERS[$i]}"
    tier_reachable "$t" && continue
    tier_declared_unreachable "$t" && continue
    [[ " ${bad_tiers[*]:-} " == *" $t "* ]] || bad_tiers+=("$t")
done

stale_tiers=()
if [[ ${#UNREACHABLE_TIERS[@]} -gt 0 ]]; then
    for t in "${UNREACHABLE_TIERS[@]}"; do
        tier_reachable "$t" && stale_tiers+=("$t")
    done
fi

missing=()
stranded=()
for c in "${COMMANDS[@]}"; do
    tiers="$(covering_tiers "$c")"
    if [[ -z "$tiers" ]]; then
        command_skipped "$c" || missing+=("$c")
        continue
    fi
    # Covered, but only counts as covered if something can run one of them.
    for t in $tiers; do
        tier_reachable "$t" && continue 2
    done
    stranded+=("$c|$tiers")
done

echo "Commands discovered: ${#COMMANDS[@]}"
echo "Recipes registered:  ${#RECIPE_SLUGS[@]}"
if [[ ${#SKIP_SLUGS[@]} -gt 0 ]]; then
    echo "Skipped, with reasons:"
    for i in "${!SKIP_SLUGS[@]}"; do
        echo "  ${SKIP_SLUGS[$i]}: ${SKIP_REASONS[$i]}"
    done
fi

if [[ ${#stranded[@]} -gt 0 ]]; then
    echo ""
    echo "REGISTERED BUT UNREACHABLE (a recipe exists; no runner can run it):"
    for entry in "${stranded[@]}"; do
        cmd="${entry%%|*}"
        tiers="${entry#*|}"
        echo "  $cmd [tier: $tiers]"
    done
    for t in "${UNREACHABLE_TIERS[@]}"; do
        echo "  tier '$t': $(unreachable_reason "$t")"
    done
fi

fail=0
if [[ ${#bad_tiers[@]} -gt 0 ]]; then
    echo ""
    echo "UNDECLARED TIER (no runner gives it and nothing says so):"
    printf '  %s\n' "${bad_tiers[@]}"
    echo "  Add it to a runner's tier list, or declare it with unreachable_tier."
    fail=1
fi
if [[ ${#stale_tiers[@]} -gt 0 ]]; then
    echo ""
    echo "STALE DECLARATION (declared unreachable, but a runner reaches it):"
    printf '  %s\n' "${stale_tiers[@]}"
    echo "  Drop the unreachable_tier line; it is now hiding a tier that works."
    fail=1
fi
if [[ ${#missing[@]} -gt 0 ]]; then
    echo ""
    echo "UNCOVERED (add a recipe, or a skip with a reason):"
    printf '  %s\n' "${missing[@]}"
    fail=1
fi
[[ $fail -eq 1 ]] && exit 1

# The summary line the fix exists for. It said "All discovered commands are
# covered" while four of them were covered only by a tier no runner could give,
# which is the same overstatement the walk itself keeps finding: registration
# confirmed, execution not, silence read as coverage.
if [[ ${#stranded[@]} -gt 0 ]]; then
    echo ""
    echo "$(( ${#COMMANDS[@]} - ${#stranded[@]} )) of ${#COMMANDS[@]} discovered commands are covered by a tier a runner can give."
    echo "${#stranded[@]} are registered against an unreachable tier and have never been executed by a walk."
    exit 0
fi
echo "All discovered commands are covered."
exit 0
