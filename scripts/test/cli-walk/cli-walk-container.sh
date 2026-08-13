#!/bin/bash
# =============================================================================
# CLI WALK, CONTAINER ORCHESTRATOR: Linux Hardener
# =============================================================================
# Recreates every container, runs the walk in each, and captures for a reading
# pass. Every container is recreated: a completed run poisons its own
# container, and this walk mutates considerably more than a test suite does.
#
# The ssh tier is arch only and runs last. boot-ssh-test-container.sh pins
# CONTAINER_IP=10.242.117.2 on one static veth pair, so two booted SSH
# fixtures cannot coexist and the tier cannot fan out. It also takes over
# hardener-test, which is the fixture that makes the GUI runner fail on
# "currently busy", so running it last bounds that window.
#
# The ssh tier runs on THIS host pointing at the fixture, not inside it. Its
# recipes are `batch` verbs that target a remote, and the booted fixture has
# no /project bound in any case. It runs as the invoking user rather than as
# root, because the fixture key lives in that user's agent and ~/.ssh, which
# is the same contract batch_ssh_integration.rs already uses.
#
# Usage: sudo ./scripts/test/cli-walk/cli-walk-container.sh [OPTIONS]
#   --distro NAME   Only this distribution
#   --jobs N        Max parallel containers (default 3)
#   --no-ssh        Skip the ssh tier entirely
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# shellcheck source=../../lib/common.sh
source "$PROJECT_DIR/scripts/lib/common.sh"
# shellcheck source=../../lib/parallel.sh
source "$PROJECT_DIR/scripts/lib/parallel.sh"
# shellcheck source=walk-lib.sh
source "$SCRIPT_DIR/walk-lib.sh"
# shellcheck source=recipes.sh
source "$SCRIPT_DIR/recipes.sh"

SINGLE_DISTRO=""
MAX_JOBS=3
RUN_SSH=true
while [[ $# -gt 0 ]]; do
    case $1 in
        --distro) SINGLE_DISTRO="$2"; shift 2 ;;
        --jobs)   MAX_JOBS="$2"; shift 2 ;;
        --no-ssh) RUN_SSH=false; shift ;;
        --help)   sed -n '2,25p' "$0"; exit 0 ;;
        *) echo "Unknown option: $1"; exit 2 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}ERROR: must run as root (systemd-nspawn requires it)${NC}"
    exit 1
fi

# Refuse early and name the collision, rather than failing obscurely later.
if machinectl status hardener-test > /dev/null 2>&1; then
    echo -e "${RED}hardener-test is currently busy.${NC}"
    echo "The SSH fixture and the GUI runner share this container. Stop it first:"
    echo "  machinectl stop hardener-test"
    exit 1
fi

TARGET_DIR="$(resolve_target_dir "x86_64-unknown-linux-musl/release/hardener" "release/hardener")"
MUSL="$TARGET_DIR/x86_64-unknown-linux-musl/release/hardener"
if [[ ! -x "$MUSL" ]]; then
    echo -e "${RED}No musl binary at $MUSL. Build it first:${NC}"
    echo "  cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli"
    exit 1
fi

TARGET_BIND=()
[[ "$TARGET_DIR" != "$PROJECT_DIR/target" ]] && TARGET_BIND=("--bind-ro=$TARGET_DIR:/project/target")

if [[ -n "$SINGLE_DISTRO" ]]; then
    DISTROS=("$SINGLE_DISTRO")
else
    DISTROS=("${DISTRO_ORDER[@]}")
fi

CAPTURE_PARENT="$PROJECT_DIR/test-results/cli-walk"

declare -A RESULT_EXIT

run_single_distro() {
    local distro="$1"
    local machine="${CONTAINERS[$distro]}"
    local path="/var/lib/machines/$machine"

    "$PROJECT_DIR/scripts/containers/create-container.sh" "$distro" clean --no-confirm > /dev/null 2>&1
    "$PROJECT_DIR/scripts/containers/create-container.sh" "$distro" --no-confirm > /dev/null 2>&1

    systemd-nspawn -D "$path" \
        --bind="$PROJECT_DIR:/project" \
        "${TARGET_BIND[@]}" \
        --pipe \
        /bin/bash /project/scripts/test/cli-walk/cli-walk-inner.sh "$distro" "unprivileged,root"
    # Written from a plain run above, never through a pipe.
    echo $? > "$CAPTURE_PARENT/.$distro.exit"
}

mkdir -p "$CAPTURE_PARENT"
echo -e "${CYAN}CLI walk across ${#DISTROS[@]} distribution(s), up to $MAX_JOBS at once${NC}"
launch_job_pool "$MAX_JOBS" DISTROS

for idx in "${!PIDS[@]}"; do
    wait "${PIDS[$idx]}" 2>/dev/null
    d="${PID_DISTROS[$idx]}"
    RESULT_EXIT[$d]="$(cat "$CAPTURE_PARENT/.$d.exit" 2>/dev/null || echo 1)"
done

# --- The ssh tier, alone, last, arch only ------------------------------------
# run_ssh_tier TARGET
# One pass, no phases: the fixture is freshly booted, so there is only ever a
# pristine state to walk. Runs the recipes in declaration order, which puts
# the two read-only verbs before the two mutating ones.
run_ssh_tier() {
    local target="$1" i slug j
    local capture="$CAPTURE_PARENT/arch-ssh"
    rm -rf "$capture"
    walk_init "$capture"

    for i in "${!RECIPE_SLUGS[@]}"; do
        [[ "${RECIPE_TIERS[$i]}" == "ssh" ]] || continue
        slug="${RECIPE_SLUGS[$i]}"
        local -a argv resolved
        mapfile -t argv <<< "${RECIPE_ARGV[$i]}"
        resolved=()
        for j in "${!argv[@]}"; do
            case "${argv[$j]}" in
                RUNTIME_SSH) resolved+=("$target") ;;
                *)           resolved+=("${argv[$j]}") ;;
            esac
        done
        echo "  $slug"
        run_recipe "$slug" pristine "${RECIPE_TIMEOUTS[$i]}" -- \
            sudo -u "$SUDO_USER" --preserve-env=SSH_AUTH_SOCK \
            "$MUSL" "${resolved[@]}"
    done

    walk_write_index "Binary: $("$MUSL" --version 2>&1 | head -1) | target: $target | tier: ssh"
}

if [[ "$RUN_SSH" == true ]]; then
    echo ""
    echo -e "${CYAN}SSH tier (arch only, single static veth pair)${NC}"
    if [[ -z "${SUDO_USER:-}" || -z "${SSH_AUTH_SOCK:-}" ]]; then
        # A skip with a reason, not an omission. `batch` authenticates by key
        # or agent only, and neither is reachable from a bare root shell, so
        # running it anyway would capture four identical auth failures and
        # read as a product defect.
        echo -e "${YELLOW}Skipped: needs SUDO_USER and a forwarded SSH_AUTH_SOCK.${NC}"
        echo "  Run as: sudo --preserve-env=SSH_AUTH_SOCK $0"
        echo "  with the fixture key loaded: ssh-add ~/.ssh/hardener_test_ed25519"
    else
        "$PROJECT_DIR/scripts/containers/boot-ssh-test-container.sh" hardener-test
        SSH_TARGET="${SSH_TEST_USER:-root}@${SSH_TEST_HOST:-10.242.117.2}"
        [[ -n "${SSH_TEST_PORT:-}" ]] && SSH_TARGET="$SSH_TARGET:$SSH_TEST_PORT"
        run_ssh_tier "$SSH_TARGET"
        machinectl stop hardener-test 2>/dev/null || true
    fi
fi

# --- Cross-distribution diff pointer -----------------------------------------
if [[ ${#DISTROS[@]} -gt 1 ]]; then
    OTHERS=()
    for d in "${DISTROS[@]}"; do
        [[ "$d" != "arch" ]] && OTHERS+=("$d")
    done
    walk_write_diff_pointer "$CAPTURE_PARENT" arch "${OTHERS[@]}"
fi

echo ""
print_boxline "  CLI WALK CAPTURES"
for d in "${DISTROS[@]}"; do
    echo "  $d: exit ${RESULT_EXIT[$d]:-?}  ->  test-results/cli-walk/$d/index.md"
done
echo ""
echo "Read test-results/cli-walk/arch/index.md. The other five are captured"
echo "for the diff pointer, not for reading."
[[ -f "$CAPTURE_PARENT/diff-pointer.md" ]] && \
    echo "Then test-results/cli-walk/diff-pointer.md for where they disagree."
