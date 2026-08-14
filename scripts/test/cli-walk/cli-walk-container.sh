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
#   --booted        Boot each container under its own systemd, which is the only
#                   way to reach the `booted` tier. Captures land in
#                   test-results/cli-walk/<distro>-booted, beside the --pipe
#                   ones rather than over them.
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
DO_BOOTED=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --distro) SINGLE_DISTRO="$2"; shift 2 ;;
        --jobs)   MAX_JOBS="$2"; shift 2 ;;
        --no-ssh) RUN_SSH=false; shift ;;
        --booted) DO_BOOTED=true; shift ;;
        --help)   sed -n '2,27p' "$0"; exit 0 ;;
        *) echo "Unknown option: $1"; exit 2 ;;
    esac
done

# A booted walk writes beside the --pipe one rather than over it. The two are
# different hosts and not two capability levels: booting arch starts auditd,
# which lays down a compiled rule set before any recipe runs, so a booted
# capture cannot reach a case that only exists on an unbooted host. Overwriting
# would leave one reading claiming to be the other.
CAPTURE_SUFFIX=""
[[ "$DO_BOOTED" == true ]] && CAPTURE_SUFFIX="-booted"

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

# The binary has to be the one the tree describes, and this is not paranoia:
# the first real run of this harness walked a binary from the previous day and
# faithfully reproduced `report --format json` printing prose, a defect fixed
# that morning. Every line of that capture was true about a binary nobody was
# asking about. A walk exists to attribute output to code, so walking the wrong
# code is not a degraded run, it is a worthless one.
#
# Three questions, the same three release-readiness-root.sh asks, from the same
# helpers in common.sh. No override: an override reintroduces exactly this.
walk_binary_line="$(binary_version_line "$MUSL")" || {
    echo -e "${RED}$MUSL would not report a version${NC}"
    exit 1
}
# "hardener 1.5.1 (e8a7640c 2026-08-12)".
read -r _ walk_bin_version walk_bin_commit _ <<< "$walk_binary_line"
walk_bin_commit="${walk_bin_commit#(}"
walk_bin_commit="${walk_bin_commit%)}"
walk_tree_version="$(workspace_version)"
walk_head_commit="$(git -C "$PROJECT_DIR" rev-parse --short HEAD 2>/dev/null || echo "")"
walk_stale_source="$(first_source_newer_than "$MUSL")"

walk_binary_problem=""
[[ "$walk_bin_version" != "$walk_tree_version" ]] &&
    walk_binary_problem="binary says version $walk_bin_version, tree says $walk_tree_version"
[[ -n "$walk_head_commit" && "$walk_bin_commit" != "$walk_head_commit" ]] &&
    walk_binary_problem="${walk_binary_problem:+$walk_binary_problem; }built at $walk_bin_commit, HEAD is $walk_head_commit"
[[ -n "$walk_stale_source" ]] &&
    walk_binary_problem="${walk_binary_problem:+$walk_binary_problem; }source newer than the binary: $walk_stale_source"

if [[ -n "$walk_binary_problem" ]]; then
    echo -e "${RED}The musl binary is not the one this tree describes.${NC}"
    echo "  $walk_binary_problem"
    echo ""
    echo "  Every container would walk that binary and every line of the capture"
    echo "  would be read as a fact about code it does not contain. Rebuild as"
    echo "  your normal user, NOT under sudo:"
    echo "    cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli"
    exit 1
fi
echo -e "${DIM}Binary: $walk_binary_line (tree $walk_tree_version at $walk_head_commit)${NC}"

TARGET_BIND=()
[[ "$TARGET_DIR" != "$PROJECT_DIR/target" ]] && TARGET_BIND=("--bind-ro=$TARGET_DIR:/project/target")

if [[ -n "$SINGLE_DISTRO" ]]; then
    DISTROS=("$SINGLE_DISTRO")
else
    DISTROS=("${DISTRO_ORDER[@]}")
fi

CAPTURE_PARENT="$PROJECT_DIR/test-results/cli-walk"

declare -A RESULT_EXIT

# Boot one container under its own systemd and run the walk as a child of it.
#
# Mirrors `nspawn_suite_booted` in run-cross-distro-tests.sh, which solved this
# first and whose two hard-won details are kept verbatim. The readiness loop
# waits on the transport rather than on `machinectl status`, which succeeds as
# soon as the machine registers and long before the container's bus is
# listening. And a container that never accepts a command is a FAILURE rather
# than a skip: `systemd-run --machine` needs dbus inside the container, only
# debian installs it explicitly, and an undeterminable result is never a skip.
#
# --private-network is a safety requirement and not a preference. nspawn grants
# CAP_NET_ADMIN only to a container that owns its network namespace, and this
# walk runs `apply --all`, firewall plugin included. A booted walk container on
# the host's namespace would write those rules into the host's own netfilter.
walk_booted() {
    local distro="$1" path="$2" capture="$3"
    local machine unit rc=0
    machine="$(basename "$path")"
    unit="hardener-walk-$machine"

    # Idempotent: a machine left behind by an interrupted run would otherwise
    # hold the container and read as a container-in-use failure.
    machinectl terminate "$machine" > /dev/null 2>&1 || true
    systemctl reset-failed "$unit" > /dev/null 2>&1 || true
    sleep 1

    if ! systemd-run --unit="$unit" \
        systemd-nspawn --machine="$machine" --directory="$path" \
        --bind="$PROJECT_DIR:/project" \
        "${TARGET_BIND[@]}" \
        --boot --private-network --console=passive > /dev/null; then
        echo "FATAL: could not launch $machine"
        return 1
    fi

    local ready=""
    for _ in $(seq 1 60); do
        if systemd-run --machine="$machine" --wait --pipe --quiet /bin/true > /dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 1
    done

    if [[ -z "$ready" ]]; then
        echo "FATAL: $machine booted but never accepted a command."
        echo "  'systemd-run --machine' needs dbus INSIDE the container. Only"
        echo "  debian installs it explicitly (create-container.sh); openSUSE"
        echo "  installs systemd with --no-recommends and may not have it."
        journalctl -u "$unit" -n 20 --no-pager 2>&1 || true
        machinectl terminate "$machine" > /dev/null 2>&1 || true
        return 1
    fi

    systemd-run --machine="$machine" --wait --pipe --quiet \
        /bin/bash /project/scripts/test/cli-walk/cli-walk-inner.sh \
        "$distro" "$WALK_CONTAINER_BOOTED_TIERS" "$capture" || rc=$?

    machinectl terminate "$machine" > /dev/null 2>&1 || true
    return "$rc"
}

run_single_distro() {
    local distro="$1"
    local machine="${CONTAINERS[$distro]}"
    local path="/var/lib/machines/$machine"
    local capture="$distro$CAPTURE_SUFFIX"

    "$PROJECT_DIR/scripts/containers/create-container.sh" "$distro" clean --no-confirm > /dev/null 2>&1
    "$PROJECT_DIR/scripts/containers/create-container.sh" "$distro" --no-confirm > /dev/null 2>&1

    if [[ "$DO_BOOTED" == true ]]; then
        walk_booted "$distro" "$path" "$capture"
    else
        systemd-nspawn -D "$path" \
            --bind="$PROJECT_DIR:/project" \
            "${TARGET_BIND[@]}" \
            --pipe \
            /bin/bash /project/scripts/test/cli-walk/cli-walk-inner.sh \
            "$distro" "$WALK_CONTAINER_TIERS" "$capture"
    fi
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
        [[ ",$WALK_SSH_TIERS," == *",${RECIPE_TIERS[$i]},"* ]] || continue
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
WROTE_POINTER=false
if [[ ${#DISTROS[@]} -gt 1 ]]; then
    OTHERS=()
    for d in "${DISTROS[@]}"; do
        [[ "$d" != "arch" ]] && OTHERS+=("$d$CAPTURE_SUFFIX")
    done
    walk_write_diff_pointer "$CAPTURE_PARENT" "arch$CAPTURE_SUFFIX" "${OTHERS[@]}"
    WROTE_POINTER=true
fi

echo ""
print_boxline "  CLI WALK CAPTURES"
for d in "${DISTROS[@]}"; do
    echo "  $d: exit ${RESULT_EXIT[$d]:-?}  ->  test-results/cli-walk/$d$CAPTURE_SUFFIX/index.md"
done
echo ""
# Says what THIS run produced, rather than describing a six-distribution walk
# whatever ran. A `--distro rhel` run used to print "Read arch/index.md. The
# other five are captured for the diff pointer", naming a capture it had not
# refreshed, and then pointed at a diff-pointer.md left by an earlier run
# purely because the file existed. That pointer described the rhel container
# as it had been before it was rebuilt, which is the reading it was least
# able to give and the one it was recommending.
if [[ "$WROTE_POINTER" == true ]]; then
    echo "Read test-results/cli-walk/arch$CAPTURE_SUFFIX/index.md. The others are captured"
    echo "for the diff pointer, not for reading."
    echo "Then test-results/cli-walk/diff-pointer.md for where they disagree."
else
    for d in "${DISTROS[@]}"; do
        echo "Read test-results/cli-walk/$d$CAPTURE_SUFFIX/index.md."
    done
    [[ -f "$CAPTURE_PARENT/diff-pointer.md" ]] &&
        echo "diff-pointer.md is left from an earlier run and does NOT cover this one."
fi
