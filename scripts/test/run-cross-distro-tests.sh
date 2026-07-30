#!/bin/bash
# =============================================================================
# CROSS-DISTRO TEST RUNNER - Linux System Hardener
# =============================================================================
# Runs full-test-suite.sh, or differential-suite.sh with --differential, across
# all supported distributions using systemd-nspawn --pipe (non-interactive, no
# boot/login needed), or with --booted under the container's own systemd.
# Serial by default; --parallel tests multiple distros simultaneously with
# background processes (~5x faster when testing all 5 distros).
#
# Usage: sudo ./scripts/test/run-cross-distro-tests.sh [OPTIONS]
#
# Options:
#   --apply           Enable destructive tests (apply + rollback)
#   --booted          Boot under systemd rather than --pipe (services, audit,
#                     firewall need PID 1 to be a service manager)
#   --differential    Run differential-suite.sh instead of full-test-suite.sh
#   --distro NAME     Run only one distro (arch|debian|fedora|rhel|opensuse)
#   --gui             Run GUI tests (Playwright Web UI) after CLI tests
#   --parallel        Run distros in parallel instead of serially
#   --jobs N          Max parallel jobs (with --parallel; default: 3)
#   --rebuild         Build musl binary before testing
#   --help            Show usage
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
RESULTS_DIR="$PROJECT_DIR/test-results"

# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"
# shellcheck source=../lib/parallel.sh
source "$SCRIPT_DIR/../lib/parallel.sh"

TARGET_DIR="$(resolve_target_dir "x86_64-unknown-linux-musl/release/hardener" "release/hardener")"
MUSL_BINARY="$TARGET_DIR/x86_64-unknown-linux-musl/release/hardener"

# Options
DO_APPLY=false
DO_BOOTED=false
DO_DIFFERENTIAL=false
SINGLE_DISTRO=""
DO_GUI=false
DO_REBUILD=false
PARALLEL=false
MAX_JOBS=3

# =============================================================================
# Argument parsing
# =============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        --apply)
            DO_APPLY=true
            shift
            ;;
        --booted)
            DO_BOOTED=true
            shift
            ;;
        --differential)
            DO_DIFFERENTIAL=true
            shift
            ;;
        --distro)
            SINGLE_DISTRO="$2"
            if [[ -z "${CONTAINERS[$SINGLE_DISTRO]+_}" ]]; then
                echo "Unknown distro: $SINGLE_DISTRO"
                echo "Valid: ${!CONTAINERS[*]}"
                exit 1
            fi
            shift 2
            ;;
        --gui)
            DO_GUI=true
            shift
            ;;
        --parallel)
            PARALLEL=true
            shift
            ;;
        --jobs)
            MAX_JOBS="$2"
            shift 2
            ;;
        --rebuild)
            DO_REBUILD=true
            shift
            ;;
        --help|-h)
            cat << EOF
Cross-Distro Test Runner for Linux System Hardener

Usage: sudo $0 [OPTIONS]

Options:
  --apply           Enable destructive tests (apply + rollback)
  --booted          Boot the container under systemd instead of --pipe, so
                    systemd is PID 1 and services/audit/firewall are testable.
                    Leaves a machine running if interrupted: clear it with
                    'machinectl terminate <container-name>'
  --differential    Run differential-suite.sh instead of full-test-suite.sh
  --distro NAME     Run only one distro (arch|debian|fedora|rhel|opensuse)
  --gui             Run GUI tests (Playwright Web UI) after CLI tests
  --parallel        Run distros in parallel instead of serially (~5x speedup)
  --jobs N          Max parallel jobs (with --parallel; default: 3)
  --rebuild         Build musl binary before testing
  --help            Show usage

--differential asks each setting's real consumer what the system is enforcing
and compares that against what the tool reported. It ALWAYS applies hardening,
whether or not --apply is given, and it creates and removes a probe account, so
it replaces the full suite for that run rather than running alongside it. A
failure means the system disagrees with the tool: a product defect, not a
flaky test.

Output:
  test-results/<distro>.log   Per-distro full output
  test-results/summary.txt    Aggregated results table

Containers must exist at /var/lib/machines/<name>.
EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# =============================================================================
# Pre-flight
# =============================================================================

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}ERROR: Must run as root (systemd-nspawn requires root)${NC}"
    exit 1
fi

if [[ "$DO_REBUILD" == "true" ]]; then
    echo -e "${CYAN}Building musl binary...${NC}"
    rustup target add x86_64-unknown-linux-musl 2>/dev/null || true
    cargo build --release --target x86_64-unknown-linux-musl \
        --manifest-path "$PROJECT_DIR/Cargo.toml" || {
        echo -e "${RED}Build failed${NC}"
        exit 1
    }
    TARGET_DIR="$(resolve_target_dir "x86_64-unknown-linux-musl/release/hardener" "release/hardener")"
    MUSL_BINARY="$TARGET_DIR/x86_64-unknown-linux-musl/release/hardener"
    echo -e "${GREEN}Build complete: $MUSL_BINARY${NC}"
fi

if [[ ! -x "$MUSL_BINARY" ]] && [[ ! -x "$TARGET_DIR/release/hardener" ]]; then
    echo -e "${RED}ERROR: No binary found. Build first or use --rebuild${NC}"
    exit 1
fi

# A redirected target dir sits outside the /project bind; mount it where the
# in-container scripts expect ./target.
TARGET_BIND=()
[[ "$TARGET_DIR" != "$PROJECT_DIR/target" ]] && TARGET_BIND=("--bind-ro=$TARGET_DIR:/project/target")

mkdir -p "$RESULTS_DIR"

# =============================================================================
# Run tests per distro
# =============================================================================

# Build list of distros to test
if [[ -n "$SINGLE_DISTRO" ]]; then
    DISTROS=("$SINGLE_DISTRO")
else
    DISTROS=("${DISTRO_ORDER[@]}")
fi

# Track results for summary
declare -A RESULT_PASSED RESULT_FAILED RESULT_SKIPPED RESULT_TOTAL RESULT_EXIT

# The suite each container runs, and the arguments it takes. The differential
# suite replaces the full suite rather than following it: it applies hardening
# unconditionally, so a run of it is never the read-only run --apply gates.
# It takes no arguments, and refuses any it is given.
INNER_SUITE="/project/scripts/test/full-test-suite.sh"
INNER_ARGS=()
SUITE_LABEL="full"
if [[ "$DO_DIFFERENTIAL" == "true" ]]; then
    INNER_SUITE="/project/scripts/test/differential-suite.sh"
    SUITE_LABEL="differential"
elif [[ "$DO_APPLY" == "true" ]]; then
    INNER_ARGS=(--apply)
fi

# The default execution mode: systemd never runs, so anything that asks the
# service manager a question is untestable here.
nspawn_suite_pipe() {
    local container_path="$1"
    systemd-nspawn -D "$container_path" \
        --bind="$PROJECT_DIR:/project" \
        "${TARGET_BIND[@]}" \
        --pipe \
        /bin/bash "$INNER_SUITE" "${INNER_ARGS[@]}"
}

# Boot the container under its own systemd and run the suite as a child of it.
#
# --private-network rather than --network-veth, measured on arch 2026-07-30
# through `systemd-run --machine` (a real child of the container's systemd, not
# nsenter, which keeps the host's capabilities and reports them instead). Both
# give CapEff 00000000fdecbfff with CAP_NET_ADMIN set, a read-write
# /proc/sys/net, and `iptables -L` rc=0. --network-veth additionally creates a
# ve-* interface on the host and needs addressing at both ends, which this suite
# has no use for: it needs the namespace, not connectivity.
#
# The private namespace is a safety requirement, not a preference. nspawn grants
# CAP_NET_ADMIN only to a container that owns its network namespace, and that is
# exactly what makes the sharing case harmless. Never hand
# --capability=CAP_NET_ADMIN to a container on the host's namespace: this suite
# runs `hardener apply --plugin firewall-hardening`, and those rules would land
# in the host's own netfilter.
#
# /proc/sys stays read-only in both configurations, so the 7 fs.* and kernel.*
# parameters remain out of reach and full-test-suite.sh's
# `apply --plugin kernel-hardening` still cannot touch this workstation. Do not
# mount it writable to "fix" a kernel oracle. The 11 net.ipv4.* parameters do
# become writable, inside the container's namespace only (host tcp_fin_timeout
# read 60 before and after a container write of 47), so the kernel apply now
# half-succeeds here where it used to fail outright.
nspawn_suite_booted() {
    local container_path="$1"
    local machine unit rc=0
    machine="$(basename "$container_path")"
    unit="hardener-suite-$machine"

    # Idempotent: a machine left behind by an interrupted run would otherwise
    # hold the container and make this look like a container-in-use failure.
    machinectl terminate "$machine" > /dev/null 2>&1 || true
    systemctl reset-failed "$unit" > /dev/null 2>&1 || true
    sleep 1

    if ! systemd-run --unit="$unit" \
        systemd-nspawn --machine="$machine" --directory="$container_path" \
        --bind="$PROJECT_DIR:/project" \
        "${TARGET_BIND[@]}" \
        --boot --private-network --console=passive > /dev/null; then
        echo "FATAL: could not launch $machine"
        return 1
    fi

    # Wait for the transport itself rather than for a proxy signal. Waiting on
    # `machinectl status` looks equivalent and is not: it succeeds as soon as
    # the machine registers, long before the container's bus is listening.
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
        echo "  Reported as a failure rather than skipped, deliberately: an"
        echo "  undeterminable result is a failure, never a skip."
        journalctl -u "$unit" -n 20 --no-pager 2>&1 || true
        machinectl terminate "$machine" > /dev/null 2>&1 || true
        return 1
    fi

    # The mode signal the differential suite reads, and the only place it is
    # ever set. It says "this run owns its network namespace, so /proc/sys/net
    # is writable and the kernel oracle can ask a question"; the --pipe branch
    # above deliberately does not set it, and the suite treats anything but the
    # literal 1 as not booted, so the 11 net.ipv4 rows there are declared
    # unaskable rather than measured against the host's own kernel.
    #
    # Set here rather than on the --setenv of the nspawn line above, because it
    # is THIS process that becomes the suite. The container's PID 1 is a
    # different process, and reaching the suite from its environment would
    # depend on the manager passing it down to a transient unit.
    systemd-run --machine="$machine" --wait --pipe --quiet \
        --setenv=HARDENER_DIFF_BOOTED=1 \
        /bin/bash "$INNER_SUITE" "${INNER_ARGS[@]}" || rc=$?

    machinectl terminate "$machine" > /dev/null 2>&1 || true
    return "$rc"
}

# The invocation shared by both execution modes.
nspawn_suite() {
    if [[ "$DO_BOOTED" == "true" ]]; then
        nspawn_suite_booted "$1"
    else
        nspawn_suite_pipe "$1"
    fi
}

# Parse pass/fail/skip/total counts from a log (strips ANSI escape codes);
# echoes "passed failed skipped total" on one line.
parse_log_counts() {
    local stripped
    stripped=$(sed 's/\x1b\[[0-9;]*m//g' "$1")
    local passed failed skipped total
    passed=$(echo "$stripped" | grep -oP 'Passed:\s+\K\d+' 2>/dev/null || echo "0")
    failed=$(echo "$stripped" | grep -oP 'Failed:\s+\K\d+' 2>/dev/null || echo "0")
    skipped=$(echo "$stripped" | grep -oP 'Skipped:\s+\K\d+' 2>/dev/null || echo "0")
    total=$(echo "$stripped" | grep -oP 'Total Tests:\s+\K\d+' 2>/dev/null || echo "0")
    echo "$passed $failed $skipped $total"
}

echo ""
BOX_W=74
echo -e "${MAGENTA}╔$(printf '═%.0s' $(seq 1 $BOX_W))╗${NC}"
print_boxline ""
if [[ "$PARALLEL" == "true" ]]; then
    print_boxline "   PARALLEL CROSS-DISTRO TEST RUNNER"
    print_boxline "   Distros: ${#DISTROS[@]}  |  Suite: $SUITE_LABEL  |  Apply: $DO_APPLY  |  Max jobs: $MAX_JOBS"
else
    print_boxline "   CROSS-DISTRO TEST RUNNER"
    print_boxline "   Distros: ${#DISTROS[@]}  |  Suite: $SUITE_LABEL  |  Apply: $DO_APPLY  |  GUI: $DO_GUI"
fi
print_boxline ""
echo -e "${MAGENTA}╚$(printf '═%.0s' $(seq 1 $BOX_W))╝${NC}"
echo ""

# Defined once, used by both serial (foreground) and parallel (backgrounded)
# execution. Runs the selected suite for one distro and prints an immediate
# one-line result. Result-array bookkeeping happens in the caller afterwards
# (a backgrounded run_single_distro cannot mutate the parent's associative
# arrays, so both modes re-derive counts from the persisted logfile there).
run_single_distro() {
    local distro="$1"
    local container="${CONTAINERS[$distro]}"
    local container_path="/var/lib/machines/$container"
    local logfile="$RESULTS_DIR/${distro}.log"

    [[ "$PARALLEL" != "true" ]] && echo -e "${CYAN}━━━ Testing: $distro ($container) ━━━${NC}"

    if [[ ! -d "$container_path" ]]; then
        if [[ "$PARALLEL" == "true" ]]; then
            echo -e "[$distro] ${YELLOW}SKIP${NC}: container not found"
        else
            echo -e "  ${RED}[SKIP]${NC} Container not found: $container_path"
        fi
        echo "CONTAINER NOT FOUND: $container_path" > "$logfile"
        return 99
    fi

    if [[ "$PARALLEL" == "true" ]]; then
        echo -e "[$distro] ${CYAN}Starting...${NC}"
    else
        if [[ "$DO_BOOTED" == "true" ]]; then
            echo -e "  ${CYAN}[RUN]${NC}  systemd-nspawn --boot --private-network -> $(basename "$INNER_SUITE") ${INNER_ARGS[*]}"
        else
            echo -e "  ${CYAN}[RUN]${NC}  systemd-nspawn --pipe -> $(basename "$INNER_SUITE") ${INNER_ARGS[*]}"
        fi
    fi

    nspawn_suite "$container_path" > "$logfile" 2>&1
    local exit_code=$?

    local passed failed skipped total
    read -r passed failed skipped total <<< "$(parse_log_counts "$logfile")"

    if [[ "$PARALLEL" == "true" ]]; then
        if [[ $exit_code -eq 0 ]] && [[ "$total" -gt 0 ]]; then
            echo -e "[$distro] ${GREEN}PASS${NC}: $passed/$total passed, $skipped skipped"
        elif [[ "$total" -eq 0 ]]; then
            echo -e "[$distro] ${RED}ERR${NC}: no results (exit: $exit_code)"
        else
            echo -e "[$distro] ${RED}FAIL${NC}: $failed failed (exit: $exit_code)"
        fi
    else
        if [[ $exit_code -eq 0 ]] && [[ "$total" -gt 0 ]]; then
            echo -e "  ${GREEN}[DONE]${NC} $passed/$total passed, $skipped skipped"
        elif [[ "$total" -eq 0 ]]; then
            echo -e "  ${RED}[ERR]${NC}  No test results parsed (exit code: $exit_code)"
        else
            echo -e "  ${RED}[FAIL]${NC} $passed/$total passed, $failed failed, $skipped skipped"
        fi
        echo ""
    fi

    return "$exit_code"
}

# Record RESULT_* for one distro by re-parsing its persisted logfile. Shared
# by both execution modes so a distro's counts are always derived the same
# way, whether run_single_distro ran in the foreground or in a background job.
record_distro_result() {
    local distro="$1" exit_code="$2"
    RESULT_EXIT[$distro]=$exit_code
    local passed failed skipped total
    read -r passed failed skipped total <<< "$(parse_log_counts "$RESULTS_DIR/${distro}.log")"
    RESULT_PASSED[$distro]=$passed
    RESULT_FAILED[$distro]=$failed
    RESULT_SKIPPED[$distro]=$skipped
    RESULT_TOTAL[$distro]=$total
}

if [[ "$PARALLEL" == "true" ]]; then
    echo -e "${CYAN}Launching parallel test jobs...${NC}"
    echo ""

    launch_job_pool "$MAX_JOBS" DISTROS

    for i in "${!PIDS[@]}"; do
        pid="${PIDS[$i]}"
        distro="${PID_DISTROS[$i]}"
        wait "$pid" 2>/dev/null
        record_distro_result "$distro" "$?"
    done
else
    for distro in "${DISTROS[@]}"; do
        run_single_distro "$distro"
        record_distro_result "$distro" "$?"
    done
fi

# =============================================================================
# Generate summary
# =============================================================================

SUMMARY_FILE="$RESULTS_DIR/summary.txt"

{
    if [[ "$PARALLEL" == "true" ]]; then
        echo "Parallel Cross-Distro Test Results"
        echo "==================================="
        echo "Date: $(date)"
        echo "Suite: $SUITE_LABEL"
        echo "Apply mode: $DO_APPLY"
        echo "Max parallel jobs: $MAX_JOBS"
    else
        echo "Cross-Distro Test Results"
        echo "========================"
        echo "Date: $(date)"
        echo "Suite: $SUITE_LABEL"
        echo "Apply mode: $DO_APPLY"
    fi
    echo ""
    printf "%-12s %6s %6s %6s %7s %5s %8s\n" "Distro" "Total" "Pass" "Fail" "Skip" "Exit" "Status"
    printf "%-12s %6s %6s %6s %7s %5s %8s\n" "--------" "-----" "----" "----" "----" "----" "------"

    for distro in "${DISTROS[@]}"; do
        total="${RESULT_TOTAL[$distro]:-0}"
        passed="${RESULT_PASSED[$distro]:-0}"
        failed="${RESULT_FAILED[$distro]:-0}"
        skipped="${RESULT_SKIPPED[$distro]:-0}"
        exit_code="${RESULT_EXIT[$distro]:-1}"

        if [[ "$exit_code" -eq 99 ]]; then
            status="MISSING"
        elif [[ "$failed" -eq 0 ]] && [[ "$total" -gt 0 ]]; then
            status="PASS"
        else
            status="FAIL"
        fi

        printf "%-12s %6s %6s %6s %7s %5s %8s\n" "$distro" "$total" "$passed" "$failed" "$skipped" "$exit_code" "$status"
    done

    echo ""
    echo "Logs: $RESULTS_DIR/<distro>.log"
} > "$SUMMARY_FILE"

# Print summary to stdout with colour
echo -e "${MAGENTA}╔$(printf '═%.0s' $(seq 1 $BOX_W))╗${NC}"
if [[ "$PARALLEL" == "true" ]]; then
    print_boxline "   PARALLEL CROSS-DISTRO SUMMARY"
else
    print_boxline "   CROSS-DISTRO SUMMARY"
fi
echo -e "${MAGENTA}╚$(printf '═%.0s' $(seq 1 $BOX_W))╝${NC}"
echo ""
printf "  ${BOLD}%-12s %6s %6s %6s %7s %8s${NC}\n" "Distro" "Total" "Pass" "Fail" "Skip" "Status"
printf "  %-12s %6s %6s %6s %7s %8s\n" "--------" "-----" "----" "----" "----" "------"

overall_exit=0
for distro in "${DISTROS[@]}"; do
    total="${RESULT_TOTAL[$distro]:-0}"
    passed="${RESULT_PASSED[$distro]:-0}"
    failed="${RESULT_FAILED[$distro]:-0}"
    skipped="${RESULT_SKIPPED[$distro]:-0}"
    exit_code="${RESULT_EXIT[$distro]:-1}"

    if [[ "$exit_code" -eq 99 ]]; then
        colour="$YELLOW"
        status="MISSING"
        overall_exit=1
    elif [[ "$failed" -eq 0 ]] && [[ "$total" -gt 0 ]]; then
        colour="$GREEN"
        status="PASS"
    else
        colour="$RED"
        status="FAIL"
        overall_exit=1
    fi

    printf "  ${colour}%-12s %6s %6s %6s %7s %8s${NC}\n" "$distro" "$total" "$passed" "$failed" "$skipped" "$status"
done

echo ""
echo -e "  Summary:  ${CYAN}$SUMMARY_FILE${NC}"
echo -e "  Logs:     ${CYAN}$RESULTS_DIR/<distro>.log${NC}"
echo ""

if [[ $overall_exit -eq 0 ]]; then
    echo -e "${GREEN}All distros passed.${NC}"
else
    echo -e "${RED}Some distros had failures: check logs.${NC}"
fi

# =============================================================================
# GUI Tests (optional)
# =============================================================================

if [[ "$DO_GUI" == "true" ]]; then
    echo ""
    echo -e "${MAGENTA}╔$(printf '═%.0s' $(seq 1 $BOX_W))╗${NC}"
    print_boxline ""
    print_boxline "   GUI TESTS (Web UI: Playwright)"
    print_boxline ""
    echo -e "${MAGENTA}╚$(printf '═%.0s' $(seq 1 $BOX_W))╝${NC}"
    echo ""

    gui_args=()
    [[ -n "$SINGLE_DISTRO" ]] && gui_args+=(--distro "$SINGLE_DISTRO")
    [[ "$PARALLEL" == "true" ]] && gui_args+=(--parallel --jobs "$MAX_JOBS")

    if "$SCRIPT_DIR/gui/run-gui-tests.sh" "${gui_args[@]}"; then
        echo -e "${GREEN}GUI tests passed.${NC}"
    else
        echo -e "${RED}GUI tests had failures: check test-results/gui/${NC}"
        overall_exit=1
    fi
fi

exit $overall_exit
