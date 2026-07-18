#!/bin/bash
# =============================================================================
# CROSS-DISTRO TEST RUNNER - Linux System Hardener
# =============================================================================
# Runs full-test-suite.sh across all supported distributions using
# systemd-nspawn --pipe (non-interactive, no boot/login needed).
# Serial by default; --parallel tests multiple distros simultaneously with
# background processes (~5x faster when testing all 5 distros).
#
# Usage: sudo ./scripts/test/run-cross-distro-tests.sh [OPTIONS]
#
# Options:
#   --apply           Enable destructive tests (apply + rollback)
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
  --distro NAME     Run only one distro (arch|debian|fedora|rhel|opensuse)
  --gui             Run GUI tests (Playwright Web UI) after CLI tests
  --parallel        Run distros in parallel instead of serially (~5x speedup)
  --jobs N          Max parallel jobs (with --parallel; default: 3)
  --rebuild         Build musl binary before testing
  --help            Show usage

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

APPLY_FLAG=""
[[ "$DO_APPLY" == "true" ]] && APPLY_FLAG="--apply"

# The nspawn invocation shared by both execution modes.
nspawn_full_suite() {
    local container_path="$1"
    systemd-nspawn -D "$container_path" \
        --bind="$PROJECT_DIR:/project" \
        "${TARGET_BIND[@]}" \
        --pipe \
        /bin/bash /project/scripts/test/full-test-suite.sh $APPLY_FLAG
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
    print_boxline "   Distros: ${#DISTROS[@]}  |  Apply: $DO_APPLY  |  Max jobs: $MAX_JOBS"
else
    print_boxline "   CROSS-DISTRO TEST RUNNER"
    print_boxline "   Distros: ${#DISTROS[@]}  |  Apply: $DO_APPLY  |  GUI: $DO_GUI"
fi
print_boxline ""
echo -e "${MAGENTA}╚$(printf '═%.0s' $(seq 1 $BOX_W))╝${NC}"
echo ""

# Defined once, used by both serial (foreground) and parallel (backgrounded)
# execution. Runs full-test-suite.sh for one distro and prints an immediate
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
        echo -e "  ${CYAN}[RUN]${NC}  systemd-nspawn --pipe -> full-test-suite.sh $APPLY_FLAG"
    fi

    nspawn_full_suite "$container_path" > "$logfile" 2>&1
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
        echo "Apply mode: $DO_APPLY"
        echo "Max parallel jobs: $MAX_JOBS"
    else
        echo "Cross-Distro Test Results"
        echo "========================"
        echo "Date: $(date)"
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
