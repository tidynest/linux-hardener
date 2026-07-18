#!/bin/bash
# =============================================================================
# WEB UI GUI TEST ORCHESTRATOR: Linux System Hardener
# =============================================================================
# Runs Playwright GUI tests inside systemd-nspawn containers.
# Serial by default; --parallel tests multiple distros simultaneously with
# background processes (~5x faster when testing all 5 distros).
#
# Usage: sudo ./scripts/test/gui/run-gui-tests.sh [OPTIONS]
#
# Options:
#   --distro NAME     Run only one distro (arch|debian|fedora|rhel|opensuse)
#   --parallel        Run distros in parallel instead of serially
#   --jobs N          Max parallel jobs (with --parallel; default: 5)
#   --help            Show usage
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
RESULTS_DIR="$PROJECT_DIR/test-results/gui"

# shellcheck source=../../lib/common.sh
source "$SCRIPT_DIR/../../lib/common.sh"
# shellcheck source=../../lib/parallel.sh
source "$SCRIPT_DIR/../../lib/parallel.sh"

# Options
SINGLE_DISTRO=""
PARALLEL=false
MAX_JOBS=5

# =============================================================================
# Argument parsing
# =============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        --distro)
            SINGLE_DISTRO="$2"
            if [[ -z "${CONTAINERS[$SINGLE_DISTRO]+_}" ]]; then
                echo "Unknown distro: $SINGLE_DISTRO"
                echo "Valid: ${!CONTAINERS[*]}"
                exit 1
            fi
            shift 2
            ;;
        --parallel)
            PARALLEL=true
            shift
            ;;
        --jobs)
            MAX_JOBS="$2"
            shift 2
            ;;
        --help|-h)
            cat << 'EOF'
Web UI GUI Test Orchestrator for Linux System Hardener

Usage: sudo ./scripts/test/gui/run-gui-tests.sh [OPTIONS]

Options:
  --distro NAME     Run only one distro (arch|debian|fedora|rhel|opensuse)
  --parallel        Run distros in parallel instead of serially (~5x speedup)
  --jobs N          Max parallel jobs (with --parallel; default: 5)
  --help            Show usage

Runs Playwright tests against the WASM frontend served with a Tauri IPC mock
inside systemd-nspawn containers with Xvfb virtual display.

Output:
  test-results/gui/<distro>-webui.log    Per-distro test output
  test-results/gui/screenshots/webui/    Theme screenshots
  test-results/gui/gui-summary.txt       Aggregated results

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

# Verify dist directory exists
if [[ ! -f "$PROJECT_DIR/crates/hardener-ui/dist/index.html" ]]; then
    echo -e "${RED}ERROR: dist/ not found. Build WASM first: cd crates/hardener-ui && trunk build --release${NC}"
    exit 1
fi

mkdir -p "$RESULTS_DIR/screenshots/webui"

if [[ -n "$SINGLE_DISTRO" ]]; then
    DISTROS=("$SINGLE_DISTRO")
else
    DISTROS=("${DISTRO_ORDER[@]}")
fi

declare -A RESULT_EXIT

BOX_W=74

# The nspawn invocation shared by both execution modes.
nspawn_gui_tests() {
    local container_path="$1"
    timeout 600 systemd-nspawn -D "$container_path" \
        --bind="$PROJECT_DIR:/project" \
        --pipe \
        /bin/bash /project/scripts/test/gui/gui-test-inner.sh
}

echo ""
echo -e "${MAGENTA}╔$(printf '═%.0s' $(seq 1 $BOX_W))╗${NC}"
print_boxline ""
if [[ "$PARALLEL" == "true" ]]; then
    print_boxline "   PARALLEL WEB UI GUI TEST RUNNER"
    print_boxline "   Distros: ${#DISTROS[@]}  |  Max jobs: $MAX_JOBS"
else
    print_boxline "   WEB UI GUI TEST RUNNER (Playwright)"
    print_boxline "   Distros: ${#DISTROS[@]}"
fi
print_boxline ""
echo -e "${MAGENTA}╚$(printf '═%.0s' $(seq 1 $BOX_W))╝${NC}"
echo ""

# =============================================================================
# Run tests per distro (serial or parallel)
# =============================================================================

# Defined once, used by both serial (foreground, tees to the terminal) and
# parallel (backgrounded, redirects only -- concurrent tees would interleave
# raw output) execution.
run_single_distro() {
    local distro="$1"
    local container="${CONTAINERS[$distro]}"
    local container_path="/var/lib/machines/$container"
    local logfile="$RESULTS_DIR/${distro}-webui.log"

    [[ "$PARALLEL" != "true" ]] && echo -e "${CYAN}━━━ Web UI Testing: $distro ($container) ━━━${NC}"

    if [[ ! -d "$container_path" ]]; then
        if [[ "$PARALLEL" == "true" ]]; then
            echo -e "[$distro] ${YELLOW}SKIP${NC}: container not found"
        else
            echo -e "  ${YELLOW}[SKIP]${NC} Container not found: $container_path"
        fi
        echo "CONTAINER NOT FOUND: $container_path" > "$logfile"
        return 99
    fi

    local exit_code
    if [[ "$PARALLEL" == "true" ]]; then
        echo -e "[$distro] ${CYAN}Starting...${NC}"
        nspawn_gui_tests "$container_path" > "$logfile" 2>&1
        exit_code=$?
        if [[ $exit_code -eq 0 ]]; then
            echo -e "[$distro] ${GREEN}PASS${NC}"
        else
            echo -e "[$distro] ${RED}FAIL${NC} (exit: $exit_code)"
        fi
    else
        echo -e "  ${CYAN}[RUN]${NC}  systemd-nspawn --pipe -> gui-test-inner.sh"
        echo -e "  ${CYAN}[LOG]${NC}  $logfile"
        nspawn_gui_tests "$container_path" 2>&1 | tee "$logfile"
        exit_code=${PIPESTATUS[0]}
        if [[ $exit_code -eq 0 ]]; then
            echo -e "  ${GREEN}[PASS]${NC} All Playwright tests passed"
        else
            echo -e "  ${RED}[FAIL]${NC} Tests failed (exit code: $exit_code)"
        fi
        echo ""
    fi

    return "$exit_code"
}

if [[ "$PARALLEL" == "true" ]]; then
    echo -e "${CYAN}Launching parallel test jobs...${NC}"
    echo ""

    launch_job_pool "$MAX_JOBS" DISTROS 10

    for i in "${!PIDS[@]}"; do
        pid="${PIDS[$i]}"
        distro="${PID_DISTROS[$i]}"
        wait "$pid" 2>/dev/null
        RESULT_EXIT[$distro]=$?
    done
else
    for distro in "${DISTROS[@]}"; do
        run_single_distro "$distro"
        RESULT_EXIT[$distro]=$?
    done
fi

# =============================================================================
# Generate summary
# =============================================================================

SUMMARY_FILE="$RESULTS_DIR/gui-summary.txt"

{
    if [[ "$PARALLEL" == "true" ]]; then
        echo "Parallel Web UI GUI Test Results"
        echo "================================="
        echo "Date: $(date)"
        echo "Max parallel jobs: $MAX_JOBS"
    else
        echo "Web UI GUI Test Results"
        echo "======================"
        echo "Date: $(date)"
    fi
    echo ""
    printf "%-12s %8s\n" "Distro" "Status"
    printf "%-12s %8s\n" "--------" "------"

    for distro in "${DISTROS[@]}"; do
        exit_code="${RESULT_EXIT[$distro]:-1}"
        if [[ "$exit_code" -eq 0 ]]; then
            status="PASS"
        elif [[ "$exit_code" -eq 99 ]]; then
            status="MISSING"
        else
            status="FAIL"
        fi
        printf "%-12s %8s\n" "$distro" "$status"
    done

    echo ""
    echo "Logs: $RESULTS_DIR/<distro>-webui.log"
    echo "Screenshots: $RESULTS_DIR/screenshots/webui/"
} > "$SUMMARY_FILE"

# Print summary
echo -e "${MAGENTA}╔$(printf '═%.0s' $(seq 1 $BOX_W))╗${NC}"
if [[ "$PARALLEL" == "true" ]]; then
    print_boxline "   PARALLEL WEB UI TEST SUMMARY"
else
    print_boxline "   WEB UI TEST SUMMARY"
fi
echo -e "${MAGENTA}╚$(printf '═%.0s' $(seq 1 $BOX_W))╝${NC}"
echo ""
printf "  ${BOLD}%-12s %8s${NC}\n" "Distro" "Status"
printf "  %-12s %8s\n" "--------" "------"

overall_exit=0
for distro in "${DISTROS[@]}"; do
    exit_code="${RESULT_EXIT[$distro]:-1}"
    if [[ "$exit_code" -eq 0 ]]; then
        colour="$GREEN"; status="PASS"
    elif [[ "$exit_code" -eq 99 ]]; then
        colour="$YELLOW"; status="MISSING"; overall_exit=1
    else
        colour="$RED"; status="FAIL"; overall_exit=1
    fi
    printf "  ${colour}%-12s %8s${NC}\n" "$distro" "$status"
done

echo ""
echo -e "  Summary:      ${CYAN}$SUMMARY_FILE${NC}"
echo -e "  Screenshots:  ${CYAN}$RESULTS_DIR/screenshots/webui/${NC}"
echo ""

if [[ $overall_exit -eq 0 ]]; then
    echo -e "${GREEN}All Web UI tests passed.${NC}"
else
    echo -e "${RED}Some distros had failures: check logs.${NC}"
fi

exit $overall_exit
