#!/bin/bash
# =============================================================================
# PARALLEL WEB UI GUI TEST ORCHESTRATOR — Linux System Hardener
# =============================================================================
# Runs Playwright GUI tests in PARALLEL across all systemd-nspawn containers.
# Uses background processes to test multiple distros simultaneously.
#
# Usage: sudo ./scripts/run-gui-tests-parallel.sh [OPTIONS]
#
# Options:
#   --distro NAME     Run only one distro (arch|debian|fedora|rhel|opensuse)
#   --jobs N          Max parallel jobs (default: auto-detect from CPU cores)
#   --help            Show usage
#
# Speed improvement: ~5x faster when testing all 5 distros
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$PROJECT_DIR/test-results/gui"

declare -A CONTAINERS=(
    [arch]="hardener-test"
    [debian]="hardener-test-debian"
    [fedora]="hardener-test-fedora"
    [rhel]="hardener-test-rhel"
    [opensuse]="hardener-test-opensuse"
)

DISTRO_ORDER=(arch debian fedora rhel opensuse)

SINGLE_DISTRO=""
MAX_JOBS=5

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

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
        --jobs)
            MAX_JOBS="$2"
            shift 2
            ;;
        --help|-h)
            cat << 'EOF'
Parallel Web UI GUI Test Orchestrator

Usage: sudo ./scripts/run-gui-tests-parallel.sh [OPTIONS]

Options:
  --distro NAME     Run only one distro (arch|debian|fedora|rhel|opensuse)
  --jobs N          Max parallel jobs (default: auto-detect CPU cores)
  --help            Show usage

Runs all distro tests in parallel for ~5x speedup.

Output:
  test-results/gui/<distro>-webui.log    Per-distro test output
  test-results/gui/screenshots/webui/    Theme screenshots
  test-results/gui/gui-summary.txt       Aggregated results
EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}ERROR: Must run as root (systemd-nspawn requires root)${NC}"
    exit 1
fi

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
declare -a PIDS
declare -a PID_DISTROS

BOX_W=74
print_boxline() {
    local content="$1"
    local visible_len=${#content}
    local pad=$((BOX_W - visible_len))
    local spaces=""
    for ((i=0; i<pad; i++)); do spaces+=" "; done
    echo -e "${MAGENTA}║${NC}${content}${spaces}${MAGENTA}║${NC}"
}

echo ""
echo -e "${MAGENTA}╔$(printf '═%.0s' $(seq 1 $BOX_W))╗${NC}"
print_boxline ""
print_boxline "   PARALLEL WEB UI GUI TEST RUNNER"
print_boxline "   Distros: ${#DISTROS[@]}  |  Max jobs: $MAX_JOBS"
print_boxline ""
echo -e "${MAGENTA}╚$(printf '═%.0s' $(seq 1 $BOX_W))╝${NC}"
echo ""

run_single_distro() {
    local distro="$1"
    local container="${CONTAINERS[$distro]}"
    local container_path="/var/lib/machines/$container"
    local logfile="$RESULTS_DIR/${distro}-webui.log"
    
    if [[ ! -d "$container_path" ]]; then
        echo "[$distro] ${YELLOW}SKIP${NC} — container not found"
        echo "CONTAINER NOT FOUND: $container_path" > "$logfile"
        return 99
    fi
    
    echo "[$distro] ${CYAN}Starting...${NC}"
    
    timeout 600 systemd-nspawn -D "$container_path" \
        --bind="$PROJECT_DIR:/project" \
        --pipe \
        /bin/bash /project/scripts/gui-test-inner.sh \
        > "$logfile" 2>&1
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        echo "[$distro] ${GREEN}PASS${NC}"
    else
        echo "[$distro] ${RED}FAIL${NC} (exit: $exit_code)"
    fi
    
    return $exit_code
}

echo -e "${CYAN}Launching parallel test jobs...${NC}"
echo ""

running=0
for distro in "${DISTROS[@]}"; do
    while [[ $running -ge $MAX_JOBS ]]; do
        wait -n 2>/dev/null || true
        ((running--)) || true
    done
    
    run_single_distro "$distro" &
    PIDS+=($!)
    PID_DISTROS+=("$distro")
    ((running++))
    echo -e "${DIM}  Started job for $distro (PID: ${PIDS[-1]})${NC}"
    # Stagger starts to reduce peak load
    sleep 10
done

echo ""
echo -e "${CYAN}Waiting for all jobs to complete...${NC}"
echo ""

for i in "${!PIDS[@]}"; do
    pid="${PIDS[$i]}"
    distro="${PID_DISTROS[$i]}"
    wait "$pid" 2>/dev/null
    RESULT_EXIT[$distro]=$?
done

SUMMARY_FILE="$RESULTS_DIR/gui-summary.txt"

{
    echo "Parallel Web UI GUI Test Results"
    echo "================================="
    echo "Date: $(date)"
    echo "Max parallel jobs: $MAX_JOBS"
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

echo -e "${MAGENTA}╔$(printf '═%.0s' $(seq 1 $BOX_W))╗${NC}"
print_boxline "   PARALLEL WEB UI TEST SUMMARY"
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
    echo -e "${RED}Some distros had failures — check logs.${NC}"
fi

exit $overall_exit
