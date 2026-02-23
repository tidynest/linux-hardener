#!/bin/bash
# =============================================================================
# WEB UI GUI TEST ORCHESTRATOR — Linux System Hardener
# =============================================================================
# Runs Playwright GUI tests inside systemd-nspawn containers.
#
# Usage: sudo ./scripts/run-gui-tests.sh [OPTIONS]
#
# Options:
#   --distro NAME     Run only one distro (arch|debian|fedora|rhel|opensuse)
#   --help            Show usage
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$PROJECT_DIR/test-results/gui"

# Distro name -> container name mapping
declare -A CONTAINERS=(
    [arch]="hardener-test"
    [debian]="hardener-test-debian"
    [fedora]="hardener-test-fedora"
    [rhel]="hardener-test-rhel"
    [opensuse]="hardener-test-opensuse"
)

DISTRO_ORDER=(arch debian fedora)

# Options
SINGLE_DISTRO=""

# Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

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
        --help|-h)
            cat << 'EOF'
Web UI GUI Test Orchestrator for Linux System Hardener

Usage: sudo ./scripts/run-gui-tests.sh [OPTIONS]

Options:
  --distro NAME     Run only one distro (arch|debian|fedora|rhel|opensuse)
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

# =============================================================================
# Run tests per distro
# =============================================================================

if [[ -n "$SINGLE_DISTRO" ]]; then
    DISTROS=("$SINGLE_DISTRO")
else
    DISTROS=("${DISTRO_ORDER[@]}")
fi

declare -A RESULT_EXIT

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
print_boxline "   WEB UI GUI TEST RUNNER (Playwright)"
print_boxline "   Distros: ${#DISTROS[@]}"
print_boxline ""
echo -e "${MAGENTA}╚$(printf '═%.0s' $(seq 1 $BOX_W))╝${NC}"
echo ""

for distro in "${DISTROS[@]}"; do
    container="${CONTAINERS[$distro]}"
    container_path="/var/lib/machines/$container"
    logfile="$RESULTS_DIR/${distro}-webui.log"

    echo -e "${CYAN}━━━ Web UI Testing: $distro ($container) ━━━${NC}"

    if [[ ! -d "$container_path" ]]; then
        echo -e "  ${YELLOW}[SKIP]${NC} Container not found: $container_path"
        RESULT_EXIT[$distro]=99
        echo "CONTAINER NOT FOUND: $container_path" > "$logfile"
        continue
    fi

    echo -e "  ${CYAN}[RUN]${NC}  systemd-nspawn --pipe -> gui-test-inner.sh"
    echo -e "  ${CYAN}[LOG]${NC}  $logfile"

    timeout 600 systemd-nspawn -D "$container_path" \
        --bind="$PROJECT_DIR:/project" \
        --pipe \
        /bin/bash /project/scripts/gui-test-inner.sh \
        2>&1 | tee "$logfile"
    RESULT_EXIT[$distro]=${PIPESTATUS[0]}

    if [[ "${RESULT_EXIT[$distro]}" -eq 0 ]]; then
        echo -e "  ${GREEN}[PASS]${NC} All Playwright tests passed"
    else
        echo -e "  ${RED}[FAIL]${NC} Tests failed (exit code: ${RESULT_EXIT[$distro]})"
    fi
    echo ""
done

# =============================================================================
# Generate summary
# =============================================================================

SUMMARY_FILE="$RESULTS_DIR/gui-summary.txt"

{
    echo "Web UI GUI Test Results"
    echo "======================"
    echo "Date: $(date)"
    echo ""
    printf "%-12s %8s\n" "Distro" "Status"
    printf "%-12s %8s\n" "--------" "------"

    for distro in "${DISTROS[@]}"; do
        exit_code="${RESULT_EXIT[$distro]}"
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
print_boxline "   WEB UI TEST SUMMARY"
echo -e "${MAGENTA}╚$(printf '═%.0s' $(seq 1 $BOX_W))╝${NC}"
echo ""
printf "  ${BOLD}%-12s %8s${NC}\n" "Distro" "Status"
printf "  %-12s %8s\n" "--------" "------"

overall_exit=0
for distro in "${DISTROS[@]}"; do
    exit_code="${RESULT_EXIT[$distro]}"
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
