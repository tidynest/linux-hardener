#!/bin/bash
# =============================================================================
# TAURI DESKTOP GUI TEST ORCHESTRATOR — Linux System Hardener
# =============================================================================
# Runs Tauri desktop tests inside Arch nspawn container (WebKitGTK ABI match).
#
# Usage: sudo ./scripts/run-tauri-gui-tests.sh [OPTIONS]
#
# Options:
#   --help            Show usage
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$PROJECT_DIR/test-results/gui"
CONTAINER="hardener-test"
CONTAINER_PATH="/var/lib/machines/$CONTAINER"

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
        --help|-h)
            cat << 'EOF'
Tauri Desktop GUI Test Orchestrator for Linux System Hardener

Usage: sudo ./scripts/run-tauri-gui-tests.sh

Runs xdotool-based tests against the real Tauri binary inside an Arch
systemd-nspawn container with Xvfb virtual display.

Tests real IPC — actual scans, real database writes, real compliance reports.
Only Arch container is used (WebKitGTK ABI must match host).

Output:
  test-results/gui/arch-tauri.log        Test output
  test-results/gui/screenshots/tauri/    13 test screenshots

Requirements:
  - Arch container at /var/lib/machines/hardener-test
  - Tauri binary built: cargo build -p linux-hardener-desktop
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

if [[ ! -d "$CONTAINER_PATH" ]]; then
    echo -e "${RED}ERROR: Arch container not found at $CONTAINER_PATH${NC}"
    exit 1
fi

if [[ ! -x "$PROJECT_DIR/target/debug/linux-hardener-desktop" ]]; then
    echo -e "${RED}ERROR: Tauri binary not found. Build with: cargo build -p linux-hardener-desktop${NC}"
    exit 1
fi

mkdir -p "$RESULTS_DIR/screenshots/tauri"

# =============================================================================
# Run tests
# =============================================================================

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
print_boxline "   TAURI DESKTOP GUI TEST RUNNER (xdotool)"
print_boxline "   Container: $CONTAINER"
print_boxline ""
echo -e "${MAGENTA}╚$(printf '═%.0s' $(seq 1 $BOX_W))╝${NC}"
echo ""

LOGFILE="$RESULTS_DIR/arch-tauri.log"

echo -e "${CYAN}━━━ Tauri Desktop Testing: Arch ($CONTAINER) ━━━${NC}"
echo -e "  ${CYAN}[RUN]${NC}  systemd-nspawn --pipe -> tauri-gui-test-inner.sh"

systemd-nspawn -D "$CONTAINER_PATH" \
    --bind="$PROJECT_DIR:/project" \
    --pipe \
    /bin/bash /project/scripts/tauri-gui-test-inner.sh \
    > "$LOGFILE" 2>&1
EXIT_CODE=$?

# Print log summary (last 20 lines with results)
echo ""
tail -20 "$LOGFILE" | while IFS= read -r line; do
    echo "  $line"
done
echo ""

# =============================================================================
# Summary
# =============================================================================

{
    echo "Tauri Desktop GUI Test Results"
    echo "=============================="
    echo "Date: $(date)"
    echo "Container: $CONTAINER"
    echo "Exit code: $EXIT_CODE"
    echo ""
    echo "Full log: $LOGFILE"
    echo "Screenshots: $RESULTS_DIR/screenshots/tauri/"
} >> "$RESULTS_DIR/gui-summary.txt"

if [[ $EXIT_CODE -eq 0 ]]; then
    echo -e "${GREEN}All Tauri desktop tests passed.${NC}"
else
    echo -e "${RED}Tauri desktop tests failed (exit code: $EXIT_CODE). See: $LOGFILE${NC}"
fi

exit $EXIT_CODE
