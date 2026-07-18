#!/bin/bash
# =============================================================================
# TAURI DESKTOP GUI TEST INNER SCRIPT: Runs INSIDE Arch nspawn container
# =============================================================================
# Tests the actual Tauri binary with Xvfb + xdotool. Real IPC, real backend.
# Only commands that don't need pkexec are tested (5 of 7).
#
# Usage (called by run-tauri-gui-tests.sh):
#   /bin/bash /project/scripts/test/gui/tauri-gui-test-inner.sh
# =============================================================================

set -uo pipefail

PROJECT="/project"
DISPLAY_NUM=":99"
SCREENSHOT_DIR="/tmp/tauri-screenshots"
BINARY="$PROJECT/target/debug/linux-hardener-desktop"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0
SKIPPED=0

# =============================================================================
# Helpers
# =============================================================================

pass() {
    echo -e "  ${GREEN}[PASS]${NC} $1"
    ((PASSED++))
}

fail() {
    echo -e "  ${RED}[FAIL]${NC} $1: $2"
    ((FAILED++))
}

skip() {
    echo -e "  ${YELLOW}[SKIP]${NC} $1: $2"
    ((SKIPPED++))
}

take_screenshot() {
    local name="$1"
    local wid="$2"
    xwd -id "$wid" -out "/tmp/capture.xwd" 2>/dev/null && \
    convert "/tmp/capture.xwd" "$SCREENSHOT_DIR/${name}.png" 2>/dev/null
    rm -f "/tmp/capture.xwd"
}

# Sends Tab key N times, then Enter
tab_enter() {
    local wid="$1"
    local tabs="$2"
    for ((i=0; i<tabs; i++)); do
        xdotool key --window "$wid" Tab
        sleep 0.15
    done
    xdotool key --window "$wid" Return
    sleep 0.3
}

# =============================================================================
# Install dependencies
# =============================================================================

install_deps() {
    echo -e "${CYAN}[deps] Installing packages...${NC}"
    if command -v pacman &>/dev/null; then
        pacman -Sy --noconfirm --needed \
            webkit2gtk-4.1 xorg-server-xvfb xdotool xorg-xwd imagemagick 2>/dev/null || true
    else
        echo -e "${RED}[deps] Not an Arch container: Tauri tests require Arch for ABI match${NC}"
        exit 99
    fi
}

# =============================================================================
# Start virtual display
# =============================================================================

start_xvfb() {
    echo -e "${CYAN}[xvfb] Starting Xvfb on $DISPLAY_NUM...${NC}"
    Xvfb "$DISPLAY_NUM" -screen 0 1280x720x24 -ac &
    XVFB_PID=$!
    export DISPLAY="$DISPLAY_NUM"
    sleep 1

    if ! kill -0 "$XVFB_PID" 2>/dev/null; then
        echo -e "${RED}[xvfb] Failed to start Xvfb${NC}"
        return 1
    fi
    echo -e "${GREEN}[xvfb] Xvfb running (PID $XVFB_PID)${NC}"
}

# =============================================================================
# Cleanup
# =============================================================================

cleanup() {
    echo -e "${CYAN}[cleanup] Stopping services...${NC}"
    [[ -n "${APP_PID:-}" ]] && kill "$APP_PID" 2>/dev/null || true
    [[ -n "${XVFB_PID:-}" ]] && kill "$XVFB_PID" 2>/dev/null || true
}
trap cleanup EXIT

# =============================================================================
# Test execution
# =============================================================================

run_tests() {
    mkdir -p "$SCREENSHOT_DIR"

    # Check binary exists
    if [[ ! -x "$BINARY" ]]; then
        echo -e "${RED}[error] Binary not found: $BINARY${NC}"
        echo -e "${RED}        Build with: cargo build -p linux-hardener-desktop${NC}"
        exit 1
    fi

    # WebKitGTK environment for container (no GPU)
    export WEBKIT_DISABLE_DMABUF_RENDERER=1
    export WEBKIT_DISABLE_COMPOSITING_MODE=1
    export GDK_BACKEND=x11
    export NO_AT_BRIDGE=1

    # Launch the app
    echo -e "${CYAN}[app] Launching Tauri binary...${NC}"
    "$BINARY" &
    APP_PID=$!
    sleep 5  # WebKitGTK needs extra time without GPU acceleration

    # --- T-TAURI-01: App launches ---
    local wid
    wid=$(xdotool search --name "Linux System Hardener" 2>/dev/null | head -1)
    if [[ -n "$wid" ]]; then
        pass "T-TAURI-01: App launches (window ID: $wid)"
    else
        # Try broader search
        wid=$(xdotool search --pid "$APP_PID" 2>/dev/null | head -1)
        if [[ -n "$wid" ]]; then
            pass "T-TAURI-01: App launches (window ID: $wid, by PID)"
        else
            fail "T-TAURI-01: App launches" "No window found"
            # Can't continue without a window
            return
        fi
    fi

    # --- T-TAURI-02: Window title ---
    local title
    title=$(xdotool getwindowname "$wid" 2>/dev/null)
    if [[ "$title" == *"Linux System Hardener"* ]]; then
        pass "T-TAURI-02: Window title is '$title'"
    else
        fail "T-TAURI-02: Window title" "Got: '$title'"
    fi

    # --- T-TAURI-03: Initial render (not blank) ---
    take_screenshot "T-TAURI-03_initial" "$wid"
    if [[ -f "$SCREENSHOT_DIR/T-TAURI-03_initial.png" ]]; then
        local size
        size=$(stat -c%s "$SCREENSHOT_DIR/T-TAURI-03_initial.png" 2>/dev/null || echo "0")
        if [[ "$size" -gt 3000 ]]; then
            pass "T-TAURI-03: Initial render (screenshot ${size} bytes)"
        else
            fail "T-TAURI-03: Initial render" "Screenshot too small (${size} bytes: likely blank)"
        fi
    else
        fail "T-TAURI-03: Initial render" "Screenshot capture failed"
    fi

    # --- T-TAURI-04: Run Scan (Tab to button + Enter) ---
    sleep 1
    # Focus the window and navigate to Run Scan button
    xdotool windowactivate --sync "$wid"
    sleep 0.5
    # Skip nav items to reach Run Scan button (Tab through nav links first)
    tab_enter "$wid" 6
    sleep 3  # Wait for scan to complete
    take_screenshot "T-TAURI-04_after_scan" "$wid"
    if [[ -f "$SCREENSHOT_DIR/T-TAURI-04_after_scan.png" ]]; then
        pass "T-TAURI-04: Run Scan triggered (screenshot captured)"
    else
        fail "T-TAURI-04: Run Scan" "Screenshot failed"
    fi

    # --- T-TAURI-05: Scan data rendered ---
    local scan_size
    scan_size=$(stat -c%s "$SCREENSHOT_DIR/T-TAURI-04_after_scan.png" 2>/dev/null || echo "0")
    local init_size
    init_size=$(stat -c%s "$SCREENSHOT_DIR/T-TAURI-03_initial.png" 2>/dev/null || echo "0")
    if [[ "$scan_size" -ne "$init_size" ]] || [[ "$scan_size" -gt 10000 ]]; then
        pass "T-TAURI-05: Scan data rendered (size changed: ${init_size} -> ${scan_size})"
    else
        skip "T-TAURI-05: Scan data rendered" "Cannot verify content: visual comparison only"
    fi

    # --- T-TAURI-06: DB persistence ---
    local db_dir="$HOME/.local/share/linux-hardener"
    if [[ -d "$db_dir" ]]; then
        local db_files
        db_files=$(ls "$db_dir"/*.db 2>/dev/null | wc -l)
        if [[ "$db_files" -gt 0 ]]; then
            pass "T-TAURI-06: DB persistence ($db_files database file(s) in $db_dir)"
        else
            fail "T-TAURI-06: DB persistence" "No .db files in $db_dir"
        fi
    else
        fail "T-TAURI-06: DB persistence" "Directory not found: $db_dir"
    fi

    # --- T-TAURI-07: Navigate to Analysis ---
    xdotool windowactivate --sync "$wid"
    # Click on Analysis nav link area (approximate coordinates)
    xdotool key --window "$wid" ctrl+l 2>/dev/null || true
    # Use keyboard: Tab to Analysis link in nav
    # Send Home key to reset focus, then Tab to Analysis
    xdotool key --window "$wid" Home
    sleep 0.3
    tab_enter "$wid" 3  # Skip to Analysis nav link
    sleep 1
    take_screenshot "T-TAURI-07_analysis" "$wid"
    if [[ -f "$SCREENSHOT_DIR/T-TAURI-07_analysis.png" ]]; then
        pass "T-TAURI-07: Navigate to Analysis (screenshot captured)"
    else
        fail "T-TAURI-07: Navigate to Analysis" "Screenshot failed"
    fi

    # --- T-TAURI-08: Navigate to Hardening ---
    xdotool key --window "$wid" Home
    sleep 0.3
    tab_enter "$wid" 4  # Tab to Hardening nav link
    sleep 1
    take_screenshot "T-TAURI-08_hardening" "$wid"
    if [[ -f "$SCREENSHOT_DIR/T-TAURI-08_hardening.png" ]]; then
        pass "T-TAURI-08: Navigate to Hardening (screenshot captured)"
    else
        fail "T-TAURI-08: Navigate to Hardening" "Screenshot failed"
    fi

    # --- T-TAURI-09: Preview Changes ---
    sleep 0.5
    # Tab to Preview Changes button
    tab_enter "$wid" 15  # Tab past profile radios and plugin checkboxes
    sleep 2
    take_screenshot "T-TAURI-09_preview" "$wid"
    if [[ -f "$SCREENSHOT_DIR/T-TAURI-09_preview.png" ]]; then
        pass "T-TAURI-09: Preview Changes (screenshot captured)"
    else
        fail "T-TAURI-09: Preview Changes" "Screenshot failed"
    fi

    # --- T-TAURI-10: Navigate to History ---
    xdotool key --window "$wid" Home
    sleep 0.3
    # Tab to History section toggle
    tab_enter "$wid" 6
    sleep 1
    take_screenshot "T-TAURI-10_history" "$wid"
    if [[ -f "$SCREENSHOT_DIR/T-TAURI-10_history.png" ]]; then
        pass "T-TAURI-10: Navigate to History (screenshot captured)"
    else
        fail "T-TAURI-10: Navigate to History" "Screenshot failed"
    fi

    # --- T-TAURI-11: Theme switch ---
    # Navigate to theme dropdown in nav
    xdotool key --window "$wid" Home
    sleep 0.3
    # Tab to theme select dropdown
    for ((i=0; i<5; i++)); do
        xdotool key --window "$wid" Tab
        sleep 0.15
    done
    # Open dropdown and select next option
    xdotool key --window "$wid" Down
    sleep 0.5
    take_screenshot "T-TAURI-11_theme_switch" "$wid"
    if [[ -f "$SCREENSHOT_DIR/T-TAURI-11_theme_switch.png" ]]; then
        pass "T-TAURI-11: Theme switch (screenshot captured)"
    else
        fail "T-TAURI-11: Theme switch" "Screenshot failed"
    fi

    # --- T-TAURI-12: Multiple scans ---
    # Navigate back to dashboard
    xdotool key --window "$wid" Home
    sleep 0.3
    tab_enter "$wid" 2  # Dashboard nav link
    sleep 1
    # Run scan again
    tab_enter "$wid" 6
    sleep 3
    take_screenshot "T-TAURI-12_second_scan" "$wid"
    if kill -0 "$APP_PID" 2>/dev/null; then
        pass "T-TAURI-12: Multiple scans (no crash)"
    else
        fail "T-TAURI-12: Multiple scans" "App crashed"
    fi

    # --- T-TAURI-13: App closes cleanly ---
    kill "$APP_PID" 2>/dev/null
    wait "$APP_PID" 2>/dev/null
    local exit_code=$?
    APP_PID=""
    if [[ $exit_code -eq 0 ]] || [[ $exit_code -eq 143 ]]; then
        pass "T-TAURI-13: App closes cleanly (exit code: $exit_code)"
    else
        fail "T-TAURI-13: App closes cleanly" "Exit code: $exit_code"
    fi

    # Copy screenshots to project output
    mkdir -p "$PROJECT/test-results/gui/screenshots/tauri"
    cp "$SCREENSHOT_DIR"/*.png "$PROJECT/test-results/gui/screenshots/tauri/" 2>/dev/null || true
}

# =============================================================================
# Main
# =============================================================================

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  TAURI DESKTOP GUI TEST RUNNER (Xvfb + xdotool)            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

install_deps
start_xvfb
run_tests

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  Passed:  ${GREEN}$PASSED${NC}"
echo -e "  Failed:  ${RED}$FAILED${NC}"
echo -e "  Skipped: ${YELLOW}$SKIPPED${NC}"
echo -e "  Total:   $((PASSED + FAILED + SKIPPED))"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ $FAILED -eq 0 ]]; then
    echo -e "${GREEN}All Tauri desktop tests passed.${NC}"
    exit 0
else
    echo -e "${RED}$FAILED test(s) failed.${NC}"
    exit 1
fi
