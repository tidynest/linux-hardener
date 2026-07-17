#!/bin/bash
# =============================================================================
# DESKTOP GUI TEST RUNNER — Linux System Hardener
# =============================================================================
# Starts Tauri desktop app, runs UX + functional tests, cleans up.
# Runs as regular user (not root) on host Wayland session.
#
# Usage: ./scripts/run-desktop-tests.sh [OPTIONS]
#
# Options:
#   --kitty           Open tests in a new kitty window
#   --ux-only         Run only UX tests (keyboard navigation)
#   --fn-only         Run only functional tests (scans, reports)
#   --no-cleanup      Leave Tauri app running after tests
#   --help            Show usage
#
# Requirements:
#   - Hyprland (or hyprctl-compatible compositor)
#   - wtype, grim, python3
#   - Tauri binary built: debug/linux-hardener-desktop under the cargo target dir
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$PROJECT_DIR/test-results/desktop"
OUTDIR="/tmp/test-grouped"

# Cargo may redirect build output away from ./target (CARGO_TARGET_DIR or a
# [build] target-dir in ~/.cargo/config.toml); probe candidates for "$@".
resolve_target_dir() {
    local dir probe home
    if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
        echo "$CARGO_TARGET_DIR"
        return
    fi
    dir=""
    if command -v cargo &>/dev/null; then
        dir=$(cargo metadata --format-version 1 --no-deps \
            --manifest-path "$PROJECT_DIR/Cargo.toml" 2>/dev/null |
            sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
    fi
    [[ -n "$dir" ]] || dir="$PROJECT_DIR/target"
    for probe in "$@"; do
        [[ -e "$dir/$probe" ]] && { echo "$dir"; return; }
    done
    for home in "${SUDO_USER:+$(getent passwd "$SUDO_USER" | cut -d: -f6)}" "$HOME"; do
        for probe in "$@"; do
            if [[ -n "$home" && -e "$home/.cache/cargo-target/$probe" ]]; then
                echo "$home/.cache/cargo-target"
                return
            fi
        done
    done
    echo "$dir"
}

TARGET_DIR="$(resolve_target_dir "debug/linux-hardener-desktop")"

USE_KITTY=false
UX_ONLY=false
FN_ONLY=false
NO_CLEANUP=false

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
DIM='\033[2m'
NC='\033[0m'

while [[ $# -gt 0 ]]; do
    case $1 in
        --kitty)
            USE_KITTY=true
            shift
            ;;
        --ux-only)
            UX_ONLY=true
            shift
            ;;
        --fn-only)
            FN_ONLY=true
            shift
            ;;
        --no-cleanup)
            NO_CLEANUP=true
            shift
            ;;
        --help|-h)
            cat << 'EOF'
Desktop GUI Test Runner for Linux System Hardener

Usage: ./scripts/run-desktop-tests.sh [OPTIONS]

Options:
  --kitty         Open tests in a new kitty window
  --ux-only       Run only UX tests (keyboard navigation)
  --fn-only       Run only functional tests (scans, reports)
  --no-cleanup    Leave Tauri app running after tests
  --help          Show usage

Requirements:
  - Hyprland compositor (hyprctl)
  - wtype (keyboard input)
  - grim (screenshots)
  - python3

The Tauri app is started automatically if not already running.
EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

check_dependencies() {
    local missing=()
    command -v hyprctl &>/dev/null || missing+=("hyprctl")
    command -v wtype &>/dev/null || missing+=("wtype")
    command -v grim &>/dev/null || missing+=("grim")
    command -v python3 &>/dev/null || missing+=("python3")
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}ERROR: Missing dependencies: ${missing[*]}${NC}"
        echo "Install with: sudo pacman -S ${missing[*]}"
        exit 1
    fi
}

check_binary() {
    if [[ ! -x "$TARGET_DIR/debug/linux-hardener-desktop" ]]; then
        echo -e "${RED}ERROR: Tauri binary not found${NC}"
        echo "Build with: cargo build -p linux-hardener-desktop"
        exit 1
    fi
}

is_tauri_running() {
    hyprctl clients -j 2>/dev/null | python3 -c "
import json,sys
for c in json.load(sys.stdin):
    if 'hardener' in c.get('class','').lower():
        print('yes'); break
" 2>/dev/null | grep -q yes
}

start_tauri() {
    echo -e "${CYAN}[STARTUP] Launching Tauri app...${NC}"
    
    cd "$PROJECT_DIR"
    WEBKIT_DISABLE_COMPOSITING_MODE=1 \
    RUST_LOG=info \
    "$TARGET_DIR/debug/linux-hardener-desktop" &
    TAURI_PID=$!
    cd - > /dev/null
    
    echo -e "${DIM}  Waiting for window to appear...${NC}"
    local attempts=0
    while [[ $attempts -lt 30 ]]; do
        if is_tauri_running; then
            echo -e "${GREEN}[STARTUP] Tauri window detected (PID: $TAURI_PID)${NC}"
            return 0
        fi
        sleep 0.5
        ((attempts++))
    done
    
    echo -e "${RED}ERROR: Tauri window did not appear within 15 seconds${NC}"
    kill "$TAURI_PID" 2>/dev/null || true
    return 1
}

stop_tauri() {
    if [[ -n "${TAURI_PID:-}" ]] && kill -0 "$TAURI_PID" 2>/dev/null; then
        echo -e "${CYAN}[CLEANUP] Stopping Tauri app (PID: $TAURI_PID)...${NC}"
        kill "$TAURI_PID" 2>/dev/null || true
        sleep 0.5
        kill -9 "$TAURI_PID" 2>/dev/null || true
    fi
}

run_ux_tests() {
    echo -e "${CYAN}[UX] Running UX tests (keyboard navigation)...${NC}"
    "$PROJECT_DIR/gui-tests/tauri-ux-test.sh"
    return $?
}

run_fn_tests() {
    echo -e "${CYAN}[FN] Running functional tests (scans, reports)...${NC}"
    "$PROJECT_DIR/gui-tests/tauri-functional-test.sh"
    return $?
}

run_tests() {
    mkdir -p "$OUTDIR" "$RESULTS_DIR"
    rm -f "$OUTDIR"/*.png 2>/dev/null || true
    
    local ux_exit=0 fn_exit=0
    
    if [[ "$UX_ONLY" == "true" ]]; then
        run_ux_tests || ux_exit=$?
    elif [[ "$FN_ONLY" == "true" ]]; then
        run_fn_tests || fn_exit=$?
    else
        run_ux_tests || ux_exit=$?
        echo ""
        run_fn_tests || fn_exit=$?
    fi
    
    cp "$OUTDIR"/*.png "$RESULTS_DIR/" 2>/dev/null || true
    
    return $((ux_exit + fn_exit))
}

print_summary() {
    local exit_code=$?
    
    echo ""
    echo -e "${MAGENTA}════════════════════════════════════════════════════════${NC}"
    echo -e "${MAGENTA}  DESKTOP GUI TEST SUMMARY${NC}"
    echo -e "${MAGENTA}════════════════════════════════════════════════════════${NC}"
    echo ""
    
    if [[ $exit_code -eq 0 ]]; then
        echo -e "  ${GREEN}All desktop tests passed!${NC}"
    else
        echo -e "  ${RED}Some desktop tests failed (exit code: $exit_code)${NC}"
    fi
    
    echo ""
    echo -e "  Screenshots: ${CYAN}$RESULTS_DIR/${NC}"
    echo ""
}

cleanup() {
    if [[ "$NO_CLEANUP" != "true" ]]; then
        stop_tauri
    else
        echo -e "${YELLOW}[CLEANUP] Leaving Tauri app running (--no-cleanup)${NC}"
    fi
}

trap cleanup EXIT

if [[ "$USE_KITTY" == "true" ]]; then
    exec kitty --title "Desktop Tests" bash -c "
        cd '$PROJECT_DIR'
        ./scripts/run-desktop-tests.sh ${UX_ONLY:+--ux-only} ${FN_ONLY:+--fn-only} ${NO_CLEANUP:+--no-cleanup}
        echo ''
        echo 'Press Enter to close...'
        read
    "
fi

BOX_W=60
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
print_boxline "   DESKTOP GUI TEST RUNNER"
print_boxline "   UX: $([ "$UX_ONLY" == "true" ] && echo "only" || echo "yes")  |  FN: $([ "$FN_ONLY" == "true" ] && echo "only" || echo "yes")"
print_boxline ""
echo -e "${MAGENTA}╚$(printf '═%.0s' $(seq 1 $BOX_W))╝${NC}"
echo ""

check_dependencies
check_binary

TAURI_PID=""
WAS_STARTED=false

if is_tauri_running; then
    echo -e "${GREEN}[STARTUP] Tauri app already running${NC}"
else
    start_tauri || exit 1
    WAS_STARTED=true
fi

echo ""
run_tests
exit_code=$?

print_summary

exit $exit_code
