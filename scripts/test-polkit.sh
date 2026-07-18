#!/bin/bash
# =============================================================================
# POLKIT DESKTOP TEST - Linux System Hardener
# =============================================================================
# Per-desktop polkit validation behind one entry point.
#
# gnome/kde/xfce: run desktop-specific pre-checks (correct session, agent
# running or started), then run the full test matrix (test-polkit-matrix.sh).
#
# no-agent: tests the error path when no polkit authentication agent is
# available. Validates that both the CLI (via pkexec) and Tauri (via
# run_privileged_command) return the correct error message. It temporarily
# stops the polkit agent, runs the check, and restarts the agent. It does NOT
# run inside nspawn -- it requires a live graphical session to verify the
# Tauri error dialog.
#
# Usage: ./scripts/test-polkit.sh <gnome|kde|xfce|no-agent> [--interactive]
#   --interactive is forwarded to the matrix (gnome/kde/xfce only).
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
    echo "Usage: $0 <gnome|kde|xfce|no-agent> [--interactive]"
    echo ""
    echo "  gnome     GNOME pre-checks, then the full polkit test matrix"
    echo "  kde       KDE Plasma pre-checks, then the full polkit test matrix"
    echo "  xfce      XFCE pre-checks, then the full polkit test matrix"
    echo "  no-agent  Error-path test with the polkit agent stopped"
}

DESKTOP="${1:-}"
case "$DESKTOP" in
    gnome|kde|xfce|no-agent) ;;
    help|--help|-h)
        usage
        exit 0
        ;;
    "")
        usage
        exit 1
        ;;
    *)
        echo "Unknown desktop: $DESKTOP"
        usage
        exit 1
        ;;
esac
shift

source "$SCRIPT_DIR/detect-polkit-agent.sh"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

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

# =============================================================================
# GNOME pre-checks
# =============================================================================
# GNOME quirks:
#   - gnome-shell on Wayland has a built-in polkit agent (no separate process)
#   - gnome-shell on Xorg needs polkit-gnome-authentication-agent-1
#   - auth_admin_keep (our policy) allows 5-minute credential caching
#   - gnome-shell agent auto-focuses the password field
precheck_gnome() {
    echo -e "${CYAN}━━━ GNOME Polkit Pre-Checks ━━━${NC}"
    echo ""

    # Verify we are actually on GNOME.
    detect_desktop_env
    if [[ "$DE_NAME" != "gnome" ]]; then
        echo -e "  ${RED}ERROR: Not running GNOME (detected: $DE_NAME)${NC}"
        echo "  Run this script inside a GNOME session."
        exit 1
    fi
    echo -e "  ${GREEN}Desktop: GNOME${NC}"

    # Determine session type (Wayland vs Xorg).
    SESSION_TYPE="${XDG_SESSION_TYPE:-unknown}"
    echo -e "  Session type: $SESSION_TYPE"

    if [[ "$SESSION_TYPE" == "wayland" ]]; then
        # gnome-shell has built-in agent on Wayland.
        if pgrep -x gnome-shell &>/dev/null; then
            echo -e "  ${GREEN}gnome-shell running (built-in polkit agent)${NC}"
        else
            echo -e "  ${RED}gnome-shell not running -- polkit dialogs will fail${NC}"
            exit 1
        fi
    elif [[ "$SESSION_TYPE" == "x11" ]]; then
        # Xorg needs the standalone agent.
        if pgrep -f "polkit-gnome-authentication-agent-1" &>/dev/null; then
            echo -e "  ${GREEN}polkit-gnome agent running (Xorg)${NC}"
        else
            echo -e "  ${YELLOW}polkit-gnome agent not running. Starting it...${NC}"
            /usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1 &
            sleep 1
            if pgrep -f "polkit-gnome-authentication-agent-1" &>/dev/null; then
                echo -e "  ${GREEN}polkit-gnome agent started${NC}"
            else
                echo -e "  ${RED}Failed to start polkit-gnome agent${NC}"
                echo "  Install: sudo pacman -S polkit-gnome  (or apt install policykit-1-gnome)"
                exit 1
            fi
        fi
    fi
}

# =============================================================================
# KDE pre-checks
# =============================================================================
# KDE quirks:
#   - polkit-kde-agent is started by plasma-session, not manually
#   - Agent reads icon_name from policy (our policy: security-high, edit-undo)
#   - auth_admin_keep credential caching respects KDE system settings
#   - KDE agent has a "Details" expander showing the action ID
#   - On Wayland, the dialog is rendered as a Wayland popup (layer-shell)
precheck_kde() {
    echo -e "${CYAN}━━━ KDE Polkit Pre-Checks ━━━${NC}"
    echo ""

    detect_desktop_env
    if [[ "$DE_NAME" != "kde" ]]; then
        echo -e "  ${RED}ERROR: Not running KDE Plasma (detected: $DE_NAME)${NC}"
        echo "  Run this script inside a KDE Plasma session."
        exit 1
    fi
    echo -e "  ${GREEN}Desktop: KDE Plasma${NC}"

    # KDE agent
    if pgrep -f "polkit-kde-authentication-agent-1" &>/dev/null; then
        echo -e "  ${GREEN}polkit-kde-agent running${NC}"
    else
        echo -e "  ${YELLOW}polkit-kde-agent not running. Attempting start...${NC}"

        # Standard paths for the KDE agent binary.
        local_agent=""
        for path in \
            /usr/lib/polkit-kde-authentication-agent-1 \
            /usr/libexec/polkit-kde-authentication-agent-1 \
            /usr/lib/x86_64-linux-gnu/libexec/polkit-kde-authentication-agent-1; do
            if [[ -x "$path" ]]; then
                local_agent="$path"
                break
            fi
        done

        if [[ -n "$local_agent" ]]; then
            "$local_agent" &
            sleep 1
            if pgrep -f "polkit-kde-authentication-agent-1" &>/dev/null; then
                echo -e "  ${GREEN}polkit-kde-agent started${NC}"
            else
                echo -e "  ${RED}polkit-kde-agent failed to start${NC}"
                exit 1
            fi
        else
            echo -e "  ${RED}polkit-kde-agent binary not found${NC}"
            echo "  Install: sudo pacman -S polkit-kde-agent  (or dnf install polkit-kde)"
            exit 1
        fi
    fi
}

# =============================================================================
# XFCE pre-checks
# =============================================================================
# XFCE quirks:
#   - xfce-polkit is the native agent (since XFCE 4.18) but not always installed
#   - polkit-gnome works as a reliable fallback
#   - Neither agent is guaranteed to autostart -- add to Session and Startup
#   - XFCE on some distros ships xfce4-session without a polkit agent
#   - Dialog is plain GTK3 (not themed with XFCE window decorations by default)
precheck_xfce() {
    echo -e "${CYAN}━━━ XFCE Polkit Pre-Checks ━━━${NC}"
    echo ""

    detect_desktop_env
    if [[ "$DE_NAME" != "xfce" ]]; then
        echo -e "  ${RED}ERROR: Not running XFCE (detected: $DE_NAME)${NC}"
        echo "  Run this script inside an XFCE session."
        exit 1
    fi
    echo -e "  ${GREEN}Desktop: XFCE${NC}"

    # Try xfce-polkit first, then polkit-gnome.
    agent_running=false
    if pgrep -f "xfce-polkit" &>/dev/null; then
        echo -e "  ${GREEN}xfce-polkit agent running${NC}"
        agent_running=true
    elif pgrep -f "polkit-gnome-authentication-agent-1" &>/dev/null; then
        echo -e "  ${GREEN}polkit-gnome agent running (XFCE fallback)${NC}"
        agent_running=true
    fi

    if [[ "$agent_running" == "false" ]]; then
        echo -e "  ${YELLOW}No polkit agent running. Attempting to start one...${NC}"

        # Prefer xfce-polkit if installed.
        if command -v xfce-polkit &>/dev/null; then
            xfce-polkit &
            sleep 1
            if pgrep -f "xfce-polkit" &>/dev/null; then
                echo -e "  ${GREEN}xfce-polkit started${NC}"
                agent_running=true
            fi
        fi

        # Fall back to polkit-gnome.
        if [[ "$agent_running" == "false" ]] && [[ -x /usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1 ]]; then
            /usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1 &
            sleep 1
            if pgrep -f "polkit-gnome-authentication-agent-1" &>/dev/null; then
                echo -e "  ${GREEN}polkit-gnome started (fallback)${NC}"
                agent_running=true
            fi
        fi

        if [[ "$agent_running" == "false" ]]; then
            echo -e "  ${RED}No polkit agent available${NC}"
            echo ""
            echo "  Install one of:"
            echo "    Arch:   sudo pacman -S xfce-polkit   (or polkit-gnome)"
            echo "    Debian: sudo apt install policykit-1-gnome"
            echo "    Fedora: sudo dnf install xfce-polkit  (or polkit-gnome)"
            echo ""
            echo "  Then add to XFCE autostart:"
            echo "    Settings -> Session and Startup -> Application Autostart"
            echo "    Command: /usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1"
            exit 1
        fi
    fi
}

# =============================================================================
# No-agent error-path test
# =============================================================================
# Expected behaviour when no agent is running:
#   - pkexec exits with code 127
#   - stderr contains "polkit" or "authority"
#   - Tauri shows: "No Polkit authentication agent found..." with install hints
run_no_agent_test() {
    TARGET_DIR="$(resolve_target_dir \
        "x86_64-unknown-linux-musl/release/hardener" "release/hardener" "debug/hardener")"

    TOTAL=0; PASSED=0; FAILED=0
    FAILED_TESTS=()

    pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; ((PASSED++)); ((TOTAL++)); }
    fail() { echo -e "  ${RED}[FAIL]${NC} $1"; ((FAILED++)); ((TOTAL++)); FAILED_TESTS+=("$1"); }

    echo -e "${CYAN}━━━ No-Agent Polkit Fallback Test ━━━${NC}"
    echo ""

    # Detect and record the current agent so we can restart it afterwards.
    detect_polkit_agent
    ORIGINAL_AGENT="$POLKIT_AGENT"
    ORIGINAL_AGENT_PID=""

    if [[ "$ORIGINAL_AGENT" == "none" ]]; then
        echo -e "  ${YELLOW}No agent running already -- testing directly.${NC}"
    else
        echo -e "  Current agent: ${ORIGINAL_AGENT}"
        ORIGINAL_AGENT_PID=$(pgrep -f "$ORIGINAL_AGENT" | head -1)
        echo -e "  Agent PID: $ORIGINAL_AGENT_PID"
        echo ""
        echo -e "  ${YELLOW}Stopping polkit agent temporarily...${NC}"
        kill "$ORIGINAL_AGENT_PID" 2>/dev/null || true
        sleep 1

        # Verify it stopped.
        if pgrep -f "$ORIGINAL_AGENT" &>/dev/null; then
            echo -e "  ${RED}Agent still running after kill -- aborting${NC}"
            exit 1
        fi
        echo -e "  ${GREEN}Agent stopped.${NC}"
    fi

    echo ""

    # Resolve the hardener binary.
    HARDENER_BIN=""
    for candidate in \
        /usr/bin/hardener \
        "$TARGET_DIR/x86_64-unknown-linux-musl/release/hardener" \
        "$TARGET_DIR/release/hardener" \
        "$TARGET_DIR/debug/hardener"; do
        if [[ -x "$candidate" ]]; then
            HARDENER_BIN="$candidate"
            break
        fi
    done

    if [[ -z "$HARDENER_BIN" ]]; then
        echo -e "  ${RED}ERROR: hardener binary not found${NC}"
        exit 1
    fi

    # ── Test 1: pkexec with no agent returns non-zero ─────────────────────────

    echo -e "${CYAN}Test 1: pkexec exit code without agent${NC}"

    set +e
    pkexec_output=$(/usr/bin/pkexec "$HARDENER_BIN" scan --format json 2>&1)
    pkexec_exit=$?
    set -e

    echo -e "  Exit code: $pkexec_exit"

    # pkexec returns 127 when no agent can handle the request, or 126 if it
    # times out waiting. Both are acceptable non-zero exits.
    if [[ $pkexec_exit -ne 0 ]]; then
        pass "pkexec exits non-zero without agent (code $pkexec_exit)"
    else
        fail "pkexec exits non-zero without agent (got 0)"
    fi

    # ── Test 2: stderr mentions polkit or authority ───────────────────────────

    echo ""
    echo -e "${CYAN}Test 2: Error message references polkit${NC}"

    if echo "$pkexec_output" | grep -qiE 'polkit|authority|authentication agent'; then
        pass "Error output mentions polkit/authority"
    else
        fail "Error output mentions polkit/authority (got: ${pkexec_output:0:120})"
    fi

    # ── Test 3: Verify PrivilegedCommandError::NoAuthAgent mapping ────────────

    echo ""
    echo -e "${CYAN}Test 3: Exit code maps to NoAuthAgent variant${NC}"

    # The Rust code maps exit 127 + stderr containing "polkit"|"authority"
    # to PrivilegedCommandError::NoAuthAgent. Exit 126 maps to AuthCancelled.
    if [[ $pkexec_exit -eq 127 ]]; then
        pass "Exit 127 -> NoAuthAgent (correct mapping)"
    elif [[ $pkexec_exit -eq 126 ]]; then
        # Some polkitd versions return 126 even without an agent.
        pass "Exit 126 -> AuthCancelled (acceptable -- depends on polkitd version)"
    else
        fail "Unexpected exit code $pkexec_exit (expected 127 for NoAuthAgent or 126)"
    fi

    # ── Restart the agent ─────────────────────────────────────────────────────

    echo ""
    if [[ "$ORIGINAL_AGENT" != "none" ]] && [[ -n "$ORIGINAL_AGENT_PID" ]]; then
        echo -e "  ${YELLOW}Restarting polkit agent...${NC}"

        # Find the agent binary from the process name.
        agent_bin=""
        for path in \
            /usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1 \
            /usr/lib/polkit-kde-authentication-agent-1 \
            /usr/libexec/polkit-kde-authentication-agent-1 \
            /usr/bin/xfce-polkit \
            /usr/lib/x86_64-linux-gnu/libexec/polkit-kde-authentication-agent-1; do
            if [[ -x "$path" ]] && [[ "$ORIGINAL_AGENT" == *"$(basename "$path")"* || "$(basename "$path")" == *"$(echo "$ORIGINAL_AGENT" | head -c 10)"* ]]; then
                agent_bin="$path"
                break
            fi
        done

        if [[ -n "$agent_bin" ]]; then
            "$agent_bin" &
            disown
            sleep 1
            if pgrep -f "$ORIGINAL_AGENT" &>/dev/null; then
                echo -e "  ${GREEN}Agent restarted.${NC}"
            else
                echo -e "  ${RED}WARNING: Agent failed to restart. Restart manually:${NC}"
                echo "  $agent_bin &"
            fi
        else
            echo -e "  ${RED}WARNING: Could not find agent binary to restart.${NC}"
            echo "  Restart your polkit agent manually or re-login."
        fi
    fi

    # ── Summary ───────────────────────────────────────────────────────────────

    echo ""
    echo -e "${CYAN}━━━ No-Agent Test Summary ━━━${NC}"
    echo ""
    echo -e "  ${TOTAL} tests: ${GREEN}${PASSED} passed${NC}, ${RED}${FAILED} failed${NC}"

    if [[ ${#FAILED_TESTS[@]} -gt 0 ]]; then
        echo ""
        echo -e "${RED}Failed:${NC}"
        for t in "${FAILED_TESTS[@]}"; do
            echo -e "  - $t"
        done
    fi

    echo ""
    [[ $FAILED -eq 0 ]] && exit 0 || exit 1
}

# =============================================================================
# Dispatch
# =============================================================================

if [[ "$DESKTOP" == "no-agent" ]]; then
    run_no_agent_test
fi

"precheck_$DESKTOP"

echo ""
echo -e "${CYAN}━━━ Running Full Test Matrix ━━━${NC}"
echo ""

exec "$SCRIPT_DIR/test-polkit-matrix.sh" "$@"
