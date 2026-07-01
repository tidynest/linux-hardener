#!/bin/bash
# =============================================================================
# XFCE POLKIT TEST - Linux System Hardener
# =============================================================================
# XFCE-specific polkit validation. Checks for xfce-polkit or polkit-gnome
# (XFCE does not always autostart a polkit agent), then runs the matrix.
#
# Usage: ./scripts/test-polkit-xfce.sh [--interactive]
#
# XFCE quirks:
#   - xfce-polkit is the native agent (since XFCE 4.18) but not always installed
#   - polkit-gnome works as a reliable fallback
#   - Neither agent is guaranteed to autostart -- add to Session and Startup
#   - XFCE on some distros ships xfce4-session without a polkit agent
#   - Dialog is plain GTK3 (not themed with XFCE window decorations by default)
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/detect-polkit-agent.sh"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

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

echo ""
echo -e "${CYAN}━━━ Running Full Test Matrix ━━━${NC}"
echo ""

exec "$SCRIPT_DIR/test-polkit-matrix.sh" "$@"
