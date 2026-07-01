#!/bin/bash
# =============================================================================
# GNOME POLKIT TEST - Linux System Hardener
# =============================================================================
# GNOME-specific polkit validation. Checks for the built-in gnome-shell
# agent (Wayland) or polkit-gnome (Xorg), then runs the full test matrix.
#
# Usage: ./scripts/test-polkit-gnome.sh [--interactive]
#
# GNOME quirks:
#   - gnome-shell on Wayland has a built-in polkit agent (no separate process)
#   - gnome-shell on Xorg needs polkit-gnome-authentication-agent-1
#   - auth_admin_keep (our policy) allows 5-minute credential caching
#   - gnome-shell agent auto-focuses the password field
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/detect-polkit-agent.sh"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

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

echo ""
echo -e "${CYAN}━━━ Running Full Test Matrix ━━━${NC}"
echo ""

exec "$SCRIPT_DIR/test-polkit-matrix.sh" "$@"
