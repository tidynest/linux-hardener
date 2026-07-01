#!/bin/bash
# =============================================================================
# KDE POLKIT TEST - Linux System Hardener
# =============================================================================
# KDE-specific polkit validation. Checks for polkit-kde-authentication-agent-1
# (started by plasma-session), then runs the full test matrix.
#
# Usage: ./scripts/test-polkit-kde.sh [--interactive]
#
# KDE quirks:
#   - polkit-kde-agent is started by plasma-session, not manually
#   - Agent reads icon_name from policy (our policy: security-high, edit-undo)
#   - auth_admin_keep credential caching respects KDE system settings
#   - KDE agent has a "Details" expander showing the action ID
#   - On Wayland, the dialog is rendered as a Wayland popup (layer-shell)
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/detect-polkit-agent.sh"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

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

echo ""
echo -e "${CYAN}━━━ Running Full Test Matrix ━━━${NC}"
echo ""

exec "$SCRIPT_DIR/test-polkit-matrix.sh" "$@"
