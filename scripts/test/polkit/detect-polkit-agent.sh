#!/bin/bash
# =============================================================================
# POLKIT AGENT DETECTION - Linux Hardener
# =============================================================================
# Detects desktop environment, running polkit agent, and pkexec readiness.
#
# Usage:
#   ./scripts/test/polkit/detect-polkit-agent.sh           # Print diagnostic report
#   source ./scripts/test/polkit/detect-polkit-agent.sh     # Import functions only
#
# Exports:
#   detect_desktop_env   -> sets DE_NAME (gnome|kde|xfce|hyprland|sway|i3|unknown)
#   detect_polkit_agent  -> sets POLKIT_AGENT (process name or "none")
#   check_pkexec_ready   -> returns 0 if pkexec can present an auth dialog
#   check_polkit_policy  -> returns 0 if our policy file is installed
# =============================================================================

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

POLICY_ID="com.tidynest.linux-hardener.apply"
POLICY_PATH="/usr/share/polkit-1/actions/com.tidynest.linux-hardener.policy"

# Detect desktop environment from session variables and running processes.
detect_desktop_env() {
    DE_NAME="unknown"

    # Check XDG_CURRENT_DESKTOP first (most reliable).
    local xdg="${XDG_CURRENT_DESKTOP:-}"
    case "${xdg,,}" in
        *gnome*)    DE_NAME="gnome" ;;
        *kde*|*plasma*) DE_NAME="kde" ;;
        *xfce*)     DE_NAME="xfce" ;;
        *hyprland*) DE_NAME="hyprland" ;;
        *sway*)     DE_NAME="sway" ;;
        *i3*)       DE_NAME="i3" ;;
    esac

    # Fallback: check running compositors/session managers.
    if [[ "$DE_NAME" == "unknown" ]]; then
        if pgrep -x gnome-shell &>/dev/null; then
            DE_NAME="gnome"
        elif pgrep -x plasmashell &>/dev/null; then
            DE_NAME="kde"
        elif pgrep -x xfce4-session &>/dev/null; then
            DE_NAME="xfce"
        elif pgrep -x Hyprland &>/dev/null; then
            DE_NAME="hyprland"
        elif pgrep -x sway &>/dev/null; then
            DE_NAME="sway"
        elif pgrep -x i3 &>/dev/null; then
            DE_NAME="i3"
        fi
    fi

    export DE_NAME
}

# Detect which polkit authentication agent (if any) is running.
detect_polkit_agent() {
    POLKIT_AGENT="none"

    # Known agent process names, ordered by specificity.
    local -a agents=(
        "polkit-gnome-authentication-agent-1"
        "polkit-kde-authentication-agent-1"
        "xfce-polkit"
        "polkitd"
        "polkit-mate-authentication-agent-1"
        "lxpolkit"
        "lxsession"
    )

    for agent in "${agents[@]}"; do
        if pgrep -f "$agent" &>/dev/null; then
            POLKIT_AGENT="$agent"
            break
        fi
    done

    # GNOME shell has a built-in agent -- not a separate process.
    if [[ "$POLKIT_AGENT" == "none" ]] && pgrep -x gnome-shell &>/dev/null; then
        POLKIT_AGENT="gnome-shell (built-in)"
    fi

    export POLKIT_AGENT
}

# Check that our polkit policy file is installed and readable by polkitd.
check_polkit_policy() {
    if [[ ! -f "$POLICY_PATH" ]]; then
        return 1
    fi

    # Verify polkitd can parse it (pkaction lists registered actions).
    if command -v pkaction &>/dev/null; then
        if pkaction --action-id "$POLICY_ID" &>/dev/null; then
            return 0
        fi
        return 1
    fi

    # No pkaction binary -- file exists, assume OK.
    return 0
}

# Check whether pkexec is likely to succeed (agent running + policy installed).
check_pkexec_ready() {
    if [[ ! -x /usr/bin/pkexec ]]; then
        return 1
    fi

    detect_polkit_agent
    if [[ "$POLKIT_AGENT" == "none" ]]; then
        return 1
    fi

    check_polkit_policy
    return $?
}

# Recommend which polkit agent to install based on the detected DE.
recommend_agent() {
    detect_desktop_env
    case "$DE_NAME" in
        gnome)
            echo "GNOME shell includes a built-in polkit agent. No additional package needed."
            echo "If running GNOME on Xorg, install: polkit-gnome" ;;
        kde)
            echo "Install: polkit-kde-agent (Arch: polkit-kde-agent, Fedora: polkit-kde, Debian: polkit-kde-agent-1)" ;;
        xfce)
            echo "Install: xfce-polkit (Arch) or polkit-gnome as fallback" ;;
        hyprland|sway|i3)
            echo "Install: polkit-gnome, then add to compositor startup:"
            echo "  exec /usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1" ;;
        *)
            echo "Install: polkit-gnome (works on most environments)" ;;
    esac
}

# When run directly (not sourced), print a diagnostic report.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo -e "${CYAN}━━━ Polkit Agent Diagnostic Report ━━━${NC}"
    echo ""

    detect_desktop_env
    echo -e "  Desktop environment:  ${GREEN}${DE_NAME}${NC}"

    detect_polkit_agent
    if [[ "$POLKIT_AGENT" == "none" ]]; then
        echo -e "  Polkit agent:         ${RED}none detected${NC}"
    else
        echo -e "  Polkit agent:         ${GREEN}${POLKIT_AGENT}${NC}"
    fi

    echo -n "  Policy file:          "
    if check_polkit_policy; then
        echo -e "${GREEN}installed (${POLICY_PATH})${NC}"
    else
        echo -e "${RED}missing or invalid${NC}"
    fi

    echo -n "  pkexec ready:         "
    if check_pkexec_ready; then
        echo -e "${GREEN}yes${NC}"
    else
        echo -e "${RED}no${NC}"
    fi

    echo ""
    echo -e "${CYAN}━━━ Recommendation ━━━${NC}"
    echo ""
    recommend_agent
    echo ""
fi
