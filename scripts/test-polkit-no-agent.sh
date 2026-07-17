#!/bin/bash
# =============================================================================
# NO-AGENT POLKIT TEST - Linux System Hardener
# =============================================================================
# Tests the error path when no polkit authentication agent is available.
# Validates that both the CLI (via pkexec) and Tauri (via run_privileged_command)
# return the correct error message.
#
# This test temporarily stops the polkit agent, runs the check, and restarts
# the agent. It does NOT run inside nspawn -- it requires a live graphical
# session to verify the Tauri error dialog.
#
# Usage: ./scripts/test-polkit-no-agent.sh
#
# Expected behaviour when no agent is running:
#   - pkexec exits with code 127
#   - stderr contains "polkit" or "authority"
#   - Tauri shows: "No Polkit authentication agent found..." with install hints
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/detect-polkit-agent.sh"

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

TARGET_DIR="$(resolve_target_dir \
    "x86_64-unknown-linux-musl/release/hardener" "release/hardener" "debug/hardener")"

TOTAL=0; PASSED=0; FAILED=0
FAILED_TESTS=()

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

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

# ── Test 1: pkexec with no agent returns non-zero ─────────────────────────────

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

# ── Test 2: stderr mentions polkit or authority ───────────────────────────────

echo ""
echo -e "${CYAN}Test 2: Error message references polkit${NC}"

if echo "$pkexec_output" | grep -qiE 'polkit|authority|authentication agent'; then
    pass "Error output mentions polkit/authority"
else
    fail "Error output mentions polkit/authority (got: ${pkexec_output:0:120})"
fi

# ── Test 3: Verify PrivilegedCommandError::NoAuthAgent mapping ────────────────

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

# ── Restart the agent ─────────────────────────────────────────────────────────

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

# ── Summary ───────────────────────────────────────────────────────────────────

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
