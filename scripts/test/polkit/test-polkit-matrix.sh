#!/bin/bash
# =============================================================================
# POLKIT DE TEST MATRIX - Linux System Hardener
# =============================================================================
# Tests pkexec/polkit privilege escalation across desktop environments.
#
# Automated tests (no user interaction):
#   - polkit daemon running
#   - policy file installed and parseable
#   - pkexec binary present
#   - polkit agent detected
#   - hardener binary resolvable
#
# Semi-automated tests (user must interact with auth dialog):
#   - Auth success: user enters password -> apply succeeds
#   - Auth cancel: user clicks Cancel -> exit code 126
#   - No-agent: agent killed -> correct error message
#
# Usage:
#   ./scripts/test/polkit/test-polkit-matrix.sh              # Automated tests only
#   ./scripts/test/polkit/test-polkit-matrix.sh --interactive # Include auth dialog tests
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# shellcheck source=../../lib/common.sh
source "$SCRIPT_DIR/../../lib/common.sh"
source "$SCRIPT_DIR/detect-polkit-agent.sh"

TARGET_DIR="$(resolve_target_dir \
    "x86_64-unknown-linux-musl/release/hardener" "release/hardener" "debug/hardener")"

INTERACTIVE=false
[[ "${1:-}" == "--interactive" ]] && INTERACTIVE=true

# Test counters
TOTAL=0; PASSED=0; FAILED=0; SKIPPED=0
FAILED_TESTS=()

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; ((PASSED++)); ((TOTAL++)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; ((FAILED++)); ((TOTAL++)); FAILED_TESTS+=("$1"); }
skip() { echo -e "  ${YELLOW}[SKIP]${NC} $1"; ((SKIPPED++)); ((TOTAL++)); }
section() { echo -e "\n${CYAN}━━━ $1 ━━━${NC}\n"; }

# ═══════════════════════════════════════════════════════════════════════════════
# AUTOMATED CHECKS
# ═══════════════════════════════════════════════════════════════════════════════

section "Environment Detection"

detect_desktop_env
echo -e "  Desktop: ${BOLD}${DE_NAME}${NC}"

detect_polkit_agent
echo -e "  Agent:   ${BOLD}${POLKIT_AGENT}${NC}"
echo ""

section "Polkit Infrastructure"

# 1. polkitd running
if pgrep -x polkitd &>/dev/null; then
    pass "polkitd daemon is running"
else
    fail "polkitd daemon is running"
fi

# 2. pkexec binary
if [[ -x /usr/bin/pkexec ]]; then
    pass "/usr/bin/pkexec exists and is executable"
else
    fail "/usr/bin/pkexec exists and is executable"
fi

# 3. Policy file installed
if [[ -f "$POLICY_PATH" ]]; then
    pass "Policy file installed at $POLICY_PATH"
else
    fail "Policy file installed at $POLICY_PATH"
fi

# 4. Policy file parseable by polkitd
if command -v pkaction &>/dev/null; then
    if pkaction --action-id "$POLICY_ID" &>/dev/null; then
        pass "pkaction recognises $POLICY_ID"
    else
        fail "pkaction recognises $POLICY_ID"
    fi

    # Also check the rollback action
    if pkaction --action-id "com.tidynest.linux-hardener.rollback" &>/dev/null; then
        pass "pkaction recognises com.tidynest.linux-hardener.rollback"
    else
        fail "pkaction recognises com.tidynest.linux-hardener.rollback"
    fi
else
    skip "pkaction not available (polkit-devel not installed)"
    skip "pkaction not available (polkit-devel not installed)"
fi

# 5. Policy permissions correct
if [[ -f "$POLICY_PATH" ]]; then
    local_mode=$(stat -c '%a' "$POLICY_PATH")
    if [[ "$local_mode" == "644" ]]; then
        pass "Policy file permissions ($local_mode)"
    else
        fail "Policy file permissions (expected 644, got $local_mode)"
    fi
fi

section "Agent Detection"

# 6. Polkit agent running
if [[ "$POLKIT_AGENT" != "none" ]]; then
    pass "Polkit agent detected: $POLKIT_AGENT"
else
    fail "Polkit agent detected (none found)"
    echo ""
    echo -e "  ${YELLOW}Recommendation:${NC}"
    recommend_agent | sed 's/^/    /'
    echo ""
fi

# 7. Agent matches DE expectation
case "$DE_NAME" in
    gnome)
        if [[ "$POLKIT_AGENT" == *"gnome"* ]]; then
            pass "Agent matches DE (GNOME -> gnome agent)"
        else
            skip "Agent/DE mismatch (GNOME expects gnome agent, got $POLKIT_AGENT)"
        fi ;;
    kde)
        if [[ "$POLKIT_AGENT" == *"kde"* ]]; then
            pass "Agent matches DE (KDE -> kde agent)"
        else
            skip "Agent/DE mismatch (KDE expects kde agent, got $POLKIT_AGENT)"
        fi ;;
    xfce)
        if [[ "$POLKIT_AGENT" == *"xfce"* ]] || [[ "$POLKIT_AGENT" == *"gnome"* ]]; then
            pass "Agent matches DE (XFCE -> xfce or gnome agent)"
        else
            skip "Agent/DE mismatch (XFCE expects xfce/gnome agent, got $POLKIT_AGENT)"
        fi ;;
    *)
        skip "Agent/DE match check (DE=$DE_NAME, not in test matrix)" ;;
esac

section "Binary Resolution"

# 8. hardener binary findable
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

if [[ -n "$HARDENER_BIN" ]]; then
    pass "hardener binary found: $HARDENER_BIN"
else
    fail "hardener binary found"
fi

# 9. Binary is not a symlink (security check from validate_binary_path)
if [[ -n "$HARDENER_BIN" ]] && [[ ! -L "$HARDENER_BIN" ]]; then
    pass "hardener binary is not a symlink"
elif [[ -n "$HARDENER_BIN" ]]; then
    fail "hardener binary is a symlink (rejected by validate_binary_path)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# INTERACTIVE TESTS (--interactive flag)
# ═══════════════════════════════════════════════════════════════════════════════

if [[ "$INTERACTIVE" == "true" ]]; then
    section "Interactive: Auth Success"

    echo -e "  ${YELLOW}A polkit dialog will appear. Enter your password to authenticate.${NC}"
    echo -e "  ${YELLOW}Press Enter to continue...${NC}"
    read -r

    # Use 'scan' as a safe privileged operation (read-only).
    if pkexec "$HARDENER_BIN" scan --format json &>/dev/null; then
        pass "pkexec auth success (scan completed)"
    else
        exit_code=$?
        if [[ $exit_code -eq 126 ]]; then
            fail "pkexec auth success (user cancelled instead of authenticating)"
        else
            fail "pkexec auth success (exit code: $exit_code)"
        fi
    fi

    section "Interactive: Auth Cancel"

    echo -e "  ${YELLOW}A polkit dialog will appear. Click CANCEL (do not authenticate).${NC}"
    echo -e "  ${YELLOW}Press Enter to continue...${NC}"
    read -r

    pkexec "$HARDENER_BIN" scan --format json &>/dev/null
    cancel_exit=$?
    if [[ $cancel_exit -eq 126 ]]; then
        pass "pkexec auth cancel returns exit code 126"
    else
        fail "pkexec auth cancel (expected exit 126, got $cancel_exit)"
    fi

    section "Interactive: Tauri Error Handling"

    echo -e "  ${YELLOW}This test verifies the Tauri desktop app shows the correct error"
    echo -e "  when auth is cancelled. Start the desktop app, click Apply, then"
    echo -e "  cancel the polkit dialog.${NC}"
    echo ""
    echo -e "  Expected: Toast/banner says \"Authentication cancelled. Root privileges"
    echo -e "  are required for this operation.\"${NC}"
    echo ""
    echo -e "  ${YELLOW}Did the correct error message appear? [y/N]${NC}"
    read -r -n 1 answer
    echo ""
    if [[ "${answer,,}" == "y" ]]; then
        pass "Tauri shows auth-cancelled error message"
    else
        fail "Tauri shows auth-cancelled error message"
    fi
else
    skip "Auth success test (use --interactive)"
    skip "Auth cancel test (use --interactive)"
    skip "Tauri error handling test (use --interactive)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════

section "POLKIT TEST MATRIX SUMMARY"

echo ""
echo -e "  ${BOLD}Desktop:${NC}       $DE_NAME"
echo -e "  ${BOLD}Agent:${NC}         $POLKIT_AGENT"
echo -e "  ${BOLD}Total Tests:${NC}   $TOTAL"
echo -e "  ${GREEN}Passed:${NC}        $PASSED"
echo -e "  ${RED}Failed:${NC}        $FAILED"
echo -e "  ${YELLOW}Skipped:${NC}       $SKIPPED"
echo ""

if [[ ${#FAILED_TESTS[@]} -gt 0 ]]; then
    echo -e "${RED}Failed Tests:${NC}"
    for t in "${FAILED_TESTS[@]}"; do
        echo -e "  - $t"
    done
    echo ""
fi

if [[ $FAILED -eq 0 ]]; then
    echo -e "${GREEN}All polkit tests passed for $DE_NAME!${NC}"
    exit 0
else
    echo -e "${RED}$FAILED test(s) failed. See above for details.${NC}"
    exit 1
fi
