#!/bin/bash
# =============================================================================
# POLKIT DE TEST MATRIX - Linux Hardener
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
#
# Exit codes:
#   0  every check that ran passed, and no precondition was absent
#   1  a check ran and disagreed: something on this host is wrong
#   2  nothing failed, but a precondition was absent, so part of the matrix was
#      never asked and this run is not a complete result
#
# The 0/2 split is what the bookkeeping below exists for. polkit itself, this
# project's policy file and the hardener binary are all things the matrix needs
# and never installs, and nothing in this repository states them as
# requirements, so an absent one is not a defect in the code under test and is
# reported as a named skip rather than a failure.
#
# The other half of that bargain is the summary. A suite whose checks all
# degrade to skips when their preconditions are missing prints a clean sweep
# and exits 0, and a clean sweep of skips is indistinguishable from a clean
# sweep of passes to anything reading only the exit code. So an absent
# precondition is recorded, and the summary refuses to call such a run a pass.
# Same three-state rule release-readiness-root.sh is built around: passed,
# failed and never-ran are three outcomes, never two.
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
# One entry per distinct thing this host was missing, deduplicated because a
# single absent package removes several checks. Read by the summary: any entry
# means part of the matrix was never asked.
MISSING_PRECONDITIONS=()

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; ((PASSED++)); ((TOTAL++)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; ((FAILED++)); ((TOTAL++)); FAILED_TESTS+=("$1"); }
skip() { echo -e "  ${YELLOW}[SKIP]${NC} $1"; ((SKIPPED++)); ((TOTAL++)); }
section() { echo -e "\n${CYAN}━━━ $1 ━━━${NC}\n"; }

# skip_absent CHECK ABSENT REMEDY
#
# A check that could not be asked at all because something it needs is not on
# this host. Names the check, what was missing and what would supply it, so a
# reader can tell it from a check skipped because it does not apply to this run
# (the plain skip above). Only these skips move the verdict.
#
# Every line carries what was absent, because a reader who scrolls to one skip
# should not have to find another to learn why. The remedy is printed once per
# distinct precondition: one missing package removes four checks here, and four
# copies of the same install command buries the rest of the output.
skip_absent() {
    local check="$1" absent="$2" remedy="$3" seen
    skip "$check"
    echo -e "         ${DIM}absent:${NC} $absent"
    for seen in "${MISSING_PRECONDITIONS[@]}"; do
        [[ "$seen" == "$absent" ]] && return 0
    done
    echo -e "         ${DIM}needs:${NC}  $remedy"
    MISSING_PRECONDITIONS+=("$absent")
}

# ═══════════════════════════════════════════════════════════════════════════════
# PRECONDITIONS
# ═══════════════════════════════════════════════════════════════════════════════
#
# Established once, before any check that depends on them, so that a check
# reports on the code rather than on this host's package list.

POLKIT_PACKAGE="the polkit package (Arch: polkit, Debian: policykit-1, Fedora/RHEL: polkit, openSUSE: polkit)"
POLICY_REMEDY="the linux-hardener package, or from the project root: sudo install -Dm644 packaging/assets/$(basename "$POLICY_PATH") $POLICY_PATH"
BINARY_REMEDY="the linux-hardener package, or: cargo build --release -p hardener-cli"

# polkit counts as present when any one of the three things it ships is here.
# A disjunction on purpose: a distribution that splits the daemon from the
# tools would otherwise look like an absent polkit to whichever half is
# missing, and the checks below would be skipped instead of reporting the
# half-installed polkit they actually found.
POLKIT_PRESENT=false
if [[ -x /usr/bin/pkexec ]] || command -v pkaction &>/dev/null || pgrep -x polkitd &>/dev/null; then
    POLKIT_PRESENT=true
fi

POLICY_INSTALLED=false
[[ -f "$POLICY_PATH" ]] && POLICY_INSTALLED=true

# Every action ID the policy file registers. Listed rather than checked twice
# with one string changed, so the pair stays in one place when a third action
# is added and so each skip can name the action it is about.
POLICY_ACTIONS=("$POLICY_ID" "com.tidynest.linux-hardener.rollback")

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

# 1. polkitd running. Asked only once polkit is known to be installed: with no
# polkit at all this would be a statement about the host's package list, and
# only a stopped daemon on a host that has polkit is a result.
if [[ "$POLKIT_PRESENT" != "true" ]]; then
    skip_absent "polkitd daemon is running" "polkit is not installed on this host" "$POLKIT_PACKAGE"
elif pgrep -x polkitd &>/dev/null; then
    pass "polkitd daemon is running"
else
    fail "polkitd daemon is running"
fi

# 2. pkexec binary. Same split: absent polkit is a precondition, a polkit
# without pkexec is a broken install and is reported as one.
if [[ "$POLKIT_PRESENT" != "true" ]]; then
    skip_absent "/usr/bin/pkexec exists and is executable" "polkit is not installed on this host" "$POLKIT_PACKAGE"
elif [[ -x /usr/bin/pkexec ]]; then
    pass "/usr/bin/pkexec exists and is executable"
else
    fail "/usr/bin/pkexec exists and is executable"
fi

# 3. Policy file installed. The package ships it, so its absence says the
# package is not installed here. That is a precondition nothing in this
# repository states, not a defect in the code under test.
if [[ "$POLICY_INSTALLED" == "true" ]]; then
    pass "Policy file installed at $POLICY_PATH"
else
    skip_absent "Policy file installed at $POLICY_PATH" "$POLICY_PATH" "$POLICY_REMEDY"
fi

# 4. Policy file parseable by polkitd. A pkaction that does not recognise an
# action while the policy file IS installed is a genuine failure: polkitd could
# not parse what the package shipped. With no policy file there is nothing to
# recognise, and with no pkaction there is nothing to ask with.
for action in "${POLICY_ACTIONS[@]}"; do
    if [[ "$POLICY_INSTALLED" != "true" ]]; then
        skip_absent "pkaction recognises $action" "$POLICY_PATH" "$POLICY_REMEDY"
    elif ! command -v pkaction &>/dev/null; then
        skip_absent "pkaction recognises $action" "the pkaction tool" "$POLKIT_PACKAGE"
    elif pkaction --action-id "$action" &>/dev/null; then
        pass "pkaction recognises $action"
    else
        fail "pkaction recognises $action"
    fi
done

# 5. Policy permissions correct. With the file absent this check used to happen
# not at all: no pass, no fail, no skip, and missing from the total, so a run
# that never asked it looked exactly like a run that had no such check.
if [[ "$POLICY_INSTALLED" != "true" ]]; then
    skip_absent "Policy file permissions" "$POLICY_PATH" "$POLICY_REMEDY"
else
    policy_mode=$(stat -c '%a' "$POLICY_PATH" 2>/dev/null)
    if [[ "$policy_mode" == "644" ]]; then
        pass "Policy file permissions ($policy_mode)"
    else
        fail "Policy file permissions (expected 644, got ${policy_mode:-unreadable})"
    fi
fi

section "Agent Detection"

# 6. Polkit agent running. A desktop's authentication agent is a third-party
# package that this project neither ships nor declares a dependency on, so an
# absent one is a precondition, in the same class as the two above and as the
# agent/DE mismatch immediately below, which has always been a skip. The
# error path taken when no agent is running has its own test in test-polkit.sh.
if [[ "$POLKIT_AGENT" != "none" ]]; then
    pass "Polkit agent detected: $POLKIT_AGENT"
else
    skip_absent "Polkit agent detected" "no polkit authentication agent is running" \
        "an authentication agent for this desktop, per the recommendation below"
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

BINARY_ABSENT="no hardener binary at /usr/bin or under $TARGET_DIR"

# Installed by the package or left behind by a build, and neither is guaranteed
# on an arbitrary host, so an absent one is a precondition like the rest.
if [[ -n "$HARDENER_BIN" ]]; then
    pass "hardener binary found: $HARDENER_BIN"
else
    skip_absent "hardener binary found" "$BINARY_ABSENT" "$BINARY_REMEDY"
fi

# 9. Binary is not a symlink (security check from validate_binary_path). With
# no binary this reported nothing at all before: neither branch matched, so the
# check left no line and no entry in the total.
if [[ -z "$HARDENER_BIN" ]]; then
    skip_absent "hardener binary is not a symlink" "$BINARY_ABSENT" "$BINARY_REMEDY"
elif [[ ! -L "$HARDENER_BIN" ]]; then
    pass "hardener binary is not a symlink"
else
    fail "hardener binary is a symlink (rejected by validate_binary_path)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# INTERACTIVE TESTS (--interactive flag)
# ═══════════════════════════════════════════════════════════════════════════════

if [[ "$INTERACTIVE" != "true" ]]; then
    # Not a precondition: the caller chose this mode, and release-readiness-root.sh
    # chooses it deliberately because the three tests below block on a human at
    # an authentication dialog. A plain skip, so it does not move the verdict.
    skip "Auth success test (use --interactive)"
    skip "Auth cancel test (use --interactive)"
    skip "Tauri error handling test (use --interactive)"
elif [[ -z "$HARDENER_BIN" ]]; then
    # Without a binary there is nothing for pkexec to run. Each test below would
    # raise a dialog for an empty command and report whatever came back as a
    # verdict on this project.
    section "Interactive Tests"
    for interactive_test in "Auth success test" "Auth cancel test" "Tauri error handling test"; do
        skip_absent "$interactive_test" "$BINARY_ABSENT" "$BINARY_REMEDY"
    done
else
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
fi

# ═══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════

section "POLKIT TEST MATRIX SUMMARY"

# What the run actually asked, as opposed to what it printed a line for. A
# skipped check prints a line and lands in TOTAL, so TOTAL alone cannot tell a
# run that verified nine things from a run that verified none.
EXECUTED=$((PASSED + FAILED))

echo ""
echo -e "  ${BOLD}Desktop:${NC}       $DE_NAME"
echo -e "  ${BOLD}Agent:${NC}         $POLKIT_AGENT"
echo -e "  ${BOLD}Total Tests:${NC}   $TOTAL"
echo -e "  ${GREEN}Passed:${NC}        $PASSED"
echo -e "  ${RED}Failed:${NC}        $FAILED"
echo -e "  ${YELLOW}Skipped:${NC}       $SKIPPED"
echo -e "  ${BOLD}Checks run:${NC}    $EXECUTED"
echo ""

if [[ ${#FAILED_TESTS[@]} -gt 0 ]]; then
    echo -e "${RED}Failed Tests:${NC}"
    for t in "${FAILED_TESTS[@]}"; do
        echo -e "  - $t"
    done
    echo ""
fi

if [[ ${#MISSING_PRECONDITIONS[@]} -gt 0 ]]; then
    echo -e "${YELLOW}Absent preconditions:${NC}"
    for p in "${MISSING_PRECONDITIONS[@]}"; do
        echo -e "  - $p"
    done
    echo ""
fi

# Three outcomes, never two.
#
# A failure is a check that ran and disagreed. An absent precondition is a
# check that never got to say anything. Those are different facts about
# different things, so they are printed apart and they exit apart, and neither
# of them may exit 0: a check that reports nothing looks identical whether it
# is clean or broken.
#
# The zero-checks test below is deliberately kept alongside the precondition
# list rather than replaced by it. The list only holds what someone remembered
# to record through skip_absent; the count needs nobody to have thought of the
# case, so it is what catches a group added later that forgets to.
if [[ $FAILED -gt 0 ]]; then
    echo -e "${RED}$FAILED test(s) failed. See above for details.${NC}"
    exit 1
fi

if [[ $EXECUTED -eq 0 ]]; then
    echo -e "${YELLOW}Nothing could be checked on this host: every check was skipped.${NC}"
    echo -e "${YELLOW}This is not a pass. Satisfy the preconditions above and run again.${NC}"
    exit 2
fi

if [[ ${#MISSING_PRECONDITIONS[@]} -gt 0 ]]; then
    echo -e "${YELLOW}$EXECUTED check(s) passed and none failed, but ${#MISSING_PRECONDITIONS[@]} precondition(s)"
    echo -e "were absent, so part of the matrix was never asked. Nothing here says the"
    echo -e "code is wrong; this run is simply not a complete result for $DE_NAME.${NC}"
    exit 2
fi

echo -e "${GREEN}All polkit tests passed for $DE_NAME!${NC}"
exit 0
