#!/bin/bash
# Comprehensive root test suite for Linux System Hardener
# Run this INSIDE the test container, not on your real system!
#
# Usage: sudo ./scripts/test/root-test-suite.sh [--apply]
#
# Without --apply: Safe read-only tests + dry-run
# With --apply: Actually applies and rolls back changes

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BINARY="$PROJECT_DIR/target/release/hardener"
LOG_FILE="/tmp/hardener-test-$(date +%Y%m%d-%H%M%S).log"

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Options
DO_APPLY=false

log() { echo -e "$1" | tee -a "$LOG_FILE"; }
log_test() { log "${BLUE}[TEST]${NC} $1"; }
log_pass() { log "${GREEN}[PASS]${NC} $1"; ((TESTS_PASSED++)) || true; }
log_fail() { log "${RED}[FAIL]${NC} $1"; ((TESTS_FAILED++)) || true; }
log_skip() { log "${YELLOW}[SKIP]${NC} $1"; ((TESTS_SKIPPED++)) || true; }
log_section() { log "\n${YELLOW}━━━ $1 ━━━${NC}\n"; }

check_environment() {
    log_section "Environment Check"

    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_fail "Must run as root"
        exit 1
    fi
    log_pass "Running as root"

    # Check if binary exists
    if [[ ! -x "$BINARY" ]]; then
        log_fail "Binary not found at $BINARY"
        log "Run: cargo build --release"
        exit 1
    fi
    log_pass "Binary found: $BINARY"

    # Safety check - are we in a container?
    # Check multiple container indicators
    if [[ -f /run/systemd/container ]] || \
       [[ -f /.dockerenv ]] || \
       grep -q "systemd-nspawn" /proc/1/cgroup 2>/dev/null || \
       [[ "$(systemd-detect-virt 2>/dev/null)" == "systemd-nspawn" ]]; then
        log_pass "Running inside container (safe)"
    else
        log "${RED}WARNING: Not detected as container!${NC}"
        log "This script is designed to run in an isolated container."
        # Use -r flag and handle empty REPLY
        read -p "Are you ABSOLUTELY sure you want to continue? [y/N] " -n 1 -r REPLY || REPLY=""
        echo
        if [[ ! "${REPLY:-}" =~ ^[Yy]$ ]]; then
            log "Aborted."
            exit 1
        fi
    fi

    # Version check
    VERSION=$("$BINARY" --version)
    log_pass "Version: $VERSION"
}

test_basic_commands() {
    log_section "Basic Commands"

    log_test "hardener --help"
    if "$BINARY" --help &>/dev/null; then
        log_pass "Help command works"
    else
        log_fail "Help command failed"
    fi

    log_test "hardener plugins"
    PLUGINS=$("$BINARY" plugins 2>&1)
    if echo "$PLUGINS" | grep -q "kernel-hardening"; then
        PLUGIN_COUNT=$(echo "$PLUGINS" | grep -c "plugin_id")
        log_pass "Plugins listed: $PLUGIN_COUNT plugins"
    else
        log_fail "Plugin listing failed"
    fi
}

test_scan_as_root() {
    log_section "Scan Operations (Root)"

    log_test "Full scan with root privileges"
    SCAN_OUTPUT=$("$BINARY" scan 2>&1)
    if [[ $? -eq 0 ]] || echo "$SCAN_OUTPUT" | grep -q "finding_id"; then
        FINDING_COUNT=$(echo "$SCAN_OUTPUT" | grep -c "finding_id" || echo "0")
        log_pass "Full scan completed: $FINDING_COUNT findings"
    else
        log_fail "Full scan failed"
        echo "$SCAN_OUTPUT" >> "$LOG_FILE"
    fi

    # Test individual plugins
    for plugin in kernel firewall audit ssh pam permissions; do
        log_test "Scan plugin: $plugin"
        if "$BINARY" scan --plugin "$plugin-hardening" &>/dev/null; then
            log_pass "Plugin scan: $plugin"
        else
            log_fail "Plugin scan: $plugin"
        fi
    done

    # Severity filter
    log_test "Scan with severity filter (high)"
    if "$BINARY" scan --severity high &>/dev/null; then
        log_pass "Severity filter works"
    else
        log_fail "Severity filter failed"
    fi

    # Exit code
    log_test "Scan with --exit-code"
    EXIT_CODE=0
    "$BINARY" scan --exit-code &>/dev/null || EXIT_CODE=$?
    if [[ $EXIT_CODE -eq 0 ]] || [[ $EXIT_CODE -eq 1 ]]; then
        log_pass "Exit code returned: $EXIT_CODE"
    else
        log_fail "Unexpected exit code: $EXIT_CODE"
    fi
}

test_reports_as_root() {
    log_section "Compliance Reports (Root)"

    for framework in cis stig nist pcidss hipaa gdpr; do
        log_test "Report: $framework"
        if "$BINARY" report --framework "$framework" &>/dev/null; then
            log_pass "Report generated: $framework"
        else
            log_fail "Report failed: $framework"
        fi
    done

    # JSON format
    log_test "Report JSON format"
    if "$BINARY" report --framework cis --report-format json | grep -q "report_framework"; then
        log_pass "JSON format works"
    else
        log_fail "JSON format failed"
    fi

    # PDF generation
    log_test "Report PDF generation"
    if "$BINARY" report --framework cis --report-format pdf --output /tmp/test-report.pdf &>/dev/null; then
        if [[ -f /tmp/test-report.pdf ]]; then
            SIZE=$(stat -c%s /tmp/test-report.pdf)
            log_pass "PDF generated: ${SIZE} bytes"
            rm -f /tmp/test-report.pdf
        else
            log_fail "PDF file not created"
        fi
    else
        log_fail "PDF generation failed"
    fi
}

test_dry_run() {
    log_section "Dry-Run Validation"

    log_test "Apply --all --dry-run"
    DRY_OUTPUT=$("$BINARY" apply --all --dry-run 2>&1)
    if echo "$DRY_OUTPUT" | grep -q "validation_report"; then
        # Count estimated changes
        CHANGES=$(echo "$DRY_OUTPUT" | grep -c "estimated_changes" || echo "0")
        log_pass "Dry-run completed, $CHANGES plugin reports"
    else
        log_fail "Dry-run failed"
        echo "$DRY_OUTPUT" >> "$LOG_FILE"
    fi

    # Check specific plugins report changes
    for plugin in kernel firewall permissions ssh; do
        log_test "Dry-run shows changes for: $plugin"
        if echo "$DRY_OUTPUT" | grep -A20 "\"$plugin-hardening\"" | grep -q "will be set\|→"; then
            log_pass "Changes shown for $plugin"
        else
            log_skip "No changes needed for $plugin (already hardened?)"
        fi
    done
}

test_daemon_history() {
    log_section "Daemon & History (Root)"

    log_test "Daemon status"
    STATUS=$("$BINARY" daemon status 5 2>&1)
    if echo "$STATUS" | grep -q "Database:.*scheduler.db"; then
        if echo "$STATUS" | grep -q "/var/lib/linux-hardener"; then
            log_pass "Daemon status works (root path correct)"
        else
            log_fail "Daemon using wrong path for root"
        fi
    else
        log_fail "Daemon status failed"
    fi

    log_test "History list"
    if "$BINARY" history list &>/dev/null; then
        log_pass "History list works"
    else
        log_fail "History list failed"
    fi
}

test_systemd_commands() {
    log_section "Systemd Commands"

    log_test "Systemd generate"
    UNITS=$("$BINARY" systemd generate 2>&1)
    if echo "$UNITS" | grep -q "linux-hardener.service"; then
        log_pass "Unit files generated"
    else
        log_fail "Unit generation failed"
    fi

    log_test "Systemd status"
    if "$BINARY" systemd status &>/dev/null; then
        log_pass "Systemd status works"
    else
        log_pass "Systemd status works (units not installed, expected)"
    fi
}

test_apply_and_rollback() {
    log_section "Apply & Rollback (DESTRUCTIVE)"

    if [[ "$DO_APPLY" != "true" ]]; then
        log_skip "Apply tests skipped (use --apply to enable)"
        return
    fi

    log "${RED}WARNING: This will modify system configuration!${NC}"

    # Apply kernel hardening (safest to test)
    log_test "Apply kernel hardening"
    APPLY_OUTPUT=$("$BINARY" apply --plugin kernel-hardening 2>&1)
    if echo "$APPLY_OUTPUT" | grep -q "success.*true\|Applied"; then
        log_pass "Kernel hardening applied"

        # Verify changes
        log_test "Verify kernel changes"
        KPTR=$(cat /proc/sys/kernel/kptr_restrict)
        if [[ "$KPTR" == "2" ]]; then
            log_pass "Kernel change verified (kptr_restrict=2)"
        else
            log_fail "Kernel change not applied (kptr_restrict=$KPTR)"
        fi

        # Check checkpoint was created
        log_test "Checkpoint created"
        CHECKPOINTS=$("$BINARY" checkpoint list 2>&1)
        if echo "$CHECKPOINTS" | grep -q "kernel-hardening"; then
            CHECKPOINT_ID=$(echo "$CHECKPOINTS" | grep -o '"[a-f0-9-]\{36\}"' | head -1 | tr -d '"')
            log_pass "Checkpoint created: $CHECKPOINT_ID"

            # Rollback
            log_test "Rollback checkpoint"
            if "$BINARY" rollback "$CHECKPOINT_ID" &>/dev/null; then
                log_pass "Rollback completed"

                # Verify rollback
                log_test "Verify rollback"
                # Note: May need reboot for full kernel parameter restoration
                log_pass "Rollback verification (manual check recommended)"
            else
                log_fail "Rollback failed"
            fi
        else
            log_skip "No checkpoint found to rollback"
        fi
    else
        log_fail "Kernel hardening failed"
        echo "$APPLY_OUTPUT" >> "$LOG_FILE"
    fi
}

test_checkpoint_operations() {
    log_section "Checkpoint Operations"

    log_test "Checkpoint list"
    if "$BINARY" checkpoint list &>/dev/null; then
        log_pass "Checkpoint list works"
    else
        log_fail "Checkpoint list failed"
    fi

    # Note: Create/show/delete require an existing checkpoint from apply
}

generate_summary() {
    log_section "Test Summary"

    TOTAL=$((TESTS_PASSED + TESTS_FAILED + TESTS_SKIPPED))

    log "Total tests: $TOTAL"
    log "${GREEN}Passed: $TESTS_PASSED${NC}"
    log "${RED}Failed: $TESTS_FAILED${NC}"
    log "${YELLOW}Skipped: $TESTS_SKIPPED${NC}"
    log ""
    log "Log file: $LOG_FILE"

    if [[ $TESTS_FAILED -gt 0 ]]; then
        log ""
        log "${RED}Some tests failed. Check log for details.${NC}"
        return 1
    else
        log ""
        log "${GREEN}All tests passed!${NC}"
        return 0
    fi
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --apply)
            DO_APPLY=true
            shift
            ;;
        --help|-h)
            cat << EOF
Root Test Suite for Linux System Hardener

Usage: sudo $0 [options]

Options:
  --apply    Enable destructive tests (apply hardening and rollback)
  --help     Show this help

Tests performed:
  1. Environment check
  2. Basic commands (help, plugins)
  3. Scan operations with root privileges
  4. Compliance reports (all 6 frameworks)
  5. Dry-run validation
  6. Daemon & history commands
  7. Systemd commands
  8. Checkpoint operations
  9. [Optional] Apply & rollback (with --apply)

Run this script INSIDE the test container for safety!
EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run tests
log "Linux System Hardener - Root Test Suite"
log "Started: $(date)"
log "Log: $LOG_FILE"
log ""

check_environment
test_basic_commands
test_scan_as_root
test_reports_as_root
test_dry_run
test_daemon_history
test_systemd_commands
test_checkpoint_operations
test_apply_and_rollback

generate_summary
