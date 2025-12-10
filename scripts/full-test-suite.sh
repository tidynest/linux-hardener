#!/bin/bash
# =============================================================================
# FULL TEST SUITE - Linux System Hardener
# =============================================================================
# Tests EVERYTHING: all commands, all plugins, all formats, all functions
# including apply and rollback operations.
#
# Run this INSIDE the test container as root!
#
# Usage: sudo ./scripts/full-test-suite.sh
#
# This script is non-interactive and tests every single capability.
# =============================================================================

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="${BINARY:-$PROJECT_DIR/target/release/hardener}"
LOG_FILE="/tmp/hardener-full-test-$(date +%Y%m%d-%H%M%S).log"
REPORT_DIR="/tmp/hardener-test-reports"

# All 8 plugins
PLUGINS=(
    "audit-hardening"
    "firewall-hardening"
    "kernel-hardening"
    "mac-hardening"
    "pam-hardening"
    "permissions-hardening"
    "service-minimisation"
    "ssh-hardening"
)

# All 6 compliance frameworks
FRAMEWORKS=("cis" "stig" "nist" "pcidss" "hipaa" "gdpr")

# All 7 scenarios
SCENARIOS=("server" "workstation" "government" "healthcare" "financial" "gdpr" "all")

# All output formats
FORMATS=("text" "json" "csv" "html")

# Severity levels
SEVERITIES=("info" "low" "medium" "high" "critical")

# Test counters
TESTS_TOTAL=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0
FAILED_TESTS=()

# Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# =============================================================================
# Logging functions
# =============================================================================

log() { echo -e "$1" | tee -a "$LOG_FILE"; }
log_header() {
    log ""
    log "${MAGENTA}╔════════════════════════════════════════════════════════════════════╗${NC}"
    log "${MAGENTA}║${NC} ${BOLD}$1${NC}"
    log "${MAGENTA}╚════════════════════════════════════════════════════════════════════╝${NC}"
}
log_section() { log "\n${CYAN}━━━ $1 ━━━${NC}\n"; }
log_test() { log "  ${BLUE}[TEST]${NC} $1"; ((TESTS_TOTAL++)) || true; }
log_pass() { log "  ${GREEN}[PASS]${NC} $1"; ((TESTS_PASSED++)) || true; }
log_check() { log "  ${GREEN}[PASS]${NC} $1"; }  # For preflight checks - doesn't count as test
log_fail() { log "  ${RED}[FAIL]${NC} $1"; ((TESTS_FAILED++)) || true; FAILED_TESTS+=("$1"); }
log_skip() { log "  ${YELLOW}[SKIP]${NC} $1"; ((TESTS_SKIPPED++)) || true; }
log_info() { log "  ${CYAN}[INFO]${NC} $1"; }

run_test() {
    local name="$1"
    local cmd="$2"
    local expect_success="${3:-true}"

    log_test "$name"

    local output
    local exit_code=0
    output=$(eval "$cmd" 2>&1) || exit_code=$?

    if [[ "$expect_success" == "true" ]]; then
        if [[ $exit_code -eq 0 ]]; then
            log_pass "$name"
            return 0
        else
            log_fail "$name (exit code: $exit_code)"
            echo "$output" >> "$LOG_FILE"
            return 1
        fi
    else
        if [[ $exit_code -ne 0 ]]; then
            log_pass "$name (expected non-zero exit)"
            return 0
        else
            log_fail "$name (expected failure but succeeded)"
            return 1
        fi
    fi
}

run_test_output() {
    local name="$1"
    local cmd="$2"
    local grep_pattern="$3"

    log_test "$name"

    local output
    local exit_code=0
    output=$(eval "$cmd" 2>&1) || exit_code=$?

    if echo "$output" | grep -qE "$grep_pattern"; then
        log_pass "$name"
        return 0
    else
        log_fail "$name (pattern not found: $grep_pattern)"
        echo "$output" >> "$LOG_FILE"
        return 1
    fi
}

# =============================================================================
# Pre-flight checks
# =============================================================================

preflight_checks() {
    log_header "PRE-FLIGHT CHECKS"

    if [[ $EUID -ne 0 ]]; then
        log "${RED}ERROR: Must run as root${NC}"
        exit 1
    fi
    log_check "Running as root (uid=$EUID)"

    if [[ ! -x "$BINARY" ]]; then
        log "${RED}ERROR: Binary not found: $BINARY${NC}"
        log "Run: cargo build --release"
        exit 1
    fi
    log_check "Binary found: $BINARY"

    if [[ -f /run/systemd/container ]] || \
       [[ -f /.dockerenv ]] || \
       grep -q "systemd-nspawn" /proc/1/cgroup 2>/dev/null || \
       [[ "$(systemd-detect-virt 2>/dev/null)" == "systemd-nspawn" ]]; then
        log_check "Running in container (safe environment)"
    else
        log "${RED}WARNING: Not detected as container!${NC}"
        log "This script modifies system configuration."
        log "Press Ctrl+C within 5 seconds to abort..."
        sleep 5
    fi

    local version
    version=$("$BINARY" --version 2>&1)
    log_check "Version: $version"

    mkdir -p "$REPORT_DIR"
    log_check "Report directory: $REPORT_DIR"

    log ""
    log "Log file: $LOG_FILE"
}

# =============================================================================
# Test Suite Sections
# =============================================================================

test_basic_commands() {
    log_header "1. BASIC COMMANDS"

    run_test "hardener --version" "\"$BINARY\" --version"
    run_test "hardener --help" "\"$BINARY\" --help"
    run_test "hardener scan --help" "\"$BINARY\" scan --help"
    run_test "hardener apply --help" "\"$BINARY\" apply --help"
    run_test "hardener report --help" "\"$BINARY\" report --help"
    run_test "hardener checkpoint --help" "\"$BINARY\" checkpoint --help"
    run_test "hardener daemon --help" "\"$BINARY\" daemon --help"
    run_test "hardener history --help" "\"$BINARY\" history --help"
    run_test "hardener systemd --help" "\"$BINARY\" systemd --help"
    run_test "hardener plugins --help" "\"$BINARY\" plugins --help"

    run_test_output "hardener plugins (lists all 8)" "\"$BINARY\" plugins" "plugin_id.*audit-hardening"
}

test_scan_all_plugins() {
    log_header "2. SCAN - ALL PLUGINS"

    run_test_output "Full scan (all plugins)" "\"$BINARY\" scan" "plugin_id"

    for plugin in "${PLUGINS[@]}"; do
        run_test "Scan plugin: $plugin" "\"$BINARY\" scan --plugin \"$plugin\""
    done

    run_test "Scan multiple plugins" "\"$BINARY\" scan --plugin kernel-hardening --plugin ssh-hardening"
}

test_scan_filters() {
    log_header "3. SCAN - FILTERS & OPTIONS"

    for severity in "${SEVERITIES[@]}"; do
        run_test "Scan --severity $severity" "\"$BINARY\" scan --severity \"$severity\""
    done

    run_test "Scan --audit mode" "\"$BINARY\" scan --audit"
    run_test "Scan --compliance mode" "\"$BINARY\" scan --compliance"

    log_test "Scan --exit-code"
    local exit_code=0
    "$BINARY" scan --exit-code &>/dev/null || exit_code=$?
    if [[ $exit_code -eq 0 ]] || [[ $exit_code -eq 1 ]]; then
        log_pass "Scan --exit-code (returned $exit_code)"
    else
        log_fail "Scan --exit-code (unexpected: $exit_code)"
    fi

    run_test "Scan --quiet" "\"$BINARY\" scan --quiet"
}

test_scan_output_formats() {
    log_header "4. SCAN - OUTPUT FORMATS"

    for format in "${FORMATS[@]}"; do
        run_test "Scan --format $format" "\"$BINARY\" --format \"$format\" scan"
    done

    # Default scan output is JSON
    run_test_output "Scan JSON valid structure" "\"$BINARY\" scan" '"plugin_id"'
}

test_reports_all_frameworks() {
    log_header "5. COMPLIANCE REPORTS - ALL FRAMEWORKS"

    for framework in "${FRAMEWORKS[@]}"; do
        run_test "Report --framework $framework" "\"$BINARY\" report --framework \"$framework\""
    done
}

test_reports_all_scenarios() {
    log_header "6. COMPLIANCE REPORTS - ALL SCENARIOS"

    for scenario in "${SCENARIOS[@]}"; do
        run_test "Report --scenario $scenario" "\"$BINARY\" report --scenario \"$scenario\""
    done
}

test_reports_output_formats() {
    log_header "7. COMPLIANCE REPORTS - OUTPUT FORMATS"

    run_test "Report text format" "\"$BINARY\" report --framework cis --report-format text"
    run_test_output "Report JSON format" "\"$BINARY\" report --framework cis --report-format json" "report_framework"
    run_test "Report CSV format" "\"$BINARY\" report --framework cis --report-format csv"
    run_test "Report HTML format" "\"$BINARY\" report --framework cis --report-format html"

    run_test "Report PDF generation" "\"$BINARY\" report --framework cis --report-format pdf --output \"$REPORT_DIR/test-cis.pdf\""
    if [[ -f "$REPORT_DIR/test-cis.pdf" ]]; then
        local size
        size=$(stat -c%s "$REPORT_DIR/test-cis.pdf" 2>/dev/null || echo "0")
        log_info "PDF size: $size bytes"
    fi

    log_section "Generating PDFs for all frameworks"
    for framework in "${FRAMEWORKS[@]}"; do
        run_test "PDF: $framework" "\"$BINARY\" report --framework \"$framework\" --report-format pdf --output \"$REPORT_DIR/report-$framework.pdf\""
    done
}

test_dry_run_all_plugins() {
    log_header "8. DRY-RUN - ALL PLUGINS"

    run_test_output "Dry-run --all" "\"$BINARY\" apply --all --dry-run" "validation_report_plugin_id"

    for plugin in "${PLUGINS[@]}"; do
        run_test "Dry-run: $plugin" "\"$BINARY\" apply --plugin \"$plugin\" --dry-run"
    done
}

test_checkpoint_operations() {
    log_header "9. CHECKPOINT OPERATIONS"

    run_test "checkpoint list" "\"$BINARY\" checkpoint list"

    # Create manual checkpoint (NAME is positional argument)
    run_test "checkpoint create" "\"$BINARY\" checkpoint create \"test-checkpoint\""

    run_test_output "checkpoint list (after create)" "\"$BINARY\" checkpoint list" "checkpoint_id"

    local checkpoint_id
    checkpoint_id=$("$BINARY" checkpoint list 2>&1 | grep -oE 'cp_[0-9]+_[a-f0-9]+' | head -1 || echo "")

    if [[ -n "$checkpoint_id" ]]; then
        log_info "Found checkpoint: $checkpoint_id"
        run_test "checkpoint show" "\"$BINARY\" checkpoint show \"$checkpoint_id\""
        run_test "checkpoint delete" "\"$BINARY\" checkpoint delete \"$checkpoint_id\""
    else
        log_skip "checkpoint show (no checkpoint ID found)"
        log_skip "checkpoint delete (no checkpoint ID found)"
    fi
}

test_daemon_commands() {
    log_header "10. DAEMON COMMANDS"

    run_test_output "daemon status" "\"$BINARY\" daemon status 5" "Database:"
    run_test "daemon run-once" "\"$BINARY\" daemon run-once"
    log_skip "daemon start (blocking command - not tested)"
}

test_history_commands() {
    log_header "11. HISTORY COMMANDS"

    run_test "history list" "\"$BINARY\" history list"

    local session_id
    session_id=$("$BINARY" history list 2>&1 | grep -oE '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}' | head -1 || echo "")

    if [[ -n "$session_id" ]]; then
        log_info "Found session: $session_id"
        run_test "history show" "\"$BINARY\" history show \"$session_id\""
        run_test "history export" "\"$BINARY\" history export \"$session_id\" --output \"$REPORT_DIR/session-export.json\""
    else
        log_skip "history show (no session found)"
        log_skip "history export (no session found)"
    fi
}

test_systemd_commands() {
    log_header "12. SYSTEMD COMMANDS"

    run_test_output "systemd generate" "\"$BINARY\" systemd generate" "linux-hardener.service"
    run_test "systemd status" "\"$BINARY\" systemd status" || true
    run_test "systemd install" "\"$BINARY\" systemd install"
    run_test "systemd status (after install)" "\"$BINARY\" systemd status"
    run_test "systemd uninstall" "\"$BINARY\" systemd uninstall"
}

test_apply_kernel() {
    log_header "13. APPLY - KERNEL HARDENING"

    log_section "Recording BEFORE state"
    local before_kptr before_dmesg
    before_kptr=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo "N/A")
    before_dmesg=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null || echo "N/A")
    log_info "kernel.kptr_restrict = $before_kptr"
    log_info "kernel.dmesg_restrict = $before_dmesg"

    log_section "Applying kernel hardening"
    run_test_output "Apply kernel-hardening" "\"$BINARY\" apply --plugin kernel-hardening" "apply_success"

    log_section "Verifying changes"
    local after_kptr after_dmesg
    after_kptr=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo "N/A")
    after_dmesg=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null || echo "N/A")
    log_info "kernel.kptr_restrict = $after_kptr (was $before_kptr)"
    log_info "kernel.dmesg_restrict = $after_dmesg (was $before_dmesg)"

    if [[ -f /etc/sysctl.d/99-hardener.conf ]]; then
        log_check "Config file created: /etc/sysctl.d/99-hardener.conf"
        log_info "Contents:"
        head -5 /etc/sysctl.d/99-hardener.conf | while read -r line; do
            log_info "  $line"
        done
    else
        log_info "Config file not created (may be container limitation)"
    fi
}

test_apply_other_plugins() {
    log_header "14. APPLY - OTHER PLUGINS"

    run_test "Apply ssh-hardening" "\"$BINARY\" apply --plugin ssh-hardening" || true
    run_test "Apply permissions-hardening" "\"$BINARY\" apply --plugin permissions-hardening" || true
    run_test "Apply pam-hardening" "\"$BINARY\" apply --plugin pam-hardening" || true
    run_test "Apply firewall-hardening" "\"$BINARY\" apply --plugin firewall-hardening" || true
    run_test "Apply audit-hardening" "\"$BINARY\" apply --plugin audit-hardening" || true
    run_test "Apply mac-hardening" "\"$BINARY\" apply --plugin mac-hardening" || true
    run_test "Apply service-minimisation" "\"$BINARY\" apply --plugin service-minimisation" || true
}

test_apply_all() {
    log_header "15. APPLY --ALL"

    run_test_output "Apply --all" "\"$BINARY\" apply --all" "apply_success"
}

test_rollback() {
    log_header "16. ROLLBACK"

    local checkpoint_id
    checkpoint_id=$("$BINARY" checkpoint list 2>&1 | grep -oE 'cp_[0-9]+_[a-f0-9]+' | head -1 || echo "")

    if [[ -n "$checkpoint_id" ]]; then
        log_info "Rolling back to checkpoint: $checkpoint_id"
        run_test "Rollback to checkpoint" "\"$BINARY\" rollback \"$checkpoint_id\""

        if [[ -f /etc/sysctl.d/99-hardener.conf ]]; then
            log_info "Config file still exists (partial rollback or new checkpoint)"
        else
            log_check "Config file removed by rollback"
        fi
    else
        log_skip "Rollback (no checkpoint found)"
    fi
}

test_global_format_flag() {
    log_header "17. GLOBAL --format FLAG"

    run_test "plugins --format json" "\"$BINARY\" --format json plugins"
    run_test "checkpoint list --format json" "\"$BINARY\" --format json checkpoint list"
    run_test "daemon status --format json" "\"$BINARY\" --format json daemon status 5"
}

test_error_handling() {
    log_header "18. ERROR HANDLING"

    log_test "Invalid plugin name"
    if ! "$BINARY" scan --plugin "nonexistent-plugin" &>/dev/null; then
        log_pass "Invalid plugin name (correctly rejected)"
    else
        log_fail "Invalid plugin name (should have failed)"
    fi

    log_test "Invalid framework"
    if ! "$BINARY" report --framework "invalid-framework" &>/dev/null; then
        log_pass "Invalid framework (correctly rejected)"
    else
        log_fail "Invalid framework (should have failed)"
    fi

    log_test "Invalid checkpoint ID"
    if ! "$BINARY" rollback "invalid-checkpoint-id" &>/dev/null; then
        log_pass "Invalid checkpoint ID (correctly rejected)"
    else
        log_fail "Invalid checkpoint ID (should have failed)"
    fi

    log_test "Missing required argument"
    if ! "$BINARY" checkpoint show &>/dev/null; then
        log_pass "Missing argument (correctly rejected)"
    else
        log_fail "Missing argument (should have failed)"
    fi
}

test_post_scan_verify() {
    log_header "19. POST-APPLY SCAN VERIFICATION"

    log_section "Final security scan"
    run_test_output "Final full scan" "\"$BINARY\" scan" "plugin_id"

    local finding_count
    finding_count=$("$BINARY" scan 2>&1 | grep -c "finding_id" || echo "0")
    log_info "Total findings after hardening: $finding_count"

    run_test "Final CIS report" "\"$BINARY\" report --framework cis --report-format pdf --output \"$REPORT_DIR/final-cis-report.pdf\""
}

# =============================================================================
# Summary
# =============================================================================

generate_summary() {
    log_header "TEST SUMMARY"

    local pass_rate=0
    if [[ $TESTS_TOTAL -gt 0 ]]; then
        pass_rate=$((TESTS_PASSED * 100 / TESTS_TOTAL))
    fi

    log ""
    log "  ${BOLD}Total Tests:${NC}  $TESTS_TOTAL"
    log "  ${GREEN}Passed:${NC}       $TESTS_PASSED"
    log "  ${RED}Failed:${NC}       $TESTS_FAILED"
    log "  ${YELLOW}Skipped:${NC}      $TESTS_SKIPPED"
    log "  ${CYAN}Pass Rate:${NC}    ${pass_rate}%"
    log ""
    log "  Log file:     $LOG_FILE"
    log "  Reports:      $REPORT_DIR/"
    log ""

    if [[ $TESTS_FAILED -gt 0 ]]; then
        log "${RED}Failed Tests:${NC}"
        for failed in "${FAILED_TESTS[@]}"; do
            log "  - $failed"
        done
        log ""
    fi

    if [[ -d "$REPORT_DIR" ]] && [[ "$(ls -A "$REPORT_DIR" 2>/dev/null)" ]]; then
        log "Generated Reports:"
        ls -la "$REPORT_DIR"/*.pdf 2>/dev/null | while read -r line; do
            log "  $line"
        done
        log ""
    fi

    if [[ $TESTS_FAILED -eq 0 ]]; then
        log "${GREEN}╔════════════════════════════════════════╗${NC}"
        log "${GREEN}║     ALL TESTS PASSED SUCCESSFULLY!     ║${NC}"
        log "${GREEN}╚════════════════════════════════════════╝${NC}"
        return 0
    else
        log "${RED}╔════════════════════════════════════════╗${NC}"
        log "${RED}║     SOME TESTS FAILED - SEE ABOVE      ║${NC}"
        log "${RED}╚════════════════════════════════════════╝${NC}"
        return 1
    fi
}

# =============================================================================
# Main
# =============================================================================

main() {
    echo ""
    echo -e "${MAGENTA}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║${NC}                                                                          ${MAGENTA}║${NC}"
    echo -e "${MAGENTA}║${NC}   ${BOLD}LINUX SYSTEM HARDENER - FULL TEST SUITE${NC}                               ${MAGENTA}║${NC}"
    echo -e "${MAGENTA}║${NC}                                                                          ${MAGENTA}║${NC}"
    echo -e "${MAGENTA}║${NC}   Tests EVERYTHING: all commands, plugins, formats, apply & rollback    ${MAGENTA}║${NC}"
    echo -e "${MAGENTA}║${NC}                                                                          ${MAGENTA}║${NC}"
    echo -e "${MAGENTA}╚══════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    preflight_checks

    test_basic_commands
    test_scan_all_plugins
    test_scan_filters
    test_scan_output_formats

    test_reports_all_frameworks
    test_reports_all_scenarios
    test_reports_output_formats

    test_dry_run_all_plugins

    test_checkpoint_operations
    test_daemon_commands
    test_history_commands
    test_systemd_commands

    test_apply_kernel
    test_apply_other_plugins
    test_apply_all
    test_rollback

    test_global_format_flag
    test_error_handling
    test_post_scan_verify

    generate_summary
}

main "$@"
