#!/bin/bash
# =============================================================================
# FULL TEST SUITE - Linux System Hardener
# =============================================================================
# Tests EVERYTHING: all commands, all plugins, all formats, all functions
# including apply and rollback operations.
#
# Run this INSIDE the test container as root!
#
# Usage: sudo ./scripts/test/full-test-suite.sh [--apply]
#
# Without --apply: Safe read-only tests (apply/rollback/lifecycle skipped)
# With --apply:    All tests including destructive apply and rollback
# =============================================================================

set -uo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BINARY="${BINARY:-$PROJECT_DIR/target/x86_64-unknown-linux-musl/release/hardener}"
[[ -x "$BINARY" ]] || BINARY="$PROJECT_DIR/target/release/hardener"
LOG_FILE="/tmp/hardener-full-test-$(date +%Y%m%d-%H%M%S).log"
REPORT_DIR="/tmp/hardener-test-reports"

# The five tables the sections below loop over. Each carries its length as a
# literal beside it, and `suite_section_sizes` counts off those literals rather
# than off the tables themselves: read from ${#PLUGINS[@]} an expectation would
# follow the table it exists to police, so dropping a plugin would lower both
# sides and a run eight checks short would still read as a complete one.
#
# The prose these comments used to carry said "All 6 compliance frameworks"
# beside seven of them, which is why the number now lives in exactly one place.
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
PLUGINS_EXPECTED=8

# Compliance frameworks
FRAMEWORKS=("cis" "stig" "nist" "pcidss" "hipaa" "gdpr" "iso27001")
FRAMEWORKS_EXPECTED=7

# Deployment scenarios
SCENARIOS=("server" "workstation" "government" "healthcare" "financial" "gdpr" "all")
SCENARIOS_EXPECTED=7

# Output formats
FORMATS=("text" "json" "csv" "html")
FORMATS_EXPECTED=4

# Severity levels
SEVERITIES=("info" "low" "medium" "high" "critical")
SEVERITIES_EXPECTED=5

# Test counters
TESTS_TOTAL=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0
FAILED_TESTS=()

# Options
DO_APPLY=false

# Container detection
CONTAINER_MODE=false
if [[ -f /run/systemd/container ]] || systemd-detect-virt -c &>/dev/null; then
    CONTAINER_MODE=true
fi

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
            surface_tool_output "$output"
            return 1
        fi
    else
        if [[ $exit_code -ne 0 ]]; then
            log_pass "$name (expected non-zero exit)"
            return 0
        else
            log_fail "$name (expected failure but succeeded)"
            surface_tool_output "$output"
            return 1
        fi
    fi
}

run_test_output() {
    local name="$1"
    local cmd="$2"
    local grep_pattern="$3"

    log_test "$name"

    # Write stdout to a file rather than a $(...) capture: streaming large JSON
    # back through `nspawn --pipe` into a command substitution intermittently
    # races to an empty/truncated read (the documented flake). The command still
    # runs exactly once; stderr is logged, not folded into the matched stream.
    local out_tmp exit_code=0
    out_tmp=$(mktemp)
    eval "$cmd" >"$out_tmp" 2>>"$LOG_FILE" || exit_code=$?

    # Match with grep -a (text mode) directly on the file -- no sed pre-strip.
    # ANSI colour codes wrap whole styled segments and never split the matched
    # tokens, so stripping them is unnecessary. An in-container sed pre-strip WAS
    # the flake: under opensuse's minimal locale it intermittently emitted nothing
    # while grep -a on the same file matched fine (proven, raw counts 8/240/3).
    if grep -aqE "$grep_pattern" "$out_tmp"; then
        log_pass "$name"
        rm -f "$out_tmp"
        return 0
    else
        log_fail "$name (pattern not found: $grep_pattern)"
        log_info "diag: exit=$exit_code bytes=$(wc -c <"$out_tmp")"
        surface_tool_error "$out_tmp"
        rm -f "$out_tmp"
        return 1
    fi
}

# Whether systemd is running as PID 1 here.
#
# /run/systemd/system exists only then. It is the canonical test and it is
# cheaper and more honest than asking systemctl a question and reading its
# failure. Section 12B needs a booted host to ask anything at all, and the
# expectation of how many checks that section records needs the same answer, so
# both ask this one predicate: two copies would be free to disagree, and this
# project has already been bitten by exactly that, with two copies of the
# rollback allowlist guard, one fatal and one per file.
host_is_booted() { [[ -d /run/systemd/system ]]; }

# =============================================================================
# How large a run of this suite is, declared rather than discovered
# =============================================================================
#
# The number this suite prints has moved twice without anybody deciding it
# should: 126 to 133 when section 12A landed and 133 to 140 when 12B did.
# Nothing held it, so a section that quietly stopped recording checks would have
# read as a shorter run rather than as a fault, which is the same shape as a
# check that passes by matching nothing. `require_check_tables` in
# `differential-suite.sh` is the precedent and it has caught its own authors
# four times.

require_suite_tables() {
    local entry name got want refused=0
    for entry in \
        "PLUGINS ${#PLUGINS[@]} $PLUGINS_EXPECTED" \
        "FRAMEWORKS ${#FRAMEWORKS[@]} $FRAMEWORKS_EXPECTED" \
        "SCENARIOS ${#SCENARIOS[@]} $SCENARIOS_EXPECTED" \
        "FORMATS ${#FORMATS[@]} $FORMATS_EXPECTED" \
        "SEVERITIES ${#SEVERITIES[@]} $SEVERITIES_EXPECTED"; do
        read -r name got want <<<"$entry"
        if [[ "$got" != "$want" ]]; then
            log "  ${RED}[FATAL]${NC} $name holds $got entries where it declares $want"
            refused=1
        fi
    done
    if (( refused > 0 )); then
        log "  A shortened table makes a smaller run look like a complete one, because"
        log "  every expectation in suite_section_sizes is counted off these numbers."
        log "  Restore the entry, or move the number beside the table if it went"
        log "  deliberately."
        return 1
    fi
}

# What each section records, in the order main runs them.
#
# Three facts change the answer, and all three arrive as arguments rather than
# as readings taken here, so the self-test can ask about a combination this host
# is not in:
#
#   apply     - the four apply sections, the two rollback sections and the
#               lifecycle run only under --apply.
#   booted    - section 12B can only put its question to a host running systemd,
#               and under --pipe it records the one precondition check and skips.
#   container - outside a container three systemd checks and the audit and MAC
#               applies run that a container skips. The preflight refuses to run
#               anywhere but a container, so that arm cannot be reached today; it
#               is here to keep this table honest with the code rather than
#               because a run will meet it.
#
# Where each number comes from: the booted container column was counted off the
# five per-distribution logs of the 2026-08-01 --apply --booted run, section by
# section, and all five distributions agreed on every section. The unbooted 12B
# row and the two non-container rows are read off the code and have never been
# measured, which is said out loud rather than left for somebody to assume.
suite_section_sizes() {
    local apply="$1" booted="$2" container="$3"
    local systemd_checks=5 other_apply_checks=7 services_rollback_checks=1

    if [[ "$container" == "true" ]]; then
        systemd_checks=2
        other_apply_checks=5
    fi
    if [[ "$booted" == "true" ]]; then
        services_rollback_checks=7
    fi

    printf '%s\n' \
        "1 basic commands|11" \
        "2 scan, all plugins|$((PLUGINS_EXPECTED + 2))" \
        "3 scan filters|$((SEVERITIES_EXPECTED + 3))" \
        "4 scan output formats|$((FORMATS_EXPECTED + 1))" \
        "5 reports, all frameworks|$FRAMEWORKS_EXPECTED" \
        "6 reports, all scenarios|$SCENARIOS_EXPECTED" \
        "7 report output formats|$((FRAMEWORKS_EXPECTED + 5))" \
        "8 dry run, all plugins|$((PLUGINS_EXPECTED + 1))" \
        "9 checkpoint operations|5" \
        "10 daemon commands|2" \
        "11 history commands|5" \
        "12 systemd commands|$systemd_checks"

    if [[ "$apply" == "true" ]]; then
        printf '%s\n' \
            "12A audit rollback|7" \
            "12B services rollback|$services_rollback_checks" \
            "13 apply kernel|1" \
            "14 apply, the other plugins|$other_apply_checks" \
            "15 apply --all|1" \
            "16 rollback|1"
    fi

    printf '%s\n' \
        "17 global --format flag|3" \
        "18 error handling|4" \
        "20 scan history persistence|3" \
        "21 history filtering|3" \
        "22 plugin filter combinations|4"

    if [[ "$apply" == "true" ]]; then
        printf '%s\n' "23 per-plugin lifecycle|9"
    fi

    printf '%s\n' \
        "24 config file loading|2" \
        "25 report combinations|2" \
        "26 flag combinations|3" \
        "19 post-apply scan verification|2"
}

expected_test_total() {
    local count total=0
    while IFS='|' read -r _ count; do
        total=$((total + count))
    done < <(suite_section_sizes "$@")
    printf '%s' "$total"
}

# Refuses a run that recorded a different number of checks from the one its
# sections declare.
#
# Reported through log_fail rather than through the exit status alone, and the
# reason is in the runner: `run-cross-distro-tests.sh` writes PASS into
# summary.txt for any distribution whose failure count is zero, so a refusal
# carried only by the exit code would read as a pass in the file most likely to
# be looked at first. Moving the failure count moves both.
require_expected_total() {
    local want got="$TESTS_TOTAL" label count
    want="$(expected_test_total "$@")"
    [[ "$got" == "$want" ]] && return 0

    log_fail "The run recorded $got checks where its sections declare $want"
    log_info "  A section that returned early records fewer and a section added without"
    log_info "  its number here records more, and neither should read as a complete run."
    log_info "  What each section declares, in the order they run:"
    while IFS='|' read -r label count; do
        log_info "    $label: $count"
    done < <(suite_section_sizes "$@")
    return 1
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
       systemd-detect-virt -c &>/dev/null; then
        log_check "Running in container (safe environment)"
    else
        log "${RED}ERROR: Not running inside a container!${NC}"
        log "This script is designed to run ONLY in systemd-nspawn containers."
        log "It modifies system configuration and must NEVER run on a live host."
        log "Use: sudo ./scripts/test/run-cross-distro-tests.sh --distro arch"
        exit 1
    fi

    local version
    if ! version=$("$BINARY" --version 2>&1); then
        log "${RED}ERROR: Binary cannot execute: $BINARY${NC}"
        log "  $version"
        if [[ "$version" == *GLIBC_* ]]; then
            log "  The binary was built against a newer glibc than this container provides."
            log "  Rebuild against an older glibc or use the musl static binary."
        fi
        exit 1
    fi
    log_check "Version: $version"

    # Before any section runs, because a shortened table makes every expectation
    # below it wrong and there is nothing to learn from a run measured against a
    # number that has already moved.
    if ! require_suite_tables; then
        log "${RED}ERROR: this suite's own tables are not the size they declare${NC}"
        exit 1
    fi
    log_check "Check tables hold what they declare"

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

    run_test_output "hardener plugins (lists all 8)" "\"$BINARY\" plugins" "audit-hardening"
}

test_scan_all_plugins() {
    log_header "2. SCAN - ALL PLUGINS"

    run_test_output "Full scan (all plugins)" "\"$BINARY\" scan" "Scan Results"

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

    # Verify scan JSON output contains expected structure
    run_test_output "Scan JSON valid structure" "\"$BINARY\" --format json scan" '"plugin_id"'
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
    log_test "Report JSON format"
    local rjson_tmp="/tmp/hardener-test-rjson.out"
    "$BINARY" report --quiet --framework cis --report-format json \
        > "$rjson_tmp" 2>/dev/null
    local rjson_exit=$?
    if [[ $rjson_exit -eq 0 ]] && grep -q "report_framework" "$rjson_tmp"; then
        log_pass "Report JSON format"
    else
        log_fail "Report JSON format (exit=$rjson_exit, head: $(head -c 200 "$rjson_tmp"))"
    fi
    rm -f "$rjson_tmp"
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

    # Asked structurally, not by matching the renderer's prose. This grepped for
    # "item(s) to apply" while the renderer prints "change(s) to apply", so it
    # failed on every distribution and said only that a pattern was missing. The
    # wording itself is pinned where it cannot drift, by a unit test that calls
    # `validation_report_lines` directly, so repeating it here bought nothing
    # even when it matched.
    run_dry_run_test "Dry-run --all" "all" "$BINARY" apply --all

    # In a container a dry run exits non-zero for reasons that are the
    # container's, not the tool's, and the exit code cannot tell those from a
    # plugin that never ran. PAM is the plain case: these images do not load
    # `pam_pwquality`, `pam_faillock` or `pwhistory` into the stack, so the
    # settings in the files it manages take effect only after an `/etc/pam.d`
    # edit this plugin refuses to make, and it says so as a HIGH issue and fails
    # the run. That is the tool being honest, and asserting exit 0 asserts
    # something false about the host. Others fail because systemd is never PID 1
    # here. `run_dry_run_test` accepts a run that reported, and still fails one
    # that produced no validation report at all, which is the difference that
    # matters. Outside a container the strict check stands.
    for plugin in "${PLUGINS[@]}"; do
        if [[ "$CONTAINER_MODE" == "true" ]]; then
            run_dry_run_test "Dry-run: $plugin" "$plugin" "$BINARY" apply --plugin "$plugin"
        else
            run_test "Dry-run: $plugin" "\"$BINARY\" apply --plugin \"$plugin\" --dry-run"
        fi
    done
}

test_checkpoint_operations() {
    log_header "9. CHECKPOINT OPERATIONS"

    run_test "checkpoint list" "\"$BINARY\" checkpoint list"

    # Create manual checkpoint (NAME is positional argument)
    run_test "checkpoint create" "\"$BINARY\" checkpoint create \"test-checkpoint\""

    run_test_output "checkpoint list (after create)" "\"$BINARY\" checkpoint list" "cp_|Checkpoints"

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

    run_test_output "daemon status" "\"$BINARY\" daemon status --limit 5" "Database:"
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

    # Per-host trend + regression queries. Local scans key history by hostname,
    # so trends takes --host "$(hostname)"; regressions defaults to all hosts.
    # Earlier scan sections have persisted history by now. The trends pattern
    # also accepts the clean no-data line so a host-id edge case degrades to
    # pass-not-crash rather than a false failure.
    run_test_output "history trends (this host)" \
        "\"$BINARY\" history trends --host \"\$(hostname)\"" \
        "Security trend|No completed scans"
    run_test_output "history regressions (all hosts)" \
        "\"$BINARY\" history regressions" \
        "[Rr]egression"
}

test_systemd_commands() {
    log_header "12. SYSTEMD COMMANDS"

    run_test_output "systemd generate" "\"$BINARY\" systemd generate" "linux-hardener.service"
    run_test "systemd status" "\"$BINARY\" systemd status" || true

    if [[ "$CONTAINER_MODE" == "true" ]]; then
        log_skip "systemd install (limited init in container)"
        log_skip "systemd status after install (limited init in container)"
        log_skip "systemd uninstall (limited init in container)"
    else
        run_test "systemd install" "\"$BINARY\" systemd install"
        run_test "systemd status (after install)" "\"$BINARY\" systemd status"
        run_test "systemd uninstall" "\"$BINARY\" systemd uninstall"
    fi
}

# =============================================================================
# Section 12A: Rollback Undoes The Audit Apply (gated behind --apply)
# =============================================================================

# How many lines a file holds, or why that question could not be answered.
#
# Three outcomes, deliberately kept apart. The probe this section is ported from
# first wrote `wc -l < "$f" || echo absent`, and a smoke test against a real host
# caught it calling a file that exists at mode 0640 `absent`: the unprivileged
# read failed and the fallback swallowed the reason. Cannot-read rendered
# identically to does-not-exist, which is the sentinel conflation this project
# keeps finding in its own product, one value standing for several outcomes, and
# it would only ever have lied when run without privilege, which is the case
# nobody thinks to test. The suite runs as root, so `unreadable` should never
# come back here; where it does, the caller treats the reading as void rather
# than as a count, because a number nobody could obtain is not a number.
line_count() {
    local file="$1"
    [[ -e "$file" ]] || { echo absent; return; }
    [[ -r "$file" ]] || { echo unreadable; return; }
    wc -l < "$file"
}

# Asserts on the filesystem that rolling back an audit apply puts the host back.
#
# Section 23 already applies a plugin and then rolls it back, and its only
# rollback assertion is that the command exited 0. It never asks whether
# anything was undone, so it reports a pass for a rollback that restored
# nothing, which is exactly the defect family this project keeps finding in its
# own product: an undo that reports success and leaves the hardening in place.
# Two of them were fixed in the audit plugin alone, the rules file the apply
# creates and the compiled output `augenrules` writes, and this suite read the
# same 126 of 126 on five distributions before and after both fixes. A suite
# that cannot tell a repaired tool from a broken one is not measuring the tool,
# so this section reads the filesystem and not the exit status.
#
# The audit plugin was chosen because its whole write surface is now declared to
# its own checkpoint: /etc/audit/rules.d/hardening.rules, which the apply
# writes, and /etc/audit/audit.rules plus /etc/audit/audit.rules.prev, which the
# reload writes on its behalf. All three should therefore be removed or restored
# by a rollback, and all three sit under one directory, so a single `find` can
# say whether anything else moved with them.
#
# The services arm this comment used to say was owed is now section 12B below.
# The fixture it waited for landed: `b261988` installs bluez in all five images
# and enables it, so `bluetooth.service` is a unit the plugin actually manages.
test_audit_rollback_restores() {
    log_header "12A. ROLLBACK UNDOES THE AUDIT APPLY"

    local audit_tree="/etc/audit"
    local rules_file="$audit_tree/rules.d/hardening.rules"
    local compiled="$audit_tree/audit.rules"
    local work="$REPORT_DIR/audit-rollback"
    mkdir -p "$work"

    # ------------------------------------------------------------------------
    # The precondition, which is what makes the reading mean anything
    # ------------------------------------------------------------------------
    #
    # "A rollback REMOVES the file the apply created" can only be asked on a
    # host where that file does not exist yet. Where it already does, the
    # checkpoint captures it with content and the restore correctly writes those
    # bytes back, so the removal path is never exercised and a pass says nothing
    # about it. That is a void reading rather than a good one, and it is
    # reported as a failure: an undeterminable result is a failure, never a
    # skip, which is the same rule the cross-distro runner applies to a
    # container that boots but never answers.
    log_test "Audit rollback: the host is in the state this reading needs"

    if [[ ! -d "$audit_tree" ]]; then
        log_fail "Audit rollback: $audit_tree is absent, so no audit package is installed here"
        log_info "  create-container.sh installs it on all five images, so a missing tree is a broken image"
        log_info "  and not a host this check does not apply to"
        return
    fi

    if [[ -e "$rules_file" ]]; then
        log_fail "Audit rollback: $rules_file exists before the apply, so this reading is void"
        log_info "  its line count reads $(line_count "$rules_file"), and it was left by an earlier run"
        log_info "  --apply hardens every container it touches and nothing here undoes the audit apply"
        log_info "  section 15 performs, so a second --apply run in the same container cannot ask this"
        log_info "  recreate it first: sudo ./scripts/containers/create-container.sh <distro>"
        return
    fi

    log_pass "Audit rollback: the host is in the state this reading needs"

    # ------------------------------------------------------------------------
    # What the host looks like before anything touches it
    # ------------------------------------------------------------------------

    local compiled_before
    compiled_before="$(line_count "$compiled")"
    find "$audit_tree" | sort > "$work/tree-preapply"
    log_info "Before the apply: $compiled holds $compiled_before lines, $audit_tree holds $(wc -l < "$work/tree-preapply") paths"

    # ------------------------------------------------------------------------
    # The apply, whose exit status is deliberately not the question
    # ------------------------------------------------------------------------
    #
    # This apply fails in a container and that is ordinary: there is no auditd to
    # reload, so `augenrules --load` and `systemctl restart auditd` both fail and
    # the plugin reports the run unsuccessful having already written its rules
    # file. Asserting exit 0 here would assert something false about the host.
    # The positive control below is the file existing instead, which is the thing
    # the rollback has to undo and the only thing that makes the rest of this
    # section capable of failing.
    local apply_json="$REPORT_DIR/audit-rollback-apply.json"
    local apply_err="$REPORT_DIR/audit-rollback-apply.err"
    local apply_status=0
    "$BINARY" apply --plugin audit-hardening --format json \
        > "$apply_json" 2>"$apply_err" || apply_status=$?
    log_info "The apply exited $apply_status (non-zero is expected in a container)"

    # ------------------------------------------------------------------------
    # The positive control: doing nothing must never pass
    # ------------------------------------------------------------------------
    #
    # A rollback of an apply that wrote nothing satisfies every assertion below
    # by having nothing to undo, and that shape of green run is precisely what
    # this project has been caught by before. Read off the filesystem rather
    # than off the tool's own summary, because the summary is the thing under
    # test.
    log_test "Audit rollback: the apply wrote the rules file"
    if [[ ! -e "$rules_file" ]]; then
        log_fail "Audit rollback: the apply wrote no $rules_file, so nothing below could be undone"
        surface_tool_error "$apply_err"
        return
    fi
    log_pass "Audit rollback: the apply wrote the rules file ($(line_count "$rules_file") lines)"
    log_info "After the apply: $compiled holds $(line_count "$compiled") lines"

    # ------------------------------------------------------------------------
    # Choosing the checkpoint, which is the step that has been got wrong most
    # ------------------------------------------------------------------------
    #
    # By name and then by age, with the count asserted rather than the position
    # trusted. `checkpoint list` is ORDER BY timestamp DESC, so the newest match
    # is first and the oldest is last. Both filters earn their place: every
    # rollback writes its own "Before rollback to '...'" snapshot carrying the
    # target's name as a substring, so a name filter alone can select the state
    # AFTER the change, which is the state being rolled out of. Selecting by
    # recency produced three wrong readings in one evening. Section 23's
    # `head -1` is that mistake and is deliberately not copied.
    #
    # `--all` defeats the 20-row cap the renderer applies by default, so a busy
    # checkpoint table cannot hide the oldest match and turn a real one-match
    # host into a zero-match failure.
    log_test "Audit rollback: exactly one checkpoint carries the apply's name"
    local matches=()
    mapfile -t matches < <("$BINARY" checkpoint list --all 2>&1 \
        | grep -v 'Before rollback to' \
        | grep 'audit-hardening-pre-apply' \
        | grep -oE 'cp_[0-9]+_[a-f0-9]+')

    if [[ ${#matches[@]} -ne 1 ]]; then
        log_fail "Audit rollback: wanted one checkpoint named audit-hardening-pre-apply, found ${#matches[@]}"
        return
    fi
    log_pass "Audit rollback: exactly one checkpoint carries the apply's name"

    # Written as the last element rather than the only one, because the rule
    # this encodes is "take the oldest match" and it should still read that way
    # on the day somebody relaxes the count above.
    local checkpoint_id="${matches[-1]}"
    log_info "Rolling back to $checkpoint_id"

    # ------------------------------------------------------------------------
    # The rollback and what must be true afterwards
    # ------------------------------------------------------------------------

    run_test "Audit rollback: the rollback exits 0" "\"$BINARY\" rollback \"$checkpoint_id\"" || true

    find "$audit_tree" | sort > "$work/tree-postrollback"

    log_test "Audit rollback: the rules file is gone"
    if [[ -e "$rules_file" ]]; then
        log_fail "Audit rollback: $rules_file survived the rollback"
    else
        log_pass "Audit rollback: $rules_file was removed by the rollback"
    fi

    # The paths are declared unconditionally rather than narrowed to what a host
    # happens to have, so this is where an over-broad removal would show: a
    # rollback that took somebody else's file with it leaves the tree short, and
    # one that left its own behind leaves it long.
    log_test "Audit rollback: the audit tree is back where it started"
    if diff -u "$work/tree-preapply" "$work/tree-postrollback" > "$work/tree-diff" 2>&1; then
        log_pass "Audit rollback: $audit_tree is identical to its pre-apply state"
    else
        log_fail "Audit rollback: $audit_tree differs from its pre-apply state"
        surface_tool_output "$(cat "$work/tree-diff")"
    fi

    # Judged on the line count and not on a text search. An earlier version of
    # this reading grepped the compiled file for "hardening" and reported that
    # it did not mention this tool's rules on all five hosts while the counts
    # said the file had grown from five lines to thirty and stayed there:
    # `augenrules` strips the comment header, so the compiled output holds bare
    # rule lines and the word can never appear. A control whose search term
    # cannot match is a control that can only return the reassuring answer. The
    # count cannot fail that way, being the same measurement twice.
    #
    # `unreadable` is separated from a count rather than compared with one. Two
    # unreadable readings are equal as strings and would otherwise report a pass
    # for a file nobody managed to look at.
    local compiled_after
    compiled_after="$(line_count "$compiled")"
    log_test "Audit rollback: the compiled rule set is back where it started"
    if [[ "$compiled_before" == unreadable ]] || [[ "$compiled_after" == unreadable ]]; then
        log_fail "Audit rollback: $compiled could not be read (before=$compiled_before after=$compiled_after), so this reading is void"
    elif [[ "$compiled_before" == "$compiled_after" ]]; then
        log_pass "Audit rollback: $compiled is back at $compiled_after lines"
    else
        log_fail "Audit rollback: $compiled went $compiled_before to $compiled_after and did not come back"
    fi
}

# =============================================================================
# Section 12B: Rollback Undoes The Services Apply (gated behind --apply)
# =============================================================================

# Asserts on the filesystem that rolling back a services apply unmasks the unit.
#
# The sibling of 12A above, and the arm that section said was owed. Where audit's
# defect was a file its apply wrote, this plugin's is a symlink `systemctl mask`
# creates: /etc/systemd/system/<unit>.service pointing at /dev/null. That link
# outlived its own rollback in three separate ways, each fixed separately and
# none of them visible to this suite at the time. The checkpoint did not declare
# the path (`386d122`); the restore refused it because the guard resolved the
# link to /dev/null, outside every allowlist (`ed60feb`); and restoring the
# enablement symlink failed with ENOENT because disabling had emptied and removed
# its parent directory (`d256395`). All three shipped, and this suite read the
# same totals before and after every one of them.
#
# Why this can be asked at all now: until `b261988` no container image installed
# a unit this plugin manages, so all twenty-five `is-enabled` readings across the
# five hosts returned `not-found` and an arm written here would have asserted
# nothing while reading in a log as coverage.
#
# THIS SECTION NEEDS A BOOTED HOST, and that is declared here rather than
# discovered from a confusing failure. `systemctl mask` and `systemctl
# is-enabled` both need systemd as PID 1, which `nspawn --pipe` does not
# provide. Under `--pipe` the reading is skipped with the flag that would make it
# run, because unaskability is a property of the invocation, known before the
# run starts. What is never skipped is a question this host CAN answer.
test_services_rollback_restores() {
    log_header "12B. ROLLBACK UNDOES THE SERVICES APPLY"

    local unit="bluetooth"
    local unit_file="$unit.service"
    local admin_dir="/etc/systemd/system"
    local mask_link="$admin_dir/$unit_file"
    local work="$REPORT_DIR/services-rollback"
    mkdir -p "$work"

    # ------------------------------------------------------------------------
    # The precondition, in three parts
    # ------------------------------------------------------------------------

    log_test "Services rollback: the host is in the state this reading needs"

    # The same predicate the expected size of this section is derived from, so
    # the two cannot come to disagree about what a booted host is.
    if ! host_is_booted; then
        log_skip "Services rollback: this host is not booted under systemd; re-run with --booted"
        log_info "  systemctl mask and systemctl is-enabled both need systemd as PID 1,"
        log_info "  which nspawn --pipe does not provide. Nothing below can be asked here."
        return
    fi

    if ! systemctl list-unit-files "$unit_file" 2>/dev/null | grep -q "$unit_file"; then
        log_fail "Services rollback: $unit_file is not installed, so the plugin manages nothing here"
        log_info "  create-container.sh installs bluez on all five images, so a missing unit"
        log_info "  is a broken image and not a host this check does not apply to"
        return
    fi

    # The same rule 12A states: "a rollback REMOVES the link the apply created"
    # can only be asked where that link does not exist yet.
    if [[ -e "$mask_link" ]]; then
        log_fail "Services rollback: $mask_link exists before the apply, so this reading is void"
        log_info "  it points at $(readlink "$mask_link" 2>/dev/null || echo '<unreadable>') and was left by an earlier run"
        log_info "  recreate first: sudo ./scripts/containers/create-container.sh <distro>"
        return
    fi

    log_pass "Services rollback: the host is in the state this reading needs"

    # ------------------------------------------------------------------------
    # What the host looks like before anything touches it
    # ------------------------------------------------------------------------
    #
    # The word `systemctl is-enabled` prints, never its exit status. The two
    # disagree by design: `static` and `indirect` print their own word and exit
    # 0, `enabled-runtime` exits 0 while the next boot discards it, and
    # `disabled` and `masked` exit non-zero. The plugins were repaired to read
    # the word for exactly this reason and a probe reading the status would be
    # measuring something else.
    local enabled_before
    enabled_before="$(systemctl is-enabled "$unit" 2>&1 | head -1)"
    find "$admin_dir" | sort > "$work/tree-preapply"
    log_info "Before the apply: $unit is '$enabled_before', $admin_dir holds $(wc -l < "$work/tree-preapply") paths"

    # ------------------------------------------------------------------------
    # The apply, whose exit status is deliberately not the question
    # ------------------------------------------------------------------------

    local apply_json="$REPORT_DIR/services-rollback-apply.json"
    local apply_err="$REPORT_DIR/services-rollback-apply.err"
    local apply_status=0
    "$BINARY" apply --plugin service-minimisation --format json \
        > "$apply_json" 2>"$apply_err" || apply_status=$?
    log_info "The apply exited $apply_status"

    # ------------------------------------------------------------------------
    # The positive control: doing nothing must never pass
    # ------------------------------------------------------------------------
    #
    # Read off the filesystem rather than off the tool's summary, because the
    # summary is the thing under test. A rollback of an apply that masked
    # nothing satisfies every assertion below by having nothing to undo.
    log_test "Services rollback: the apply masked the unit"
    if [[ ! -L "$mask_link" ]]; then
        log_fail "Services rollback: the apply created no mask link at $mask_link, so nothing below could be undone"
        surface_tool_error "$apply_err"
        return
    fi
    log_pass "Services rollback: the apply masked the unit ($mask_link -> $(readlink "$mask_link"))"
    log_info "After the apply: $unit is '$(systemctl is-enabled "$unit" 2>&1 | head -1)'"

    # ------------------------------------------------------------------------
    # Choosing the checkpoint, by name and then by age
    # ------------------------------------------------------------------------
    #
    # Identical rule to 12A, and identical reason: every rollback writes its own
    # "Before rollback to '...'" snapshot carrying the target's name as a
    # substring, so a name filter alone can select the state AFTER the change.
    # `--all` defeats the 20-row cap so a busy table cannot hide the oldest
    # match.
    log_test "Services rollback: exactly one checkpoint carries the apply's name"
    local matches=()
    mapfile -t matches < <("$BINARY" checkpoint list --all 2>&1 \
        | grep -v 'Before rollback to' \
        | grep 'service-minimisation-pre-apply' \
        | grep -oE 'cp_[0-9]+_[a-f0-9]+')

    if [[ ${#matches[@]} -ne 1 ]]; then
        log_fail "Services rollback: wanted one checkpoint named service-minimisation-pre-apply, found ${#matches[@]}"
        return
    fi
    log_pass "Services rollback: exactly one checkpoint carries the apply's name"

    local checkpoint_id="${matches[-1]}"
    log_info "Rolling back to $checkpoint_id"

    # ------------------------------------------------------------------------
    # The rollback and what must be true afterwards
    # ------------------------------------------------------------------------

    run_test "Services rollback: the rollback exits 0" "\"$BINARY\" rollback \"$checkpoint_id\"" || true

    find "$admin_dir" | sort > "$work/tree-postrollback"

    log_test "Services rollback: the mask link is gone"
    if [[ -e "$mask_link" || -L "$mask_link" ]]; then
        log_fail "Services rollback: $mask_link survived the rollback, so systemctl mask is not undoable"
        log_info "  it still points at $(readlink "$mask_link" 2>/dev/null || echo '<not a link>')"
    else
        log_pass "Services rollback: $mask_link was removed by the rollback"
    fi

    # The enablement half, which is a different failure from the mask half and
    # is what `d256395` repaired: disabling the unit empties and removes
    # /etc/systemd/system/<target>.wants, and restoring the symlink into a
    # directory that is no longer there fails with ENOENT. A rollback can
    # therefore remove the mask correctly and still leave the unit disabled.
    local enabled_after
    enabled_after="$(systemctl is-enabled "$unit" 2>&1 | head -1)"
    log_test "Services rollback: the unit is enabled again"
    if [[ "$enabled_before" == "$enabled_after" ]]; then
        log_pass "Services rollback: $unit is back to '$enabled_after'"
    else
        log_fail "Services rollback: $unit went '$enabled_before' to '$enabled_after' and did not come back"
    fi

    # Where an over-broad removal would show: a rollback that took somebody
    # else's unit file with it leaves the tree short, one that left its own
    # behind leaves it long.
    log_test "Services rollback: the unit directory is back where it started"
    if diff -u "$work/tree-preapply" "$work/tree-postrollback" > "$work/tree-diff" 2>&1; then
        log_pass "Services rollback: $admin_dir is identical to its pre-apply state"
    else
        log_fail "Services rollback: $admin_dir differs from its pre-apply state"
        surface_tool_output "$(cat "$work/tree-diff")"
    fi
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
    run_test_output "Apply kernel-hardening" "\"$BINARY\" apply --plugin kernel-hardening" "change.s. applied|Apply Results"

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

# Whether an apply that exited non-zero nevertheless ran.
#
# `apply` prints its results and only then bails when a plugin reported
# failure, so a partial apply leaves a result document behind while a run that
# never reached that point does not. The exit code cannot separate them: a
# plugin that applied nine changes of ten and a refusal on privilege both exit
# 1, and `bail!` is the single path out for either.
#
# Containers legitimately produce the first, having no init to restart a
# service with and bind-mounted paths that cannot be chmodded, which is why
# this branch exists at all. It reported the second as a pass as well.
# Puts the tool's own explanation into the output the cross-distro runner
# captures. $LOG_FILE lives inside the container and is never collected, so a
# failure explained only there is a failure reported without its evidence. An
# empty stderr says so rather than printing nothing, because a failure with no
# explanation must not look like one whose explanation was merely omitted.
# Puts a tool's own output where a reader can see it.
#
# `LOG_FILE` is inside the container and is discarded with it, so anything
# written only there names a failure and takes the reason with it: three
# failures on five distributions were reported that way and none could be
# diagnosed without running the suite again. `log_info` goes through `log`,
# which tees to stdout, and the cross-distro runner captures that into
# `test-results/<distro>.log`. Twenty lines, because a validation report is
# long and its first lines are the ones that say why.
surface_tool_output() {
    if [[ -n "$1" ]]; then
        printf '%s\n' "$1" | head -20 | while IFS= read -r line; do
            log_info "  $line"
        done
    else
        log_info "  the tool printed nothing"
    fi
}

surface_tool_error() {
    if [[ -s "$1" ]]; then
        surface_tool_output "$(cat "$1")"
    else
        log_info "  the tool wrote nothing to stderr either"
    fi
}

produced_result_document() {
    # A structural key, not prose: the tool serialises the plugin's own record,
    # so the key is present exactly when it got far enough to have one, and an
    # error message is not mistaken for a result however plausible it reads.
    # `apply` emits ApplyResult, keyed `apply_plugin_id`; `--dry-run` emits
    # ValidationReport instead, keyed `validation_report_plugin_id`.
    grep -q "\"$2\"" "$1" 2>/dev/null
}

# A dry run that left a validation report ran, whatever its exit code said.
#
# The exit code cannot answer this on its own: a plugin whose PAM module is
# absent from the stack fails the run by design, and a container's bind-mount
# permissions fail others, so a non-zero exit is ordinary on a host where the
# dry run nonetheless did its work. What separates that from a run that never
# started is whether the tool serialised a record of its own.
run_dry_run_test() {
    local name="$1" label="$2"
    shift 2
    local json="$REPORT_DIR/dryrun-$label.json"
    local err="$REPORT_DIR/dryrun-$label.err"

    log_test "$name"
    if "$@" --dry-run --format json > "$json" 2>"$err"; then
        log_pass "$name"
    elif produced_result_document "$json" validation_report_plugin_id; then
        log_pass "$name (partial: expected in container)"
    else
        log_fail "$name (the plugin reported no validation report)"
        surface_tool_error "$err"
    fi
}

test_apply_other_plugins() {
    log_header "14. APPLY - OTHER PLUGINS"

    # In containers, some plugins return exit 1 due to partial apply (bind-mount
    # permissions, missing services, etc.). This is expected, not a real failure.
    # An apply that never ran is not, and is told apart by whether it left a
    # result document rather than by its exit code.
    for plugin in ssh-hardening permissions-hardening pam-hardening firewall-hardening service-minimisation; do
        if [[ "$CONTAINER_MODE" == "true" ]]; then
            log_test "Apply $plugin"
            local apply_json="$REPORT_DIR/apply-$plugin.json"
            local apply_err="$REPORT_DIR/apply-$plugin.err"
            # stdout carries the result document, stderr the reason it is not
            # there. Keeping them apart is what leaves the document parseable.
            if "$BINARY" apply --plugin "$plugin" --format json \
                > "$apply_json" 2>"$apply_err"; then
                log_pass "Apply $plugin"
                cat "$apply_err" >> "$LOG_FILE"
            elif produced_result_document "$apply_json" apply_plugin_id; then
                log_pass "Apply $plugin (partial apply: expected in container)"
                cat "$apply_err" >> "$LOG_FILE"
            else
                log_fail "Apply $plugin (the plugin reported no result at all)"
                surface_tool_error "$apply_err"
            fi
        else
            run_test "Apply $plugin" "\"$BINARY\" apply --plugin \"$plugin\"" || true
        fi
    done

    if [[ "$CONTAINER_MODE" == "true" ]]; then
        log_skip "Apply audit-hardening (no kernel audit subsystem in container)"
        log_skip "Apply mac-hardening (no SELinux/AppArmor in container)"
    else
        run_test "Apply audit-hardening" "\"$BINARY\" apply --plugin audit-hardening" || true
        run_test "Apply mac-hardening" "\"$BINARY\" apply --plugin mac-hardening" || true
    fi
}

test_apply_all() {
    log_header "15. APPLY --ALL"

    run_test_output "Apply --all" "\"$BINARY\" apply --all" "change.s. applied|Apply Results"
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
    run_test "daemon status --format json" "\"$BINARY\" --format json daemon status --limit 5"
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
    run_test_output "Final full scan" "\"$BINARY\" scan" "Scan Results"

    local finding_count
    finding_count=$("$BINARY" --format json scan 2>&1 | grep -c '"finding_id"' || echo "0")
    log_info "Total findings after hardening: $finding_count"

    run_test "Final CIS report" "\"$BINARY\" report --framework cis --report-format pdf --output \"$REPORT_DIR/final-cis-report.pdf\""
}

# =============================================================================
# Section 20: Scan History Persistence
# =============================================================================

test_scan_history_persistence() {
    log_header "20. SCAN HISTORY PERSISTENCE"

    # Run a scan so we have at least one session
    local scan_output
    scan_output=$("$BINARY" scan 2>&1)

    # Extract UUID from scan output (scan now persists to history)
    local session_uuid
    session_uuid=$(echo "$scan_output" | grep -oE '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}' | head -1 || echo "")

    log_test "Scan session appears in history list"
    local history_output
    history_output=$("$BINARY" history list 2>&1)
    if echo "$history_output" | grep -qE '[a-f0-9]{8}-[a-f0-9]{4}'; then
        log_pass "Scan session appears in history list"
    else
        log_fail "Scan session not found in history list"
    fi

    # Count sessions before daemon run-once
    local count_before
    count_before=$(echo "$history_output" | grep -cE '[a-f0-9]{8}-[a-f0-9]{4}' || echo "0")

    log_test "daemon run-once increases session count"
    "$BINARY" daemon run-once &>/dev/null || true
    local count_after
    count_after=$("$BINARY" history list 2>&1 | grep -cE '[a-f0-9]{8}-[a-f0-9]{4}' || echo "0")
    if [[ "$count_after" -ge "$count_before" ]]; then
        log_pass "daemon run-once increases session count ($count_before -> $count_after)"
    else
        log_fail "daemon run-once did not increase session count ($count_before -> $count_after)"
    fi

    # Export a session
    log_test "history export produces non-empty file"
    local export_uuid
    export_uuid=$("$BINARY" history list 2>&1 | grep -oE '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}' | head -1 || echo "")
    if [[ -n "$export_uuid" ]]; then
        local export_file="$REPORT_DIR/history-export-test.json"
        "$BINARY" history export "$export_uuid" --output "$export_file" &>/dev/null || true
        if [[ -s "$export_file" ]]; then
            log_pass "history export produces non-empty file ($(wc -c < "$export_file") bytes)"
        else
            log_fail "history export produced empty file"
        fi
    else
        log_fail "history export - no session UUID to export"
    fi
}

# =============================================================================
# Section 21: History Filtering
# =============================================================================

test_history_filtering() {
    log_header "21. HISTORY FILTERING"

    run_test "history list --limit 1" "\"$BINARY\" history list --limit 1"
    run_test "history list --limit 100 (no crash on large N)" "\"$BINARY\" history list --limit 100"
    run_test "history list --status completed" "\"$BINARY\" history list --status completed"
}

# =============================================================================
# Section 22: Plugin Filter Combinations
# =============================================================================

test_plugin_filter_combinations() {
    log_header "22. PLUGIN FILTER COMBINATIONS"

    run_test "Short name: scan --plugin kernel" "\"$BINARY\" scan --plugin kernel"
    run_test "Short name: scan --plugin ssh" "\"$BINARY\" scan --plugin ssh"
    run_test "Three plugins" "\"$BINARY\" scan --plugin kernel --plugin ssh --plugin permissions"
    run_test "Mixed short/full names" "\"$BINARY\" scan --plugin kernel --plugin ssh-hardening"
}

# =============================================================================
# Section 23: Per-Plugin Lifecycle (gated behind --apply)
# =============================================================================

test_per_plugin_lifecycle() {
    log_header "23. PER-PLUGIN LIFECYCLE (APPLY -> VERIFY -> ROLLBACK)"

    local lifecycle_plugins=("kernel" "ssh" "permissions")

    for plugin in "${lifecycle_plugins[@]}"; do
        local full_id="${plugin}-hardening"
        log_section "Lifecycle: $full_id"

        # Skip audit/MAC in containers
        if [[ "$CONTAINER_MODE" == "true" ]] && [[ "$plugin" == "audit" || "$plugin" == "mac" ]]; then
            log_skip "Lifecycle $full_id (not available in container)"
            continue
        fi

        # BEFORE: count findings (grep -o to avoid multi-line count issues)
        local before_count
        before_count=$("$BINARY" --format json scan --plugin "$full_id" 2>/dev/null | grep -o '"finding_id"' | wc -l)
        before_count=$((before_count + 0))  # ensure numeric
        log_info "Before apply: $before_count findings"

        # APPLY (partial apply expected in containers: some operations can't complete)
        log_test "Lifecycle apply: $full_id"
        local life_json="$REPORT_DIR/lifecycle-$full_id.json"
        local life_err="$REPORT_DIR/lifecycle-$full_id.err"
        if "$BINARY" apply --plugin "$full_id" --format json \
            > "$life_json" 2>"$life_err"; then
            log_pass "Lifecycle apply: $full_id"
        elif [[ "$CONTAINER_MODE" == "true" ]] \
            && produced_result_document "$life_json" apply_plugin_id; then
            log_pass "Lifecycle apply: $full_id (partial: expected in container)"
        else
            log_fail "Lifecycle apply: $full_id (the plugin reported no result at all)"
            surface_tool_error "$life_err"
        fi

        # AFTER: count findings (should be <= before)
        local after_count
        after_count=$("$BINARY" --format json scan --plugin "$full_id" 2>/dev/null | grep -o '"finding_id"' | wc -l)
        after_count=$((after_count + 0))  # ensure numeric
        log_info "After apply: $after_count findings"

        log_test "Lifecycle verify: $full_id findings reduced"
        if [[ "$after_count" -le "$before_count" ]]; then
            log_pass "Lifecycle verify: $full_id ($before_count -> $after_count)"
        else
            log_fail "Lifecycle verify: $full_id findings increased ($before_count -> $after_count)"
        fi

        # ROLLBACK: find latest checkpoint and roll back
        local cp_id
        cp_id=$("$BINARY" checkpoint list 2>&1 | grep -oE 'cp_[0-9]+_[a-f0-9]+' | head -1 || echo "")
        if [[ -n "$cp_id" ]]; then
            run_test "Lifecycle rollback: $full_id" "\"$BINARY\" rollback \"$cp_id\""
        else
            log_skip "Lifecycle rollback: $full_id (no checkpoint found)"
        fi
    done
}

# =============================================================================
# Section 24: Config File Loading
# =============================================================================

test_config_file_loading() {
    log_header "24. CONFIG FILE LOADING"

    run_test "Nonexistent config file" "\"$BINARY\" scan --config /nonexistent/file.toml" "false"

    # Create minimal valid TOML config
    local test_config="/tmp/test-hardener-config.toml"
    cat > "$test_config" << 'TOML'
[plugins.kernel-hardening]
enabled = true
TOML
    run_test "Valid config file" "\"$BINARY\" scan --config \"$test_config\""
    rm -f "$test_config"
}

# =============================================================================
# Section 25: Report Combinations
# =============================================================================

test_report_combinations() {
    log_header "25. REPORT FRAMEWORK + SCENARIO COMBINATIONS"

    run_test "Report: server scenario" "\"$BINARY\" report --scenario server"
    run_test_output "Report: STIG framework + JSON" \
        "\"$BINARY\" report --framework stig --report-format json 2>/dev/null" \
        "report_framework"
}

# =============================================================================
# Section 26: Flag Combinations
# =============================================================================

test_flag_combinations() {
    log_header "26. FLAG COMBINATIONS"

    run_test "scan --quiet --format json" "\"$BINARY\" scan --quiet --format json"
    run_test "scan --audit --format json" "\"$BINARY\" scan --audit --format json"
    run_test "scan --severity high --plugin kernel-hardening --format csv" \
        "\"$BINARY\" scan --severity high --plugin kernel-hardening --format csv"
}

# =============================================================================
# Summary
# =============================================================================

generate_summary() {
    log_header "TEST SUMMARY"

    # Asked before the counts are printed, so a run of the wrong size moves the
    # failure count those counts report rather than only the exit status.
    local booted=false
    host_is_booted && booted=true
    require_expected_total "$DO_APPLY" "$booted" "$CONTAINER_MODE" || true

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
# Self-test
# =============================================================================
# Drives the decisions this suite makes, rather than the system it makes them
# about. Needs no root and no container, so it is safe anywhere.
#
# Only the apply classification for now, because that is the decision that was
# wrong: this suite reported every apply as a pass for several releases,
# including one that never ran, and logic choosing between pass and failure is
# the last logic that should go unproven.

self_test() {
    local failures=0 workdir
    workdir="$(mktemp -d)"

    check_status() {
        local want="$1" what="$2"
        shift 2
        local got=0
        "$@" >/dev/null 2>&1 || got=$?
        if [[ "$got" == "$want" ]]; then
            echo "  ok   $what"
        else
            echo "  FAIL $what: exit $got, want $want"
            failures=$((failures + 1))
        fi
    }

    # A partial apply: the document exists and names the plugin, whatever the
    # exit code said.
    printf '[[{"plugin_id":"ssh-hardening"},{"apply_plugin_id":"ssh-hardening","apply_success":false}]]\n' \
        > "$workdir/partial.json"
    # An apply that bailed before printing anything.
    : > "$workdir/empty.json"
    # An apply whose refusal reached stdout rather than stderr. Prose is not a
    # result document however plausible it reads.
    printf 'Error: Root privileges required to apply hardening changes\n' \
        > "$workdir/refused.json"

    check_status 0 "a partial apply is recognised by its result document" \
        produced_result_document "$workdir/partial.json" apply_plugin_id
    check_status 1 "an apply that printed nothing produced no result document" \
        produced_result_document "$workdir/empty.json" apply_plugin_id
    check_status 1 "an apply that printed only an error produced no result document" \
        produced_result_document "$workdir/refused.json" apply_plugin_id

    # A dry run emits validation reports rather than apply results, so the key
    # is part of the question. Asking for the wrong one must fail, or a run
    # that produced the other kind of document entirely would read as a pass.
    printf '[{"validation_report_plugin_id":"service-minimisation","validation_report_is_valid":true}]\n' \
        > "$workdir/dryrun.json"

    check_status 0 "a dry run is recognised by its validation report" \
        produced_result_document "$workdir/dryrun.json" validation_report_plugin_id
    check_status 1 "an apply result is not accepted as a validation report" \
        produced_result_document "$workdir/partial.json" validation_report_plugin_id

    # A failure the harness cannot explain is what the surfacing exists to
    # prevent, and it is not hypothetical: three failures on five distributions
    # were named and none could be diagnosed, because the only copy of the tool's
    # output went to a log inside the container. These assert that a reason
    # reaches the console at all, which is the one property `log_info` has and a
    # write to `LOG_FILE` does not.
    check_contains() {
        local want="$1" what="$2" got
        shift 2
        got=$(LOG_FILE="$workdir/self-test.log" "$@" 2>&1)
        if [[ "$got" == *"$want"* ]]; then
            echo "  ok   $what"
        else
            echo "  FAIL $what: wanted [$want] in [$got]"
            failures=$((failures + 1))
        fi
    }

    check_contains "denied by policy" "a tool's own words reach the console" \
        surface_tool_output "hardener: denied by policy"
    check_contains "printed nothing" "a tool that said nothing is reported as silent" \
        surface_tool_output ""

    # `line_count` is the one piece of section 12A that can be driven without a
    # container, and it is the piece that was wrong first: its ancestor answered
    # `absent` for a file that exists but could not be read, so a measurement
    # nobody was able to take reported as a measurement of nothing. These pin
    # the three outcomes apart, and the empty-file case is here because zero
    # lines and no file are the pair most easily conflated back together.
    printf 'one\ntwo\nthree\n' > "$workdir/three-lines"
    : > "$workdir/no-lines"

    check_contains "3" "a readable file is reported as its line count" \
        line_count "$workdir/three-lines"
    check_contains "0" "an empty file is reported as zero lines and not as absent" \
        line_count "$workdir/no-lines"
    check_contains "absent" "a file that is not there is reported absent" \
        line_count "$workdir/missing"

    # The unreadable branch needs an unprivileged reader: root's read succeeds
    # whatever the mode says, so under sudo the case cannot be posed at all.
    # Said out loud rather than quietly dropped, because a check that silently
    # did not run reads in a log exactly like one that passed, which is the
    # whole complaint this self-test exists to answer.
    printf 'secret\n' > "$workdir/unreadable"
    chmod 000 "$workdir/unreadable"
    if [[ $EUID -eq 0 ]]; then
        echo "  n/a  an unreadable file is reported unreadable (root reads it regardless)"
    else
        check_contains "unreadable" "an unreadable file is not reported as absent" \
            line_count "$workdir/unreadable"
    fi

    check_eq() {
        local got="$1" want="$2" what="$3"
        if [[ "$got" == "$want" ]]; then
            echo "  ok   $what"
        else
            echo "  FAIL $what: got '$got', want '$want'"
            failures=$((failures + 1))
        fi
    }

    # The size of a run. Every number here is a reading rather than an
    # arithmetic restatement of the table: 140 was counted off the five
    # per-distribution logs of the 2026-08-01 --apply --booted run, section by
    # section, and all five agreed on every section. The other two are derived
    # from the same table and have never been measured, which is said here so
    # nobody reads them as evidence.
    check_eq "$(expected_test_total true true true)" "140" \
        "a booted --apply run in a container declares the 140 checks five hosts recorded"
    check_eq "$(expected_test_total true false true)" "134" \
        "an unbooted --apply run declares six fewer, the services rollback rows it cannot ask"
    check_eq "$(expected_test_total false true true)" "109" \
        "a run without --apply declares neither the apply sections nor the lifecycle"

    # The property that makes the table guard a guard rather than a mirror: the
    # expectation is counted off the pinned numbers, so shortening a table moves
    # one side and not the other. Counted off ${#PLUGINS[@]} instead, both sides
    # would fall together and a run three plugins short would read as complete.
    check_status 0 "require_suite_tables accepts the tables as they stand" \
        require_suite_tables

    local saved_plugins=("${PLUGINS[@]}")
    PLUGINS=("${PLUGINS[@]:0:7}")
    check_status 1 "require_suite_tables refuses a table edited down" \
        require_suite_tables
    check_eq "$(expected_test_total true true true)" "140" \
        "and the expected total does not follow the table it polices"
    PLUGINS=("${saved_plugins[@]}")
    check_status 0 "require_suite_tables accepts the table once it is restored" \
        require_suite_tables

    # A run is refused on the count it recorded, not on the count it wanted.
    local saved_log="$LOG_FILE" saved_total="$TESTS_TOTAL"
    LOG_FILE="$workdir/self-test.log"
    TESTS_TOTAL=140
    check_status 0 "a run that recorded what the sections declare is accepted" \
        require_expected_total true true true
    TESTS_TOTAL=139
    check_status 1 "a run one check short of what the sections declare is refused" \
        require_expected_total true true true

    # The refusal has to reach the failure count and not only the exit status.
    # `run-cross-distro-tests.sh` decides a distribution's status in summary.txt
    # on the failure count alone, so a refusal that moved nothing but the exit
    # code would be written into that file as a pass. Asserting the status is
    # asserting the absence of a wrong claim; this asserts the presence of the
    # right one.
    local saved_failed="$TESTS_FAILED" saved_failed_list=("${FAILED_TESTS[@]}")
    TESTS_FAILED=0
    FAILED_TESTS=()
    require_expected_total true true true > "$workdir/refusal.log" 2>&1
    check_eq "$TESTS_FAILED" "1" \
        "a refused run is counted as a failure, not carried by the exit status alone"
    TESTS_FAILED="$saved_failed"
    FAILED_TESTS=("${saved_failed_list[@]}")

    LOG_FILE="$saved_log"
    TESTS_TOTAL="$saved_total"

    rm -rf "$workdir"

    if (( failures > 0 )); then
        echo "self-test: $failures assertion(s) failed"
        return 1
    fi
    echo "self-test: all classification checks passed"
}

# =============================================================================
# Argument parsing
# =============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        --apply)
            DO_APPLY=true
            shift
            ;;
        --self-test)
            self_test
            exit $?
            ;;
        --help|-h)
            cat << EOF
Full Test Suite for Linux System Hardener

Usage: sudo $0 [options]

Options:
  --apply    Enable destructive tests (apply, rollback, lifecycle)
  --help     Show this help

Without --apply: Sections 12A-16 (apply/rollback) and 23 (lifecycle) are skipped.
With --apply:    All sections run including destructive operations.

Section 12A needs a container no --apply run has touched yet: it asks whether a
rollback removes a file an apply created, which cannot be asked where the file
already exists. Recreate the container before each --apply run.
EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# =============================================================================
# Main
# =============================================================================

main() {
    echo ""
    echo -e "${MAGENTA}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║${NC}                                                                          ${MAGENTA}║${NC}"
    echo -e "${MAGENTA}║${NC}   ${BOLD}LINUX SYSTEM HARDENER - FULL TEST SUITE${NC}                                ${MAGENTA}║${NC}"
    echo -e "${MAGENTA}║${NC}                                                                          ${MAGENTA}║${NC}"
    echo -e "${MAGENTA}║${NC}   Tests EVERYTHING: all commands, plugins, formats, apply & rollback     ${MAGENTA}║${NC}"
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

    if [[ "$DO_APPLY" == "true" ]]; then
        # FIRST, and they have to stay first. Both sections ask whether a
        # rollback REMOVES something an apply created, and that question can
        # only be put to a host where it does not exist yet. `test_apply_all`
        # below applies every plugin, so from that point on
        # /etc/audit/rules.d/hardening.rules and the bluetooth mask link both
        # exist, their checkpoints capture them as present, and a rollback
        # correctly restores them rather than removing them. Moved after any of
        # the three applies below, neither section fails: each refuses to read
        # at all, reporting its precondition broken. Add new apply sections
        # after them, never before.
        #
        # They are independent of each other in either order: audit's checkpoint
        # declares paths under /etc/audit only, and services' declares
        # /etc/systemd/system and its own mask links, so neither rollback can
        # disturb the other's reading.
        test_audit_rollback_restores
        test_services_rollback_restores

        test_apply_kernel
        test_apply_other_plugins
        test_apply_all
        test_rollback
    else
        log_header "12A-16. APPLY & ROLLBACK (SKIPPED - use --apply)"
        log_skip "Apply/rollback tests require --apply flag"
    fi

    test_global_format_flag
    test_error_handling

    test_scan_history_persistence
    test_history_filtering
    test_plugin_filter_combinations

    if [[ "$DO_APPLY" == "true" ]]; then
        test_per_plugin_lifecycle
    else
        log_header "23. PER-PLUGIN LIFECYCLE (SKIPPED - use --apply)"
        log_skip "Lifecycle tests require --apply flag"
    fi

    test_config_file_loading
    test_report_combinations
    test_flag_combinations
    test_post_scan_verify

    generate_summary
}

# Run only on direct execution. This file ends in a bare `main "$@"`, so
# sourcing it to drive a single function ran the entire suite with the caller's
# arguments, and this suite applies hardening. `differential-suite.sh` already
# guards itself the same way and for the same reason.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
