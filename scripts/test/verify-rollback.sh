#!/bin/bash
# =============================================================================
# ROLLBACK VERIFICATION SCRIPT
# =============================================================================
# Thorough verification that checkpoint/rollback actually restores file contents
# and runtime kernel parameters to their pre-apply state.
#
# Run INSIDE a test container as root:
#   sudo ./scripts/test/verify-rollback.sh
#
# Tests:
#   1. Kernel plugin:  sysctl values + config file content
#   2. SSH plugin:     sshd_config backup + content restoration
#   3. Permissions:    directory mode restoration
#   4. JSON output:    rollback --format json produces valid RollbackResult
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BINARY="${BINARY:-$PROJECT_DIR/target/x86_64-unknown-linux-musl/release/hardener}"
[[ -x "$BINARY" ]] || BINARY="$PROJECT_DIR/target/release/hardener"

# Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

TESTS_TOTAL=0
TESTS_PASSED=0
TESTS_FAILED=0
FAILED_TESTS=()

# ---------------------------------------------------------------------------
# Safety: refuse to run outside a container
# ---------------------------------------------------------------------------
CONTAINER_MODE=false
if [[ -f /run/systemd/container ]] || systemd-detect-virt -c &>/dev/null; then
    CONTAINER_MODE=true
fi
if [[ "$CONTAINER_MODE" != "true" ]]; then
    echo -e "${RED}ERROR: This script must run INSIDE a test container.${NC}"
    echo "Use: sudo systemd-nspawn -D /var/lib/machines/hardener-test --bind $PROJECT_DIR:/project -- /bin/bash /project/scripts/test/verify-rollback.sh"
    exit 1
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() { echo -e "$1"; }
pass() { log "  ${GREEN}[PASS]${NC} $1"; ((TESTS_PASSED++)); ((TESTS_TOTAL++)); }
fail() { log "  ${RED}[FAIL]${NC} $1"; ((TESTS_FAILED++)); ((TESTS_TOTAL++)); FAILED_TESTS+=("$1"); }
info() { log "  ${CYAN}[INFO]${NC} $1"; }
header() {
    log ""
    log "${MAGENTA}═══ $1 ═══${NC}"
}

assert_eq() {
    local label="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        pass "$label (expected=$expected)"
    else
        fail "$label (expected=$expected, got=$actual)"
    fi
}

assert_file_exists() {
    local label="$1" path="$2"
    if [[ -e "$path" ]]; then
        pass "$label exists"
    else
        fail "$label missing: $path"
    fi
}

assert_file_missing() {
    local label="$1" path="$2"
    if [[ ! -e "$path" ]]; then
        pass "$label removed"
    else
        fail "$label still exists: $path"
    fi
}

assert_contains() {
    local label="$1" haystack="$2" needle="$3"
    if echo "$haystack" | grep -q "$needle"; then
        pass "$label"
    else
        fail "$label (missing '$needle')"
    fi
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
header "PREFLIGHT"

if [[ ! -x "$BINARY" ]]; then
    log "${RED}Binary not found: $BINARY${NC}"
    exit 1
fi
info "Binary: $BINARY"

# Clean slate: remove any leftover checkpoints/database
rm -rf /var/lib/linux-hardener
info "Cleaned /var/lib/linux-hardener"

# =============================================================================
# TEST 1: KERNEL PLUGIN: sysctl values + config file
# =============================================================================
header "TEST 1: KERNEL PLUGIN ROLLBACK"

# Record BEFORE state
BEFORE_KPTR=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo "N/A")
BEFORE_DMESG=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null || echo "N/A")
BEFORE_CONF_EXISTS="false"
[[ -f /etc/sysctl.d/99-hardener.conf ]] && BEFORE_CONF_EXISTS="true"

info "BEFORE: kptr_restrict=$BEFORE_KPTR  dmesg_restrict=$BEFORE_DMESG  conf_exists=$BEFORE_CONF_EXISTS"

# Apply kernel hardening
info "Applying kernel hardening..."
APPLY_OUTPUT=$("$BINARY" apply --plugin kernel-hardening 2>&1) || true

# Verify changes took effect
AFTER_KPTR=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo "N/A")
AFTER_DMESG=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null || echo "N/A")
info "AFTER APPLY: kptr_restrict=$AFTER_KPTR  dmesg_restrict=$AFTER_DMESG"

if [[ -f /etc/sysctl.d/99-hardener.conf ]]; then
    pass "Config file created: /etc/sysctl.d/99-hardener.conf"
else
    info "Config file not created (may be container limitation with /etc bind-mount)"
fi

# Get checkpoint ID
KERNEL_CP=$("$BINARY" checkpoint list 2>&1 | grep -oE 'cp_[0-9]+_[a-f0-9]+' | head -1 || echo "")
if [[ -z "$KERNEL_CP" ]]; then
    fail "No checkpoint created during kernel apply"
else
    info "Checkpoint: $KERNEL_CP"
fi

# Rollback
if [[ -n "$KERNEL_CP" ]]; then
    info "Rolling back kernel hardening..."
    ROLLBACK_OUTPUT=$("$BINARY" rollback "$KERNEL_CP" 2>&1) || true

    # Verify sysctl values restored
    RESTORED_KPTR=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo "N/A")
    RESTORED_DMESG=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null || echo "N/A")
    info "AFTER ROLLBACK: kptr_restrict=$RESTORED_KPTR  dmesg_restrict=$RESTORED_DMESG"

    # Note: sysctl runtime values are restored via /proc/sys writes during rollback
    # The config FILE should be removed (it didn't exist before apply)
    if [[ "$BEFORE_CONF_EXISTS" == "false" ]]; then
        assert_file_missing "Config file after rollback" "/etc/sysctl.d/99-hardener.conf"
    fi

    # Verify runtime values match pre-apply state
    assert_eq "kptr_restrict restored" "$BEFORE_KPTR" "$RESTORED_KPTR"
    assert_eq "dmesg_restrict restored" "$BEFORE_DMESG" "$RESTORED_DMESG"
fi

# =============================================================================
# TEST 2: SSH PLUGIN: sshd_config content restoration
# =============================================================================
header "TEST 2: SSH PLUGIN ROLLBACK"

# Record BEFORE state
BEFORE_SSHD=""
if [[ -f /etc/ssh/sshd_config ]]; then
    BEFORE_SSHD=$(cat /etc/ssh/sshd_config)
    BEFORE_SSHD_HASH=$(sha256sum /etc/ssh/sshd_config | awk '{print $1}')
    info "BEFORE: sshd_config hash=${BEFORE_SSHD_HASH:0:16}..."
else
    info "BEFORE: /etc/ssh/sshd_config does not exist"
fi

# Clean checkpoints
rm -rf /var/lib/linux-hardener

# Apply SSH hardening
info "Applying SSH hardening..."
"$BINARY" apply --plugin ssh-hardening 2>&1 || true

# Verify sshd_config was modified
if [[ -f /etc/ssh/sshd_config ]]; then
    AFTER_SSHD_HASH=$(sha256sum /etc/ssh/sshd_config | awk '{print $1}')
    info "AFTER APPLY: sshd_config hash=${AFTER_SSHD_HASH:0:16}..."

    if [[ -n "$BEFORE_SSHD" && "$BEFORE_SSHD_HASH" != "$AFTER_SSHD_HASH" ]]; then
        pass "sshd_config modified by apply"
    elif [[ -n "$BEFORE_SSHD" ]]; then
        info "sshd_config unchanged (may already have been hardened)"
    fi
fi

# Get checkpoint and rollback
SSH_CP=$("$BINARY" checkpoint list 2>&1 | grep -oE 'cp_[0-9]+_[a-f0-9]+' | head -1 || echo "")
if [[ -n "$SSH_CP" && -n "$BEFORE_SSHD" ]]; then
    info "Rolling back SSH hardening (checkpoint: $SSH_CP)..."
    "$BINARY" rollback "$SSH_CP" 2>&1 || true

    # Verify content restored
    if [[ -f /etc/ssh/sshd_config ]]; then
        RESTORED_SSHD_HASH=$(sha256sum /etc/ssh/sshd_config | awk '{print $1}')
        info "AFTER ROLLBACK: sshd_config hash=${RESTORED_SSHD_HASH:0:16}..."
        assert_eq "sshd_config hash restored" "$BEFORE_SSHD_HASH" "$RESTORED_SSHD_HASH"
    else
        fail "sshd_config missing after rollback"
    fi
elif [[ -z "$BEFORE_SSHD" ]]; then
    info "Skipping SSH rollback verification (no original sshd_config)"
else
    fail "No SSH checkpoint found"
fi

# =============================================================================
# TEST 3: PERMISSIONS PLUGIN: directory mode restoration
# =============================================================================
header "TEST 3: PERMISSIONS PLUGIN ROLLBACK"

# Record BEFORE state: /root permissions
BEFORE_ROOT_MODE=$(stat -c '%a' /root 2>/dev/null || echo "N/A")
info "BEFORE: /root mode=$BEFORE_ROOT_MODE"

# Clean checkpoints
rm -rf /var/lib/linux-hardener

# Apply permissions hardening
info "Applying permissions hardening..."
"$BINARY" apply --plugin permissions-hardening 2>&1 || true

AFTER_ROOT_MODE=$(stat -c '%a' /root 2>/dev/null || echo "N/A")
info "AFTER APPLY: /root mode=$AFTER_ROOT_MODE"

# Get checkpoint and rollback
PERM_CP=$("$BINARY" checkpoint list 2>&1 | grep -oE 'cp_[0-9]+_[a-f0-9]+' | head -1 || echo "")
if [[ -n "$PERM_CP" ]]; then
    info "Rolling back permissions (checkpoint: $PERM_CP)..."
    "$BINARY" rollback "$PERM_CP" 2>&1 || true

    RESTORED_ROOT_MODE=$(stat -c '%a' /root 2>/dev/null || echo "N/A")
    info "AFTER ROLLBACK: /root mode=$RESTORED_ROOT_MODE"
    assert_eq "/root permissions restored" "$BEFORE_ROOT_MODE" "$RESTORED_ROOT_MODE"
else
    fail "No permissions checkpoint found"
fi

# =============================================================================
# TEST 4: JSON OUTPUT FORMAT
# =============================================================================
header "TEST 4: ROLLBACK JSON OUTPUT"

# Clean checkpoints
rm -rf /var/lib/linux-hardener

# Apply kernel (simplest plugin for JSON test)
"$BINARY" apply --plugin kernel-hardening 2>&1 >/dev/null || true

JSON_CP=$("$BINARY" checkpoint list 2>&1 | grep -oE 'cp_[0-9]+_[a-f0-9]+' | head -1 || echo "")
if [[ -n "$JSON_CP" ]]; then
    info "Rolling back with --format json..."
    # Capture stdout only (stderr may have status messages)
    "$BINARY" --format json rollback "$JSON_CP" > /tmp/rollback-json-output.txt 2>/dev/null || true

    JSON_OUTPUT=$(cat /tmp/rollback-json-output.txt)
    info "JSON output (first 500 chars): ${JSON_OUTPUT:0:500}"

    # Verify JSON structure
    if command -v python3 &>/dev/null; then
        if python3 -c "import json; json.load(open('/tmp/rollback-json-output.txt'))" 2>/dev/null; then
            pass "JSON output is valid JSON"
        else
            fail "JSON output is not valid JSON"
        fi
    elif echo "$JSON_OUTPUT" | grep -q '"rollback_success"'; then
        pass "JSON output contains rollback_success field"
    else
        fail "JSON output missing rollback_success field"
    fi

    assert_contains "JSON has checkpoint_id" "$JSON_OUTPUT" '"rollback_checkpoint_id"'
    assert_contains "JSON has rollback_files" "$JSON_OUTPUT" '"rollback_files"'
    assert_contains "JSON has restore_action" "$JSON_OUTPUT" '"restore_action"'

    rm -f /tmp/rollback-json-output.txt
else
    fail "No checkpoint for JSON test"
fi

# =============================================================================
# TEST 5: MULTI-PLUGIN APPLY + SELECTIVE ROLLBACK
# =============================================================================
header "TEST 5: MULTI-PLUGIN CHECKPOINT ORDERING"

# Clean checkpoints
rm -rf /var/lib/linux-hardener

# Apply two plugins sequentially: each creates its own checkpoint
info "Applying kernel-hardening..."
"$BINARY" apply --plugin kernel-hardening 2>&1 >/dev/null || true

info "Applying ssh-hardening..."
"$BINARY" apply --plugin ssh-hardening 2>&1 >/dev/null || true

# List checkpoints: should have at least 2
CP_COUNT=$("$BINARY" checkpoint list 2>&1 | grep -cE 'cp_[0-9]+_[a-f0-9]+' || echo "0")
info "Checkpoint count: $CP_COUNT"

if [[ "$CP_COUNT" -ge 2 ]]; then
    pass "Multiple checkpoints created ($CP_COUNT)"

    # Show checkpoint details
    "$BINARY" checkpoint list 2>&1 | grep -E 'cp_[0-9]+' | while read -r line; do
        info "  $line"
    done
else
    fail "Expected >= 2 checkpoints, got $CP_COUNT"
fi

# =============================================================================
# SUMMARY
# =============================================================================
header "SUMMARY"
log ""
log "  Total:   $TESTS_TOTAL"
log "  ${GREEN}Passed:  $TESTS_PASSED${NC}"
if [[ $TESTS_FAILED -gt 0 ]]; then
    log "  ${RED}Failed:  $TESTS_FAILED${NC}"
    log ""
    log "  ${RED}Failed tests:${NC}"
    for t in "${FAILED_TESTS[@]}"; do
        log "    - $t"
    done
else
    log "  Failed:  0"
fi
log ""

# Cleanup
rm -rf /var/lib/linux-hardener

if [[ $TESTS_FAILED -gt 0 ]]; then
    exit 1
fi
exit 0
