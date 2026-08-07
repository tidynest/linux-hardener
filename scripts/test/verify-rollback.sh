#!/bin/bash
# =============================================================================
# ROLLBACK VERIFICATION SCRIPT
# =============================================================================
# Reads back off the system what a rollback claims to have restored: file
# contents, a directory mode, and, where the container permits the question,
# a runtime kernel parameter. Nothing here trusts the tool's own report.
#
# Run INSIDE a test container as root. Two binds are needed: the project at
# /project, and cargo's target directory at /project/target, because a machine
# with CARGO_TARGET_DIR or a [build] target-dir in ~/.cargo/config.toml builds
# the binary outside the tree and the first bind then carries no binary at all:
#
#   TARGET_DIR=$(cargo metadata --format-version 1 --no-deps |
#       sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
#   sudo systemd-nspawn -D /var/lib/machines/hardener-test \
#       --bind="$PWD:/project" --bind-ro="$TARGET_DIR:/project/target" --pipe \
#       /bin/bash /project/scripts/test/verify-rollback.sh
#
# The second bind is harmless when the target directory is already inside the
# tree: it then mounts the same directory onto itself. scripts/test/
# release-readiness-root.sh adds it only when it differs, and is the only
# runner that calls this script.
#
# Tests:
#   1. Kernel plugin:  persistent config file written by the apply, then
#                      removed (or restored) by the rollback, plus the runtime
#                      sysctl value where /proc/sys/net is writable (see TEST 1)
#   2. SSH plugin:     sshd_config backup + content restoration
#   3. Permissions:    directory mode restoration
#   4. JSON output:    rollback --format json produces valid RollbackResult
#   5. Checkpoints:    two applies leave two checkpoints
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"

# Resolved the way every other runner resolves it, rather than by naming
# $PROJECT_DIR/target directly: cargo redirects its output out of the tree
# whenever CARGO_TARGET_DIR or a [build] target-dir is set, and a hand-written
# path then misses both candidates and stops the run before it starts.
if [[ -z "${BINARY:-}" ]]; then
    TARGET_DIR="$(resolve_target_dir "x86_64-unknown-linux-musl/release/hardener" "release/hardener")"
    BINARY="$TARGET_DIR/x86_64-unknown-linux-musl/release/hardener"
    [[ -x "$BINARY" ]] || BINARY="$TARGET_DIR/release/hardener"
fi

TESTS_TOTAL=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0
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
    echo "Use: sudo systemd-nspawn -D /var/lib/machines/hardener-test \\"
    echo "         --bind=$PROJECT_DIR:/project \\"
    echo "         --bind-ro=${TARGET_DIR:-$PROJECT_DIR/target}:/project/target \\"
    echo "         --pipe /bin/bash /project/scripts/test/verify-rollback.sh"
    exit 1
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() { echo -e "$1"; }
pass() { log "  ${GREEN}[PASS]${NC} $1"; ((TESTS_PASSED++)); ((TESTS_TOTAL++)); }
fail() { log "  ${RED}[FAIL]${NC} $1"; ((TESTS_FAILED++)); ((TESTS_TOTAL++)); FAILED_TESTS+=("$1"); }
# A question this environment cannot answer. Counted and printed rather than
# passed, so an arm that could not be asked never reads as an arm that was
# asked and was clean. Every call must name the reason.
skip() { log "  ${YELLOW}[SKIP]${NC} $1"; ((TESTS_SKIPPED++)); ((TESTS_TOTAL++)); }
info() { log "  ${CYAN}[INFO]${NC} $1"; }
header() {
    log ""
    log "${MAGENTA}=== $1 ===${NC}"
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

# Literal match (-F): every needle passed here is a fixed string, and the
# sysctl names among them are full of dots that a regexp would treat as
# wildcards, so a near-miss could match and be reported as a pass.
assert_contains() {
    local label="$1" haystack="$2" needle="$3"
    if echo "$haystack" | grep -qF "$needle"; then
        pass "$label"
    else
        fail "$label (missing '$needle')"
    fi
}

# Whether this container may write the sysctl at PATH, measured by writing the
# value already there (a no-op whatever the answer is).
#
# The inode cannot be asked: every file under /proc/sys is 0644 whether or not
# the mount allows writing, so `[[ -w ]]` says yes on a read-only /proc/sys and
# only the write itself tells the truth.
# The redirection is inside the group so that the shell's own "Read-only file
# system" message goes to /dev/null with everything else: a failed redirection
# is reported before a trailing 2>/dev/null on the same command takes effect,
# which would put a bare error line above the SKIP that explains it.
sysctl_write_allowed() {
    local path="$1" current
    current=$(cat "$path" 2>/dev/null) || return 1
    { printf '%s\n' "$current" > "$path"; } 2>/dev/null
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
# TEST 1: KERNEL PLUGIN: persistent config file + runtime sysctl value
# =============================================================================
# The parameter this arm asks about, and why it is a net.ipv4 one.
#
# systemd-nspawn mounts /proc/sys read-only and it is the HOST's, so the
# kernel.* and fs.* parameters the plugin manages cannot be moved by any apply
# run in here: an assertion that one of them came back would compare a constant
# with itself and pass whatever the code did. Only /proc/sys/net is remounted
# read-write, and only for a container holding its own network namespace
# (--boot --private-network, not --pipe), which is the same measured finding
# differential-suite.sh records for its own kernel table.
#
# log_martians rather than one of the other ten net.ipv4 parameters: it is the
# only one whose value cannot cost anything if the container turns out to share
# the host's network namespace after all (rp_filter and the redirect settings
# decide whether packets are dropped; this one decides whether a line is
# logged), and nothing in /usr/lib/sysctl.d names it on Arch, which is the
# distribution release-readiness-root.sh gives this script. A distribution that
# does ship a log_martians default would win over the baseline drop-in below
# under sysctl's merge order, and this arm would then report the restored value
# as that default rather than as the seed: a named failure to read, not a
# silent pass.
KERNEL_PROBE_PARAM="net.ipv4.conf.all.log_martians"
KERNEL_PROBE_PROC="/proc/sys/net/ipv4/conf/all/log_martians"
KERNEL_PROBE_BASELINE="0"   # looser than the plugin's target, so apply must move it
KERNEL_PROBE_TARGET="1"     # KERNEL_PARAMS in crates/hardener-plugins/src/kernel/mod.rs
KERNEL_BASELINE_CONF="/etc/sysctl.d/00-rollback-readback-baseline.conf"
HARDENER_CONF="/etc/sysctl.d/99-hardener.conf"

header "TEST 1: KERNEL PLUGIN ROLLBACK"

# Record BEFORE state
BEFORE_CONF_EXISTS="false"
BEFORE_CONF_HASH=""
if [[ -f "$HARDENER_CONF" ]]; then
    BEFORE_CONF_EXISTS="true"
    BEFORE_CONF_HASH=$(sha256sum "$HARDENER_CONF" | awk '{print $1}')
fi

# Seed the runtime half, where this container permits it at all.
#
# The seed is two writes, and both are needed. The runtime write puts the
# parameter below the plugin's target so the apply has to move it; the baseline
# drop-in puts the same value in the configuration that survives the rollback,
# because a rollback restores files and then runs `sysctl --system` and never
# writes /proc/sys itself. Without a surviving file naming the pre-apply value
# there is nothing for that reload to read, and the runtime value would stay
# hardened after a rollback that did everything it promises.
RUNTIME_ASKABLE=false
BEFORE_PROBE=""
if sysctl_write_allowed "$KERNEL_PROBE_PROC"; then
    RUNTIME_ASKABLE=true
    printf '# Pre-apply baseline written by verify-rollback.sh\n%s = %s\n' \
        "$KERNEL_PROBE_PARAM" "$KERNEL_PROBE_BASELINE" > "$KERNEL_BASELINE_CONF"
    printf '%s\n' "$KERNEL_PROBE_BASELINE" > "$KERNEL_PROBE_PROC"
    BEFORE_PROBE=$(cat "$KERNEL_PROBE_PROC")
    info "BEFORE: $KERNEL_PROBE_PARAM=$BEFORE_PROBE (seeded)  conf_exists=$BEFORE_CONF_EXISTS"
    # Asserted rather than assumed: if the seed did not take, the pre-apply
    # value is already the target and both assertions below would compare the
    # target with itself, which is the exact defect this arm was rebuilt to
    # get rid of.
    assert_eq "Seeded $KERNEL_PROBE_PARAM below its target" \
        "$KERNEL_PROBE_BASELINE" "$BEFORE_PROBE"
else
    skip "Runtime sysctl readback: /proc/sys/net is read-only here, so no apply can move $KERNEL_PROBE_PARAM and no rollback can bring it back"
    info "  nspawn remounts /proc/sys/net read-write only for a container holding its"
    info "  own network namespace (--boot --private-network). Under --pipe the file"
    info "  assertions below are the whole of this arm."
    info "BEFORE: conf_exists=$BEFORE_CONF_EXISTS"
fi

# Apply kernel hardening
info "Applying kernel hardening..."
"$BINARY" apply --plugin kernel-hardening > /dev/null 2>&1 || true

# The persistent file is written whether or not the runtime writes succeed, so
# these two are asked in every container. Reported as failures rather than as
# information: an apply that silently wrote nothing leaves exactly the state a
# rollback is supposed to leave, and the removal assertion further down would
# pass over a file that was never there.
assert_file_exists "Persistent sysctl config after apply" "$HARDENER_CONF"
assert_contains "Persistent sysctl config names $KERNEL_PROBE_PARAM" \
    "$(cat "$HARDENER_CONF" 2>/dev/null)" "$KERNEL_PROBE_PARAM = $KERNEL_PROBE_TARGET"

if [[ "$RUNTIME_ASKABLE" == "true" ]]; then
    AFTER_PROBE=$(cat "$KERNEL_PROBE_PROC")
    info "AFTER APPLY: $KERNEL_PROBE_PARAM=$AFTER_PROBE"
    assert_eq "Apply raised $KERNEL_PROBE_PARAM to its target" \
        "$KERNEL_PROBE_TARGET" "$AFTER_PROBE"
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
    "$BINARY" rollback "$KERNEL_CP" > /dev/null 2>&1 || true

    # The persistent file: removed if the apply created it, restored byte for
    # byte if it was already there. One of the two is always asked, so the file
    # half of this arm can never go quiet.
    if [[ "$BEFORE_CONF_EXISTS" == "false" ]]; then
        assert_file_missing "Config file after rollback" "$HARDENER_CONF"
    else
        RESTORED_CONF_HASH=$(sha256sum "$HARDENER_CONF" 2>/dev/null | awk '{print $1}')
        assert_eq "Pre-existing config file restored" \
            "$BEFORE_CONF_HASH" "${RESTORED_CONF_HASH:-<file missing>}"
    fi

    # The runtime value: back to the baseline the surviving drop-in names,
    # which is what the rollback's `sysctl --system` reload has to produce once
    # the hardener's own file is gone.
    if [[ "$RUNTIME_ASKABLE" == "true" ]]; then
        RESTORED_PROBE=$(cat "$KERNEL_PROBE_PROC")
        info "AFTER ROLLBACK: $KERNEL_PROBE_PARAM=$RESTORED_PROBE"
        assert_eq "Rollback restored $KERNEL_PROBE_PARAM" \
            "$BEFORE_PROBE" "$RESTORED_PROBE"
    fi
fi

# The baseline drop-in is this script's, not the tool's: taken back out so the
# container is left as it was found and nothing downstream reads it as an
# operator's own setting.
rm -f "$KERNEL_BASELINE_CONF"

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
"$BINARY" apply --plugin kernel-hardening > /dev/null 2>&1 || true

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
"$BINARY" apply --plugin kernel-hardening > /dev/null 2>&1 || true

info "Applying ssh-hardening..."
"$BINARY" apply --plugin ssh-hardening > /dev/null 2>&1 || true

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
log "  ${YELLOW}Skipped: $TESTS_SKIPPED${NC}"
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
