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
#   6. PAM plugin:     a login.defs directive seeded looser than its target,
#                      moved by the apply and read back after the rollback
#   7. Firewall:       the backend's own config AND what the host is actually
#                      enforcing, asked of whichever backend the plugin picks
#                      (see TEST 7)
#   8. Divergences:    a rollback with no surviving file naming a parameter
#                      reports it rather than reporting plain success
#
# Exit status:
#   0  every check ran and passed
#   1  at least one check failed
#   2  every check that ran passed, and at least one was SKIPPED
#
# 2 exists because 0 was a lie by omission. A container that cannot answer the
# runtime sysctl question skips that arm and exits 0, and the only runner then
# recorded "kernel, ssh and permissions read back after rollback", naming a
# reading it had not taken. The skip was in the log and absent from the
# summary, which is the half nobody reads twice. A caller that does not
# distinguish 2 from 0 is no worse off than before.
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
#
# The haystack arrives on a herestring rather than a pipe. Under `set -o
# pipefail`, piping a large payload into `grep -q` reports the pipeline as
# failed whenever grep matches early and leaves the writer to die of SIGPIPE,
# so the assertion fails precisely when the needle IS present and the haystack
# outgrows the 64 KB pipe buffer. Found in test-package-install.sh, where a
# 165 KB scan payload failed this way on all six distros.
assert_contains() {
    local label="$1" haystack="$2" needle="$3"
    if grep -qF "$needle" <<< "$haystack"; then
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
# read-write, and only for a container holding its own network namespace, which
# `--private-network` is sufficient to give: measured on 2026-08-08, under
# `--pipe`, without `--boot`. This comment previously said `--boot
# --private-network, not --pipe`, and the boot half was wrong. The requirement
# is the namespace, and booting is one way to have been given one rather than
# the condition itself. differential-suite.sh still conflates the two for its
# own kernel table, which is tracked separately.
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
    info "  own network namespace. Add --private-network to the invocation; --boot is"
    info "  not required. Without it the file assertions below are the whole of this arm."
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
# TEST 6: PAM PLUGIN: a login.defs directive moved by apply and restored
# =============================================================================
#
# Part 2 of issue #131: pam, firewall and mac had no rollback readback of any
# kind. This closes pam, which the #125 assessment called the achievable one.
#
# `/etc/login.defs` rather than one of the four other files the plugin manages.
# It is shipped by shadow, so it is present on every distribution this suite
# runs against, where `/etc/security/pwquality.conf` arrives with libpwquality
# and `faillock.conf` and `pwhistory.conf` with pam itself: a container without
# them would skip rather than read, and a skip is the outcome this arm exists
# to stop being the only one available.
#
# PASS_MAX_DAYS rather than PASS_MIN_DAYS or PASS_WARN_AGE, because it is the
# one whose comparison is AtMost. Its target is 90 and shadow's own default is
# 99999, so the pre-apply state is genuinely a violation without inventing one,
# and the apply has to move the value rather than agreeing with it. Seeding a
# value that already passes is how the kernel arm used to compare a constant
# with itself.
header "TEST 6: PAM PLUGIN ROLLBACK"

rm -rf /var/lib/linux-hardener

PAM_PROBE_FILE="/etc/login.defs"
PAM_PROBE_DIRECTIVE="PASS_MAX_DAYS"
PAM_PROBE_BASELINE="99999"  # shadow's default, and looser than the target
PAM_PROBE_TARGET="90"       # PAM_DIRECTIVES in crates/hardener-plugins/src/pam/mod.rs

# The directive's value, read the way login.defs is actually parsed: first
# match wins, whitespace-separated, comments ignored because a commented line
# does not start with the key.
login_defs_value() {
    awk -v key="$PAM_PROBE_DIRECTIVE" '$1 == key { print $2; exit }' \
        "$PAM_PROBE_FILE" 2>/dev/null
}

if [[ ! -f "$PAM_PROBE_FILE" ]]; then
    skip "PAM rollback readback: $PAM_PROBE_FILE is absent, so there is no directive to move"
else
    # Seed by deleting any existing setting and appending one, rather than by
    # editing in place: a distribution that ships the directive commented out,
    # twice, or not at all would otherwise need three different edits.
    sed -i "/^[[:space:]]*${PAM_PROBE_DIRECTIVE}[[:space:]]/d" "$PAM_PROBE_FILE"
    printf '%s\t%s\n' "$PAM_PROBE_DIRECTIVE" "$PAM_PROBE_BASELINE" >> "$PAM_PROBE_FILE"

    PAM_BEFORE_HASH=$(sha256sum "$PAM_PROBE_FILE" | awk '{print $1}')
    PAM_BEFORE_VALUE=$(login_defs_value)
    info "BEFORE: $PAM_PROBE_DIRECTIVE=$PAM_BEFORE_VALUE (seeded)"
    assert_eq "Seeded $PAM_PROBE_DIRECTIVE above its target" \
        "$PAM_PROBE_BASELINE" "$PAM_BEFORE_VALUE"

    info "Applying PAM hardening..."
    "$BINARY" apply --plugin pam-hardening > /dev/null 2>&1 || true

    PAM_AFTER_VALUE=$(login_defs_value)
    info "AFTER APPLY: $PAM_PROBE_DIRECTIVE=$PAM_AFTER_VALUE"
    assert_eq "Apply lowered $PAM_PROBE_DIRECTIVE to its target" \
        "$PAM_PROBE_TARGET" "$PAM_AFTER_VALUE"

    PAM_CP=$("$BINARY" checkpoint list 2>&1 | grep -oE 'cp_[0-9]+_[a-f0-9]+' | head -1 || echo "")
    if [[ -z "$PAM_CP" ]]; then
        fail "No PAM checkpoint found"
    else
        info "Rolling back PAM (checkpoint: $PAM_CP)..."
        "$BINARY" rollback "$PAM_CP" > /dev/null 2>&1 || true

        # Both halves are asked. The value is what an operator cares about; the
        # hash is what catches a restore that produced the right directive in a
        # file it had otherwise rewritten.
        PAM_RESTORED_VALUE=$(login_defs_value)
        info "AFTER ROLLBACK: $PAM_PROBE_DIRECTIVE=$PAM_RESTORED_VALUE"
        assert_eq "Rollback restored $PAM_PROBE_DIRECTIVE" \
            "$PAM_BEFORE_VALUE" "$PAM_RESTORED_VALUE"

        PAM_RESTORED_HASH=$(sha256sum "$PAM_PROBE_FILE" 2>/dev/null | awk '{print $1}')
        assert_eq "Rollback restored $PAM_PROBE_FILE byte for byte" \
            "$PAM_BEFORE_HASH" "${PAM_RESTORED_HASH:-<file missing>}"
    fi
fi

# =============================================================================
# TEST 7: FIREWALL PLUGIN: the restored config AND the live enforcement state
# =============================================================================
#
# Part 2 of issue #131, for firewall. The #125 assessment recorded the live
# half as needing "a booted container with its own network namespace", so only
# the file half was thought reachable. Measured on 2026-08-08: nft creates,
# lists and deletes a table under `--private-network --pipe` with no `--boot`.
# That is the third place where a requirement stated as "booted" turned out to
# be "has its own network namespace", after the kernel arm above and
# differential-suite.sh (#137).
#
# The backend is asked for rather than assumed. The first draft of this arm
# asserted nftables specifics and failed on the arch container, which has ufw
# installed as well: the plugin picked ufw, correctly, and reported so. A test
# that hard-codes one backend does not test the plugin, it tests the container.
#
# The order below mirrors `classify_installed` in
# crates/hardener-plugins/src/firewall/mod.rs and must be changed with it.
# `find_winner` prefers an ACTIVE backend over installed-order, which nothing
# in a freshly built container is, so the two agree here. Where they ever
# disagree the assertions below fail loudly rather than passing on the wrong
# backend's state, which is the safe direction.
header "TEST 7: FIREWALL PLUGIN ROLLBACK"

rm -rf /var/lib/linux-hardener

FW_BACKEND=""
if command -v firewall-cmd > /dev/null 2>&1; then
    FW_BACKEND="firewalld"
elif command -v ufw > /dev/null 2>&1; then
    FW_BACKEND="ufw"
elif command -v nft > /dev/null 2>&1; then
    FW_BACKEND="nftables"
fi

# What the host is actually enforcing, as one line, asked of the backend in
# charge and of nothing else. Compared before and after rather than matched
# against an expected string: the point is that the rollback returns the host
# to where it started, not that it reaches some particular wording.
firewall_live_state() {
    case "$FW_BACKEND" in
        ufw)       ufw status 2>/dev/null | head -1 ;;
        nftables)  if nft list table inet linux_hardener > /dev/null 2>&1;
                   then echo "managed table present"; else echo "managed table absent"; fi ;;
        firewalld) firewall-cmd --state 2>&1 | head -1 ;;
    esac
}

# Whether a live state string means the host is being protected. Derived from
# the string `firewall_live_state` produced rather than re-asking, so the two
# can never answer about different moments.
# Whitespace is squeezed and the match is exact. `*active*` was the first
# version and it reported "Status: inactive" as enforcing, "inactive" containing
# "active": the arm would then have called a firewall that a rollback switched
# off no worse than one it left on, which is the precise failure it exists to
# catch.
firewall_enforcing() {
    local state="${1// /}"
    case "$FW_BACKEND" in
        ufw)       [[ "$state" == "Status:active" ]] ;;
        nftables)  [[ "$state" == "managedtablepresent" ]] ;;
        firewalld) [[ "$state" == "running" ]] ;;
        *)         return 1 ;;
    esac
}

# The configuration the backend owns, as one digest. A directory for ufw and
# firewalld, a single file for nftables, so it is hashed as a tree either way.
firewall_config_digest() {
    local path="$1"
    if [[ ! -e "$path" ]]; then
        echo "<absent>"
        return
    fi
    find "$path" -type f -exec sha256sum {} + 2>/dev/null | sort | sha256sum | awk '{print $1}'
}

case "$FW_BACKEND" in
    ufw)       FW_CONFIG_PATH="/etc/ufw" ;;
    nftables)  FW_CONFIG_PATH="/etc/nftables.conf" ;;
    firewalld) FW_CONFIG_PATH="/etc/firewalld" ;;
    *)         FW_CONFIG_PATH="" ;;
esac

if [[ -z "$FW_BACKEND" ]]; then
    skip "Firewall rollback readback: no firewall backend is installed in this container"
elif [[ "$FW_BACKEND" == "nftables" ]] && ! nft list tables > /dev/null 2>&1; then
    skip "Firewall rollback readback: nft cannot reach a ruleset here, which needs --private-network"
else
    info "Backend in charge: $FW_BACKEND (config: $FW_CONFIG_PATH)"

    FW_BEFORE_STATE=$(firewall_live_state)
    FW_BEFORE_DIGEST=$(firewall_config_digest "$FW_CONFIG_PATH")
    info "BEFORE: live='$FW_BEFORE_STATE'  config=${FW_BEFORE_DIGEST:0:16}"

    info "Applying firewall hardening..."
    "$BINARY" apply --plugin firewall-hardening > /dev/null 2>&1 || true

    FW_AFTER_STATE=$(firewall_live_state)
    FW_AFTER_DIGEST=$(firewall_config_digest "$FW_CONFIG_PATH")
    info "AFTER APPLY: live='$FW_AFTER_STATE'  config=${FW_AFTER_DIGEST:0:16}"

    # The apply has to have moved something, or every assertion after it
    # compares a constant with itself. Both halves are asked because a backend
    # may express hardening in either: ufw flips from inactive to active and
    # rewrites /etc/ufw, nftables writes a file and loads a table.
    if [[ "$FW_AFTER_STATE" == "$FW_BEFORE_STATE" && "$FW_AFTER_DIGEST" == "$FW_BEFORE_DIGEST" ]]; then
        fail "Apply changed neither the live firewall state nor $FW_CONFIG_PATH, so nothing here can be read back"
    else
        pass "Apply changed the firewall (live and/or $FW_CONFIG_PATH)"

        FW_CP=$("$BINARY" checkpoint list 2>&1 | grep -oE 'cp_[0-9]+_[a-f0-9]+' | head -1 || echo "")
        if [[ -z "$FW_CP" ]]; then
            fail "No firewall checkpoint found"
        else
            info "Rolling back firewall (checkpoint: $FW_CP)..."
            "$BINARY" rollback "$FW_CP" > /dev/null 2>&1 || true

            FW_RESTORED_DIGEST=$(firewall_config_digest "$FW_CONFIG_PATH")
            assert_eq "Rollback restored $FW_CONFIG_PATH" \
                "$FW_BEFORE_DIGEST" "$FW_RESTORED_DIGEST"

            # The half nothing has ever asked, and the contract it is asked
            # against is NOT "the live state comes back".
            #
            # The first version of this assertion demanded exactly that and
            # failed: ufw was inactive before the apply and active after the
            # rollback. Reading the plugin, that is deliberate.
            # `reload_after_rollback` re-reads the restored configuration and
            # "never starts or enables a unit either", because the settled rule
            # is that undoing a hardening run must not leave a host less secure
            # than it was found. Disabling a firewall the operator now has would
            # do exactly that.
            #
            # So what is asserted is the rule itself: a rollback may leave the
            # host better protected than it found it, and may never leave it
            # worse. Where the live state has not come back, that is reported
            # rather than failed, because the running host then disagrees with
            # its own configuration files and an operator should know: see the
            # issue named below.
            FW_RESTORED_STATE=$(firewall_live_state)
            info "AFTER ROLLBACK: live='$FW_RESTORED_STATE'"

            if firewall_enforcing "$FW_BEFORE_STATE" && ! firewall_enforcing "$FW_RESTORED_STATE"; then
                fail "Rollback left the host less protected than it found it (was '$FW_BEFORE_STATE', now '$FW_RESTORED_STATE')"
            else
                pass "Rollback did not leave the host less protected"
            fi

            if [[ "$FW_RESTORED_STATE" != "$FW_BEFORE_STATE" ]]; then
                info "  Divergence: $FW_CONFIG_PATH is back to its pre-apply bytes while the"
                info "  running host is still '$FW_RESTORED_STATE'. Deliberate, and it means a"
                info "  reboot can change the posture with nothing having been asked. See #139."
            fi
        fi
    fi
fi

# =============================================================================
# TEST 8: A ROLLBACK REPORTS WHAT IT LEFT DIVERGED
# =============================================================================
# TEST 1 seeds a baseline drop-in so a surviving file names the pre-apply
# value. This arm deliberately does not: with nothing naming it, the rollback
# restores files, runs `sysctl --system`, and leaves the parameter hardened.
# That is correct behaviour and it is issue #138. What is asserted here is
# that the rollback SAYS so.
header "TEST 8: DIVERGENCE REPORTING"

if [[ "$RUNTIME_ASKABLE" == "true" ]]; then
    rm -f "$KERNEL_BASELINE_CONF"
    printf '%s\n' "$KERNEL_PROBE_BASELINE" > "$KERNEL_PROBE_PROC"
    assert_eq "Seeded $KERNEL_PROBE_PARAM with no file naming it" \
        "$KERNEL_PROBE_BASELINE" "$(cat "$KERNEL_PROBE_PROC")"

    "$BINARY" apply --plugin kernel-hardening > /dev/null 2>&1 || true

    # The script's own idiom for both halves, taken from TEST 4: the id is
    # grepped out of the text listing, and `--format json` is a GLOBAL flag
    # that precedes the verb. The verb is a top-level `rollback`, not
    # `checkpoint rollback`.
    DIVERGE_CP=$("$BINARY" checkpoint list 2>&1 | grep -oE 'cp_[0-9]+_[a-f0-9]+' | head -1 || echo "")
    "$BINARY" --format json rollback "$DIVERGE_CP" > /tmp/diverge.json 2>/dev/null || true

    # Read back out of a file rather than a pipe: this shell reports the last
    # command in a pipeline, which has inverted an assertion here before.
    DIVERGE_SUBJECTS=$(python3 -c 'import json;print("\n".join(d["divergence_subject"] for d in json.load(open("/tmp/diverge.json")).get("rollback_divergences",[])))')

    if printf '%s' "$DIVERGE_SUBJECTS" | grep -qx "$KERNEL_PROBE_PARAM"; then
        pass "The rollback reported $KERNEL_PROBE_PARAM as diverged"
    else
        fail "The rollback left $KERNEL_PROBE_PARAM hardened and reported nothing. Subjects: ${DIVERGE_SUBJECTS:-none}"
    fi

    info "Rows reported: $(printf '%s' "$DIVERGE_SUBJECTS" | grep -c . || true)"

    rm -f /tmp/diverge.json
else
    skip "Divergence reporting: /proc/sys/net is read-only here, so no apply can move $KERNEL_PROBE_PARAM"
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
# A skip is not a failure and must not read as a pass either. See the exit
# status block in this file's header.
if [[ $TESTS_SKIPPED -gt 0 ]]; then
    log "  ${YELLOW}Exit 2: passed, but $TESTS_SKIPPED check(s) were not asked.${NC}"
    exit 2
fi
exit 0
