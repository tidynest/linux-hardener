#!/bin/bash
# Manual Verification Test for Linux System Hardener
# This script provides step-by-step verification with visible evidence
#
# Usage: sudo ./scripts/test/manual-verification-test.sh
#
# Run this INSIDE the test container for safety!

set -euo pipefail

BINARY="/project/target/release/hardener"

# Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

section() { echo -e "\n${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; echo -e "${YELLOW}$1${NC}"; echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
evidence() { echo -e "${CYAN}[EVIDENCE]${NC} $1"; }

pause() {
    echo ""
    read -p "Press Enter to continue to next step..." -r
    echo ""
}

# Check root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
    exit 1
fi

# Check binary
if [[ ! -x "$BINARY" ]]; then
    error "Binary not found at $BINARY"
    exit 1
fi

echo -e "${GREEN}"
cat << 'EOF'
 _    _                 _                         _____         _
| |  | |               | |                       |_   _|       | |
| |__| | __ _ _ __ __ _| | ___ _ __   ___ _ __     | | ___  ___| |_
|  __  |/ _` | '__/ _` | |/ _ \ '_ \ / _ \ '__|    | |/ _ \/ __| __|
| |  | | (_| | | | (_| | |  __/ | | |  __/ |       | |  __/\__ \ |_
|_|  |_|\__,_|_|  \__,_|_|\___|_| |_|\___|_|       \_/\___||___/\__|

         Manual Verification Test - Iterative Cycle
EOF
echo -e "${NC}"

section "CYCLE 1: SCAN VERIFICATION"

info "Step 1.1: Record BEFORE state of key kernel parameters"
echo ""
evidence "Current kernel parameter values:"
echo "  kernel.kptr_restrict    = $(cat /proc/sys/kernel/kptr_restrict)"
echo "  kernel.dmesg_restrict   = $(cat /proc/sys/kernel/dmesg_restrict)"
echo "  kernel.randomize_va_space = $(cat /proc/sys/kernel/randomize_va_space)"
echo "  fs.suid_dumpable        = $(cat /proc/sys/fs/suid_dumpable)"
echo "  net.ipv4.tcp_syncookies = $(cat /proc/sys/net/ipv4/tcp_syncookies)"

pause

info "Step 1.2: Check if hardener config file exists"
if [[ -f /etc/sysctl.d/99-hardener.conf ]]; then
    warn "99-hardener.conf already exists (from previous test?)"
    cat /etc/sysctl.d/99-hardener.conf
else
    success "No 99-hardener.conf - clean state"
fi

pause

info "Step 1.3: Run kernel scan"
echo ""
evidence "Running: $BINARY scan --plugin kernel-hardening"
echo ""
$BINARY scan --plugin kernel-hardening
echo ""
success "Scan complete. Review findings above."

pause

section "CYCLE 2: APPLY VERIFICATION"

info "Step 2.1: Run dry-run first to see what would change"
echo ""
evidence "Running: $BINARY apply --plugin kernel-hardening --dry-run"
echo ""
$BINARY apply --plugin kernel-hardening --dry-run
echo ""
success "Dry-run complete. Review estimated changes above."

pause

info "Step 2.2: Check current checkpoint list (should be empty or have old checkpoints)"
echo ""
evidence "Running: $BINARY checkpoint list"
$BINARY checkpoint list
echo ""

pause

info "Step 2.3: APPLY kernel hardening (this will make real changes!)"
echo ""
evidence "Running: $BINARY apply --plugin kernel-hardening"
echo ""
$BINARY apply --plugin kernel-hardening
echo ""
success "Apply complete."

pause

info "Step 2.4: VERIFY changes were actually made"
echo ""
evidence "Kernel parameter values AFTER apply:"
echo "  kernel.kptr_restrict    = $(cat /proc/sys/kernel/kptr_restrict) (should be 2)"
echo "  kernel.dmesg_restrict   = $(cat /proc/sys/kernel/dmesg_restrict) (should be 1)"
echo "  kernel.randomize_va_space = $(cat /proc/sys/kernel/randomize_va_space) (should be 2)"
echo "  fs.suid_dumpable        = $(cat /proc/sys/fs/suid_dumpable) (should be 0)"
echo "  net.ipv4.tcp_syncookies = $(cat /proc/sys/net/ipv4/tcp_syncookies) (should be 1)"

pause

info "Step 2.5: Check persistent config file was created"
if [[ -f /etc/sysctl.d/99-hardener.conf ]]; then
    success "99-hardener.conf created!"
    echo ""
    evidence "Contents of /etc/sysctl.d/99-hardener.conf:"
    cat /etc/sysctl.d/99-hardener.conf
else
    error "99-hardener.conf was NOT created!"
fi

pause

info "Step 2.6: Check checkpoint was created"
echo ""
evidence "Running: $BINARY checkpoint list"
$BINARY checkpoint list
echo ""
info "Note the checkpoint ID for rollback step."

pause

section "CYCLE 3: ROLLBACK VERIFICATION"

info "Step 3.1: Get the checkpoint ID"
echo ""
CHECKPOINT_OUTPUT=$($BINARY checkpoint list 2>&1)
echo "$CHECKPOINT_OUTPUT"
echo ""

# Try to extract checkpoint ID (cp_TIMESTAMP_HASH format)
CHECKPOINT_ID=$(echo "$CHECKPOINT_OUTPUT" | grep -oE 'cp_[0-9]+_[a-f0-9]+' | head -1 || echo "")

if [[ -n "$CHECKPOINT_ID" ]]; then
    success "Found checkpoint ID: $CHECKPOINT_ID"
else
    warn "Could not auto-extract checkpoint ID. You may need to enter it manually."
    read -p "Enter checkpoint ID (or press Enter to skip rollback): " CHECKPOINT_ID
fi

if [[ -n "$CHECKPOINT_ID" ]]; then
    pause

    info "Step 3.2: ROLLBACK to checkpoint"
    echo ""
    evidence "Running: $BINARY rollback $CHECKPOINT_ID"
    echo ""
    $BINARY rollback "$CHECKPOINT_ID" || warn "Rollback may have failed"
    echo ""

    pause

    info "Step 3.3: VERIFY rollback restored original state"
    echo ""
    evidence "Kernel parameter values AFTER rollback:"
    echo "  kernel.kptr_restrict    = $(cat /proc/sys/kernel/kptr_restrict)"
    echo "  kernel.dmesg_restrict   = $(cat /proc/sys/kernel/dmesg_restrict)"
    echo "  kernel.randomize_va_space = $(cat /proc/sys/kernel/randomize_va_space)"
    echo "  fs.suid_dumpable        = $(cat /proc/sys/fs/suid_dumpable)"
    echo "  net.ipv4.tcp_syncookies = $(cat /proc/sys/net/ipv4/tcp_syncookies)"
    echo ""
    info "Note: Values may or may not have changed depending on original state."

    pause

    info "Step 3.4: Check if 99-hardener.conf was removed"
    if [[ -f /etc/sysctl.d/99-hardener.conf ]]; then
        warn "99-hardener.conf still exists"
        cat /etc/sysctl.d/99-hardener.conf
    else
        success "99-hardener.conf was removed by rollback"
    fi
else
    warn "Skipping rollback verification (no checkpoint ID)"
fi

pause

section "CYCLE 4: RE-SCAN TO VERIFY STATE"

info "Step 4.1: Run scan again to see current security state"
echo ""
evidence "Running: $BINARY scan --plugin kernel-hardening"
echo ""
$BINARY scan --plugin kernel-hardening
echo ""

section "TEST COMPLETE"

echo -e "${GREEN}Manual verification test complete!${NC}"
echo ""
echo "Summary of what was tested:"
echo "  1. ✓ Scan detected kernel parameter security issues"
echo "  2. ✓ Dry-run showed estimated changes"
echo "  3. ✓ Apply changed actual kernel parameters"
echo "  4. ✓ Persistent config file created"
echo "  5. ✓ Checkpoint created for rollback"
echo "  6. ✓ Rollback restored previous state (if checkpoint was available)"
echo "  7. ✓ Re-scan verified final state"
echo ""
echo "Review the evidence above to confirm each step worked correctly."
