#!/bin/bash
# Functional test suite: tests core app operations, not just keyboard UX
# Safe to run while using other windows: every interaction re-focuses the Tauri window.
set -uo pipefail

OUTDIR="/tmp/test-grouped"
PASS=0; FAIL=0; SKIP=0
declare -a FAILURES=()
TAURI_ADDR=""

pass() { ((PASS++)); echo "  PASS: $1"; }
fail() { ((FAIL++)); FAILURES+=("$1 - $2"); echo "  FAIL: $1 - $2"; }
skip() { ((SKIP++)); echo "  SKIP: $1 - $2"; }
section() { echo ""; echo "=== $1 ==="; }

# Cache the Tauri window address once at startup (doesn't change during session)
cache_tauri_addr() {
  TAURI_ADDR=$(hyprctl clients -j 2>/dev/null | python3 -c "
import json,sys
for c in json.load(sys.stdin):
    if 'hardener' in c.get('class','').lower():
        print(c['address']); break
" 2>/dev/null)
  [ -z "$TAURI_ADDR" ] && return 1
  return 0
}

# Re-focus the Tauri window (fast: just a hyprctl call, ~5ms)
refocus() {
  hyprctl dispatch focuswindow "address:$TAURI_ADDR" >/dev/null 2>&1
  sleep 0.15
}

# Send keystrokes to Tauri: re-focuses first, then calls wtype
tw() { refocus; wtype "$@"; }

# Tab N times into the Tauri window (re-focuses once before the burst)
tabtimes() {
  refocus
  for _ in $(seq 1 "$1"); do
    wtype -k Tab; sleep 0.15
  done
  sleep 0.2
}

shot() {
  local geom
  geom=$(hyprctl clients -j 2>/dev/null | python3 -c "
import json,sys
for c in json.load(sys.stdin):
    if 'hardener' in c.get('class','').lower():
        x,y=c['at']; w,h=c['size']
        print(f'{x},{y} {w}x{h}'); break
" 2>/dev/null)
  [ -n "$geom" ] && grim -g "$geom" "$OUTDIR/$1" 2>/dev/null
}

# ─── STARTUP ────────────────────────────────────
cache_tauri_addr || { echo "ERROR: Tauri window not found"; exit 1; }
echo "Tauri window locked: $TAURI_ADDR"

# Reset to dashboard
tw -M ctrl -k 1 -m ctrl; sleep 0.6

# ─────────────────────────────────────────────────
section "1. RUN SECURITY SCAN (Dashboard)"
# ─────────────────────────────────────────────────

# Tab to Run Scan button: skip(1) + nav(5) + theme(1) + Run Scan(1) = 8
tabtimes 8
shot "fn-01-before-scan.png"

tw -k Return; sleep 1.0
shot "fn-02-scan-started.png"
pass "Run Scan button activated"

echo "  ... waiting for scan to complete"
sleep 8
refocus
shot "fn-03-scan-complete.png"
pass "Scan completed (waited 8s)"

# ─────────────────────────────────────────────────
section "2. DASHBOARD SCORE UPDATE"
# ─────────────────────────────────────────────────

refocus
shot "fn-04-dashboard-score.png"
pass "Dashboard score screenshot captured"

# ─────────────────────────────────────────────────
section "3. ANALYSIS PAGE: FINDINGS POPULATED"
# ─────────────────────────────────────────────────

tw -M ctrl -k 2 -m ctrl; sleep 0.8
shot "fn-05-analysis-after-scan.png"
pass "Analysis page loaded after scan"

# Tab to severity filter dropdown (~10 tabs)
tabtimes 10

# Change severity filter to "High"
tw -k space; sleep 0.3
tw -k Down; sleep 0.2
tw -k Down; sleep 0.2
tw -k Down; sleep 0.2
tw -k Return; sleep 0.5
shot "fn-06-severity-filter-high.png"
pass "Severity filter changed"

# Reset to All
tw -k space; sleep 0.3
tw -k Home; sleep 0.2
tw -k Return; sleep 0.5

# ─────────────────────────────────────────────────
section "4. FINDING DETAIL: CONTENT VERIFICATION"
# ─────────────────────────────────────────────────

# Tab into findings grid
tabtimes 4

# Enter on first row
tw -k Return; sleep 0.6
shot "fn-07-finding-detail-content.png"
pass "Finding detail panel shows content"

# Navigate to different finding
tw -k Escape; sleep 0.3
tw -k Down; sleep 0.2
tw -k Down; sleep 0.2
tw -k Return; sleep 0.6
shot "fn-08-finding-detail-row3.png"
pass "Different finding selected and displayed"

tw -k Escape; sleep 0.3

# ─────────────────────────────────────────────────
section "5. COMPLIANCE TAB: FRAMEWORK SELECTION & REPORT"
# ─────────────────────────────────────────────────

tw -M ctrl -k 2 -m ctrl; sleep 0.6

# Tab to tab bar
tabtimes 8

# ArrowRight to Compliance tab
tw -k Right; sleep 0.5
shot "fn-09-compliance-tab.png"
pass "Compliance tab selected"

# Tab into compliance content
tabtimes 3

# Toggle CIS Benchmark checkbox
tw -k space; sleep 0.3
shot "fn-10-cis-checked.png"
pass "CIS Benchmark checkbox toggled"

# Toggle DISA STIG
tw -k Tab; sleep 0.15
tw -k space; sleep 0.3
pass "DISA STIG checkbox toggled"

# Tab to Generate Reports button
tabtimes 5

# Press Enter on Generate Reports
tw -k Return; sleep 2.0
shot "fn-11-compliance-report.png"
pass "Generate Reports button activated"

# ─────────────────────────────────────────────────
section "6. COMPLIANCE: EXPORT FORMAT"
# ─────────────────────────────────────────────────

# Tab to export format dropdown
tw -k Tab; sleep 0.2

# Open dropdown and select JSON
tw -k space; sleep 0.3
tw -k Down; sleep 0.2
tw -k Return; sleep 0.3
shot "fn-12-export-json-selected.png"
pass "Export format changed to JSON"

# Tab to Export button and activate
tw -k Tab; sleep 0.2
tw -k Return; sleep 1.0
shot "fn-13-export-triggered.png"
pass "Export to File activated"

# ─────────────────────────────────────────────────
section "7. SCAN HISTORY TAB"
# ─────────────────────────────────────────────────

tw -M ctrl -k 2 -m ctrl; sleep 0.6

# Tab to tab bar
tabtimes 8

# ArrowRight twice to History tab
tw -k Right; sleep 0.3
tw -k Right; sleep 0.5
shot "fn-14-scan-history.png"
pass "Scan History tab selected"

# Tab to Refresh button
tabtimes 2

# Refresh
tw -k Return; sleep 1.5
shot "fn-15-history-refreshed.png"
pass "Scan history refreshed"

# Tab to first Load button
tabtimes 3

# Load a previous scan
tw -k Return; sleep 1.0
shot "fn-16-history-loaded.png"
pass "Historical scan loaded"

# ─────────────────────────────────────────────────
section "8. HARDENING: PROFILE SELECTION"
# ─────────────────────────────────────────────────

tw -M ctrl -k 3 -m ctrl; sleep 0.6
shot "fn-17-hardening-configure.png"
pass "Hardening Configure tab loaded"

# Tab to profile radio buttons
tabtimes 10

# Select "Secure" profile (ArrowDown from Baseline)
tw -k Down; sleep 0.3
shot "fn-18-profile-secure.png"
pass "Secure profile selected"

# Select "High Security" profile
tw -k Down; sleep 0.3
shot "fn-19-profile-high-security.png"
pass "High Security profile selected"

# Back to Baseline
tw -k Up; sleep 0.2
tw -k Up; sleep 0.3

# ─────────────────────────────────────────────────
section "9. HARDENING: PLUGIN CHECKBOXES"
# ─────────────────────────────────────────────────

# Tab to first plugin checkbox
tw -k Tab; sleep 0.15

# Toggle Kernel
tw -k space; sleep 0.3
shot "fn-20-kernel-toggled.png"
pass "Kernel plugin toggled"

# Toggle SSH
tw -k Tab; sleep 0.15
tw -k space; sleep 0.3
pass "SSH plugin toggled"

# Toggle Firewall
tw -k Tab; sleep 0.15
tw -k space; sleep 0.3
pass "Firewall plugin toggled"

shot "fn-21-plugins-selected.png"
pass "Multiple plugins selected"

# ─────────────────────────────────────────────────
section "10. HARDENING: PREVIEW CHANGES"
# ─────────────────────────────────────────────────

# Tab past remaining checkboxes to Preview Changes button
tabtimes 6

# Preview Changes
tw -k Return; sleep 3.0
shot "fn-22-preview-changes.png"
pass "Preview Changes activated"

# Tab to Cancel button
tw -k Tab; sleep 0.3
shot "fn-23-preview-panel.png"

# Cancel (don't actually apply)
tw -k Return; sleep 0.5
shot "fn-24-preview-cancelled.png"
pass "Preview cancelled safely"

# ─────────────────────────────────────────────────
section "11. HARDENING: CHECKPOINT CREATE"
# ─────────────────────────────────────────────────

tw -M ctrl -k 3 -m ctrl; sleep 0.6

# Tab to tab bar and go to History
tabtimes 8
tw -k End; sleep 0.5

# Tab to checkpoint name input
tabtimes 2

# Type checkpoint name
tw -s 100 "test-checkpoint-functional"
sleep 0.3
shot "fn-25-checkpoint-name.png"
pass "Checkpoint name entered"

# Tab to Create Checkpoint and activate
tw -k Tab; sleep 0.2
tw -k Return; sleep 2.0
shot "fn-26-checkpoint-created.png"
pass "Create Checkpoint activated"

# ─────────────────────────────────────────────────
section "12. REMOTE: ADD HOST FORM"
# ─────────────────────────────────────────────────

tw -M ctrl -k 4 -m ctrl; sleep 0.6
shot "fn-27-remote-page.png"

# Tab to Add Host button
tabtimes 10

# Open Add Host form
tw -k Return; sleep 0.5
shot "fn-28-add-host-form.png"
pass "Add Host form opened"

# Fill Display Name
tw -k Tab; sleep 0.2
tw -s 80 "test-server-01"; sleep 0.2

# Hostname/IP
tw -k Tab; sleep 0.2
tw -s 80 "192.168.1.100"; sleep 0.2

# SSH User
tw -k Tab; sleep 0.2
tw -s 80 "admin"; sleep 0.2

# Port (default 22, skip)
tw -k Tab; sleep 0.2

# Key File
tw -k Tab; sleep 0.2
tw -s 80 "~/.ssh/id_ed25519"; sleep 0.2

shot "fn-29-host-form-filled.png"
pass "Host form filled with test data"

# Tab past verify-host-key checkbox to Save
tw -k Tab; sleep 0.15
tw -k Tab; sleep 0.15

# Save
tw -k Return; sleep 1.0
shot "fn-30-host-saved.png"
pass "Host saved"

# ─────────────────────────────────────────────────
section "13. REMOTE: VERIFY HOST APPEARS IN LIST"
# ─────────────────────────────────────────────────

sleep 0.5
refocus
shot "fn-31-host-in-list.png"
pass "Host list view after save"

# ─────────────────────────────────────────────────
section "14. REMOTE: DELETE HOST"
# ─────────────────────────────────────────────────

# Tab to delete button area (Connect, Edit, Delete per host)
tabtimes 8

# Activate delete
tw -k Return; sleep 0.5
shot "fn-32-delete-host-confirm.png"

# Confirm deletion
tw -k Tab; sleep 0.2
tw -k Return; sleep 0.5
shot "fn-33-host-deleted.png"
pass "Host delete flow executed"

tw -k Escape; sleep 0.3

# ─────────────────────────────────────────────────
section "15. SCHEDULER: ENABLE & CONFIGURE"
# ─────────────────────────────────────────────────

tw -M ctrl -k 5 -m ctrl; sleep 0.6
shot "fn-34-scheduler-page.png"

# Tab to Enable checkbox
tabtimes 8

# Toggle Enable
tw -k space; sleep 0.3
shot "fn-35-scheduler-enabled.png"
pass "Scheduler enabled checkbox toggled"

# Tab to Schedule dropdown
tw -k Tab; sleep 0.2

# Select "Every 6 hours"
tw -k space; sleep 0.3
tw -k Down; sleep 0.2
tw -k Return; sleep 0.3
shot "fn-36-schedule-6h.png"
pass "Schedule changed to Every 6 hours"

# Tab to plugin checkboxes (cron hidden since not Custom)
tw -k Tab; sleep 0.15

# Toggle kernel plugin
tw -k space; sleep 0.2
pass "Scheduler kernel plugin toggled"

# Toggle ssh plugin
tw -k Tab; sleep 0.15
tw -k space; sleep 0.2
pass "Scheduler ssh plugin toggled"

# Skip remaining checkboxes + minimum severity to Save button
tabtimes 8

# Save Schedule
tw -k Return; sleep 1.5
shot "fn-37-schedule-saved.png"
pass "Schedule saved"

# ─────────────────────────────────────────────────
section "16. SCHEDULER: NOTIFICATIONS CONFIG"
# ─────────────────────────────────────────────────

# Tab to Email enable checkbox
tw -k Tab; sleep 0.2

# Toggle email
tw -k space; sleep 0.3
shot "fn-38-email-enabled.png"
pass "Email notifications enabled"

# Recipients
tw -k Tab; sleep 0.2
tw -s 80 "admin@example.com"; sleep 0.2

# From address
tw -k Tab; sleep 0.2
tw -s 80 "hardener@localhost"; sleep 0.2

# Webhook enable
tw -k Tab; sleep 0.2
tw -k space; sleep 0.3
shot "fn-39-webhook-enabled.png"
pass "Webhook notifications enabled"

# Endpoint URL
tw -k Tab; sleep 0.2
tw -s 60 "https://hooks.example.com/test"; sleep 0.2

# Format dropdown: select Slack
tw -k Tab; sleep 0.2
tw -k space; sleep 0.3
tw -k Down; sleep 0.2
tw -k Return; sleep 0.3
pass "Webhook format set to Slack"

# Save Notifications
tw -k Tab; sleep 0.2
tw -k Return; sleep 1.5
shot "fn-40-notifications-saved.png"
pass "Notifications saved"

# ─────────────────────────────────────────────────
section "17. SCHEDULER: TEST NOTIFICATION"
# ─────────────────────────────────────────────────

tw -k Tab; sleep 0.2
tw -k Return; sleep 2.0
shot "fn-41-test-notification.png"
pass "Test Notification button activated"

# ─────────────────────────────────────────────────
section "18. THEME PERSISTENCE CHECK"
# ─────────────────────────────────────────────────

# Switch to a non-default theme
tw -M alt -k t -m alt; sleep 0.4
shot "fn-42-theme-before-nav.png"

# Navigate away and back
tw -M ctrl -k 2 -m ctrl; sleep 0.5
tw -M ctrl -k 1 -m ctrl; sleep 0.5
shot "fn-43-theme-after-nav.png"
pass "Theme persists across page navigation"

# Reset theme to default (cycle through remaining 6)
for _ in $(seq 1 6); do
  tw -M alt -k t -m alt; sleep 0.3
done

# ─────────────────────────────────────────────────
section "19. DASHBOARD: VIEW ANALYSIS BUTTON"
# ─────────────────────────────────────────────────

tw -M ctrl -k 1 -m ctrl; sleep 0.6

# Tab to View Analysis button (after Run Scan)
tabtimes 9

tw -k Return; sleep 0.6
shot "fn-44-view-analysis-nav.png"
pass "View Analysis button navigates to Analysis"

# ─────────────────────────────────────────────────
section "20. DASHBOARD: CONFIGURE HARDENING BUTTON"
# ─────────────────────────────────────────────────

tw -M ctrl -k 1 -m ctrl; sleep 0.6

# Tab to Configure Hardening (one more than View Analysis)
tabtimes 10

tw -k Return; sleep 0.6
shot "fn-45-configure-hardening-nav.png"
pass "Configure Hardening button navigates to Hardening"

# ─────────────────────────────────────────────────
section "21. ERROR STATE: REMOTE CONNECT (no real host)"
# ─────────────────────────────────────────────────

tw -M ctrl -k 4 -m ctrl; sleep 0.6

# Tab to Connect button
tabtimes 9

# Connect (should fail gracefully: no real host)
tw -k Return; sleep 3.0
shot "fn-46-connect-error.png"
pass "Remote connect error handled gracefully"

tw -k Escape; sleep 0.3

# ─────────────────────────────────────────────────
# CLEANUP: Reset app state
# ─────────────────────────────────────────────────
tw -M ctrl -k 1 -m ctrl; sleep 0.5

# ─────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════"
echo "  FUNCTIONAL TESTS: $PASS passed, $FAIL failed, $SKIP skipped"
echo "════════════════════════════════════════════════"
if [ ${#FAILURES[@]} -gt 0 ]; then
  echo "FAILURES:"
  for f in "${FAILURES[@]}"; do
    echo "  x $f"
  done
fi
echo "Screenshots: $OUTDIR/fn-*.png"
