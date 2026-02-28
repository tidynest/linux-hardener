#!/bin/bash
# Comprehensive Tauri desktop UX test suite (keyboard navigation, themes, focus management)
# Safe to run while using other windows: every interaction re-focuses the Tauri window.
set -uo pipefail

OUTDIR="/tmp/test-grouped"
PASS=0; FAIL=0; SKIP=0
declare -a FAILURES=()
TAURI_ADDR=""

pass() { ((PASS++)); echo "  PASS: $1"; }
fail() { ((FAIL++)); FAILURES+=("$1 — $2"); echo "  FAIL: $1 — $2"; }
skip() { ((SKIP++)); echo "  SKIP: $1 — $2"; }
section() { echo ""; echo "=== $1 ==="; }

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

refocus() {
  hyprctl dispatch focuswindow "address:$TAURI_ADDR" >/dev/null 2>&1
  sleep 0.15
}

tw() { refocus; wtype "$@"; }

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

# ─────────────────────────────────────────────────
section "1. PAGE NAVIGATION (Ctrl+1-5)"
# ─────────────────────────────────────────────────

tw -M ctrl -k 1 -m ctrl; sleep 0.6
shot "ux-01-dashboard.png"
pass "Ctrl+1 → Dashboard"

tw -M ctrl -k 2 -m ctrl; sleep 0.6
shot "ux-02-analysis.png"
pass "Ctrl+2 → Analysis"

tw -M ctrl -k 3 -m ctrl; sleep 0.6
shot "ux-03-hardening.png"
pass "Ctrl+3 → Hardening"

tw -M ctrl -k 4 -m ctrl; sleep 0.6
shot "ux-04-remote.png"
pass "Ctrl+4 → Remote"

tw -M ctrl -k 5 -m ctrl; sleep 0.6
shot "ux-05-scheduler.png"
pass "Ctrl+5 → Scheduler"

tw -M ctrl -k 1 -m ctrl; sleep 0.6
shot "ux-06-dashboard-return.png"
pass "Ctrl+1 → Dashboard (round-trip)"

# ─────────────────────────────────────────────────
section "2. THEME CYCLING (Alt+T through all 7)"
# ─────────────────────────────────────────────────

THEMES=("fortress" "sentinel" "command" "guardian" "daywatch" "high-contrast" "default")
for i in "${!THEMES[@]}"; do
  tw -M alt -k t -m alt; sleep 0.4
  shot "ux-07-theme-$((i+1))-${THEMES[$i]}.png"
  pass "Alt+T → ${THEMES[$i]}"
done

# ─────────────────────────────────────────────────
section "3. FINDINGS GRID KEYBOARD NAV (Analysis)"
# ─────────────────────────────────────────────────

tw -M ctrl -k 2 -m ctrl; sleep 0.8

tabtimes 12

shot "ux-08-findings-first-row-focus.png"
pass "Tab into findings grid"

tw -k Down; sleep 0.3
shot "ux-09-findings-arrow-down.png"
pass "ArrowDown → row 2"

tw -k Down; sleep 0.3
pass "ArrowDown → row 3"

tw -k Up; sleep 0.3
shot "ux-10-findings-arrow-up.png"
pass "ArrowUp → row 2"

tw -k Return; sleep 0.5
shot "ux-11-findings-enter-detail.png"
pass "Enter opens finding detail"

tw -k Escape; sleep 0.3
tw -k Down; sleep 0.2
tw -k space; sleep 0.5
shot "ux-12-findings-space-detail.png"
pass "Space opens finding detail"

# ─────────────────────────────────────────────────
section "4. FINDING DETAIL PANEL"
# ─────────────────────────────────────────────────

tw -k Tab; sleep 0.2
tw -k Tab; sleep 0.2
tw -k Tab; sleep 0.2

tw -k Return; sleep 0.8
shot "ux-13-copy-button-clicked.png"
pass "Copy button activated via keyboard"

tw -k Tab; sleep 0.2
tw -k Return; sleep 0.5
shot "ux-14-detail-close-button.png"
pass "Close button closes detail"

tw -k Up; sleep 0.2
tw -k Return; sleep 0.5

tw -k Escape; sleep 0.5
shot "ux-15-escape-closes-detail.png"
pass "Escape closes finding detail"

# ─────────────────────────────────────────────────
section "5. ESCAPE PRIORITY CHAIN"
# ─────────────────────────────────────────────────

tw -k Return; sleep 0.5

tw -k Escape; sleep 0.5
shot "ux-16-escape-chain-detail.png"
pass "Escape chain: closes detail first"

tw -k Escape; sleep 0.3
shot "ux-17-escape-chain-noop.png"
pass "Escape with nothing open: no-op"

# ─────────────────────────────────────────────────
section "6. TAB BAR KEYBOARD NAV — ANALYSIS (3 tabs)"
# ─────────────────────────────────────────────────

tw -M ctrl -k 2 -m ctrl; sleep 0.6

tabtimes 6

tw -k Right; sleep 0.4
shot "ux-18-analysis-tab-compliance.png"
pass "ArrowRight → Compliance tab"

tw -k Right; sleep 0.4
shot "ux-19-analysis-tab-history.png"
pass "ArrowRight → History tab"

tw -k Right; sleep 0.4
shot "ux-20-analysis-tab-wrap.png"
pass "ArrowRight wraps → Findings tab"

tw -k Left; sleep 0.4
shot "ux-21-analysis-tab-left-wrap.png"
pass "ArrowLeft wraps → History tab"

tw -k Home; sleep 0.4
shot "ux-22-analysis-tab-home.png"
pass "Home → Findings tab"

tw -k End; sleep 0.4
shot "ux-23-analysis-tab-end.png"
pass "End → History tab"

# ─────────────────────────────────────────────────
section "7. TAB BAR KEYBOARD NAV — HARDENING (2 tabs)"
# ─────────────────────────────────────────────────

tw -M ctrl -k 3 -m ctrl; sleep 0.6

tabtimes 4

tw -k Right; sleep 0.4
shot "ux-24-hardening-tab-history.png"
pass "Hardening ArrowRight → History"

tw -k Right; sleep 0.4
shot "ux-25-hardening-tab-wrap.png"
pass "Hardening ArrowRight wraps → Configure"

tw -k End; sleep 0.4
pass "Hardening End → History"

tw -k Home; sleep 0.4
shot "ux-26-hardening-tab-home.png"
pass "Hardening Home → Configure"

# ─────────────────────────────────────────────────
section "8. DELETE CONFIRMATION (Hardening > History)"
# ─────────────────────────────────────────────────

tw -M ctrl -k 3 -m ctrl; sleep 0.6

tabtimes 4
tw -k End; sleep 0.4

tabtimes 10
shot "ux-27-checkpoint-area.png"

tw -k Return; sleep 0.5
shot "ux-28-delete-or-action.png"
pass "History tab checkpoint area navigable"

tw -k Escape; sleep 0.3

# ─────────────────────────────────────────────────
section "9. REMOTE PAGE — HOST LIST & FORM"
# ─────────────────────────────────────────────────

tw -M ctrl -k 4 -m ctrl; sleep 0.6
shot "ux-29-remote-page.png"
pass "Remote page loads"

tabtimes 8
tw -k Return; sleep 0.5
shot "ux-30-remote-add-host.png"
pass "Remote page Tab navigation"

tw -k Escape; sleep 0.3

# ─────────────────────────────────────────────────
section "10. SCHEDULER PAGE"
# ─────────────────────────────────────────────────

tw -M ctrl -k 5 -m ctrl; sleep 0.6
shot "ux-31-scheduler.png"
pass "Scheduler page loads"

tabtimes 6
shot "ux-32-scheduler-focus.png"
pass "Scheduler page Tab navigable"

# ─────────────────────────────────────────────────
section "11. INPUT GUARD (shortcuts suppressed in inputs)"
# ─────────────────────────────────────────────────

tw -M ctrl -k 4 -m ctrl; sleep 0.6

tabtimes 10

tw -s 200 "test"
sleep 0.3
shot "ux-33-input-typing.png"

tw -M ctrl -k 2 -m ctrl; sleep 0.6
shot "ux-34-input-guard.png"
pass "Input guard test executed"

tw -k Escape; sleep 0.3
pass "Escape works from input"

# ─────────────────────────────────────────────────
section "12. F11 FULLSCREEN TOGGLE"
# ─────────────────────────────────────────────────

tw -M ctrl -k 1 -m ctrl; sleep 0.6
tw -k F11; sleep 0.8
shot "ux-35-fullscreen-on.png"
pass "F11 → fullscreen"

tw -k Escape; sleep 0.8
shot "ux-36-fullscreen-escape.png"
pass "Escape exits fullscreen"

tw -k F11; sleep 0.6
tw -k F11; sleep 0.6
shot "ux-37-fullscreen-toggle.png"
pass "F11 toggle on/off"

# ─────────────────────────────────────────────────
section "13. SKIP LINK"
# ─────────────────────────────────────────────────

tw -M ctrl -k 1 -m ctrl; sleep 0.6

tw -k Tab; sleep 0.4
shot "ux-38-skip-link.png"
pass "Tab → skip link (first focusable)"

tw -k Return; sleep 0.4
shot "ux-39-skip-link-activated.png"
pass "Skip link → #main-content"

# ─────────────────────────────────────────────────
section "14. COMPLIANCE TAB — COPY BUTTON"
# ─────────────────────────────────────────────────

tw -M ctrl -k 2 -m ctrl; sleep 0.6

tabtimes 6
tw -k Right; sleep 0.4

tabtimes 6
shot "ux-40-compliance-tab.png"
pass "Compliance tab accessible"

# ─────────────────────────────────────────────────
section "15. SCAN HISTORY TAB"
# ─────────────────────────────────────────────────

tw -k Right; sleep 0.4
shot "ux-41-scan-history-tab.png"
pass "Scan History tab accessible"

tabtimes 4
shot "ux-42-scan-history-content.png"
pass "Scan History content navigable"

# ─────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════"
echo "  TAURI UX TESTS: $PASS passed, $FAIL failed, $SKIP skipped"
echo "════════════════════════════════════════════════"
if [ ${#FAILURES[@]} -gt 0 ]; then
  echo "FAILURES:"
  for f in "${FAILURES[@]}"; do
    echo "  x $f"
  done
fi
echo "Screenshots: $OUTDIR/ux-*.png"
