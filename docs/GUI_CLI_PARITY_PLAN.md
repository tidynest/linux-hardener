# GUI vs CLI Feature Parity Improvement Plan

> **Status**: Complete (all 6 phases implemented as of 2026-02-24)
> **Target Version**: v0.4.0

## Executive Summary

The GUI currently supports basic scan/apply/rollback but lacks critical configuration options and safety features that the CLI provides. This plan addresses the gaps in priority order, grouped into implementation phases.

---

## User Decisions

| Decision | Choice |
|----------|--------|
| Dry-run UX | **Combined button** - "Preview & Apply" flow with inline preview, then confirm |
| History location | **Analysis tab** - New third tab: Findings \| Compliance \| History |
| Starting point | **Phase 1: Dry-run** - Safety-critical feature first |

---

## Priority Levels

### P0 - Critical (Safety & Core Usability)
Features without which the GUI is genuinely risky or frustrating to use.

### P1 - High (Major UX Gaps)
Features that significantly improve the user experience and match CLI functionality.

### P2 - Medium (Power User Features)
Features that enhance the GUI for advanced use cases.

### P3 - Lower (Advanced/Specialised)
Features that can be deferred to later versions.

---

## Feature Gap Analysis with Priorities

| Feature | CLI Equivalent | Priority | Rationale |
|---------|----------------|----------|-----------|
| **Dry-run preview** | `apply --dry-run` | P0 | Safety critical - users must see changes before applying |
| **Severity filter** | `scan --severity` | P0 | 47 findings is overwhelming; filtering is essential |
| **Plugin selection on scan** | `scan --plugin` | P1 | Users shouldn't scan everything every time |
| **Manual checkpoint create** | `checkpoint create` | P1 | Users need named restore points |
| **Checkpoint delete** | `checkpoint delete` | P1 | Housekeeping capability |
| **Report export to file** | `report --output` | P1 | Compliance reports useless without saving |
| **Report format selection** | `report --report-format` | P1 | PDF/HTML/CSV options needed |
| **Scan history** | `history list/show` | P2 | View past scan results |
| **Audit mode toggle** | `scan --audit` | P2 | Pure security assessment mode |
| **Compliance mode toggle** | `scan --compliance` | P2 | Policy violation focus |
| **Plugin listing** | `plugins` command | P2 | Know what's available |
| **Checkpoint details** | `checkpoint show` | P2 | View checkpoint contents |
| **Remote scanning** | `--ssh` flags | P3 | Complex SSH config UI |
| **Scheduler UI** | `daemon` commands | P3 | Daemon management |
| **Config file picker** | `--config FILE` | P3 | Power user feature |

---

## Implementation Phases

### Phase 1: Apply Safety (P0) - ✅ COMPLETE (2025-12-11)
**Goal:** Users can preview changes before applying with combined "Preview & Apply" flow

**Files to Modify:**
- `src-tauri/src/commands.rs` - Add `run_apply_dry_run` command
- `crates/hardener-ui/src/tauri_bindings.rs` - Add binding
- `src-tauri/src/main.rs` - Register command
- `crates/hardener-ui/src/components/configure_section.rs` - Replace Apply button with Preview & Apply flow
- `crates/hardener-ui/src/state/mod.rs` - Add preview state signals
- `crates/hardener-ui/styles.css` - Preview panel styles

**UX Flow (Combined Button):**
```
1. User selects plugins via profile/toggles
2. User clicks "Preview & Apply" button
3. System runs dry-run, shows inline preview panel:
   - List of changes grouped by plugin
   - Each change shows: file path, current value, new value
   - Summary: "X files will be modified, Y parameters changed"
4. User reviews changes
5. User clicks "Confirm & Apply" or "Cancel"
6. If confirmed: actual apply runs with pkexec
```

**Implementation Steps:**

**Step 1: Backend - Tauri Command**
```rust
// src-tauri/src/commands.rs
#[tauri::command]
pub async fn run_apply_dry_run(plugin_ids: Vec<String>) -> Result<Vec<ApplyResult>, String> {
    let mut args: Vec<&str> = vec!["apply", "--dry-run", "--format", "json"];
    // ... build plugin args
    // Calls CLI without pkexec (dry-run doesn't need root)
}
```

**Step 2: Frontend - Tauri Binding**
```rust
// crates/hardener-ui/src/tauri_bindings.rs
pub async fn invoke_apply_dry_run(plugin_ids: Vec<String>) -> Result<Vec<ApplyResult>, String>
```

**Step 3: State - Add Preview Signals**
```rust
// crates/hardener-ui/src/state/mod.rs
pub struct AppState {
    // ... existing fields
    pub preview_results: RwSignal<Option<Vec<ApplyResult>>>,
    pub is_previewing: RwSignal<bool>,
    pub preview_confirmed: RwSignal<bool>,
}
```

**Step 4: UI - Configure Section Changes**
1. Replace "Apply Hardening" button with "Preview & Apply"
2. Add preview panel (initially hidden, shown when preview_results is Some)
3. Preview panel shows:
   - Card per plugin with changes
   - "Confirm & Apply" primary button
   - "Cancel" secondary button
4. Clear preview state after apply completes or cancel

**Step 5: CSS - Preview Panel Styles**
- `.preview-panel` - Container with border, slight background
- `.preview-change` - Individual change row
- `.preview-value-old` / `.preview-value-new` - Value diff styling
- `.preview-actions` - Button container

**Estimated Complexity:** Medium (new command + UI component + state flow)

---

### Phase 2: Scan Filtering (P0) - COMPLETE
**Goal:** Users can filter findings and scan specific plugins

**Files to Modify:**
- `src-tauri/src/commands.rs` - Modify `run_scan` to accept options
- `crates/hardener-ui/src/tauri_bindings.rs` - Update binding signature
- `crates/hardener-ui/src/pages/analysis_page.rs` - Add filter controls
- `crates/hardener-ui/src/components/findings_tab.rs` - Client-side severity filter
- `crates/hardener-ui/src/state/mod.rs` - Add filter state signals

**Implementation:**
1. Add scan options struct:
   ```rust
   struct ScanOptions {
       plugins: Option<Vec<String>>,
       severity: Option<String>,
   }
   ```
2. Add collapsible "Scan Options" panel in Analysis header
3. Severity dropdown: Info/Low/Medium/High/Critical
4. Plugin checkboxes for selective scanning
5. Client-side filtering of displayed findings by severity

**Estimated Complexity:** Medium (API change + UI additions)

---

### Phase 3: Checkpoint Management (P1) - COMPLETE
**Goal:** Full checkpoint CRUD operations

**Files to Modify:**
- `src-tauri/src/commands.rs` - Add `create_checkpoint`, `delete_checkpoint`
- `crates/hardener-ui/src/tauri_bindings.rs` - Add bindings
- `src-tauri/src/main.rs` - Register commands
- `crates/hardener-ui/src/components/history_section.rs` - Add create/delete UI

**Implementation:**
1. `create_checkpoint(name: String)` - Creates named checkpoint
2. `delete_checkpoint(checkpoint_id: String)` - Removes checkpoint
3. Add "Create Checkpoint" button at top of History section
4. Add delete icon button on each checkpoint row
5. Confirmation dialog before delete

**Estimated Complexity:** Low-Medium (straightforward CRUD)

---

### Phase 4: Report Export (P1) - COMPLETE
**Goal:** Save compliance reports to files in various formats

**Files to Modify:**
- `src-tauri/src/commands.rs` - Add `export_report` command
- `crates/hardener-ui/src/tauri_bindings.rs` - Add binding
- `src-tauri/src/main.rs` - Register command
- `crates/hardener-ui/src/components/compliance_tab.rs` - Add export controls

**Implementation:**
1. `export_report(frameworks: Vec<String>, format: String)` command
   - Uses Tauri's file dialog for save location
   - Calls CLI report generation with format flag
   - Returns saved file path
2. Add format dropdown: Text/JSON/CSV/HTML/PDF
3. Add "Export Report" button
4. Show success message with file path

**Estimated Complexity:** Medium (file dialog integration)

---

### Phase 5: Scan History (P2) - COMPLETE
**Goal:** Browse and review past scan results in new Analysis tab

**Files to Modify:**
- `src-tauri/src/commands.rs` - Add `get_scan_history`, `get_scan_session`
- `crates/hardener-ui/src/tauri_bindings.rs` - Add bindings
- `src-tauri/src/main.rs` - Register commands
- `crates/hardener-ui/src/components/history_tab.rs` - NEW: History tab component
- `crates/hardener-ui/src/components/mod.rs` - Export HistoryTab
- `crates/hardener-ui/src/pages/analysis_page.rs` - Add third tab (Findings | Compliance | History)
- `crates/hardener-ui/src/state/mod.rs` - Add history state

**Implementation:**
1. `get_scan_history(limit: u32)` - Returns recent sessions metadata
2. `get_scan_session(session_id: String)` - Returns full session with findings
3. Add new HistoryTab component showing:
   - Session list with timestamps, plugin counts, finding severity breakdown
   - Click row to expand/view full session details
   - Export button per session
4. Update Analysis page TabBar: `["findings", "compliance", "history"]`

**Estimated Complexity:** Medium (new component + data flow)

---

### Phase 6: Mode Toggles (P2) - PARTIALLY COMPLETE
**Goal:** Audit and Compliance scan modes

**Files to Modify:**
- `src-tauri/src/commands.rs` - Extend scan options
- `crates/hardener-ui/src/pages/analysis_page.rs` - Add mode toggles

**Implementation:**
1. Add `audit_mode: bool`, `compliance_mode: bool` to scan options
2. Add toggle switches in Scan Options panel
3. Show mode indicator badge when active

**Estimated Complexity:** Low (extends Phase 2 work)

---

## Recommended Implementation Order

```
Phase 1 (Dry-run Preview)         - COMPLETE (2025-12-11)
Phase 2 (Scan Filtering)          - COMPLETE
Phase 3 (Checkpoint Management)   - COMPLETE
Phase 4 (Report Export)           - COMPLETE
Phase 5 (Scan History)            - COMPLETE
Phase 6 (Mode Toggles)            - PARTIALLY COMPLETE
```

> All core phases are complete. Phase 6 mode toggles have partial implementation.

---

## UI Location Summary

| Feature | Page | Component/Location |
|---------|------|-------------------|
| Dry-run preview | Hardening | Configure section - new "Preview" button + panel |
| Severity filter | Analysis | Header - dropdown control |
| Plugin scan select | Analysis | Header - collapsible options panel |
| Checkpoint create | Hardening | History section - button at top |
| Checkpoint delete | Hardening | History section - icon on each row |
| Report export | Analysis | Compliance tab - format dropdown + export button |
| Scan history | Analysis | New third tab (Findings \| Compliance \| History) |
| Mode toggles | Analysis | Scan Options panel - toggle switches |

---

## Key Files Reference

**Backend (Tauri):**
- `src-tauri/src/commands.rs` - Command implementations
- `src-tauri/src/main.rs` - Command registration

**Frontend (Leptos WASM):**
- `crates/hardener-ui/src/tauri_bindings.rs` - JS interop
- `crates/hardener-ui/src/state/mod.rs` - Reactive state
- `crates/hardener-ui/src/pages/*.rs` - Page layouts
- `crates/hardener-ui/src/components/*.rs` - Reusable components
- `crates/hardener-ui/styles.css` - Styling

---

## Approach: Guided Implementation

**You write the code, I guide you through each step.**

For each step, I will:
1. Explain what we're building and why
2. Show you exactly where in the file to add code (with line numbers)
3. Provide the code snippet (5-15 lines at a time)
4. Explain how it connects to other parts

This keeps you in control while learning the architecture.

---

## Current Tauri Commands (Reference)

| Command | Function | Notes |
|---------|----------|-------|
| `run_scan(plugin_ids, config_path)` | System scan with optional plugin/config filter | Returns `Result<Vec<ScanResult>, String>` |
| `run_apply(plugin_ids, config_path)` | Apply selected plugins | Uses pkexec for root |
| `run_apply_dry_run(plugin_ids, config_path)` | Preview changes without applying | No root required |
| `run_rollback(checkpoint_id)` | Restore checkpoint | Uses pkexec for root |
| `get_checkpoints()` | List checkpoints | Reads user + system DBs |
| `create_checkpoint(name)` | Create a named checkpoint | Returns checkpoint ID |
| `delete_checkpoint(checkpoint_id)` | Delete a checkpoint | Returns bool |
| `get_checkpoint_detail(checkpoint_id)` | View checkpoint contents | Returns file list |
| `generate_compliance_report(frameworks)` | Generate reports | Returns `Vec<ComplianceReport>` |
| `export_compliance_report(frameworks, format, output_path)` | Export report to file | Returns file path |
| `get_scan_history(limit)` | List recent scan sessions | Returns session metadata |
| `get_scan_session(session_id)` | Load full session results | Returns `Vec<ScanResult>` |
| `get_latest_scan()` | Load saved scan results | For state restoration |
| `list_plugins()` | List all available plugins | Returns `Vec<PluginMetadata>` |
| `list_remote_hosts()` | List saved SSH host profiles | Returns `Vec<RemoteHostProfile>` |
| `save_remote_host(profile)` | Save/update SSH host profile | Persists to hosts.toml |
| `delete_remote_host(name)` | Delete SSH host profile | Removes from hosts.toml |
| `connect_remote(name, state)` | Connect to remote host via SSH | Returns connection status |
| `disconnect_remote(state)` | Disconnect active SSH session | Clears connection state |
| `run_remote_scan(plugin_ids, state)` | Scan remote host via SSH | Returns `Vec<ScanResult>` |
| `get_scheduler_config()` | Load scheduler configuration | Returns `SchedulerUiConfig` |
| `save_scheduler_config(config)` | Save scheduler configuration | Writes to config.toml |
| `test_notification()` | Send test notification | Returns `TestNotificationResult` |
| `validate_config(path)` | Validate a config file | Returns `ConfigSummary` |
| `pick_config_file(app)` | Open file dialog for config | Returns selected path |

All planned commands from the original plan have been implemented.

---

**Last Updated**: 2026-02-27
