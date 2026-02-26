# Severity Filter Implementation Plan

**Goal:** Add a client-side severity filter dropdown to the GUI findings tab, matching the CLI's `--severity` flag.

**Architecture:** Add `severity_filter` signal to `AppState`, a dropdown `<select>` in the `FindingsTab` header, and pass filtered findings to `FindingsGrid` as a prop. All filtering is client-side using `Severity`'s derived `PartialOrd`.

**Tech Stack:** Leptos (reactive signals, components, props), `hardener-types::Severity`

---

### Task 1: Add `severity_filter` signal to AppState

**Files:**
- Modify: `crates/hardener-ui/src/state/mod.rs:1` (import), `:17` (field), `:49` (default)

**Step 1: Add import**

At line 1, add `Severity` to the existing import:

```rust
use crate::types::{ApplyResult, ComplianceReport, Finding, RollbackResult, ScanResult, Severity};
```

**Step 2: Add field to AppState struct**

After `selected_finding` (line 17), add:

```rust
    /// Minimum severity threshold for findings display.
    /// None shows all findings; Some(level) filters to findings >= level.
    pub severity_filter: RwSignal<Option<Severity>>,
```

**Step 3: Add default initialisation**

In `Default::default()`, after `selected_finding` (line 48), add:

```rust
            severity_filter: RwSignal::new(None),
```

**Step 4: Verify build**

Run: `cargo check -p hardener-ui --target wasm32-unknown-unknown`
Expected: compiles cleanly (unused field warning is fine for now)

---

### Task 2: Refactor FindingsGrid to accept filtered findings as a prop

**Files:**
- Modify: `crates/hardener-ui/src/components/findings_grid.rs`

**Step 1: Replace internal state read with a prop**

Replace the full component with:

```rust
use crate::components::SeverityBadge;
use crate::state::AppState;
use crate::types::Finding;
use leptos::prelude::*;

/// Displays a table of security findings.
///
/// Receives a pre-filtered list of findings from the parent component.
/// Handles row selection for the detail view.
#[component]
pub fn FindingsGrid(
    /// Findings to display, already filtered by the parent.
    findings: Signal<Vec<Finding>>,
) -> impl IntoView {
    let app_state = expect_context::<AppState>();

    let on_row_click = move |finding: Finding| {
        app_state.selected_finding.set(Some(finding));
    };

    view! {
        <section class="findings-grid">
            {move || {
                let findings = findings.get();
                if findings.is_empty() {
                    view! {
                        <p class="empty-state">
                            "No security findings to display. Run a scan to see results."
                        </p>
                    }.into_any()
                } else {
                    view! {
                        <table class="findings-table">
                            <thead>
                                <tr>
                                    <th>"Severity"</th>
                                    <th>"Category"</th>
                                    <th>"Title"</th>
                                    <th>"Current Value"</th>
                                    <th>"Recommended Value"</th>
                                </tr>
                            </thead>
                            <tbody>
                                {findings.into_iter().map(|finding| {
                                    let finding_clone = finding.clone();
                                    view! {
                                        <tr
                                            class="finding-row"
                                            on:click=move |_| on_row_click(finding_clone.clone())
                                        >
                                            <td><SeverityBadge severity=finding.finding_severity/></td>
                                            <td>{format!("{:?}", finding.finding_category)}</td>
                                            <td>{finding.finding_title.clone()}</td>
                                            <td class="value-cell">{finding.finding_current_value.clone()}</td>
                                            <td class="value-cell">{finding.finding_recommended_value.clone()}</td>
                                        </tr>
                                    }
                                }).collect::<Vec<_>>()}
                            </tbody>
                        </table>
                    }.into_any()
                }
            }}
        </section>
    }
}
```

Key change: `findings: Signal<Vec<Finding>>` prop replaces internal `app_state.scan_results` read.

**Step 2: Verify build**

Run: `cargo check -p hardener-ui --target wasm32-unknown-unknown`
Expected: Compile error in `findings_tab.rs` (calling `FindingsGrid` without prop) — expected, fixed in Task 3.

---

### Task 3: Wire the severity filter dropdown in FindingsTab

**Files:**
- Modify: `crates/hardener-ui/src/components/findings_tab.rs`

This is the core logic. The `FindingsTab` component now:
1. Reads all findings from state
2. Computes filtered findings using the `severity_filter` signal
3. Renders a dropdown in the header
4. Passes filtered findings to `FindingsGrid`

**Step 1: Replace the full component**

```rust
//! Findings tab content for the Analysis page.
//!
//! Wraps the FindingsGrid and FindingDetail components with severity filtering.

use crate::components::{FindingDetail, FindingsGrid};
use crate::state::AppState;
use crate::types::Severity;
use leptos::prelude::*;

/// Maps a severity level to a numeric rank for comparison.
fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

/// Parses a dropdown value string into an Option<Severity>.
fn parse_severity(value: &str) -> Option<Severity> {
    match value {
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

/// Findings tab content displaying the scanner results.
///
/// Contains a severity filter dropdown in the header, the findings grid,
/// and the detail panel. Filtering is client-side — all findings remain
/// in memory and the dropdown instantly adjusts which are visible.
#[component]
pub fn FindingsTab() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // All findings flattened from scan results
    let all_findings = move || {
        app_state
            .scan_results
            .get()
            .iter()
            .flat_map(|r| r.scan_findings.clone())
            .collect::<Vec<_>>()
    };

    // Filtered findings based on severity threshold
    let filtered_findings = Signal::derive(move || {
        let all = all_findings();
        match app_state.severity_filter.get() {
            None => all,
            Some(min) => {
                let threshold = severity_rank(min);
                all.into_iter()
                    .filter(|f| severity_rank(f.finding_severity) >= threshold)
                    .collect()
            }
        }
    });

    let total_count = move || all_findings().len();
    let filtered_count = move || filtered_findings.get().len();
    let has_findings = move || !all_findings().is_empty();
    let is_filtered = move || app_state.severity_filter.get().is_some();

    // Handle dropdown change
    let on_filter_change = move |ev: leptos::ev::Event| {
        let value = event_target_value(&ev);
        app_state.severity_filter.set(parse_severity(&value));
    };

    view! {
        <div class="findings-tab">
            <Show
                when=has_findings
                fallback=|| view! {
                    <div class="empty-state">
                        <div class="empty-state-icon">"🔍"</div>
                        <p class="empty-state-title">"No findings yet"</p>
                        <p class="empty-state-hint">
                            "Click 'Run Security Scan' above to analyse your system. "
                            "Findings are grouped by severity: Critical, High, Medium, and Low."
                        </p>
                    </div>
                }
            >
                <header class="results-header">
                    <p>
                        {move || if is_filtered() {
                            format!("{} of {} findings", filtered_count(), total_count())
                        } else {
                            format!("{} findings detected", total_count())
                        }}
                    </p>

                    <div class="severity-filter">
                        <label for="severity-select">"Min severity"</label>
                        <select
                            id="severity-select"
                            on:change=on_filter_change
                        >
                            <option value="" selected=true>"All"</option>
                            <option value="low">"Low"</option>
                            <option value="medium">"Medium"</option>
                            <option value="high">"High"</option>
                            <option value="critical">"Critical"</option>
                        </select>
                    </div>
                </header>

                <div class="scanner-layout">
                    <FindingsGrid findings=filtered_findings />
                    <FindingDetail />
                </div>
            </Show>
        </div>
    }
}
```

**Step 2: Verify build**

Run: `cargo check -p hardener-ui --target wasm32-unknown-unknown`
Expected: compiles cleanly

**Step 3: Verify full test suite**

Run: `cargo test --workspace`
Expected: all tests pass (no test changes needed — this is UI-only)

**Step 4: Commit**

```bash
git add crates/hardener-ui/src/state/mod.rs \
       crates/hardener-ui/src/components/findings_grid.rs \
       crates/hardener-ui/src/components/findings_tab.rs
git commit -m "feat: add severity filter dropdown to findings tab"
```

---

### Task 4: Visual verification

**Step 1: Build WASM and launch**

```bash
cd crates/hardener-ui && trunk build --release && cd ../..
cargo tauri dev
```

**Step 2: Verify dropdown**

1. Run a scan
2. Confirm "X findings detected" shows in header
3. Select "High" from dropdown
4. Confirm count updates to "Y of X findings"
5. Confirm only High + Critical rows visible
6. Select "All" — full list returns

**Step 3: Update ROADMAP.md**

Change severity filter status from `⬜ Pending` to `✅ Complete`.
