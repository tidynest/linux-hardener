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
