//! Findings tab content for the Analysis page.
//!
//! Wraps the FindingsGrid and FindingDetail components with severity and
//! view-mode filtering. View modes: All (audit-style, default), Compliance
//! (hides policy-excepted findings to show only real violations).

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

/// View mode for findings display.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ViewMode {
    /// Show all findings (audit-style — full assessment).
    All,
    /// Show only findings without policy exceptions (compliance violations).
    Compliance,
}

/// Findings tab content displaying the scanner results.
///
/// Contains severity and view-mode filters in the header, the findings grid,
/// and the detail panel. Both filters are client-side — all findings remain
/// in memory and the dropdowns instantly adjust which are visible.
#[component]
pub fn FindingsTab() -> impl IntoView {
    let app_state = expect_context::<AppState>();
    let view_mode = RwSignal::new(ViewMode::All);

    // All findings flattened from scan results
    let all_findings = move || {
        app_state
            .scan_results
            .get()
            .iter()
            .flat_map(|r| r.scan_findings.clone())
            .collect::<Vec<_>>()
    };

    // Filtered findings based on severity threshold and view mode
    let filtered_findings = Signal::derive(move || {
        let mut findings = all_findings();

        // Apply view mode filter
        if view_mode.get() == ViewMode::Compliance {
            findings.retain(|f| f.finding_policy_exception.is_none());
        }

        // Apply severity filter
        if let Some(min) = app_state.severity_filter.get() {
            let threshold = severity_rank(min);
            findings.retain(|f| severity_rank(f.finding_severity) >= threshold);
        }

        findings
    });

    let total_count = move || all_findings().len();
    let filtered_count = move || filtered_findings.get().len();
    let has_findings = move || !all_findings().is_empty();
    let is_filtered =
        move || app_state.severity_filter.get().is_some() || view_mode.get() != ViewMode::All;

    let on_severity_change = move |ev: leptos::ev::Event| {
        let value = event_target_value(&ev);
        app_state.severity_filter.set(parse_severity(&value));
    };

    let on_view_mode_change = move |ev: leptos::ev::Event| {
        let value = event_target_value(&ev);
        view_mode.set(match value.as_str() {
            "compliance" => ViewMode::Compliance,
            _ => ViewMode::All,
        });
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

                    <div class="findings-filters">
                        <div class="severity-filter">
                            <label for="severity-select">"Min severity"</label>
                            <select
                                id="severity-select"
                                on:change=on_severity_change
                            >
                                <option value="" selected=true>"All"</option>
                                <option value="low">"Low"</option>
                                <option value="medium">"Medium"</option>
                                <option value="high">"High"</option>
                                <option value="critical">"Critical"</option>
                            </select>
                        </div>

                        <div class="severity-filter">
                            <label for="view-mode-select">"View"</label>
                            <select
                                id="view-mode-select"
                                on:change=on_view_mode_change
                            >
                                <option value="all" selected=true>"All (Audit)"</option>
                                <option value="compliance">"Compliance Only"</option>
                            </select>
                        </div>
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
