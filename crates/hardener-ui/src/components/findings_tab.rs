//! Findings tab content for the Analysis page.
//!
//! Wraps the FindingsGrid and FindingDetail components.

use crate::components::{FindingDetail, FindingsGrid};
use crate::state::AppState;
use leptos::prelude::*;

/// Findings tab content displaying the scanner results.
///
/// Contains the findings grid with severity filtering and the detail panel.
#[component]
pub fn FindingsTab() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Flatten all findings from scan results
    let findings = move || {
        app_state
            .scan_results
            .get()
            .iter()
            .flat_map(|r| r.scan_findings.clone())
            .collect::<Vec<_>>()
    };

    let finding_count = move || findings().len();
    let has_findings = move || !findings().is_empty();

    view! {
        <div class="findings-tab">
            <Show
                when=has_findings
                fallback=|| view! {
                    <div class="empty-state">
                        <p class="empty-state-title">"No findings yet"</p>
                        <p class="empty-state-hint">
                            "Click 'Run Security Scan' above to analyse your system. "
                            "Findings are grouped by severity: Critical, High, Medium, and Low."
                        </p>
                    </div>
                }
            >
                <header class="results-header">
                    <p>{move || format!("{} findings detected", finding_count())}</p>
                </header>

                <div class="scanner-layout">
                    <FindingsGrid />
                    <FindingDetail />
                </div>
            </Show>
        </div>
    }
}
