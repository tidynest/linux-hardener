//! Recent activity component for the Dashboard.
//!
//! Displays a summary of the last scan and apply operations.

use super::icons::{IconAnalysis, IconHardening};
use crate::components::{Card, HeadingLevel};
use crate::state::AppState;
use leptos::prelude::*;
use leptos_router::components::A;

/// Recent activity summary for the Dashboard.
///
/// Shows the last scan date, finding count, and last apply status.
#[component]
pub fn RecentActivity() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Get finding count from last scan
    let finding_count = move || {
        app_state
            .scan_results
            .get()
            .iter()
            .flat_map(|r| r.scan_findings.iter())
            .count()
    };

    // Check if we have scan results
    let has_scan = move || !app_state.scan_results.get().is_empty();

    // Check if we have apply results
    let has_apply = move || !app_state.apply_results.get().is_empty();

    // Get last apply status
    let last_apply_success = move || {
        app_state
            .apply_results
            .get()
            .last()
            .map(|r| r.apply_success)
    };

    // Summarise the last apply honestly: "made" counts only successes,
    // failures and skips are named separately (shared phrase builder).
    let last_apply_summary = move || {
        app_state
            .apply_results
            .get()
            .last()
            .map(crate::utils::apply_change_summary)
            .unwrap_or_default()
    };

    view! {
        <Card title="Recent Activity" title_level=HeadingLevel::H2 class="recent-activity">
            <Show
                when=move || has_scan() || has_apply()
                fallback=|| view! {
                    <div class="empty-state">
                        <p class="empty-state-title">"No activity yet"</p>
                        <p class="empty-state-hint">"Run a security scan to see activity here."</p>
                    </div>
                }
            >
                <ul class="activity-list">
                    <Show when=has_scan>
                        <li class="activity-item">
                            <IconAnalysis class="activity-icon" />
                            <div class="activity-content">
                                <span class="activity-title">"Security Scan"</span>
                                <span class="activity-meta">
                                    {move || {
                                        let count = finding_count();
                                        format!(
                                            "{} finding{} detected",
                                            count,
                                            if count == 1 { "" } else { "s" },
                                        )
                                    }}
                                </span>
                            </div>
                            <A href="/analysis" attr:class="activity-link">"View"</A>
                        </li>
                    </Show>
                    <Show when=has_apply>
                        <li class="activity-item">
                            <IconHardening class="activity-icon" />
                            <div class="activity-content">
                                <span class="activity-title">
                                    {move || if last_apply_success().unwrap_or(false) {
                                        "Hardening Applied"
                                    } else {
                                        "Hardening Failed"
                                    }}
                                </span>
                                <span class="activity-meta">{last_apply_summary}</span>
                            </div>
                            <A href="/hardening" attr:class="activity-link">"Hardening History"</A>
                        </li>
                    </Show>
                </ul>
            </Show>
        </Card>
    }
}
