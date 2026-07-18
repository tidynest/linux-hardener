//! Recent activity component for the Dashboard.
//!
//! Displays a summary of the last scan and apply operations.

use crate::components::{Card, HeadingLevel};
use crate::state::AppState;
use leptos::prelude::*;

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

    // Get last apply change count, excluding skips (no MAC system, etc.)
    // that never touched the host.
    let last_apply_changes = move || {
        app_state
            .apply_results
            .get()
            .last()
            .map(|r| r.applied_change_count())
            .unwrap_or(0)
    };

    view! {
        <Card title="Recent Activity" title_level=HeadingLevel::H2 class="recent-activity">
            <Show
                when=move || has_scan() || has_apply()
                fallback=|| view! {
                    <div class="empty-state">
                        <div class="empty-state-icon">"📋"</div>
                        <p class="empty-state-title">"No activity yet"</p>
                        <p class="empty-state-hint">"Use Quick Actions above to run a scan and see activity here."</p>
                    </div>
                }
            >
                <div class="activity-list">
                    <Show when=has_scan>
                        <div class="activity-item">
                            <div class="activity-icon scan">"⌕"</div>
                            <div class="activity-content">
                                <div class="activity-title">"Security Scan"</div>
                                <div class="activity-meta">
                                    {move || format!("{} findings detected", finding_count())}
                                </div>
                            </div>
                        </div>
                    </Show>

                    <Show when=has_apply>
                        <div class="activity-item">
                            <div class="activity-icon apply">"✓"</div>
                            <div class="activity-content">
                                <div class="activity-title">
                                    {move || if last_apply_success().unwrap_or(false) {
                                        "Hardening Applied"
                                    } else {
                                        "Hardening Failed"
                                    }}
                                </div>
                                <div class="activity-meta">
                                    {move || format!("{} changes made", last_apply_changes())}
                                </div>
                            </div>
                        </div>
                    </Show>
                </div>
            </Show>
        </Card>
    }
}
