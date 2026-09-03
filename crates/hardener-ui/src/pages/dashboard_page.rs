//! Dashboard landing page: header, security score hero, the hardening area
//! map, and recent activity.

use crate::components::{AreaMap, RecentActivity, SecurityScore};
use crate::state::AppState;
use crate::utils::last_scanned_label;
use leptos::prelude::*;

/// Dashboard page: the score hero, the area map and recent activity, under a
/// compact header whose subtitle is the last completed scan.
///
/// The subtitle reads `AppState::last_scan_completed_at`, which the `Effect`
/// in `App` refreshes after every scan from anywhere in the app. This page
/// used to run its own history fetch; the posture strip needed the same
/// stamp on every route, so the fetch moved up and the page reads it.
#[component]
pub fn DashboardPage() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    view! {
        <article class="dashboard-page">
            <header class="dashboard-header">
                <h1>"Dashboard"</h1>
                <p class="dashboard-subtitle">
                    {move || last_scanned_label(app_state.last_scan_completed_at.get().as_deref())}
                </p>
            </header>

            <SecurityScore />
            <AreaMap />
            <RecentActivity />
        </article>
    }
}
