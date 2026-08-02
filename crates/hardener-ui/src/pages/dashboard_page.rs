//! Dashboard landing page: header, security score hero, and recent activity.

use crate::components::{RecentActivity, SecurityScore};
use crate::state::AppState;
use crate::tauri_bindings::invoke_get_scan_history;
use crate::utils::last_scanned_label;
use leptos::prelude::*;

/// Dashboard page: the score hero plus recent activity, under a compact header
/// whose subtitle is the last completed scan.
#[component]
pub fn DashboardPage() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Header subtitle: most recent completed scan, or "Not scanned yet".
    //
    // Re-read whenever a scan finishes rather than once on mount. Two of the
    // three places that run a scan can do it with this page in front of the
    // operator: the score hero's own privileged re-run sits on this page, and
    // the keyboard shortcut works from anywhere. Fetched once, the score, the
    // unchecked line and the activity list all moved while the subtitle went on
    // naming an older scan, so the one element on the page whose entire job is
    // to say how current the rest of it is was the only one that was not.
    //
    // `is_scanning` starts false, so the effect also performs the initial read
    // and the mount case needs no separate spelling. `analysis_page.rs` solves
    // the same problem inline in its own handler, which works there because it
    // owns the only scan that page can start.
    let last_scanned = RwSignal::new(String::from("Not scanned yet"));
    Effect::new(move |_| {
        if app_state.is_scanning.get() {
            return;
        }
        leptos::task::spawn_local(async move {
            if let Ok(sessions) = invoke_get_scan_history(Some(1)).await {
                last_scanned.set(last_scanned_label(&sessions));
            }
        });
    });

    view! {
        <article class="dashboard-page">
            <header class="dashboard-header">
                <h1>"Dashboard"</h1>
                <p class="dashboard-subtitle">{move || last_scanned.get()}</p>
            </header>

            <SecurityScore />
            <RecentActivity />
        </article>
    }
}
