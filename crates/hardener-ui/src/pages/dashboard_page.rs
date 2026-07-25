//! Dashboard landing page: header, security score hero, and recent activity.

use crate::components::{RecentActivity, SecurityScore};
use crate::tauri_bindings::invoke_get_scan_history;
use crate::utils::last_scanned_label;
use leptos::prelude::*;

/// Dashboard page: the score hero plus recent activity, under a compact header
/// whose subtitle is the last completed scan (fetched on mount).
#[component]
pub fn DashboardPage() -> impl IntoView {
    // Header subtitle: most recent completed scan, or "Not scanned yet".
    let last_scanned = RwSignal::new(String::from("Not scanned yet"));
    leptos::task::spawn_local(async move {
        if let Ok(sessions) = invoke_get_scan_history(Some(1)).await {
            last_scanned.set(last_scanned_label(&sessions));
        }
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
