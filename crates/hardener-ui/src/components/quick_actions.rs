use leptos::prelude::*;
use leptos_router::components::A;

use crate::state::AppState;
use crate::utils::create_mock_scan_results;

/// Quick action buttons for common tasks.
///
/// Provides:
/// - "Run Scan" button - Triggers a system scan (currently uses mock data)
/// - "View Findings" button - Navigates to the scanner page to see all findings
#[component]
pub fn QuickActions() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    let on_run_scan = move |_| {
        // Set scanning state to true
        app_state.is_scanning.set(true);

        // Simulate async scan operation
        // TODO: Replace with real Tauri backend call in Week 19
        let mock_results = create_mock_scan_results();
        app_state.scan_results.set(mock_results);

        // Set scanning state to false
        app_state.is_scanning.set(false);
    };

    view! {
        <section class="quick-actions">
            <h2>"Quick Actions"</h2>
            <nav class="action-buttons">
                <button
                    class="btn btn-primary"
                    on:click=on_run_scan
                    disabled=move || app_state.is_scanning.get()
                >
                    {move || if app_state.is_scanning.get() {
                        "Scanning..."
                    } else {
                        "Run Scan"
                    }}
                </button>

                <A href="/scan" attr: class="btn btn-secondary">
                "View Findings"
                </A>
            </nav>
        </section>
    }
}
