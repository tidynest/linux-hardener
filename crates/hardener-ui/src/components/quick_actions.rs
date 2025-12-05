use leptos::prelude::*;
use leptos_router::hooks::use_navigate;

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
    let navigate = use_navigate();

    let on_run_scan = move |_| {
        // Set scanning state to true
        app_state.is_scanning.set(true);

        // TODO: Replace with real Tauri backend call
        let mock_results = create_mock_scan_results();
        app_state.scan_results.set(mock_results);

        // Set scanning state to false
        app_state.is_scanning.set(false);
    };

    let on_view_findings = move |_| {
        navigate("/scan", Default::default());
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

                <button
                    class="btn btn-secondary"
                    on:click=on_view_findings
                >
                    "View Findings"
                </button>
            </nav>
        </section>
    }
}
