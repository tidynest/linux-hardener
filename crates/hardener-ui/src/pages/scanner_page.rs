use leptos::prelude::*;

use crate::components::{FindingDetail, FindingsGrid};
use crate::state::AppState;
use crate::tauri_bindings::invoke_scan;

/// Scanner page for running system scans and viewing findings.
///
/// Features:
/// - Scan button to trigger system analysis
/// - Findings grid showing all security issues
/// - Finding detail panel for selected findings
/// - Empty state when no scan results exist
/// - Scanning state indicator
#[component]
pub fn ScannerPage() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Handler for running a scan
    let on_run_scan = move |_| {
        // Set scanning state
        app_state.is_applying.set(true);

        // Spawn async task to call backend
        leptos::task::spawn_local(async move {
            match invoke_scan().await {
                Ok(results) => {
                    app_state.scan_results.set(results);
                }
                Err(e) => {
                    // Log error - could add error state to AppState later
                    tracing::error!("Scan failed: {}", e);
                }
            }
            // Clear scanning state
            app_state.is_scanning.set(false);

        });
    };

    // Flatten all findings from all scan results
    let all_findings = move || {
        let results = app_state.scan_results.get();
        results
            .iter()
            .flat_map(|scan_result| scan_result.scan_findings.clone())
            .collect::<Vec<_>>()
    };

    // Check if we have any scan results
    let has_results = move || !app_state.scan_results.get().is_empty();

    view! {
        <article class="scanner-page">
        <header class="scanner-header">
        <h1>"Security Scanner"</h1>
        <p>"Run a comprehensive security scan to identify configuration issues."</p>
        </header>

        <section class="scanner-controls">
        <button
            class="btn btn-primary btn-large"
            on:click=on_run_scan
            disabled=move || app_state.is_scanning.get()
        >
        {move || if app_state.is_scanning.get() {
            "Scanning System..."
        } else {
            "Run Security Scan"
        }}
        </button>
        </section>

            <Show
                when=has_results
                fallback=|| view! {
                    <section class="empty-state">
                    <p>"No scan results yet. Click 'Run Security Scan' to begin analysis."</p>
                    </section>
                }
                >
                <section class="scanner-results">
                    <header class="results-header">

                        <h2>"Scan Results"</h2>
                        <p class="results-count">
                        {move || {
                            let count = all_findings().len();
                            format!("{} security finding{} detected", count, if count == 1 { "" } else { "s" })
                        }}
                        </p>
                        </header>

                        <div class="scanner-layout">
                        <FindingsGrid/>
                        <FindingDetail/>
                    </div>
                </section>
            </Show>
        </article>
    }
}
