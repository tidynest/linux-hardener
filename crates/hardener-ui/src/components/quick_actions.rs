use leptos::prelude::*;
use leptos_router::hooks::use_navigate;

use crate::state::AppState;
use crate::tauri_bindings::invoke_scan;

/// Quick action buttons for common tasks.
///
/// Provides:
/// - "Run Scan" button - Triggers a system scan via Tauri backend
/// - "View Analysis" button - Navigates to the Analysis page
/// - "Configure Hardening" button - Navigates to the Hardening page
#[component]
pub fn QuickActions() -> impl IntoView {
    let app_state = expect_context::<AppState>();
    let navigate = use_navigate();
    let navigate_hardening = use_navigate();

    let on_run_scan = move |_| {
        app_state.is_scanning.set(true);

        leptos::task::spawn_local(async move {
            match invoke_scan().await {
                Ok(results) => {
                    app_state.scan_results.set(results);
                }
                Err(e) => {
                    web_sys::console::error_1(&format!("Scan failed: {}", e).into());
                }
            }
            app_state.is_scanning.set(false);
        });
    };

    let on_view_analysis = move |_| {
        navigate("/analysis", Default::default());
    };

    let on_configure_hardening = move |_| {
        navigate_hardening("/hardening", Default::default());
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
                    on:click=on_view_analysis
                >
                    "View Analysis"
                </button>

                <button
                    class="btn btn-secondary"
                    on:click=on_configure_hardening
                >
                    "Configure Hardening"
                </button>
            </nav>
        </section>
    }
}
