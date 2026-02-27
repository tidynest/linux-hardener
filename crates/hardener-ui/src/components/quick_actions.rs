use leptos::prelude::*;
use leptos_router::hooks::use_navigate;

use crate::components::{Card, HeadingLevel};
use crate::state::AppState;
use crate::tauri_bindings::{invoke_generate_report, invoke_scan};

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
            match invoke_scan(vec![], app_state.config_path.get_untracked()).await {
                Ok(results) => {
                    app_state.scan_results.set(results);

                    // Generate compliance reports for all frameworks after scan.
                    // This populates the data needed for the Security Score calculation.
                    let frameworks = vec![
                        "CIS".to_string(),
                        "STIG".to_string(),
                        "NIST".to_string(),
                        "PCIDSS".to_string(),
                        "HIPAA".to_string(),
                        "GDPR".to_string(),
                    ];
                    match invoke_generate_report(frameworks).await {
                        Ok(reports) => {
                            app_state.compliance_reports.set(reports);
                        }
                        Err(e) => {
                            web_sys::console::warn_1(
                                &format!("Compliance generation failed: {}", e).into(),
                            );
                        }
                    }
                }
                Err(e) => {
                    web_sys::console::error_1(&format!("Scan failed: {}", e).into());
                    app_state
                        .error_message
                        .set(Some(format!("Scan failed: {}", e)));
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
        <Card title="Quick Actions" title_level=HeadingLevel::H2 class="quick-actions">
            <nav class="action-buttons">
                <button
                    class="btn btn-primary"
                    on:click=on_run_scan
                    disabled=move || app_state.is_scanning.get()
                    aria-live="polite"
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
        </Card>
    }
}
