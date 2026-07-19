//! Banner offering a privileged deep scan when unprivileged results contain
//! checks that could not be verified.

use crate::state::{AppState, total_unchecked};
use crate::tauri_bindings::{invoke_deep_scan, invoke_generate_report};
use leptos::prelude::*;

/// Shown when the current scan contains unchecked entries: names the count
/// and offers a pkexec deep scan that replaces the current results.
#[component]
pub fn UncheckedBanner() -> impl IntoView {
    let app_state = expect_context::<AppState>();
    let running = RwSignal::new(false);

    let unchecked_count = move || total_unchecked(&app_state.scan_results.get());

    let on_run_deep_scan = move |_| {
        running.set(true);

        leptos::task::spawn_local(async move {
            match invoke_deep_scan(vec![], app_state.config_path.get_untracked()).await {
                Ok(results) => {
                    app_state.scan_results.set(results);

                    // Regenerate compliance reports: this refreshes the
                    // compliance view (still computed at process privilege;
                    // covered-but-unchecked controls stay ManualReview),
                    // consistent with QuickActions.
                    let frameworks = hardener_types::ComplianceFramework::ALL
                        .iter()
                        .map(|f| f.id().to_string())
                        .collect();
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
                    web_sys::console::error_1(&format!("Deep scan failed: {}", e).into());
                    app_state
                        .error_message
                        .set(Some(format!("Deep scan failed: {}", e)));
                }
            }
            running.set(false);
        });
    };

    view! {
        <Show when=move || unchecked_count() != 0>
            <div class="unchecked-banner" role="status">
                <span class="unchecked-banner-text">
                    {move || format!(
                        "{} check(s) need privileges to verify",
                        unchecked_count()
                    )}
                </span>
                <button
                    class="unchecked-banner-button"
                    on:click=on_run_deep_scan
                    disabled=move || running.get()
                >
                    {move || if running.get() { "Scanning..." } else { "Run deep scan" }}
                </button>
            </div>
        </Show>
    }
}
