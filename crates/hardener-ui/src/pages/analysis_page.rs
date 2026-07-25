//! Analysis page combining Scanner and Compliance functionality.
//!
//! Provides a tabbed interface for viewing findings and compliance reports.

use crate::components::{ComplianceTab, FindingsTab, ScanHistoryTab, TabBar, TabDef, TabPanel};
use crate::state::AppState;
use crate::tauri_bindings::{invoke_generate_report, invoke_get_scan_history, invoke_scan};
use crate::utils::last_scanned_label;
use leptos::prelude::*;

/// Analysis page with tabbed interface for Findings and Compliance.
#[component]
pub fn AnalysisPage() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Tab state: 0 = Findings, 1 = Compliance, 2 = History
    let active_tab = RwSignal::new(0_usize);

    let last_scanned = RwSignal::new(String::from("Not scanned yet"));
    leptos::task::spawn_local(async move {
        if let Ok(sessions) = invoke_get_scan_history(Some(1)).await {
            last_scanned.set(last_scanned_label(&sessions));
        }
    });

    // Finding count for badge
    let finding_count = move || {
        app_state
            .scan_results
            .get()
            .iter()
            .flat_map(|r| r.scan_findings.iter())
            .count()
    };

    // Unified scan handler
    let on_scan = move |_| {
        app_state.is_scanning.set(true);

        leptos::task::spawn_local(async move {
            match invoke_scan(vec![], app_state.config_path.get_untracked()).await {
                Ok(results) => {
                    app_state.scan_results.set(results);

                    // Auto-generate compliance reports for all frameworks (consistent with Dashboard)
                    let frameworks = hardener_types::ComplianceFramework::ALL
                        .iter()
                        .map(|f| f.id().to_string())
                        .collect();
                    match invoke_generate_report(frameworks).await {
                        Ok(reports) => app_state.compliance_reports.set(reports),
                        Err(e) => {
                            web_sys::console::warn_1(
                                &format!("Compliance report generation failed: {e}").into(),
                            );
                        }
                    }

                    // Refresh the header subtitle so it reflects this scan
                    // rather than the value fetched once on mount.
                    if let Ok(sessions) = invoke_get_scan_history(Some(1)).await {
                        last_scanned.set(last_scanned_label(&sessions));
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

    // Build tab definitions with dynamic badge
    let tabs = move || {
        vec![
            TabDef {
                id: "findings",
                label: "Findings",
                badge: {
                    let count = finding_count();
                    if count > 0 { Some(count) } else { None }
                },
            },
            TabDef {
                id: "compliance",
                label: "Compliance",
                badge: None,
            },
            TabDef {
                id: "history",
                label: "History",
                badge: None,
            },
        ]
    };

    view! {
        <article class="analysis-page">
            <header class="analysis-header">
                <div class="header-content">
                    <h1>"Analysis"</h1>
                    <p class="header-subtitle">{move || last_scanned.get()}</p>
                </div>
                <button
                    class="btn btn-primary"
                    on:click=on_scan
                    disabled=move || app_state.is_scanning.get()
                    aria-live="polite"
                >
                    {move || if app_state.is_scanning.get() { "Scanning..." } else { "Run Security Scan" }}
                </button>
            </header>

            <TabBar tabs=Signal::derive(tabs) active_tab=active_tab aria_label="Analysis options" />

            <div class="tab-content">
                <TabPanel id="findings" index=0 active_tab=active_tab>
                    <FindingsTab />
                </TabPanel>
                <TabPanel id="compliance" index=1 active_tab=active_tab>
                    <ComplianceTab />
                </TabPanel>
                <TabPanel id="history" index=2 active_tab=active_tab>
                    <ScanHistoryTab active_tab=active_tab />
                </TabPanel>
            </div>
        </article>
    }
}
