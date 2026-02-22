//! Analysis page combining Scanner and Compliance functionality.
//!
//! Provides a tabbed interface for viewing findings and compliance reports.

use crate::components::{ComplianceTab, FindingsTab, MiniSecurityScore, TabBar, TabDef, TabPanel};
use crate::state::AppState;
use crate::tauri_bindings::invoke_scan;
use leptos::prelude::*;

/// Analysis page with tabbed interface for Findings and Compliance.
#[component]
pub fn AnalysisPage() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Tab state: 0 = Findings, 1 = Compliance
    let active_tab = RwSignal::new(0_usize);

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
            match invoke_scan().await {
                Ok(results) => {
                    app_state.scan_results.set(results);
                }
                Err(e) => {
                    web_sys::console::error_1(&format!("Scan failed: {}", e).into());
                    app_state.error_message.set(Some(format!("Scan failed: {}", e)));
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
        ]
    };

    view! {
        <article class="analysis-page">
            <header class="analysis-header">
                <div class="header-content">
                    <h1>"Security Analysis"</h1>
                    <p class="header-subtitle">
                        {move || match active_tab.get() {
                            0 => "Scan findings and security issues",
                            1 => "Compliance framework reports",
                            _ => "",
                        }}
                    </p>
                </div>
                <div class="header-actions">
                    <MiniSecurityScore />
                    <button
                        class="btn btn-primary"
                        on:click=on_scan
                        disabled=move || app_state.is_scanning.get()
                    >
                        {move || if app_state.is_scanning.get() {
                            "Scanning..."
                        } else {
                            "Run Security Scan"
                        }}
                    </button>
                </div>
            </header>

            <TabBar tabs=tabs() active_tab=active_tab aria_label="Analysis options" />

            <div class="tab-content">
                <TabPanel id="findings" index=0 active_tab=active_tab>
                    <FindingsTab />
                </TabPanel>
                <TabPanel id="compliance" index=1 active_tab=active_tab>
                    <ComplianceTab />
                </TabPanel>
            </div>
        </article>
    }
}
