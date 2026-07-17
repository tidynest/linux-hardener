//! Compliance tab content for the Analysis page.
//!
//! Contains framework selection and report generation.

use crate::components::{Card, CopyButton, HeadingLevel};
use crate::state::AppState;
use crate::tauri_bindings::{invoke_export_report, invoke_generate_report};
use leptos::prelude::*;

/// Compliance tab content with framework selection and reports.
#[component]
pub fn ComplianceTab() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Available compliance frameworks
    let frameworks = vec![
        ("cis", "CIS Benchmark"),
        ("stig", "DISA STIG"),
        ("nist", "NIST 800-53"),
        ("pci", "PCI-DSS"),
        ("hipaa", "HIPAA"),
        ("gdpr", "GDPR"),
        ("iso27001", "ISO 27001"),
        ("soc2", "SOC 2"),
        ("800-171", "NIST 800-171"),
        ("fedramp", "FedRAMP"),
    ];

    // Track selected frameworks
    let selected_frameworks = RwSignal::new(vec!["cis".to_string()]);

    // Status message for user feedback
    let status_message = RwSignal::new(Option::<(String, bool)>::None);

    // Export format state
    let export_format = RwSignal::new("text".to_string());
    let is_exporting = RwSignal::new(false);

    // Toggle framework selection
    let toggle_framework = move |framework: &str| {
        let framework = framework.to_string();
        selected_frameworks.update(|selected| {
            if selected.contains(&framework) {
                selected.retain(|f| f != &framework);
            } else {
                selected.push(framework);
            }
        });
    };

    // Generate reports handler
    let on_generate = move |_| {
        let frameworks = selected_frameworks.get();
        if frameworks.is_empty() {
            return;
        }

        app_state.is_generating_report.set(true);
        status_message.set(None);

        leptos::task::spawn_local(async move {
            match invoke_generate_report(frameworks).await {
                Ok(reports) => {
                    let count = reports.len();
                    app_state.compliance_reports.set(reports);
                    status_message.set(Some((
                        format!(
                            "Generated {} compliance report{}",
                            count,
                            if count == 1 { "" } else { "s" }
                        ),
                        true,
                    )));
                }
                Err(e) => {
                    web_sys::console::error_1(&format!("Report generation failed: {}", e).into());
                    status_message.set(Some((format!("Failed: {}", e), false)));
                }
            }
            app_state.is_generating_report.set(false);
        });
    };

    // Export handler: generates + saves to file
    let on_export = move |_| {
        let frameworks = selected_frameworks.get();
        if frameworks.is_empty() {
            return;
        }
        let format = export_format.get();
        is_exporting.set(true);
        status_message.set(None);

        leptos::task::spawn_local(async move {
            match invoke_export_report(frameworks, format, None).await {
                Ok(path) => {
                    status_message.set(Some((format!("Exported to {}", path), true)));
                }
                Err(e) => {
                    web_sys::console::error_1(&format!("Export failed: {}", e).into());
                    status_message.set(Some((format!("Export failed: {}", e), false)));
                }
            }
            is_exporting.set(false);
        });
    };

    view! {
        <div class="compliance-tab">
            <Card title="Select Compliance Frameworks" title_level=HeadingLevel::H2 class="framework-selection">
                <div class="framework-grid" role="group" aria-label="Compliance frameworks">
                    {frameworks.into_iter().map(|(id, label)| {
                        let id_str = id.to_string();
                        let id_for_check = id_str.clone();
                        let id_for_click = id_str.clone();

                        view! {
                            <label class="framework-checkbox">
                                <input
                                    type="checkbox"
                                    checked=move || selected_frameworks.get().contains(&id_for_check)
                                    on:change=move |_| toggle_framework(&id_for_click)
                                />
                                {label}
                            </label>
                        }
                    }).collect::<Vec<_>>()}
                </div>

                <div class="generate-actions">
                    <button
                        class="btn btn-primary"
                        on:click=on_generate
                        disabled=move || {
                            selected_frameworks.get().is_empty() || app_state.is_generating_report.get()
                        }
                    >
                        {move || if app_state.is_generating_report.get() {
                            "Generating..."
                        } else {
                            "Generate Reports"
                        }}
                    </button>

                    <div class="export-controls">
                        <select
                            class="format-select"
                            on:change=move |ev| {
                                export_format.set(event_target_value(&ev));
                            }
                        >
                            <option value="text" selected=true>"Text"</option>
                            <option value="json">"JSON"</option>
                            <option value="csv">"CSV"</option>
                            <option value="html">"HTML"</option>
                            <option value="pdf">"PDF"</option>
                        </select>
                        <button
                            class="btn btn-secondary"
                            on:click=on_export
                            disabled=move || {
                                selected_frameworks.get().is_empty() || is_exporting.get()
                            }
                        >
                            {move || if is_exporting.get() {
                                "Exporting..."
                            } else {
                                "Export to File"
                            }}
                        </button>
                    </div>

                    {move || status_message.get().map(|(msg, is_success)| {
                        let class = if is_success { "status-success" } else { "status-error" };
                        view! {
                            <span class=format!("status-message {}", class)>{msg}</span>
                        }
                    })}
                </div>
            </Card>

            <Card class="compliance-results">
                <Show
                    when=move || !app_state.compliance_reports.get().is_empty()
                    fallback=|| view! {
                        <div class="empty-state">
                            <div class="empty-state-icon">"📊"</div>
                            <p class="empty-state-title">"No reports generated yet"</p>
                            <p class="empty-state-hint">"Select frameworks and generate reports to see compliance status."</p>
                        </div>
                    }
                >
                    {move || app_state.compliance_reports.get().iter().map(|report| {
                        let framework = format!("{:?}", report.report_framework);
                        let score = report.report_summary.summary_score_percentage;
                        let passing = report.report_summary.summary_passing;
                        let failing = report.report_summary.summary_failing;
                        let manual = report.report_summary.summary_manual_review;
                        let na = report.report_summary.summary_not_applicable;

                        let copy_text = format!(
                            "{}: {:.0}%\nPassing: {} | Failing: {} | Manual: {} | N/A: {}",
                            framework, score, passing, failing, manual, na,
                        );

                        let score_class = if score >= 80.0 {
                            "score-high"
                        } else if score >= 60.0 {
                            "score-medium"
                        } else {
                            "score-low"
                        };

                        view! {
                            <div class="report-card">
                                <div class="report-card-header">
                                    <h3>{framework}</h3>
                                    <div class="report-card-actions">
                                        <span class=format!("compliance-score {}", score_class)>
                                            {format!("{:.0}%", score)}
                                        </span>
                                        <CopyButton text=Signal::derive(move || copy_text.clone()) />
                                    </div>
                                </div>

                                <div class="report-summary">
                                    <div class="summary-stat summary-pass">
                                        <span class="stat-value">{passing}</span>
                                        <span class="stat-label">"Passing"</span>
                                    </div>
                                    <div class="summary-stat summary-fail">
                                        <span class="stat-value">{failing}</span>
                                        <span class="stat-label">"Failing"</span>
                                    </div>
                                    <div class="summary-stat summary-manual">
                                        <span class="stat-value">{manual}</span>
                                        <span class="stat-label">"Manual"</span>
                                    </div>
                                    <div class="summary-stat summary-na">
                                        <span class="stat-value">{na}</span>
                                        <span class="stat-label">"N/A"</span>
                                    </div>
                                </div>
                            </div>
                        }
                    }).collect::<Vec<_>>()}
                </Show>
            </Card>
        </div>
    }
}
