//! Compliance tab content for the Analysis page.
//!
//! Contains framework selection and report generation.

use crate::state::AppState;
use crate::tauri_bindings::invoke_generate_report;
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
    ];

    // Track selected frameworks
    let selected_frameworks = RwSignal::new(vec!["cis".to_string()]);

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

        leptos::task::spawn_local(async move {
            match invoke_generate_report(frameworks).await {
                Ok(reports) => {
                    app_state.compliance_reports.set(reports);
                }
                Err(e) => {
                    web_sys::console::error_1(&format!("Report generation failed: {}", e).into());
                }
            }
            app_state.is_generating_report.set(false);
        });
    };

    view! {
        <div class="compliance-tab">
            <section class="framework-selection">
                <h3>"Select Compliance Frameworks"</h3>
                <div class="framework-grid">
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
            </section>

            <section class="compliance-results">
                <Show
                    when=move || !app_state.compliance_reports.get().is_empty()
                    fallback=|| view! {
                        <div class="empty-state">
                            <p>"Select frameworks and generate reports to see compliance status."</p>
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
                                    <span class=format!("compliance-score {}", score_class)>
                                        {format!("{:.0}%", score)}
                                    </span>
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
            </section>
        </div>
    }
}
