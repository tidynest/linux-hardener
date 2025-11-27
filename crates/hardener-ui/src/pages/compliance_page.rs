use leptos::prelude::*;
use tracing::error;

use crate::state::AppState;
use crate::tauri_bindings::invoke_generate_report;
use crate::types::{ComplianceReport, ControlStatus};

/// Available compliance frameworks for selection.
const FRAMEWORKS: &[(&str, &str)] = &[
    ("CIS", "CIS Benchmark"),
    ("STIG", "DISA STIG"),
    ("NIST", "NIST 800-53"),
    ("PCIDSS", "PCI-DSS v4.0"),
    ("HIPAA", "HIPAA Security Rule"),
    ("GDPR", "GDPR Article 32"),
];

/// Compliance reporting page for generating and viewing compliance reports.
///
/// Features:
/// - Framework selection checkboxes
/// - Generate report button
/// - Report display with summary and control results
#[component]
pub fn CompliancePage() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Local state for selected frameworks
    let selected_frameworks = RwSignal::new(vec!["CIS".to_string()]);

    // Toggle framework selection
    let toggle_framework = move |framework: String| {
        selected_frameworks.update(|frameworks| {
            if frameworks.contains(&framework) {
                frameworks.retain(|f| f != &framework);
            } else {
                frameworks.push(framework);
            }
        });
    };

    // Handler for generating reports
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
                    error!("Report generation failed: {}", e);
                }
            }
            app_state.is_generating_report.set(false);
        });
    };

    // Check there are any reports
    let has_reports = move || !app_state.compliance_reports.get().is_empty();

    view! {
        <article class="compliance-page">
            <header class="compliance-header">
                <h1>"Compliance Reports"</h1>
                <p>"Generate compliance reports against industry security frameworks."</p>
            </header>

            <section class="framework-selection">
                <h2>"Select Frameworks"</h2>
                <div class="framework-grid">
                    {FRAMEWORKS.iter().map(|(id, name)| {
                        let framework_id = id.to_string();
                        let framework_id_clone = framework_id.clone();
                        let is_selected = move || {
                            selected_frameworks.get().contains(&framework_id_clone)
                        };
                        view! {
                            <label class="framework-checkbox">
                                <input
                                    type="checkbox"
                                    checked=is_selected
                                    on:change=move |_| toggle_framework(framework_id.clone())
                                />
                                {*name}
                            </label>
                        }
                    }).collect::<Vec<_>>()}
                </div>

                <button
                    class="btn btn-primary"
                    on:click=on_generate
                    disabled=move || {
                        app_state.is_generating_report.get() || selected_frameworks.get().is_empty()
                    }
                >
                    {move || if app_state.is_generating_report.get() {
                        "Generating Reports..."
                    } else {
                        "Generate Reports"
                    }}
                </button>
            </section>

            <Show
                when=has_reports
                fallback=|| view! {
                    <section class="empty-state">
                        <p>"Select frameworks and click 'Generate Reports' to view compliance status."</p>
                    </section>
                }
            >
                <section class="compliance-results">
                    {move || app_state.compliance_reports.get().iter().map(|report| {
                        view! { <ReportCard report=report.clone()/> }
                    }).collect::<Vec<_>>()}
                </section>
            </Show>
        </article>
    }
}

/// Displays a single compliance report as a card.
#[component]
fn ReportCard(report: ComplianceReport) -> impl IntoView {
    let framework_name = report.report_framework.full_name();
    let summary = report.report_summary.clone();
    let score = summary.summary_score_percentage;

    let score_class = if score >= 80.0 {
        "score-high"
    } else if score >= 60.0 {
        "score-medium"
    } else {
        "score-low"
    };

    view! {
          <article class="report-card">
              <header class="report-card-header">
                  <h2>{framework_name}</h2>
                  <span class=format!("compliance-score {}", score_class)>
                      {format!("{:.0}%", score)}
                  </span>
              </header>

              <div class="report-summary">
                  <div class="summary-stat summary-pass">
                      <span class="stat-value">{summary.summary_passing}</span>
                      <span class="stat-label">"Passing"</span>
                  </div>
                  <div class="summary-stat summary-fail">
                      <span class="stat-value">{summary.summary_failing}</span>
                      <span class="stat-label">"Failing"</span>
                  </div>
                  <div class="summary-stat summary-manual">
                      <span class="stat-value">{summary.summary_manual_review}</span>
                      <span class="stat-label">"Manual Review"</span>
                  </div>
                  <div class="summary-stat summary-na">
                      <span class="stat-value">{summary.summary_not_applicable}</span>
                      <span class="stat-label">"N/A"</span>
                  </div>
              </div>

              <details class="report-controls">
                  <summary>"View Controls ("{report.report_controls.len()}" total)"</summary>
                  <table class="controls-table">
                      <thead>
                          <tr>
                              <th>"Control"</th>
                              <th>"Status"</th>
                              <th>"Title"</th>
                          </tr>
                      </thead>
                      <tbody>
                          {report.report_controls.iter().map(|control| {
                              let status_class = match control.control_status {
                                  ControlStatus::Pass => "status-pass",
                                  ControlStatus::Fail => "status-fail",
                                  ControlStatus::ManualReview => "status-manual",
                                  ControlStatus::NotApplicable => "status-na",
                              };
                              let status_text = match control.control_status {
                                  ControlStatus::Pass => "PASS",
                                  ControlStatus::Fail => "FAIL",
                                  ControlStatus::ManualReview => "REVIEW",
                                  ControlStatus::NotApplicable => "N/A",
                              };
                              view! {
                                  <tr>
                                      <td class="control-id">{control.control_id.clone()}</td>
                                      <td class=format!("control-status {}", status_class)>
                                          {status_text}
                                      </td>
                                      <td class="control-title">{control.control_title.clone()}</td>
                                  </tr>
                              }
                          }).collect::<Vec<_>>()}
                      </tbody>
                  </table>
              </details>
          </article>
      }
}
