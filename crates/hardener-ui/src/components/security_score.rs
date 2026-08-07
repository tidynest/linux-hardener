//! Security score calculation based on compliance reports.
//!
//! Computes weighted scores per framework and an overall average.

use crate::state::{AppState, unchecked_tally};
use crate::tauri_bindings::{invoke_deep_scan, invoke_generate_report, invoke_scan};
use crate::types::{ComplianceReport, ControlStatus, Severity};
use crate::utils::{
    is_auth_cancelled, score_band, score_band_class, score_band_label, unchecked_honesty_line,
};
use leptos::prelude::*;
use std::cmp::Ordering;

/// Converts finding severity to a score weight for failed controls.
///
/// Higher severity findings result in lower scores:
/// - Critical: 0 points (complete failure)
/// - High: 25 points (major issue)
/// - Medium: 50 points (moderate issue)
/// - Low: 75 points (minor issue)
/// - Info: 90 points (informational only)
fn severity_to_weight(severity: &Severity) -> f64 {
    match severity {
        Severity::Critical => 0.0,
        Severity::High => 25.0,
        Severity::Medium => 50.0,
        Severity::Low => 75.0,
        Severity::Info => 90.0,
    }
}

/// Calculates the weighted score for a single compliance framework.
///
/// Each control contributes to the score based on its status:
/// - Pass: 100 points
/// - NotApplicable: excluded from calculation
/// - ManualReview: 80 points (slight penalty for uncertainty)
/// - Fail: weighted by worst finding severity
fn calculate_framework_score(report: &ComplianceReport) -> Option<f64> {
    let applicable_controls: Vec<_> = report
        .report_controls
        .iter()
        .filter(|c| c.control_status != ControlStatus::NotApplicable)
        .collect();

    if applicable_controls.is_empty() {
        return None; // No applicable controls for this framework
    }

    let total_score: f64 = applicable_controls
        .iter()
        .map(|control| match control.control_status {
            ControlStatus::Pass => 100.0,
            ControlStatus::NotApplicable => 0.0, // Excluded above
            ControlStatus::ManualReview => 80.0,
            ControlStatus::Fail => {
                // Use worst (lowest) severity weight from the live findings. A
                // failing control can also carry an excepted finding as
                // evidence; a documented deviation must not weigh on the score.
                control
                    .control_findings
                    .iter()
                    .filter(|f| !f.is_policy_excepted())
                    .map(|f| severity_to_weight(&f.finding_severity))
                    .min_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal))
                    .unwrap_or(50.0) // Default to Medium if no findings
            }
        })
        .sum();

    Some(total_score / applicable_controls.len() as f64)
}

/// Holds the calculated score for a single framework.
#[derive(Clone)]
pub struct FrameworkScore {
    pub name: String,
    pub score: f64,
    pub passing: usize,
    pub total: usize,
}

/// Calculates scores for all frameworks and returns overall average.
/// Returns (overall_score, framework_scores) tuple.
pub fn calculate_all_scores(reports: &[ComplianceReport]) -> (i32, Vec<FrameworkScore>) {
    let framework_scores: Vec<FrameworkScore> = reports
        .iter()
        .filter_map(|report| {
            calculate_framework_score(report).map(|score| FrameworkScore {
                name: format!("{:?}", report.report_framework),
                score,
                passing: report.report_summary.summary_passing,
                total: report.report_summary.summary_total_controls
                    - report.report_summary.summary_not_applicable,
            })
        })
        .collect();

    if framework_scores.is_empty() {
        return (0, vec![]);
    }

    let avg = framework_scores.iter().map(|f| f.score).sum::<f64>() / framework_scores.len() as f64;
    (avg.round() as i32, framework_scores)
}

/// The Dashboard security-score hero: a band-coloured number with a thin bar,
/// a status pill, the primary Run Security Scan action, an in-hero honesty line
/// (offering a privileged deep scan when checks are unverified), and a collapsed
/// per-framework compliance disclosure. Empty until the first scan.
#[component]
pub fn SecurityScore() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    let has_compliance_data = move || !app_state.compliance_reports.get().is_empty();
    let tally = move || unchecked_tally(&app_state.scan_results.get());
    let scores = move || calculate_all_scores(&app_state.compliance_reports.get());
    let score = move || scores().0;
    let framework_scores = move || scores().1;
    let band = move || score_band(score());

    // Primary (unprivileged) scan: the hero's one accent action.
    let on_run_scan = move |_| {
        app_state.is_scanning.set(true);
        leptos::task::spawn_local(async move {
            match invoke_scan(vec![], app_state.config_path.get_untracked()).await {
                Ok(results) => {
                    app_state.scan_results.set(results);
                    let frameworks = hardener_types::ComplianceFramework::ALL
                        .iter()
                        .map(|f| f.id().to_string())
                        .collect();
                    match invoke_generate_report(frameworks).await {
                        Ok(reports) => app_state.compliance_reports.set(reports),
                        Err(e) => web_sys::console::warn_1(
                            &format!("Compliance generation failed: {e}").into(),
                        ),
                    }
                }
                Err(e) => {
                    web_sys::console::error_1(&format!("Scan failed: {e}").into());
                    app_state
                        .error_message
                        .set(Some(format!("Scan failed: {e}")));
                }
            }
            app_state.is_scanning.set(false);
        });
    };

    // Privileged deep scan, offered from the honesty line. Cancelled pkexec
    // is not an error.
    let deep_running = app_state.deep_scan_running;
    let on_deep_scan = move |_| {
        deep_running.set(true);
        leptos::task::spawn_local(async move {
            match invoke_deep_scan(vec![], app_state.config_path.get_untracked()).await {
                Ok(results) => {
                    app_state.scan_results.set(results);
                    let frameworks = hardener_types::ComplianceFramework::ALL
                        .iter()
                        .map(|f| f.id().to_string())
                        .collect();
                    if let Ok(reports) = invoke_generate_report(frameworks).await {
                        app_state.compliance_reports.set(reports);
                    }
                }
                Err(e) if is_auth_cancelled(&e) => {}
                Err(e) => {
                    app_state
                        .error_message
                        .set(Some(format!("Deep scan failed: {e}")));
                }
            }
            deep_running.set(false);
        });
    };

    view! {
        <section class="score-hero">
            <Show
                when=has_compliance_data
                fallback=move || view! {
                    <div class="score-empty">
                        <p class="score-empty-title">"Not scanned yet"</p>
                        <button
                            class="btn btn-primary"
                            on:click=on_run_scan
                            disabled=move || app_state.is_scanning.get()
                            aria-live="polite"
                        >
                            {move || if app_state.is_scanning.get() { "Scanning..." } else { "Run Security Scan" }}
                        </button>
                    </div>
                }
            >
                <div class=move || format!("score-hero-main {}", score_band_class(band()))>
                    <div class="score-hero-head">
                        <output class="score-number">
                            {score}<span class="score-max">"/100"</span>
                        </output>
                        <span class="score-pill">{move || score_band_label(band())}</span>
                        <button
                            class="btn btn-primary score-scan-btn"
                            on:click=on_run_scan
                            disabled=move || app_state.is_scanning.get()
                            aria-live="polite"
                        >
                            {move || if app_state.is_scanning.get() { "Scanning..." } else { "Run Security Scan" }}
                        </button>
                    </div>
                    <div class="score-bar">
                        <div class="score-bar-fill" style=move || format!("width: {}%", score().clamp(0, 100))></div>
                    </div>
                    <Show when=move || tally().total != 0>
                        <p class="score-honesty">
                            {move || unchecked_honesty_line(tally())}
                            <Show when=move || tally().privilege_would_help()>
                                <button
                                    class="link-button"
                                    on:click=on_deep_scan
                                    disabled=move || deep_running.get()
                                >
                                    {move || if deep_running.get() { "Scanning..." } else { "Run with sudo" }}
                                </button>
                            </Show>
                        </p>
                    </Show>
                </div>

                <details class="compliance-disclosure">
                    <summary>"Compliance by framework"</summary>
                    <ul class="compliance-list">
                        {move || framework_scores().into_iter().map(|fs| {
                            let cls = score_band_class(score_band(fs.score.round() as i32));
                            view! {
                                <li class=format!("compliance-item {}", cls)>
                                    <span class="compliance-name">{fs.name}</span>
                                    <span class="compliance-score">{format!("{:.0}%", fs.score)}</span>
                                    <span class="compliance-detail">{format!("{}/{}", fs.passing, fs.total)}</span>
                                </li>
                            }
                        }).collect::<Vec<_>>()}
                    </ul>
                </details>
            </Show>
        </section>
    }
}
