//! Security score calculation based on compliance reports.
//!
//! Computes weighted scores per framework and an overall average.

use crate::components::{Card, HeadingLevel};
use crate::state::AppState;
use crate::types::{ComplianceReport, ControlStatus, Severity};
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
                // Use worst (lowest) severity weight from findings
                control
                    .control_findings
                    .iter()
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

/// Displays the calculated security score based on compliance reports.
///
/// Shows "Run a scan" when no data is available.
///
/// Score calculation:
/// - Uses compliance-based weighted scoring across all frameworks
/// - Each control's contribution is weighted by finding severity
/// - Pass = 100pts, Critical fail = 0pts, High = 25pts, Medium = 50pts, Low = 75pts
/// - Overall score is the average across all framework scores
///
/// Colour coding:
/// - No scan: Grey (neutral)
/// - 0-40: Red (critical state)
/// - 41-70: Yellow (needs attention)
/// - 71-100: Green (good state)
#[component]
pub fn SecurityScore() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    let has_compliance_data = move || !app_state.compliance_reports.get().is_empty();

    // Calculate score from compliance reports with severity weighting
    let scores = move || {
        let reports = app_state.compliance_reports.get();
        calculate_all_scores(&reports)
    };

    let score = move || scores().0;
    let framework_scores = move || scores().1;

    let score_class = move || {
        if !has_compliance_data() {
            return "score-pending";
        }
        let current_score = score();
        if current_score <= 40 {
            "score-critical"
        } else if current_score <= 70 {
            "score-warning"
        } else {
            "score-good"
        }
    };

    let score_status = move || {
        if !has_compliance_data() {
            return "Run a scan to see your score";
        }
        let current_score = score();
        if current_score <= 40 {
            "Critical - Immediate action required"
        } else if current_score <= 70 {
            "Needs attention"
        } else {
            "Good security posture"
        }
    };

    view! {
        <Card title="Security Score" title_level=HeadingLevel::H2 class="security-score">
            <output class={move || format!("score-display {}", score_class())}>
                {move || if has_compliance_data() {
                    view! {
                        <span class="score-value">{score}</span>
                        <span class="score-max">"/100"</span>
                    }.into_any()
                } else {
                    view! {
                        <span class="score-value">"--"</span>
                        <span class="score-max">"/100"</span>
                    }.into_any()
                }}
            </output>
            <p class="score-status">{score_status}</p>

            // Framework breakdown - only shown when we have data
            {move || {
                if has_compliance_data() {
                    let scores = framework_scores();
                    if scores.is_empty() {
                        view! { <div></div> }.into_any()
                    } else {
                        view! {
                            <details class="score-breakdown">
                                <summary class="breakdown-toggle">"Framework Breakdown"</summary>
                                <ul class="breakdown-list">
                                    {scores.into_iter().map(|fs| {
                                        let score_class = if fs.score >= 70.0 {
                                            "breakdown-good"
                                        } else if fs.score >= 40.0 {
                                            "breakdown-warning"
                                        } else {
                                            "breakdown-critical"
                                        };
                                        view! {
                                            <li class={format!("breakdown-item {}", score_class)}>
                                                <span class="breakdown-name">{fs.name}</span>
                                                <span class="breakdown-score">
                                                    {format!("{:.0}%", fs.score)}
                                                </span>
                                                <span class="breakdown-detail">
                                                    {format!("({}/{})", fs.passing, fs.total)}
                                                </span>
                                            </li>
                                        }
                                    }).collect::<Vec<_>>()}
                                </ul>
                            </details>
                        }.into_any()
                    }
                } else {
                    view! { <div></div> }.into_any()
                }
            }}
        </Card>
    }
}
