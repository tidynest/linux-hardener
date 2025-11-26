use hardener_common::types::Severity;
use leptos::prelude::*;

use crate::state::AppState;

/// Displays the calculated security score based on scan findings.
///
/// Score calculation:
/// - Start at 100
/// - Critical: -10 points each
/// - High: -5 points each
/// - Medium: -2 points each
/// - Low: -1 point each
/// - Info: -0 points
/// - Minimum score: 0
///
/// Colour coding:
/// - 0-40: Red (critical state)
/// - 41-70: Yellow (needs attention)
/// - 71-100: Green (good state)
#[component]
pub fn SecurityScore() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Calculate score from all findings across all scan results
    let score = move || {
        let results = app_state.scan_results.get();

        let mut total_score: i32 = 100;

        for scan_result in results.iter() {
            for finding in scan_result.scan_findings.iter() {
                let deduction = match finding.finding_severity {
                    Severity::Critical => 10,
                    Severity::High => 5,
                    Severity::Medium => 2,
                    Severity::Low => 1,
                    Severity::Info => 0,
                };
                total_score = total_score.saturating_sub(deduction);
            }
        }

        total_score
    };

    let score_class = move || {
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
        <section class="security-score">
            <h2>"Security Score"</h2>
            <output class={move || format!("score-display {}", score_class())}>
                <span class="score-value">{score}</span>
                <span class="score-max">"/100"</span>
            </output>
            <p class="score-status">{score_status}</p>
        </section>
    }
}
