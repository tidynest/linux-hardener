//! Compact security score display for page headers.

use crate::state::AppState;
use leptos::prelude::*;

/// Compact security score badge for headers.
///
/// Displays a smaller version of the security score with color coding.
/// Used in the Analysis page header alongside the scan button.
#[component]
pub fn MiniSecurityScore() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Calculate score from scan results (same logic as SecurityScore)
    let score = move || {
        let results = app_state.scan_results.get();
        if results.is_empty() {
            return None;
        }

        let mut total = 100i32;
        for result in &results {
            for finding in &result.scan_findings {
                let deduction = match finding.finding_severity {
                    hardener_types::Severity::Critical => 10,
                    hardener_types::Severity::High => 5,
                    hardener_types::Severity::Medium => 2,
                    hardener_types::Severity::Low => 1,
                    hardener_types::Severity::Info => 0,
                };
                total -= deduction;
            }
        }
        Some(total.max(0))
    };

    // Determine color class based on score
    let score_class = move || match score() {
        None => "score-pending",
        Some(s) if s >= 71 => "score-good",
        Some(s) if s >= 41 => "score-warning",
        Some(_) => "score-critical",
    };

    view! {
        <div class="mini-security-score">
            <span class=move || format!("mini-score-value {}", score_class())>
                {move || match score() {
                    Some(s) => format!("{}", s),
                    None => "--".to_string(),
                }}
            </span>
            <span class="mini-score-label">"Score"</span>
        </div>
    }
}
