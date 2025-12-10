//! Compact security score display for page headers.

use crate::components::calculate_all_scores;
use crate::state::AppState;
use leptos::prelude::*;

/// Compact security score badge for headers.
///
/// Displays a smaller version of the security score with color coding.
/// Uses the same compliance-based calculation as the main SecurityScore component.
#[component]
pub fn MiniSecurityScore() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Check if we have compliance data
    let has_data = move || !app_state.compliance_reports.get().is_empty();

    // Calculate score using the shared compliance-based algorithm
    let score = move || {
        let reports = app_state.compliance_reports.get();
        if reports.is_empty() {
            return None;
        }
        let (overall_score, _) = calculate_all_scores(&reports);
        Some(overall_score)
    };

    // Determine color class based on score
    let score_class = move || {
        if !has_data() {
            return "score-pending";
        }
        match score() {
            None => "score-pending",
            Some(s) if s >= 71 => "score-good",
            Some(s) if s >= 41 => "score-warning",
            Some(_) => "score-critical",
        }
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
