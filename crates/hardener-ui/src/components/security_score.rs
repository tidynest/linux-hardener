//! Security score calculation based on compliance reports.
//!
//! Reads the per-framework score off each report and averages them for the
//! hero. **There is one scoring function in this project and it is not here**:
//! `ComplianceSummary::from_controls` in `hardener-types`, which is simply
//! `passing / (total - not_applicable)`.
//!
//! # Why this module no longer scores anything itself
//!
//! It used to hold a second, graded scorer - `Pass` 100, `ManualReview` 80, a
//! failing control 25 to 90 by worst live finding severity. That score was
//! always greater than or equal to the report's for the same scan and could be
//! far greater, so the dashboard and the compliance report published two
//! numbers for one host. Worse, `FrameworkScore` carried both and the row
//! rendered them together, so a single line read `91%` beside `30/44`, which
//! is 68 per cent. It contradicted itself without needing a second screen.
//!
//! The tie was not broken on taste. The project had already answered the
//! question the graded scorer reopened, in three places that all agree:
//! `assessment_honesty.rs` pins that an unassessed framework must not read as
//! compliant, the text report prints `Manual Review: N` immediately above the
//! score, and `report_coverage_note` exists (#161) to say in the artefact that
//! the checks which could not run are in the score's denominator. Unassessed
//! stays in the denominator and the count is shown beside the number.
//!
//! Grading contradicted all three silently: it priced a coverage gap at 80 and
//! a `High` failure at 25 with no count and no caveat, so a framework where
//! every control fails could publish 25 per cent with nothing passing.
//!
//! **The cost of the binary score is real and is answered by rendering, not by
//! arithmetic.** `ManualReview` means the engine has no check for that control,
//! which is a statement about this tool's coverage rather than about the host,
//! and it scores zero. So the row carries [`FrameworkScore::manual_review`] and
//! prints it: a low number reads "unassessed", not "failing". Pricing that
//! uncertainty at 80 hid it instead.

use crate::state::{AppState, unchecked_tally};
use crate::tauri_bindings::{invoke_deep_scan, invoke_generate_report, invoke_scan};
use crate::types::ComplianceReport;
use crate::utils::{
    is_auth_cancelled, score_band, score_band_class, score_band_label, unchecked_honesty_line,
};
use leptos::prelude::*;

/// Holds the score for a single framework, as the report scores it.
#[derive(Clone)]
pub struct FrameworkScore {
    pub name: String,
    pub score: f64,
    pub passing: usize,
    pub total: usize,
    /// Controls the engine has no check for. Not a judgement about the host,
    /// so the row renders it beside the score rather than letting an operator
    /// read a low number as failure.
    pub manual_review: usize,
    /// Controls a human declared not applicable. Distinct from `manual_review`
    /// because this count *raised* the score and that one lowered it.
    pub excluded: usize,
}

/// Calculates scores for all frameworks and returns overall average.
/// Returns (overall_score, framework_scores) tuple.
///
/// A framework with no applicable controls is dropped rather than rendered.
/// `ComplianceSummary::from_controls` used to score an empty denominator as
/// full compliance and now scores it 0, because an operator can reach that
/// state by excluding every control and a report claiming 100% with nothing
/// assessed is the one reading this project forbids. Neither number belongs on
/// a row: 100 overstates, and 0 reads as a failing framework when the truth is
/// that none of it was measured. So the row is dropped and the count of
/// excluded controls carries the explanation instead.
pub fn calculate_all_scores(reports: &[ComplianceReport]) -> (i32, Vec<FrameworkScore>) {
    let framework_scores: Vec<FrameworkScore> = reports
        .iter()
        .filter_map(|report| {
            let summary = &report.report_summary;
            let total = summary
                .summary_total_controls
                .saturating_sub(summary.summary_not_applicable);
            if total == 0 {
                return None;
            }
            Some(FrameworkScore {
                name: format!("{:?}", report.report_framework),
                score: summary.summary_score_percentage,
                passing: summary.summary_passing,
                total,
                manual_review: summary.summary_manual_review,
                excluded: summary.summary_not_applicable,
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
                                    // Without this an unassessed control is
                                    // indistinguishable from a failing one, and
                                    // the score counts both against the host.
                                    <Show when=move || fs.manual_review != 0>
                                        <span class="compliance-manual" title="Controls this build has no check for. Counted as unmet, not as failed.">
                                            {format!("{} unassessed", fs.manual_review)}
                                        </span>
                                    </Show>
                                    // The opposite direction to the count above:
                                    // an exclusion left the denominator and so
                                    // raised this score. A number that rose
                                    // because a human said so must not render
                                    // identically to one that rose because the
                                    // host improved.
                                    <Show when=move || fs.excluded != 0>
                                        <span class="compliance-excluded" title="Controls declared not applicable in configuration. These leave the score's denominator.">
                                            {format!("{} excluded by policy", fs.excluded)}
                                        </span>
                                    </Show>
                                </li>
                            }
                        }).collect::<Vec<_>>()}
                    </ul>
                </details>
            </Show>
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ComplianceSummary, ControlResult, ControlStatus};
    use serde_json::json;

    /// Builds a report whose summary is derived from its own controls.
    ///
    /// The summary is computed by [`ComplianceSummary::from_controls`] rather
    /// than written out, so the fixture cannot state a percentage its controls
    /// disagree with - which is the whole defect these tests are about. The
    /// report is assembled through JSON because `report_generated_at` is a
    /// `DateTime<Utc>` and this crate has no chrono; that is also the path the
    /// running application takes, since the UI only ever deserialises reports.
    fn report_of(statuses: &[ControlStatus]) -> ComplianceReport {
        let controls: Vec<ControlResult> = statuses
            .iter()
            .enumerate()
            .map(|(i, status)| ControlResult {
                control_id: format!("1.{i}"),
                control_title: format!("Control {i}"),
                control_section: "Fixture".to_string(),
                control_status: status.clone(),
                control_findings: Vec::new(),
            })
            .collect();
        let summary = ComplianceSummary::from_controls(&controls);

        serde_json::from_value(json!({
            "report_framework": "CIS",
            "report_generated_at": "2026-08-18T00:00:00Z",
            "report_controls": serde_json::to_value(&controls).expect("controls serialise"),
            "report_summary": serde_json::to_value(&summary).expect("summary serialises"),
        }))
        .expect("fixture deserialises as a report")
    }

    /// A `ManualReview` control is one the engine has no check for, so it is
    /// unassessed rather than met. The report, the PDF and the fleet columns
    /// all count it in the denominator and not in the numerator; the dashboard
    /// used to price it at 80, which is why one row could read 91% beside
    /// 30/44.
    #[test]
    fn manual_review_weighs_as_unmet_in_the_dashboard_score() {
        let (_, rows) = calculate_all_scores(&[report_of(&[
            ControlStatus::Pass,
            ControlStatus::ManualReview,
        ])]);

        let row = rows.first().expect("one framework");
        assert_eq!(row.score, 50.0, "one of two assessable controls passes");
        assert_eq!((row.passing, row.total), (1, 2));
    }

    /// The row prints a percentage and a fraction side by side, so the only
    /// defensible relationship between them is equality. `NotApplicable` is
    /// excluded from both, which is what makes the fraction's denominator 4
    /// rather than 5.
    #[test]
    fn dashboard_row_percentage_equals_the_fraction_beside_it() {
        let (overall, rows) = calculate_all_scores(&[report_of(&[
            ControlStatus::Pass,
            ControlStatus::Pass,
            ControlStatus::Pass,
            ControlStatus::ManualReview,
            ControlStatus::NotApplicable,
        ])]);

        let row = rows.first().expect("one framework");
        assert_eq!((row.passing, row.total), (3, 4), "NotApplicable excluded");
        assert_eq!(
            row.score,
            row.passing as f64 / row.total as f64 * 100.0,
            "the percentage must equal the fraction printed beside it"
        );
        assert_eq!(overall, 75, "the hero is the mean of those same numbers");
    }

    /// `unassessed` and `excluded` point in opposite directions: unassessed stays
    /// in the denominator and pushes the score down, excluded leaves it and pushes
    /// the score up. The row carries both counts so they cannot be read as one.
    #[test]
    fn the_row_carries_the_excluded_count_separately_from_the_unassessed_one() {
        let (_, rows) = calculate_all_scores(&[report_of(&[
            ControlStatus::Pass,
            ControlStatus::ManualReview,
            ControlStatus::NotApplicable,
            ControlStatus::NotApplicable,
        ])]);

        let row = rows.first().expect("one framework");
        assert_eq!(
            (row.passing, row.total),
            (1, 2),
            "excluded controls leave the denominator"
        );
        assert_eq!(row.manual_review, 1);
        assert_eq!(row.excluded, 2);
        assert_eq!(row.score, 50.0);
    }
}
