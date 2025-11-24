use hardener_core::plugin::Finding;
use leptos::prelude::*;

use crate::components::SeverityBadge;
use crate::state::AppState;

/// Displays a table of security findings with sortable columns.
///
/// Features:
/// - Table layout with severity, category, title, current/recommended values
/// - Click row to select finding for detailed view
/// - Empty state when no findings exist
/// - Semantic HTML table structure
#[component]
pub fn FindingsGrid() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Flatten all findings from scan results
    let all_findings = move || {
        let results = app_state.scan_results.get();
        results
            .iter()
            .flat_map(|scan_result| scan_result.scan_findings.clone())
            .collect::<Vec<_>>()
    };

    // Handle row click - set selected finding in state
    let on_row_click = move |finding: Finding| {
        app_state.selected_finding.set(Some(finding));
    };

    view! {
        <section class="findings-grid">
            {move || {
                let findings = all_findings();
                if findings.is_empty() {
                    view! {
                        <p class="empty-state">
                            "No security findings to display. Run a scan to see results."
                        </p>
                    }.into_any()
                } else {
                    view! {
                        <table class="findings-table">
                            <thead>
                                <tr>
                                    <th>"Severity"</th>
                                    <th>"Category"</th>
                                    <th>"Title"</th>
                                    <th>"Current Value"</th>
                                    <th>"Recommended Value"</th>
                                </tr>
                            </thead>
                            <tbody>
                                {findings.into_iter().map(|finding| {
                                    let finding_clone = finding.clone();
                                    view! {
                                        <tr
                                            class="finding-row"
                                            on:click=move |_| on_row_click(finding_clone.clone())
                                        >
                                            <td><SeverityBadge severity=finding.finding_severity/></td>
                                            <td>{format!("{:?}", finding.finding_category)}</td>
                                            <td>{finding.finding_title.clone()}</td>
                                            <td class="value-cell">{finding.finding_current_value.clone()}</td>
                                            <td class="value-cell">{finding.finding_recommended_value.clone()}</td>
                                        </tr>
                                    }
                                }).collect::<Vec<_>>()}
                            </tbody>
                        </table>
                    }.into_any()
                }
            }}
        </section>
    }
}