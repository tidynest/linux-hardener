use crate::components::SeverityBadge;
use crate::state::AppState;
use crate::types::Finding;
use leptos::prelude::*;

/// Displays a table of security findings.
///
/// Receives a pre-filtered list of findings from the parent component.
/// Handles row selection for the detail view.
#[component]
pub fn FindingsGrid(
    /// Findings to display, already filtered by the parent.
    findings: Signal<Vec<Finding>>,
) -> impl IntoView {
    let app_state = expect_context::<AppState>();

    let on_row_click = move |finding: Finding| {
        app_state.selected_finding.set(Some(finding));
    };

    view! {
        <section class="findings-grid">
            {move || {
                let findings = findings.get();
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
