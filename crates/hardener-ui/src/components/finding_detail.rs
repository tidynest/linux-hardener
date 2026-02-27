use leptos::prelude::*;

use crate::components::{CopyButton, SeverityBadge};
use crate::state::AppState;

/// Displays detailed information about a selected finding.
///
/// Features:
/// - Full finding details including description, explanation, impact
/// - Current vs recommended values comparison
/// - Step-by-step remediation instructions
/// - Close button to deselect finding
/// - Only renders when a finding is selected
/// - Semantic HTML structure with aside element
#[component]
pub fn FindingDetail() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Handler to close the detail panel
    let on_close = move |_| {
        app_state.selected_finding.set(None);
    };

    view! {
        <Show when=move || app_state.selected_finding.get().is_some()>
            {move || {
                app_state.selected_finding.get().map(|finding| {
                    // Build a structured text summary for clipboard
                    let copy_text = {
                        let mut text = format!(
                            "{}\nSeverity: {:?} | Category: {:?}\n\n{}\n",
                            finding.finding_title,
                            finding.finding_severity,
                            finding.finding_category,
                            finding.finding_description,
                        );
                        text.push_str(&format!(
                            "\nCurrent: {}\nRecommended: {}\n",
                            finding.finding_current_value,
                            finding.finding_recommended_value,
                        ));
                        if !finding.finding_remediation_steps.is_empty() {
                            text.push_str("\nRemediation:\n");
                            for (i, step) in finding.finding_remediation_steps.iter().enumerate() {
                                text.push_str(&format!("  {}. {}\n", i + 1, step));
                            }
                        }
                        text
                    };

                    view! {
                        <aside class="finding-detail">
                            <header class="detail-header">
                                <h2>{finding.finding_title.clone()}</h2>
                                <div class="detail-header-actions">
                                    <CopyButton text=Signal::derive(move || copy_text.clone()) />
                                    <button class="close-button" on:click=on_close>
                                        "Close"
                                    </button>
                                </div>
                            </header>

                            <section class="detail-severity">
                                <SeverityBadge severity=finding.finding_severity/>
                                <span class="detail-category">
                                    {format!("{:?}", finding.finding_category)}
                                </span>
                            </section>

                            <section class="detail-description">
                                <h3>"Description"</h3>
                                <p>{finding.finding_description.clone()}</p>
                            </section>

                            <section class="detail-explanation">
                                <h3>"Why This Matters"</h3>
                                <p>{finding.finding_explanation.clone()}</p>
                            </section>

                            <section class="detail-impact">
                                <h3>"Security Impact"</h3>
                                <p>{finding.finding_impact.clone()}</p>
                            </section>

                            <section class="detail-values">
                                <h3>"Values"</h3>
                                <dl>
                                    <dt>"Current (Insecure):"</dt>
                                    <dd class="value-current">{finding.finding_current_value.clone()}</dd>
                                    <dt>"Recommended (Secure):"</dt>
                                    <dd class="value-recommended">{finding.finding_recommended_value.clone()}</dd>
                                </dl>
                            </section>

                            <section class="detail-remediation">
                                <h3>"How to Fix"</h3>
                                <ol>
                                    {finding.finding_remediation_steps.iter().map(|step| {
                                        view! {
                                            <li>{step.clone()}</li>
                                        }
                                    }).collect::<Vec<_>>()}
                                </ol>
                            </section>
                        </aside>
                    }
                })
            }}
        </Show>
    }
}
