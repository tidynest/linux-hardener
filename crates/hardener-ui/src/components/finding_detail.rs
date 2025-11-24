use leptos::prelude::*;

use crate::components::SeverityBadge;
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
                    view! {
                        <aside class="finding-detail">
                            <header class="detail-header">
                                <h2>{finding.finding_title.clone()}</h2>
                                <button class="close-button" on:click=on_close>
                                    "Close"
                                </button>
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
