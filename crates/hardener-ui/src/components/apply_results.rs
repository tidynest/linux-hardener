use crate::state::AppState;
use leptos::prelude::*;

/// Displays the results of applying hardening changes.
///
/// Shows a summary of the apply operation including success/failure status,
/// the list of changes made, checkpoint information for rollback, and navigation
/// back to the scanner page.
#[component]
pub fn ApplyResults() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Get the most recent apply result (must access signal inside the view closure)
    let get_latest_result = move || {
        app_state
            .apply_results
            .with(|results| results.last().cloned())
    };

    view! {
        <article class="apply-results">
            <h1>"Apply Results"</h1>

            <Show
                when=move || get_latest_result().is_some()
                fallback=|| view! {
                    <section class="no-results">
                        <p>"No apply operations have been performed yet."</p>
                        <p>"Go to the Configuration page to apply hardening changes."</p>
                    </section>
                }
            >
                {move || {
                    let result = get_latest_result().unwrap();

                    view! {
                        <section class="apply-summary">
                            <h2>"Summary"</h2>
                            <dl>
                                <dd>{if result.apply_success { "✓ Success" } else { "✗ Failed" }}</dd>

                                <dd>{result.apply_changes.len()}" changes"</dd>

                            </dl>
                        </section>

                        <section class="changes-list">
                            <h2>"Changes Made"</h2>
                            <ol>
                                {result.apply_changes.iter().map(|change| {
                                    view! {
                                        <li class={if change.change_success { "change-success" } else { "change-failure" }}>
                                        <strong>{change.change_description.clone()}</strong>
                                            {if !change.change_success {
                                                view! { <span class="error">" - Failed"</span> }.into_any()
                                            } else {
                                                view! { <span></span> }.into_any()
                                            }}
                                        </li>
                                    }
                                }).collect::<Vec<_>>()}
                            </ol>
                        </section>

                        <section class="checkpoint-info">
                            <h2>"Rollback Information"</h2>
                            <dl>
                                <dt>"Checkpoint ID"</dt>
                        <dd><code>{result.apply_checkpoint_id.clone()}</code></dd>
                            </dl>
                            <p>"Use this checkpoint ID to rollback changes if needed."</p>
                        </section>

                         <nav class="navigation">
                              <a href="/checkpoints" class="button">"Manage Checkpoints"</a>
                              <a href="/config" class="button">"Back to Configuration"</a>
                              <a href="/scan" class="button">"Back to Scanner"</a>
                          </nav>
                    }
                }}
            </Show>
        </article>
    }
}
