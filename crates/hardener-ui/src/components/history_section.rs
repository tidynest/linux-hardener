//! History section for the Hardening page.
//!
//! Displays apply results and checkpoint management.

use crate::state::AppState;
use crate::tauri_bindings::{invoke_get_checkpoints, invoke_rollback};
use crate::types::CheckpointInfo;
use leptos::prelude::*;

/// History section with apply results and checkpoints.
#[component]
pub fn HistorySection() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Local checkpoint state
    let checkpoints = RwSignal::new(Vec::<CheckpointInfo>::new());
    let is_loading = RwSignal::new(false);

    // Load checkpoints on mount
    leptos::task::spawn_local(async move {
        is_loading.set(true);
        match invoke_get_checkpoints().await {
            Ok(cp) => checkpoints.set(cp),
            Err(e) => {
                web_sys::console::error_1(&format!("Failed to load checkpoints: {}", e).into());
            }
        }
        is_loading.set(false);
    });

    // Rollback handler
    let handle_rollback = move |checkpoint_id: String| {
        leptos::task::spawn_local(async move {
            match invoke_rollback(checkpoint_id.clone()).await {
                Ok(_) => {
                    web_sys::console::log_1(
                        &format!("Rolled back to checkpoint: {}", checkpoint_id).into(),
                    );
                    // Refresh checkpoints
                    if let Ok(cp) = invoke_get_checkpoints().await {
                        checkpoints.set(cp);
                    }
                }
                Err(e) => {
                    web_sys::console::error_1(&format!("Rollback failed: {}", e).into());
                }
            }
        });
    };

    view! {
        <div class="history-section">
            <p class="section-guidance">
                "Review past hardening operations and restore previous configurations. "
                "Checkpoints preserve your system state before each change, enabling safe rollback."
            </p>

            // Latest Apply Result
            <section class="apply-results-summary">
                <h2>"Latest Apply Operation"</h2>
                <Show
                    when=move || app_state.apply_results.get().last().is_some()
                    fallback=|| view! {
                        <p class="empty-state">"No apply operations performed yet."</p>
                    }
                >
                    {move || {
                        let results = app_state.apply_results.get();
                        let result = results.last().unwrap();
                        let success = result.apply_success;
                        let changes_count = result.apply_changes.len();
                        let checkpoint_id = result.apply_checkpoint_id.clone();
                        let changes = result.apply_changes.clone();

                        view! {
                            <div class="result-summary-card">
                                <div class=format!("result-status {}", if success { "success" } else { "failed" })>
                                    {if success { "Success" } else { "Failed" }}
                                </div>
                                <div class="result-changes">
                                    {format!("{} changes made", changes_count)}
                                </div>
                                {checkpoint_id.map(|id| view! {
                                    <div class="result-checkpoint">
                                        "Checkpoint: "<code>{id}</code>
                                    </div>
                                })}
                                <details>
                                    <summary>"View Changes"</summary>
                                    <ol class="changes-list">
                                        {changes.iter().map(|change| {
                                            let desc = change.change_description.clone();
                                            let success = change.change_success;
                                            view! {
                                                <li class=if success { "change-success" } else { "change-failure" }>
                                                    {desc}
                                                </li>
                                            }
                                        }).collect::<Vec<_>>()}
                                    </ol>
                                </details>
                            </div>
                        }
                    }}
                </Show>
            </section>

            // Checkpoints Table
            <section class="checkpoints-section">
                <h2>"System Checkpoints"</h2>
                <Show
                    when=move || !checkpoints.get().is_empty()
                    fallback=move || {
                        if is_loading.get() {
                            view! { <p>"Loading checkpoints..."</p> }.into_any()
                        } else {
                            view! {
                                <p class="empty-state">"No checkpoints available. Checkpoints are created automatically when applying changes."</p>
                            }.into_any()
                        }
                    }
                >
                    <table>
                        <thead>
                            <tr>
                                <th>"ID"</th>
                                <th>"Name"</th>
                                <th>"Created"</th>
                                <th>"Actions"</th>
                            </tr>
                        </thead>
                        <tbody>
                            {move || checkpoints.get().iter().map(|cp| {
                                let id = cp.checkpoint_id.clone();
                                let name = cp.checkpoint_name.clone();
                                let created = cp.checkpoint_created.clone();
                                let rollback_id = id.clone();

                                view! {
                                    <tr>
                                        <td><code>{id}</code></td>
                                        <td>{name}</td>
                                        <td>{created}</td>
                                        <td>
                                            <button
                                                class="rollback-button"
                                                on:click=move |_| handle_rollback(rollback_id.clone())
                                            >
                                                "Rollback"
                                            </button>
                                        </td>
                                    </tr>
                                }
                            }).collect::<Vec<_>>()}
                        </tbody>
                    </table>
                </Show>
            </section>
        </div>
    }
}
