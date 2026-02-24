//! History section for the Hardening page.
//!
//! Displays apply results and checkpoint management.

use crate::components::{Card, HeadingLevel};
use crate::state::AppState;
use crate::tauri_bindings::{
    invoke_create_checkpoint, invoke_delete_checkpoint, invoke_get_checkpoints, invoke_rollback,
};
use crate::types::{CheckpointInfo, FileRestoreAction};
use leptos::prelude::*;

/// Formats a `FileRestoreAction` variant for display.
fn format_restore_action(action: FileRestoreAction) -> &'static str {
    match action {
        FileRestoreAction::Restored => "Restored",
        FileRestoreAction::Removed => "Removed",
        FileRestoreAction::PermissionsRestored => "Permissions Restored",
        FileRestoreAction::Skipped => "Skipped",
    }
}

/// History section with apply results and checkpoints.
#[component]
pub fn HistorySection() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Local checkpoint state
    let checkpoints = RwSignal::new(Vec::<CheckpointInfo>::new());
    let is_loading = RwSignal::new(false);
    let checkpoint_name = RwSignal::new(String::new());
    let is_creating = RwSignal::new(false);

    // Function to load checkpoints
    let load_checkpoints = move || {
        leptos::task::spawn_local(async move {
            is_loading.set(true);
            match invoke_get_checkpoints().await {
                Ok(cp) => checkpoints.set(cp),
                Err(e) => {
                    web_sys::console::error_1(&format!("Failed to load checkpoints: {}", e).into());
                    app_state
                        .error_message
                        .set(Some(format!("Failed to load checkpoints: {}", e)));
                }
            }
            is_loading.set(false);
        });
    };

    // Load checkpoints on mount
    load_checkpoints();

    // Create checkpoint handler
    let handle_create = move |_| {
        let name = checkpoint_name.get();
        if name.trim().is_empty() {
            return;
        }
        is_creating.set(true);
        leptos::task::spawn_local(async move {
            match invoke_create_checkpoint(name).await {
                Ok(_id) => {
                    checkpoint_name.set(String::new());
                    if let Ok(cp) = invoke_get_checkpoints().await {
                        checkpoints.set(cp);
                    }
                }
                Err(e) => {
                    web_sys::console::error_1(
                        &format!("Create checkpoint failed: {}", e).into(),
                    );
                    app_state
                        .error_message
                        .set(Some(format!("Create checkpoint failed: {}", e)));
                }
            }
            is_creating.set(false);
        });
    };

    // Delete checkpoint handler
    let handle_delete = move |checkpoint_id: String| {
        leptos::task::spawn_local(async move {
            match invoke_delete_checkpoint(checkpoint_id).await {
                Ok(_) => {
                    if let Ok(cp) = invoke_get_checkpoints().await {
                        checkpoints.set(cp);
                    }
                }
                Err(e) => {
                    web_sys::console::error_1(
                        &format!("Delete checkpoint failed: {}", e).into(),
                    );
                    app_state
                        .error_message
                        .set(Some(format!("Delete checkpoint failed: {}", e)));
                }
            }
        });
    };

    // Rollback handler
    let handle_rollback = move |checkpoint_id: String| {
        leptos::task::spawn_local(async move {
            match invoke_rollback(checkpoint_id).await {
                Ok(result) => {
                    app_state.rollback_result.set(Some(result));
                    if let Ok(cp) = invoke_get_checkpoints().await {
                        checkpoints.set(cp);
                    }
                }
                Err(e) => {
                    web_sys::console::error_1(&format!("Rollback failed: {}", e).into());
                    app_state
                        .error_message
                        .set(Some(format!("Rollback failed: {}", e)));
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
            <Card title="Latest Apply Operation" title_level=HeadingLevel::H2 class="apply-results-summary">
                <Show
                    when=move || app_state.apply_results.get().last().is_some()
                    fallback=|| view! {
                        <div class="empty-state">
                            <div class="empty-state-icon">"⚡"</div>
                            <p class="empty-state-title">"No apply operations yet"</p>
                            <p class="empty-state-hint">"Apply hardening to see results here."</p>
                        </div>
                    }
                >
                    {move || {
                        let results = app_state.apply_results.get();
                        let result = results.last().expect("guarded by Show when=");
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
            </Card>

            // Latest Rollback Result
            <Card title="Latest Rollback" title_level=HeadingLevel::H2 class="rollback-results-summary">
                <Show
                    when=move || app_state.rollback_result.get().is_some()
                    fallback=|| view! {
                        <div class="empty-state">
                            <div class="empty-state-icon">"↩"</div>
                            <p class="empty-state-title">"No rollback performed yet"</p>
                            <p class="empty-state-hint">"Click Rollback on a checkpoint to restore a previous state."</p>
                        </div>
                    }
                >
                    {move || {
                        let result = app_state.rollback_result.get().expect("guarded by Show when=");
                        let success = result.rollback_success;
                        let files_count = result.rollback_files.len();
                        let checkpoint_id = result.rollback_checkpoint_id.clone();
                        let files = result.rollback_files.clone();

                        view! {
                            <div class="result-summary-card">
                                <div class=format!("result-status {}", if success { "success" } else { "failed" })>
                                    {if success { "Rollback Successful" } else { "Rollback Failed" }}
                                </div>
                                <div class="result-changes">
                                    {format!("{} files processed", files_count)}
                                </div>
                                <div class="result-checkpoint">
                                    "Checkpoint: "<code>{checkpoint_id}</code>
                                </div>
                                <details>
                                    <summary>"View Restored Files"</summary>
                                    <ol class="changes-list">
                                        {files.iter().map(|file| {
                                            let path = file.restore_path.clone();
                                            let action = format_restore_action(file.restore_action);
                                            let ok = file.restore_success;
                                            view! {
                                                <li class=if ok { "change-success" } else { "change-failure" }>
                                                    <code>{path}</code>" — "{action}
                                                </li>
                                            }
                                        }).collect::<Vec<_>>()}
                                    </ol>
                                </details>
                            </div>
                        }
                    }}
                </Show>
            </Card>

            // Checkpoints Table
            <Card title="System Checkpoints" title_level=HeadingLevel::H2 class="checkpoints-section">
                <div class="checkpoint-header">
                    <div class="create-checkpoint-form">
                        <input
                            type="text"
                            class="input-text"
                            placeholder="Checkpoint name..."
                            prop:value=move || checkpoint_name.get()
                            on:input=move |ev| {
                                checkpoint_name.set(event_target_value(&ev));
                            }
                        />
                        <button
                            class="btn btn-primary btn-small"
                            on:click=handle_create
                            disabled=move || {
                                is_creating.get() || checkpoint_name.get().trim().is_empty()
                            }
                        >
                            {move || if is_creating.get() { "Creating..." } else { "Create Checkpoint" }}
                        </button>
                    </div>
                    <button
                        class="btn btn-secondary btn-small"
                        on:click=move |_| load_checkpoints()
                        disabled=move || is_loading.get()
                    >
                        {move || if is_loading.get() { "Refreshing..." } else { "Refresh" }}
                    </button>
                </div>
                <Show
                    when=move || !checkpoints.get().is_empty()
                    fallback=move || {
                        if is_loading.get() {
                            view! {
                                <div class="empty-state">
                                    <div class="empty-state-icon">"⏳"</div>
                                    <p class="empty-state-title">"Loading checkpoints..."</p>
                                </div>
                            }.into_any()
                        } else {
                            view! {
                                <div class="empty-state">
                                    <div class="empty-state-icon">"💾"</div>
                                    <p class="empty-state-title">"No checkpoints available"</p>
                                    <p class="empty-state-hint">"Checkpoints are created automatically when applying changes."</p>
                                </div>
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

                                let delete_id = id.clone();

                                view! {
                                    <tr>
                                        <td><code>{id}</code></td>
                                        <td>{name}</td>
                                        <td>{created}</td>
                                        <td class="actions-cell">
                                            <button
                                                class="rollback-button"
                                                on:click=move |_| handle_rollback(rollback_id.clone())
                                            >
                                                "Rollback"
                                            </button>
                                            <button
                                                class="btn btn-danger btn-small"
                                                on:click=move |_| handle_delete(delete_id.clone())
                                            >
                                                "Delete"
                                            </button>
                                        </td>
                                    </tr>
                                }
                            }).collect::<Vec<_>>()}
                        </tbody>
                    </table>
                </Show>
            </Card>
        </div>
    }
}
