//! History section for the Hardening page.
//!
//! Displays apply results and checkpoint management.

use crate::components::{ConfirmDeleteButton, CopyButton, RollbackModal};
use crate::state::AppState;
use crate::tauri_bindings::{
    invoke_create_checkpoint, invoke_delete_checkpoint, invoke_get_checkpoint_detail,
    invoke_get_checkpoints,
};
use crate::types::{CheckpointDetail, CheckpointInfo};
use crate::utils::{checkpoint_time, group_checkpoints_by_date};
use leptos::prelude::*;

/// History section with apply results and checkpoints.
#[component]
pub fn HistorySection() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Local checkpoint state
    let checkpoints = RwSignal::new(Vec::<CheckpointInfo>::new());
    let is_loading = RwSignal::new(false);
    // Whether the root-owned system database was skipped. Rendered as a note
    // under the guidance bar; without it an incomplete list reads as complete.
    let system_unreadable = RwSignal::new(false);
    let checkpoint_name = RwSignal::new(String::new());
    let is_creating = RwSignal::new(false);
    let expanded_detail = RwSignal::new(None::<CheckpointDetail>);
    // Tracks which checkpoint ID has a pending delete confirmation (None = no confirmation shown)
    let pending_delete = RwSignal::new(None::<String>);
    // Checkpoint currently open in the rollback modal (None = closed).
    let rollback_target = RwSignal::new(None::<CheckpointInfo>);

    // Function to load checkpoints
    let load_checkpoints = move || {
        leptos::task::spawn_local(async move {
            is_loading.set(true);
            match invoke_get_checkpoints().await {
                Ok(list) => {
                    checkpoints.set(list.checkpoints);
                    system_unreadable.set(list.system_unreadable);
                }
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

    // The checkpoint this session's most recent apply created, if any. Used to
    // mark one rail node "Latest"; falls back to "newest node" when absent
    // (e.g. after a restart), handled in the render below.
    let latest_applied_id = move || {
        app_state
            .apply_results
            .get()
            .last()
            .and_then(|r| r.apply_checkpoint_id.clone())
    };

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
                    if let Ok(list) = invoke_get_checkpoints().await {
                        checkpoints.set(list.checkpoints);
                        system_unreadable.set(list.system_unreadable);
                    }
                }
                Err(e) => {
                    web_sys::console::error_1(&format!("Create checkpoint failed: {}", e).into());
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
                    if let Ok(list) = invoke_get_checkpoints().await {
                        checkpoints.set(list.checkpoints);
                        system_unreadable.set(list.system_unreadable);
                    }
                }
                Err(e) => {
                    web_sys::console::error_1(&format!("Delete checkpoint failed: {}", e).into());
                    app_state
                        .error_message
                        .set(Some(format!("Delete checkpoint failed: {}", e)));
                }
            }
        });
    };

    // Detail toggle handler
    let handle_detail = move |checkpoint_id: String| {
        // Toggle off if already showing this checkpoint
        if let Some(ref detail) = expanded_detail.get()
            && detail.checkpoint_id == checkpoint_id
        {
            expanded_detail.set(None);
            return;
        }
        leptos::task::spawn_local(async move {
            match invoke_get_checkpoint_detail(checkpoint_id).await {
                Ok(detail) => expanded_detail.set(Some(detail)),
                Err(e) => {
                    web_sys::console::error_1(
                        &format!("Failed to load checkpoint detail: {}", e).into(),
                    );
                }
            }
        });
    };

    view! {
        <div class="history-section">
            <p class="section-guidance">
                "Every apply saves a checkpoint first. Restore any of them to return "
                "the system to how it was at that moment."
            </p>

            <div class="checkpoint-controls">
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
                        aria-live="polite"
                    >
                        {move || if is_creating.get() { "Creating..." } else { "Create Checkpoint" }}
                    </button>
                </div>
                <button
                    class="btn btn-secondary btn-small"
                    on:click=move |_| load_checkpoints()
                    disabled=move || is_loading.get()
                    aria-live="polite"
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
                                <p class="empty-state-title">"No checkpoints yet"</p>
                                <p class="empty-state-hint">"Checkpoints are created automatically when you apply hardening."</p>
                            </div>
                        }.into_any()
                    }
                }
            >
                <ol class="timeline">
                    {move || {
                        let latest_id = latest_applied_id();
                        // Newest node overall gets "Latest" when no session apply id matches.
                        let newest_id = checkpoints.get().first().map(|c| c.checkpoint_id.clone());
                        let mark_id = latest_id.or(newest_id);
                        group_checkpoints_by_date(&checkpoints.get()).into_iter().map(|(date, cps)| {
                            let nodes = cps.into_iter().map(|cp| {
                                let id = cp.checkpoint_id.clone();
                                let name = cp.checkpoint_name.clone();
                                let time = checkpoint_time(&cp.checkpoint_created).to_string();
                                let user = cp.checkpoint_user.clone();
                                let is_latest = mark_id.as_deref() == Some(id.as_str());
                                let detail_id = id.clone();
                                let cp_for_modal = cp.clone();
                                let delete_id = id.clone();
                                let row_id = id.clone();

                                view! {
                                    <li class="timeline-node">
                                        <span class=move || if is_latest {
                                            "timeline-dot timeline-dot-latest"
                                        } else {
                                            "timeline-dot"
                                        } aria-hidden="true"></span>
                                        <div class="timeline-body">
                                            <div class="timeline-head">
                                                <span class="timeline-name">{name}</span>
                                                {is_latest.then(|| view! {
                                                    <span class="timeline-latest-pill">"Latest"</span>
                                                })}
                                            </div>
                                            <div class="timeline-meta">
                                                <span class="timeline-time">{time}</span>
                                                <span class="timeline-user">{user}</span>
                                            </div>
                                            <div class="timeline-actions">
                                                <button
                                                    class="btn btn-secondary btn-small"
                                                    on:click=move |_| handle_detail(detail_id.clone())
                                                >
                                                    "Details"
                                                </button>
                                                <button
                                                    class="btn btn-danger btn-small"
                                                    on:click=move |_| rollback_target.set(Some(cp_for_modal.clone()))
                                                >
                                                    "Roll back"
                                                </button>
                                                <ConfirmDeleteButton
                                                    item_key=delete_id.clone()
                                                    pending=pending_delete
                                                    on_confirm=Callback::new(move |id: String| handle_delete(id))
                                                />
                                            </div>
                                            <Show when=move || {
                                                expanded_detail.get()
                                                    .as_ref()
                                                    .is_some_and(|d| d.checkpoint_id == row_id)
                                            }>
                                                {move || {
                                                    let detail = expanded_detail.get();
                                                    let detail = detail.as_ref().expect("guarded by Show when=");
                                                    let file_count = detail.file_count;
                                                    let files = detail.files.clone();
                                                    let copy_text = {
                                                        let mut text = format!("Checkpoint: {} files\n", file_count);
                                                        for f in &files {
                                                            text.push_str(&format!("  {} ({})\n", f.path, f.permissions));
                                                        }
                                                        text
                                                    };
                                                    view! {
                                                        <div class="timeline-detail">
                                                            <div class="detail-file-header">
                                                                <p class="detail-file-count">
                                                                    {format!("{} files captured", file_count)}
                                                                </p>
                                                                <CopyButton text=Signal::derive(move || copy_text.clone()) />
                                                            </div>
                                                            <ul class="detail-file-list">
                                                                {files.iter().map(|f| {
                                                                    let path = f.path.clone();
                                                                    let perms = f.permissions.clone();
                                                                    let has = f.has_content;
                                                                    view! {
                                                                        <li>
                                                                            <code>{path}</code>
                                                                            <span class="detail-file-perms">{perms}</span>
                                                                            {if has { " (content saved)" } else { " (metadata only)" }}
                                                                        </li>
                                                                    }
                                                                }).collect::<Vec<_>>()}
                                                            </ul>
                                                        </div>
                                                    }
                                                }}
                                            </Show>
                                        </div>
                                    </li>
                                }
                            }).collect::<Vec<_>>();

                            view! {
                                <li class="timeline-group">
                                    <p class="timeline-date">{date}</p>
                                    <ol class="timeline-nodes">{nodes}</ol>
                                </li>
                            }
                        }).collect::<Vec<_>>()
                    }}
                </ol>
            </Show>

            <RollbackModal
                target=rollback_target
                on_close=Callback::new(move |ran: bool| {
                    if ran {
                        load_checkpoints();
                    }
                })
            />
        </div>
    }
}
