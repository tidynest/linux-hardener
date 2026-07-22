//! Rollback confirmation modal for the Hardening History timeline.
//!
//! Owns the whole rollback lifecycle in one dialog: Confirm (preview the
//! captured files + honest caveat), Restoring (neutral progress), Result
//! (per-file outcome). Presentation-only: reuses `invoke_get_checkpoint_detail`
//! and `invoke_rollback` and the shared status icons. The rollback result is
//! held locally here rather than in `AppState`, so History has a single result
//! surface.

use crate::components::{IconCheck, IconX};
use crate::state::AppState;
use crate::tauri_bindings::{invoke_get_checkpoint_detail, invoke_rollback};
use crate::types::{CheckpointDetail, CheckpointInfo, RollbackResult};
use crate::utils::{is_auth_cancelled, restore_action_label, restore_kind, rollback_summary_sentence};
use leptos::html;
use leptos::prelude::*;

/// The modal's lifecycle stage.
#[derive(Clone)]
enum Stage {
    Confirm,
    Restoring,
    Result(RollbackResult),
}

/// Rollback modal. Rendered only when `target` holds a checkpoint. `on_close`
/// is called when the dialog dismisses; its `bool` is true when a rollback
/// actually ran (so the parent can refresh the checkpoint list).
#[component]
pub fn RollbackModal(
    /// The checkpoint to roll back to; `None` hides the modal.
    target: RwSignal<Option<CheckpointInfo>>,
    /// Called on dismiss; `true` if a rollback ran.
    on_close: Callback<bool>,
) -> impl IntoView {
    let app_state = expect_context::<AppState>();

    let stage = RwSignal::new(Stage::Confirm);
    let detail = RwSignal::new(None::<CheckpointDetail>);
    let did_rollback = RwSignal::new(false);
    // Bound to the dialog element so it can be focused as soon as it mounts -
    // without this, a keydown listener on the dialog never fires because
    // nothing inside it holds focus (key events bubble from whatever *is*
    // focused, which by default is outside this subtree entirely).
    let dialog_ref = NodeRef::<html::Div>::new();

    // Load the captured-file preview whenever a new target opens the modal.
    Effect::new(move |_| {
        if let Some(cp) = target.get() {
            stage.set(Stage::Confirm);
            detail.set(None);
            did_rollback.set(false);
            let id = cp.checkpoint_id.clone();
            leptos::task::spawn_local(async move {
                if let Ok(d) = invoke_get_checkpoint_detail(id).await {
                    detail.set(Some(d));
                }
            });
        }
    });

    // Move focus into the dialog every time it mounts (i.e. every time the
    // modal opens), so Escape and Tab work immediately.
    Effect::new(move |_| {
        if let Some(el) = dialog_ref.get() {
            let _ = el.focus();
        }
    });

    let close = move |ran: bool| {
        target.set(None);
        on_close.run(ran);
    };

    let on_confirm = move |_| {
        let Some(cp) = target.get() else { return };
        let id = cp.checkpoint_id.clone();
        stage.set(Stage::Restoring);
        leptos::task::spawn_local(async move {
            match invoke_rollback(id, app_state.config_path.get_untracked()).await {
                Ok(result) => {
                    did_rollback.set(true);
                    stage.set(Stage::Result(result));
                }
                // A cancelled pkexec is not an error: return to Confirm silently.
                Err(e) if is_auth_cancelled(&e) => stage.set(Stage::Confirm),
                Err(e) => {
                    app_state.error_message.set(Some(format!("Rollback failed: {e}")));
                    target.set(None);
                    on_close.run(false);
                }
            }
        });
    };

    // Escape key: cancel from Confirm, close from Result, inert while Restoring.
    let on_keydown = move |ev: web_sys::KeyboardEvent| {
        if ev.key() == "Escape" && !matches!(stage.get(), Stage::Restoring) {
            close(did_rollback.get());
        }
    };

    view! {
        <Show when=move || target.get().is_some()>
            <div
                class="modal-backdrop"
                on:click=move |_| {
                    if matches!(stage.get(), Stage::Confirm) {
                        close(false);
                    }
                }
            >
                <div
                    class="modal rollback-modal"
                    role="dialog"
                    aria-modal="true"
                    aria-labelledby="rollback-modal-title"
                    tabindex="-1"
                    node_ref=dialog_ref
                    on:click=move |ev| ev.stop_propagation()
                    on:keydown=on_keydown
                >
                    {move || {
                        let cp = target.get();
                        let cp = match cp.as_ref() {
                            Some(c) => c.clone(),
                            None => return ().into_any(),
                        };
                        match stage.get() {
                            Stage::Confirm => confirm_view(cp, detail, on_confirm, close).into_any(),
                            Stage::Restoring => view! {
                                <div class="rollback-restoring">
                                    <h3 id="rollback-modal-title">"Restoring..."</h3>
                                    <p class="rollback-progress">
                                        "Applying the checkpoint. Do not close this window."
                                    </p>
                                </div>
                            }.into_any(),
                            Stage::Result(result) => result_view(result, close).into_any(),
                        }
                    }}
                </div>
            </div>
        </Show>
    }
}

/// The Confirm stage: title, capture summary, file preview, caveat, buttons.
fn confirm_view(
    cp: CheckpointInfo,
    detail: RwSignal<Option<CheckpointDetail>>,
    on_confirm: impl Fn(web_sys::MouseEvent) + 'static + Copy,
    close: impl Fn(bool) + 'static + Copy,
) -> impl IntoView {
    let name = cp.checkpoint_name.clone();
    let created = cp.checkpoint_created.clone();
    let user = cp.checkpoint_user.clone();
    view! {
        <h3 id="rollback-modal-title">{format!("Roll back to '{name}'?")}</h3>
        <p class="rollback-sub">{format!("Captured {created} by {user}.")}</p>
        {move || match detail.get() {
            None => view! { <p class="rollback-progress">"Loading captured files..."</p> }.into_any(),
            Some(d) => {
                let count = d.file_count;
                let files = d.files.clone();
                view! {
                    <p class="rollback-body">
                        {format!("Restores {count} files to their state then and overwrites the current configuration.")}
                    </p>
                    <ul class="rollback-file-list">
                        {files.iter().map(|f| {
                            let path = f.path.clone();
                            let kind = restore_kind(f.has_content);
                            view! {
                                <li>
                                    <code>{path}</code>
                                    <span class="rollback-file-kind">{kind}</span>
                                </li>
                            }
                        }).collect::<Vec<_>>()}
                    </ul>
                    <p class="rollback-caveat">
                        "Files saved as metadata only can have their permissions "
                        "restored, not their contents."
                    </p>
                }.into_any()
            }
        }}
        <div class="modal-actions">
            <button class="btn btn-secondary" on:click=move |_| close(false)>"Cancel"</button>
            <button class="btn btn-danger" on:click=on_confirm>
                {move || match detail.get() {
                    Some(d) => format!("Roll back {} files", d.file_count),
                    None => "Roll back".to_string(),
                }}
            </button>
        </div>
    }
}

/// The Result stage: outcome header, summary, per-file list, Done.
fn result_view(result: RollbackResult, close: impl Fn(bool) + 'static + Copy) -> impl IntoView {
    let success = result.rollback_success;
    let summary = rollback_summary_sentence(&result);
    let files = result.rollback_files.clone();
    view! {
        <div class=move || if success { "rollback-outcome ok" } else { "rollback-outcome fail" }>
            {if success {
                view! { <IconCheck class="rollback-outcome-icon".to_string() /> }.into_any()
            } else {
                view! { <IconX class="rollback-outcome-icon".to_string() /> }.into_any()
            }}
            <h3 id="rollback-modal-title">
                {if success { "Restored" } else { "Rollback failed" }}
            </h3>
        </div>
        <p class="rollback-summary">{summary}</p>
        <ul class="rollback-file-list">
            {files.iter().map(|f| {
                let path = f.restore_path.clone();
                let label = restore_action_label(f.restore_action);
                let ok = f.restore_success;
                let err = f.restore_error.clone();
                view! {
                    <li class=if ok { "restore-ok" } else { "restore-fail" }>
                        {if ok {
                            view! { <IconCheck class="restore-icon".to_string() /> }.into_any()
                        } else {
                            view! { <IconX class="restore-icon".to_string() /> }.into_any()
                        }}
                        <code>{path}</code>
                        <span class="restore-action">{label}</span>
                        {err.map(|e| view! { <span class="restore-error">{e}</span> })}
                    </li>
                }
            }).collect::<Vec<_>>()}
        </ul>
        <div class="modal-actions">
            <button class="btn btn-primary" on:click=move |_| close(true)>"Done"</button>
        </div>
    }
}
