//! Rollback confirmation modal for the Hardening History timeline.
//!
//! Owns the whole rollback lifecycle in one dialog: Confirm (preview the
//! captured files + honest caveat), Restoring (neutral progress), Result
//! (per-file outcome). Presentation-only: reuses `invoke_get_checkpoint_detail`
//! and `invoke_rollback` and the shared status icons. The rollback result is
//! held locally here rather than in `AppState`, so History has a single result
//! surface.

use crate::components::{IconCheck, IconX, Modal};
use crate::state::AppState;
use crate::tauri_bindings::{invoke_get_checkpoint_detail, invoke_rollback};
use crate::types::{CheckpointDetail, CheckpointInfo, DivergenceState, RollbackResult};
use crate::utils::{
    is_auth_cancelled, restore_action_label, restore_kind, rollback_summary_sentence,
};
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
                if let Ok(d) = invoke_get_checkpoint_detail(id.clone()).await {
                    // Guard a stale response: if the user closed this checkpoint
                    // and opened a different one while the fetch was in flight,
                    // drop the result rather than render one checkpoint's files
                    // under another's confirm (a preview/action mismatch in a
                    // destructive flow).
                    let still_current = target
                        .get_untracked()
                        .is_some_and(|cp| cp.checkpoint_id == id);
                    if still_current {
                        detail.set(Some(d));
                    }
                }
            });
        }
    });

    // Move focus into the dialog on mount and again on every stage change.
    // Only the inner content is swapped between Confirm/Restoring/Result -
    // the dialog div itself stays mounted - so a stage transition that
    // removes the DOM node currently holding focus (e.g. the "Roll back N
    // files" button, gone as soon as Restoring replaces Confirm) drops
    // focus back onto <body>. From there the dialog's keydown handler,
    // bound only within this subtree, would never see Escape again, so
    // Escape would silently stop closing the modal once Result renders.
    // Tracking `stage` (rather than just `dialog_ref`) makes this effect
    // re-run on every transition and pull focus back in each time.
    Effect::new(move |_| {
        stage.track();
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
            match invoke_rollback(id).await {
                Ok(result) => {
                    did_rollback.set(true);
                    stage.set(Stage::Result(result));
                }
                // A cancelled pkexec is not an error: return to Confirm silently.
                Err(e) if is_auth_cancelled(&e) => stage.set(Stage::Confirm),
                Err(e) => {
                    app_state
                        .error_message
                        .set(Some(format!("Rollback failed: {e}")));
                    target.set(None);
                    on_close.run(false);
                }
            }
        });
    };

    // Dismissal (Escape or a backdrop click) cancels from Confirm and closes
    // from Result, but stays inert while a rollback is in flight. Both paths
    // report `did_rollback`, so dismissing from Result cannot tell the parent
    // that nothing happened.
    let can_dismiss = Signal::derive(move || !stage.with(|s| matches!(s, Stage::Restoring)));
    let on_dismiss = Callback::new(move |_| close(did_rollback.get()));

    view! {
        <Show when=move || target.get().is_some()>
            <Modal
                on_dismiss=on_dismiss
                dismissible=can_dismiss
                class="rollback-modal"
                aria_labelledby="rollback-modal-title"
                dialog_ref=dialog_ref
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
            </Modal>
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
                        {format!("Restores {count} files to how they were then, overwriting the current configuration.")}
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
    // A rollback that put every file back but left a plugin running the old
    // configuration is not a success the desktop should celebrate: the CLI
    // already exits 1 for exactly this case (`reloads_ok()`), and the two
    // surfaces must agree on what "restored" means.
    let success = result.rollback_success && result.reloads_ok();
    let summary = rollback_summary_sentence(&result);
    let files = result.rollback_files.clone();
    let reloads = result.rollback_reloads.clone();
    // Ranking is the same argument the CLI's `divergence_lines` makes (#152):
    // a routine row printed beside a surprising one teaches the operator to
    // skip the block that carries both. Unexpected rows keep "Still
    // diverged:"; expected ones move under their own heading with the reason
    // the plugin gave, muted by opacity in styles.css and, for an
    // `Unverifiable` row, by the same colour rule the unexpected branch below
    // applies, rather than hidden, because clipping or dropping a row here is
    // the defect #143 fixed. `result` is owned by this function, so the
    // divergence rows move out of it directly rather than through an
    // intermediate clone that `.iter().cloned()` would then clone a second
    // time, element by element.
    let (expected, mut unexpected): (Vec<_>, Vec<_>) = result
        .rollback_divergences
        .into_iter()
        .partition(|d| d.divergence_expected.is_some());
    // Within the unexpected group only (#152 follow-up): a `Diverged` row is
    // the surprise this block exists to surface, and on every systemd host
    // it lands behind the constant glob-source `Unverifiable` rows unless it
    // is sorted forward. The expected group keeps registry order untouched,
    // and no row changes classification. `sort_by_key` is stable, so rows
    // that share a state keep the order they arrived in.
    unexpected.sort_by_key(|d| d.divergence_state != DivergenceState::Diverged);
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
        {(!reloads.is_empty()).then(|| view! {
            <p class="rollback-body">"Configuration reload:"</p>
            <ul class="rollback-file-list">
                {reloads.iter().map(|r| {
                    let plugin = r.reload_plugin_id.clone();
                    let action = r.reload_action.clone();
                    let ok = r.reload_success;
                    let err = r.reload_error.clone();
                    view! {
                        <li class=if ok { "restore-ok" } else { "restore-fail" }>
                            {if ok {
                                view! { <IconCheck class="restore-icon".to_string() /> }.into_any()
                            } else {
                                view! { <IconX class="restore-icon".to_string() /> }.into_any()
                            }}
                            <code>{plugin}</code>
                            <span class="restore-action">{action}</span>
                            {err.map(|e| view! { <span class="restore-error">{e}</span> })}
                        </li>
                    }
                }).collect::<Vec<_>>()}
            </ul>
        })}
        {(!unexpected.is_empty()).then(|| view! {
            <p class="rollback-body">"Still diverged:"</p>
            // Its own class beside the shared one. The shared list caps itself
            // at 14rem, which was sized for a column of filenames; two
            // divergence sentences exceed it and the first render cut the
            // second one mid-word (#143).
            <ul class="rollback-file-list rollback-divergence-list">
                {unexpected.iter().map(|d| {
                    let subject = d.divergence_subject.clone();
                    let detail = d.divergence_detail.clone();
                    let checked = d.divergence_state == DivergenceState::Diverged;
                    // Two lines, not one flex row (#143). The restore rows
                    // above carry a path and a few words of error; these carry
                    // a sentence of 200 to 400 characters, and the shared row
                    // was built for the first shape. `restore-warn` stays, so
                    // the warning colour rule keyed on it still reaches the
                    // detail.
                    // A measurement and a probe that could not answer are not
                    // the same news, and the first render gave them the same
                    // warning colour. The unchecked one is muted instead: it
                    // accuses the host of nothing.
                    view! {
                        <li class=if checked {
                            "restore-warn rollback-divergence"
                        } else {
                            "restore-warn rollback-divergence rollback-divergence-unchecked"
                        }>
                            <div class="divergence-head">
                                <code>{subject}</code>
                                <span class="restore-action">
                                    {if checked { "diverged" } else { "could not check" }}
                                </span>
                            </div>
                            <span class="restore-error divergence-detail">{detail}</span>
                        </li>
                    }
                }).collect::<Vec<_>>()}
            </ul>
        })}
        {(!expected.is_empty()).then(|| view! {
            <p class="rollback-body rollback-expected-heading">"Expected, by design:"</p>
            <ul class="rollback-file-list rollback-divergence-list">
                {expected.iter().map(|d| {
                    let subject = d.divergence_subject.clone();
                    let detail = d.divergence_detail.clone();
                    let reason = d.divergence_expected.clone().unwrap_or_default();
                    let checked = d.divergence_state == DivergenceState::Diverged;
                    view! {
                        <li class=if checked {
                            "restore-warn rollback-divergence rollback-divergence-expected"
                        } else {
                            "restore-warn rollback-divergence rollback-divergence-unchecked \
                             rollback-divergence-expected"
                        }>
                            <div class="divergence-head">
                                <code>{subject}</code>
                                <span class="restore-action">
                                    {if checked { "diverged" } else { "could not check" }}
                                </span>
                            </div>
                            <span class="restore-error divergence-detail">{detail}</span>
                            <span class="divergence-reason">{reason}</span>
                        </li>
                    }
                }).collect::<Vec<_>>()}
            </ul>
        })}
        <div class="modal-actions">
            <button class="btn btn-primary" on:click=move |_| close(true)>"Done"</button>
        </div>
    }
}
