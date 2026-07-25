//! Fleet Apply page: apply/roll back hardening across saved hosts (mutating).

use std::collections::HashSet;

/// Deterministic key for a (mode, hosts, ad-hoc targets, plugins) selection.
/// Sorting makes the key insertion-order independent, so the Execute gate
/// compares like with like: Execute is allowed only when the current selection
/// key equals the previewed one.
fn selection_key(
    mode: &str,
    hosts: &HashSet<String>,
    adhoc: &[String],
    plugins: &HashSet<String>,
) -> SelKey {
    let mut h: Vec<String> = hosts.iter().cloned().collect();
    let mut a: Vec<String> = adhoc.to_vec();
    let mut p: Vec<String> = plugins.iter().cloned().collect();
    h.sort();
    a.sort();
    p.sort();
    (mode.to_string(), h, a, p)
}

use crate::components::{AdhocHostInput, Card, FleetOutcomeRow, Modal, SegmentedControl};
use crate::tauri_bindings::{
    invoke_fleet_apply, invoke_fleet_rollback, invoke_list_plugins, invoke_list_remote_hosts,
};
use crate::types::{ApplyOutcome, PluginMetadata, RollbackOutcome};
use crate::utils::{
    fleet_apply_aggregate, fleet_apply_cells, fleet_rollback_aggregate, fleet_rollback_cells,
};
use hardener_types::remote::RemoteHostProfile;
use leptos::prelude::*;

type SelKey = (String, Vec<String>, Vec<String>, Vec<String>);

/// The two Fleet Apply modes, in display order, for the segmented control.
const MODE_SEGMENTS: &[(&str, &str)] = &[("apply", "Apply"), ("rollback", "Roll back")];

/// Mutating fleet page: apply or roll back across saved hosts. Execute is gated
/// behind a mandatory dry-run for the exact current selection + a confirm modal.
#[component]
pub fn FleetApplyPage() -> impl IntoView {
    let mode = RwSignal::new("apply".to_string()); // "apply" | "rollback"
    let hosts = RwSignal::new(Vec::<RemoteHostProfile>::new());
    let plugins = RwSignal::new(Vec::<PluginMetadata>::new());
    let sel_hosts = RwSignal::new(HashSet::<String>::new());
    let adhoc = RwSignal::new(Vec::<String>::new());
    let sel_plugins = RwSignal::new(HashSet::<String>::new()); // empty = all
    let preview_apply = RwSignal::new(Vec::<ApplyOutcome>::new());
    let preview_rollback = RwSignal::new(Vec::<RollbackOutcome>::new());
    let results_apply = RwSignal::new(Vec::<ApplyOutcome>::new());
    let results_rollback = RwSignal::new(Vec::<RollbackOutcome>::new());
    let previewed_key = RwSignal::new(None::<SelKey>);
    let busy = RwSignal::new(false);
    let confirm_open = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);

    leptos::task::spawn_local(async move {
        match invoke_list_remote_hosts().await {
            Ok(l) => hosts.set(l),
            Err(e) => error.set(Some(e)),
        }
        match invoke_list_plugins().await {
            Ok(l) => plugins.set(l),
            Err(e) => error.set(Some(e)),
        }
    });

    let current_key = move || {
        selection_key(
            &mode.get(),
            &sel_hosts.get(),
            &adhoc.get(),
            &sel_plugins.get(),
        )
    };
    let can_execute = move || previewed_key.get().as_ref() == Some(&current_key()) && !busy.get();
    let invalidate = move || previewed_key.set(None);

    // The armed selection, shown in the action bar - this IS the preview key
    // made legible, so the user reads exactly what Execute will run.
    let selection_summary = move || {
        let n = sel_hosts.get().len() + adhoc.get().len();
        let host_word = if n == 1 { "host" } else { "hosts" };
        if mode.get() == "apply" {
            let p = sel_plugins.get().len();
            let plugin_part = if p == 0 {
                "all plugins".to_string()
            } else {
                format!("{p} plugins")
            };
            format!("{n} {host_word} \u{b7} {plugin_part} \u{b7} Apply")
        } else {
            format!("{n} {host_word} \u{b7} Roll back")
        }
    };
    // True once the current selection has a matching dry-run (Execute armed).
    let previewed = move || previewed_key.get().as_ref() == Some(&current_key());
    let nothing_selected = move || sel_hosts.get().is_empty() && adhoc.get().is_empty();
    let has_results = move || !results_apply.get().is_empty() || !results_rollback.get().is_empty();

    let toggle_host = move |name: String| {
        sel_hosts.update(|s| {
            if !s.remove(&name) {
                s.insert(name);
            }
        });
        invalidate();
    };
    let toggle_plugin = move |id: String| {
        sel_plugins.update(|s| {
            if !s.remove(&id) {
                s.insert(id);
            }
        });
        invalidate();
    };
    let set_mode = move |m: &str| {
        mode.set(m.to_string());
        invalidate();
    };

    let run = move |execute: bool| {
        let names: Vec<String> = sel_hosts.get().into_iter().collect();
        let targets = adhoc.get();
        if names.is_empty() && targets.is_empty() {
            return;
        }
        let plugin_ids: Vec<String> = sel_plugins.get().into_iter().collect();
        let key = current_key();
        let is_apply = mode.get() == "apply";
        busy.set(true);
        error.set(None);
        confirm_open.set(false);
        leptos::task::spawn_local(async move {
            if is_apply {
                match invoke_fleet_apply(names, targets, plugin_ids, execute).await {
                    Ok(out) => {
                        if execute {
                            results_apply.set(out);
                            results_rollback.set(Vec::new());
                            previewed_key.set(None);
                        } else {
                            preview_apply.set(out);
                            previewed_key.set(Some(key));
                            results_apply.set(Vec::new());
                            results_rollback.set(Vec::new());
                        }
                    }
                    Err(e) => error.set(Some(e)),
                }
            } else {
                match invoke_fleet_rollback(names, targets, plugin_ids, execute).await {
                    Ok(out) => {
                        if execute {
                            results_rollback.set(out);
                            results_apply.set(Vec::new());
                            previewed_key.set(None);
                        } else {
                            preview_rollback.set(out);
                            previewed_key.set(Some(key));
                            results_apply.set(Vec::new());
                            results_rollback.set(Vec::new());
                        }
                    }
                    Err(e) => error.set(Some(e)),
                }
            }
            busy.set(false);
        });
    };

    view! {
        <div class="fleet-page">
            <Card title="Fleet Apply".to_string()>
                <Show when=move || error.get().is_some()>
                    <div class="error-banner" role="alert">
                        {move || error.get().unwrap_or_default()}
                    </div>
                </Show>

                <SegmentedControl
                    aria_label="Action"
                    segments=MODE_SEGMENTS
                    selected=mode
                    on_select=Callback::new(move |m: String| set_mode(&m))
                    disabled=busy
                />

                <fieldset class="fleet-host-select">
                    <legend>"Hosts"</legend>
                    {move || {
                        let list = hosts.get();
                        if list.is_empty() {
                            return view! {
                                <p class="empty-state">
                                    "No saved hosts. Add hosts on the Hosts page first."
                                </p>
                            }
                            .into_any();
                        }
                        list.into_iter()
                            .map(|h| {
                                let name = h.name.clone();
                                let n2 = name.clone();
                                let checked = move || sel_hosts.get().contains(&n2);
                                let on_toggle = {
                                    let name = name.clone();
                                    move |_| toggle_host(name.clone())
                                };
                                view! {
                                    <label class="fleet-host-option">
                                        <input
                                            type="checkbox"
                                            prop:checked=checked
                                            on:change=on_toggle
                                        />
                                        {format!("{} ({})", h.name, h.hostname)}
                                    </label>
                                }
                            })
                            .collect_view()
                            .into_any()
                    }}
                </fieldset>

                <AdhocHostInput adhoc=adhoc on_change=Callback::new(move |_| invalidate()) />

                <Show when=move || mode.get() == "apply">
                    <fieldset class="fleet-plugin-select">
                        <legend>"Plugins (none selected = all)"</legend>
                        {move || {
                            plugins
                                .get()
                                .into_iter()
                                .map(|p| {
                                    let id = p.plugin_id.to_string();
                                    let i2 = id.clone();
                                    let checked = move || sel_plugins.get().contains(&i2);
                                    let on_toggle = {
                                        let id = id.clone();
                                        move |_| toggle_plugin(id.clone())
                                    };
                                    view! {
                                        <label class="fleet-host-option">
                                            <input
                                                type="checkbox"
                                                prop:checked=checked
                                                on:change=on_toggle
                                            />
                                            {id}
                                        </label>
                                    }
                                })
                                .collect_view()
                        }}
                    </fieldset>
                </Show>

                <div class="fleet-apply-bar">
                    <span class="fleet-apply-summary">{selection_summary}</span>
                    <div class="fleet-apply-bar-actions">
                        <Show
                            when=previewed
                            fallback=move || {
                                view! {
                                    // Keep the button focusable when nothing is
                                    // selected (aria-disabled, not disabled) so a
                                    // screen reader reaches the reason hint; the run
                                    // handler no-ops on an empty selection. A real
                                    // `disabled` only guards the in-flight state.
                                    <Show when=nothing_selected>
                                        <span class="fleet-apply-hint" id="fleet-preview-hint">
                                            "Select at least one host to preview."
                                        </span>
                                    </Show>
                                    <button
                                        class="btn btn-primary"
                                        on:click=move |_| run(false)
                                        disabled=move || busy.get()
                                        aria-disabled=move || {
                                            (busy.get() || nothing_selected()).to_string()
                                        }
                                        aria-describedby="fleet-preview-hint"
                                    >
                                        {move || {
                                            if busy.get() { "Working\u{2026}" } else { "Preview Changes" }
                                        }}
                                    </button>
                                }
                            }
                        >
                            <button
                                class="btn btn-secondary"
                                on:click=move |_| run(false)
                                disabled=move || busy.get()
                            >
                                "Preview Again"
                            </button>
                            <button
                                class="btn btn-danger"
                                on:click=move |_| confirm_open.set(true)
                                disabled=move || !can_execute()
                            >
                                "Execute\u{2026}"
                            </button>
                        </Show>
                    </div>
                </div>

                // Review: the dry-run, per host, until a real Execute replaces it.
                <Show when=move || previewed() && !has_results()>
                    <div class="fleet-review">
                        {move || {
                            if mode.get() == "apply" {
                                preview_apply
                                    .get()
                                    .into_iter()
                                    .map(|o| {
                                        let v = fleet_apply_cells(&o);
                                        view! { <FleetOutcomeRow name=o.name target=o.target view=v /> }
                                    })
                                    .collect_view()
                                    .into_any()
                            } else {
                                preview_rollback
                                    .get()
                                    .into_iter()
                                    .map(|o| {
                                        let v = fleet_rollback_cells(&o);
                                        view! { <FleetOutcomeRow name=o.name target=o.target view=v /> }
                                    })
                                    .collect_view()
                                    .into_any()
                            }
                        }}
                    </div>
                </Show>

                // Results: the executed outcome, per host.
                <Show when=has_results>
                    <div class="fleet-results-list">
                        {move || {
                            let a = results_apply.get();
                            if !a.is_empty() {
                                a.into_iter()
                                    .map(|o| {
                                        let v = fleet_apply_cells(&o);
                                        view! { <FleetOutcomeRow name=o.name target=o.target view=v /> }
                                    })
                                    .collect_view()
                                    .into_any()
                            } else {
                                results_rollback
                                    .get()
                                    .into_iter()
                                    .map(|o| {
                                        let v = fleet_rollback_cells(&o);
                                        view! { <FleetOutcomeRow name=o.name target=o.target view=v /> }
                                    })
                                    .collect_view()
                                    .into_any()
                            }
                        }}
                    </div>
                </Show>

                <Show when=move || confirm_open.get()>
                    <Modal
                        on_dismiss=Callback::new(move |_| confirm_open.set(false))
                        aria_labelledby="fleet-apply-modal-title"
                    >
                        <h3 id="fleet-apply-modal-title">
                            {move || {
                                let mode_label =
                                    if mode.get() == "apply" { "Apply" } else { "Roll back" };
                                let n = sel_hosts.get().len() + adhoc.get().len();
                                let host_word = if n == 1 { "host" } else { "hosts" };
                                format!("Execute {mode_label} on {n} {host_word}?")
                            }}
                        </h3>
                        <p>
                            "This mutates the selected hosts. Checkpoints are created automatically."
                        </p>
                        <p class="fleet-apply-stakes">
                            {move || {
                                if mode.get() == "apply" {
                                    fleet_apply_aggregate(&preview_apply.get())
                                } else {
                                    fleet_rollback_aggregate(&preview_rollback.get())
                                }
                            }}
                        </p>
                        <div class="fleet-actions">
                            <button
                                class="btn btn-secondary"
                                on:click=move |_| confirm_open.set(false)
                            >
                                "Cancel"
                            </button>
                            <button class="btn btn-danger" on:click=move |_| run(true)>
                                {move || {
                                    let n = sel_hosts.get().len() + adhoc.get().len();
                                    let host_word = if n == 1 { "host" } else { "hosts" };
                                    format!("Yes, Execute on {n} {host_word}")
                                }}
                            </button>
                        </div>
                    </Modal>
                </Show>
            </Card>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_key_is_order_independent_and_mode_sensitive() {
        let h1: HashSet<String> = ["a".into(), "b".into()].into_iter().collect();
        let h2: HashSet<String> = ["b".into(), "a".into()].into_iter().collect();
        let p: HashSet<String> = ["ssh".into()].into_iter().collect();
        assert_eq!(
            selection_key("apply", &h1, &[], &p),
            selection_key("apply", &h2, &[], &p)
        );
        assert_ne!(
            selection_key("apply", &h1, &[], &p),
            selection_key("rollback", &h1, &[], &p)
        );
    }

    #[test]
    fn selection_key_includes_adhoc_targets() {
        let h: HashSet<String> = ["a".into()].into_iter().collect();
        let p = HashSet::new();
        assert_ne!(
            selection_key("apply", &h, &[], &p),
            selection_key("apply", &h, &["root@10.0.0.5".into()], &p),
            "adding an ad-hoc target must invalidate a previous dry-run"
        );
        assert_eq!(
            selection_key("apply", &h, &["x@1".into(), "y@2".into()], &p),
            selection_key("apply", &h, &["y@2".into(), "x@1".into()], &p),
            "ad-hoc order must not matter"
        );
    }
}
