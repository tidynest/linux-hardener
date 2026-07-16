//! Fleet Apply page — apply/roll back hardening across saved hosts (mutating).

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

use crate::components::{AdhocHostInput, Card};
use crate::tauri_bindings::{
    invoke_fleet_apply, invoke_fleet_rollback, invoke_list_plugins, invoke_list_remote_hosts,
};
use crate::types::{ApplyOutcome, PluginMetadata, RollbackOutcome};
use hardener_types::remote::RemoteHostProfile;
use hardener_types::{ApplyStatus, RollbackStatus};
use leptos::prelude::*;

type SelKey = (String, Vec<String>, Vec<String>, Vec<String>);

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
    let previewed_key = RwSignal::new(None::<SelKey>);
    let results = RwSignal::new(String::new());
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
                            results.set(render_apply(&out));
                            previewed_key.set(None);
                        } else {
                            preview_apply.set(out);
                            previewed_key.set(Some(key));
                            results.set(String::new());
                        }
                    }
                    Err(e) => error.set(Some(e)),
                }
            } else {
                match invoke_fleet_rollback(names, targets, plugin_ids, execute).await {
                    Ok(out) => {
                        if execute {
                            results.set(render_rollback(&out));
                            previewed_key.set(None);
                        } else {
                            preview_rollback.set(out);
                            previewed_key.set(Some(key));
                            results.set(String::new());
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

                <fieldset class="fleet-mode">
                    <legend>"Action"</legend>
                    <label>
                        <input
                            type="radio"
                            name="mode"
                            prop:checked=move || mode.get() == "apply"
                            on:change=move |_| set_mode("apply")
                        />
                        " Apply"
                    </label>
                    <label>
                        <input
                            type="radio"
                            name="mode"
                            prop:checked=move || mode.get() == "rollback"
                            on:change=move |_| set_mode("rollback")
                        />
                        " Roll back"
                    </label>
                </fieldset>

                <fieldset class="fleet-host-select">
                    <legend>"Hosts"</legend>
                    {move || {
                        let list = hosts.get();
                        if list.is_empty() {
                            return view! {
                                <p class="empty-state">
                                    "No saved hosts. Add hosts on the Remote page first."
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

                <fieldset class="fleet-plugin-select">
                    <legend>"Plugins (none selected = all)"</legend>
                    {move || {
                        plugins.get().into_iter().map(|p| {
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
                        }).collect_view()
                    }}
                </fieldset>

                <div class="fleet-actions">
                    <button
                        class="btn-secondary"
                        on:click=move |_| run(false)
                        disabled=move || {
                            busy.get() || (sel_hosts.get().is_empty() && adhoc.get().is_empty())
                        }
                    >
                        {move || if busy.get() { "Working\u{2026}" } else { "Dry-run" }}
                    </button>
                    <button
                        class="btn-primary"
                        on:click=move |_| confirm_open.set(true)
                        disabled=move || !can_execute()
                    >
                        "Execute\u{2026}"
                    </button>
                </div>

                <Show when=move || previewed_key.get().is_some() && results.get().is_empty()>
                    <pre class="fleet-preview">
                        {move || {
                            if mode.get() == "apply" {
                                render_apply(&preview_apply.get())
                            } else {
                                render_rollback(&preview_rollback.get())
                            }
                        }}
                    </pre>
                </Show>

                <Show when=move || !results.get().is_empty()>
                    <pre class="fleet-results">{move || results.get()}</pre>
                </Show>

                <Show when=move || confirm_open.get()>
                    <div class="modal-backdrop">
                        <div
                            class="modal"
                            role="dialog"
                            aria-modal="true"
                            aria-labelledby="fleet-apply-modal-title"
                        >
                            <h3 id="fleet-apply-modal-title">
                                {move || {
                                    format!(
                                        "Execute {} on {} host(s)?",
                                        mode.get(),
                                        sel_hosts.get().len() + adhoc.get().len(),
                                    )
                                }}
                            </h3>
                            <p>
                                "This mutates the selected hosts. Checkpoints are created automatically."
                            </p>
                            <pre class="fleet-preview">
                                {move || {
                                    if mode.get() == "apply" {
                                        render_apply(&preview_apply.get())
                                    } else {
                                        render_rollback(&preview_rollback.get())
                                    }
                                }}
                            </pre>
                            <div class="fleet-actions">
                                <button
                                    class="btn-secondary"
                                    on:click=move |_| confirm_open.set(false)
                                >
                                    "Cancel"
                                </button>
                                <button class="btn-danger" on:click=move |_| run(true)>
                                    {move || {
                                        format!(
                                            "Yes, execute on {} host(s)",
                                            sel_hosts.get().len() + adhoc.get().len(),
                                        )
                                    }}
                                </button>
                            </div>
                        </div>
                    </div>
                </Show>
            </Card>
        </div>
    }
}

fn render_apply(out: &[ApplyOutcome]) -> String {
    out.iter()
        .map(|o| {
            let s = match &o.status {
                ApplyStatus::Validated {
                    plugins,
                    would_change,
                    failed,
                } => format!("{plugins} plugins, {would_change} would change, {failed} failed"),
                ApplyStatus::Applied { ok, failed } => format!("applied {ok}, failed {failed}"),
                ApplyStatus::Failed { error } => format!("ERROR: {error}"),
            };
            format!("{} ({}) \u{2014} {}", o.name, o.target, s)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_rollback(out: &[RollbackOutcome]) -> String {
    out.iter()
        .map(|o| {
            let s = match &o.status {
                RollbackStatus::Previewed { checkpoints } => {
                    format!("{checkpoints} checkpoints would restore")
                }
                RollbackStatus::RolledBack { restored, failed } => {
                    format!("restored {restored}, failed {failed}")
                }
                RollbackStatus::NothingToDo => "nothing to roll back".to_string(),
                RollbackStatus::Failed { error } => format!("ERROR: {error}"),
            };
            format!("{} ({}) \u{2014} {}", o.name, o.target, s)
        })
        .collect::<Vec<_>>()
        .join("\n")
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
