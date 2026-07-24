//! Hosts page: the merged inventory. Bulk read-only scan across selected hosts
//! plus the single-host connect session, both surfaced through one expandable
//! row per host. Replaces the old Remote and Fleet pages.

use crate::components::form_helpers::input_value;
use crate::components::{HostConnState, HostForm, HostRow};
use crate::state::AppState;
use crate::tauri_bindings::{
    invoke_connect_remote, invoke_delete_remote_host, invoke_disconnect_remote, invoke_fleet_scan,
    invoke_list_remote_hosts, invoke_remote_scan, listen_event,
};
use crate::types::{FleetHostScan, FleetHostStatus, SeverityTallies};
use crate::utils::{adhoc_canonical, adhoc_target_error};
use hardener_types::remote::{
    FLEET_PROGRESS_EVENT, FleetProgress, RemoteConnectionInfo, RemoteConnectionStatus,
    RemoteHostProfile,
};
use leptos::prelude::*;
use std::collections::{HashMap, HashSet};

#[component]
pub fn HostsPage() -> impl IntoView {
    let app = expect_context::<AppState>();

    let adhoc = RwSignal::new(Vec::<String>::new());
    let selected = RwSignal::new(HashSet::<String>::new());
    let scans = RwSignal::new(HashMap::<String, FleetHostScan>::new());
    let scanning = RwSignal::new(false);
    let expected = RwSignal::new(Vec::<String>::new());
    let progress = RwSignal::new(HashMap::<String, bool>::new());
    let error = RwSignal::new(None::<String>);
    let expanded = RwSignal::new(None::<String>);
    let connecting_host = RwSignal::new(None::<String>);
    let modal_open = RwSignal::new(false);
    let editing = RwSignal::new(None::<RemoteHostProfile>);
    let adhoc_draft = RwSignal::new(String::new());
    let adhoc_error = RwSignal::new(None::<String>);
    let adhoc_open = RwSignal::new(false);

    let load_hosts = move || {
        leptos::task::spawn_local(async move {
            match invoke_list_remote_hosts().await {
                Ok(list) => app.remote_hosts.set(list),
                Err(e) => error.set(Some(e)),
            }
        });
    };
    load_hosts();

    // --- selection helpers ---
    let saved_names = move || {
        app.remote_hosts
            .get()
            .into_iter()
            .map(|h| h.name)
            .collect::<HashSet<_>>()
    };
    let toggle_select = move |key: String| {
        selected.update(|s| {
            if !s.remove(&key) {
                s.insert(key);
            }
        });
    };
    let select_all = move |_| {
        let mut all: HashSet<String> = saved_names();
        all.extend(adhoc.get());
        let full = selected.get().len() == all.len() && !all.is_empty();
        selected.set(if full { HashSet::new() } else { all });
    };
    // Failed hosts must not expand: a failed row has no panel content worth
    // opening, and letting it open regressed a Task-3 review finding. Guard so
    // a failed host can only ever close (if somehow already open), never open.
    let toggle_expand = move |key: String| {
        let currently_open = expanded.get().as_deref() == Some(key.as_str());
        let is_failed = scans.with(|m| {
            matches!(
                m.get(&key).map(|s| &s.status),
                Some(FleetHostStatus::Failed(_))
            )
        });
        if is_failed && !currently_open {
            return;
        }
        expanded.update(|c| *c = if currently_open { None } else { Some(key) });
    };

    // --- ad-hoc add/remove ---
    let add_adhoc = move || {
        let raw = adhoc_draft.get().trim().to_string();
        match adhoc_target_error(&raw, &adhoc.get()) {
            Some(e) => adhoc_error.set(Some(e)),
            None => {
                adhoc.update(|v| v.push(adhoc_canonical(&raw)));
                adhoc_draft.set(String::new());
                adhoc_error.set(None);
            }
        }
    };
    let remove_adhoc = move |target: String| {
        adhoc.update(|v| v.retain(|t| t != &target));
        selected.update(|s| {
            s.remove(&target);
        });
        scans.update(|m| {
            m.remove(&target);
        });
    };

    // --- bulk scan ---
    let scan_selected = move |_| {
        let sel = selected.get();
        let saved = saved_names();
        let adhoc_now: HashSet<String> = adhoc.get().into_iter().collect();
        let names: Vec<String> = sel.iter().filter(|k| saved.contains(*k)).cloned().collect();
        let targets: Vec<String> = sel
            .iter()
            .filter(|k| adhoc_now.contains(*k))
            .cloned()
            .collect();
        if names.is_empty() && targets.is_empty() {
            return;
        }
        let mut all = names.clone();
        all.extend(targets.iter().cloned());
        expected.set(all);
        progress.set(HashMap::new());
        scanning.set(true);
        error.set(None);
        leptos::task::spawn_local(async move {
            let _sub = listen_event::<FleetProgress, _>(FLEET_PROGRESS_EVENT, move |p| {
                progress.update(|m| {
                    m.insert(p.host, p.failed);
                });
            })
            .await
            .ok();
            match invoke_fleet_scan(names, targets, None).await {
                Ok(results) => scans.update(|m| {
                    for r in results {
                        m.insert(r.host_name.clone(), r);
                    }
                }),
                Err(e) => error.set(Some(e)),
            }
            scanning.set(false);
        });
    };

    // --- connection wiring (single session) ---
    let connect = move |name: String| {
        connecting_host.set(Some(name.clone()));
        app.is_connecting.set(true);
        leptos::task::spawn_local(async move {
            match invoke_connect_remote(name.clone()).await {
                Ok(RemoteConnectionStatus::Connected { host, user }) => {
                    app.remote_connection.set(Some(RemoteConnectionInfo {
                        profile_name: name,
                        host,
                        user,
                    }));
                }
                Ok(RemoteConnectionStatus::Failed { error: e }) => {
                    error.set(Some(format!("Connection failed: {e}")))
                }
                Err(e) => error.set(Some(format!("Connection error: {e}"))),
            }
            app.is_connecting.set(false);
            connecting_host.set(None);
        });
    };
    let disconnect = move |_name: String| {
        leptos::task::spawn_local(async move {
            if let Err(e) = invoke_disconnect_remote().await {
                error.set(Some(format!("Disconnect failed: {e}")));
                return;
            }
            app.remote_connection.set(None);
        });
    };
    let session_scan = move |name: String| {
        app.is_remote_scanning.set(true);
        leptos::task::spawn_local(async move {
            match invoke_remote_scan(None).await {
                Ok(results) => {
                    let synthesised = FleetHostScan {
                        host_name: name.clone(),
                        status: FleetHostStatus::Ok,
                        tallies: SeverityTallies::from_results(&results),
                        scan_results: results,
                        compliance: Vec::new(),
                    };
                    scans.update(|m| {
                        m.insert(name, synthesised);
                    });
                }
                Err(e) => error.set(Some(format!("Remote scan failed: {e}"))),
            }
            app.is_remote_scanning.set(false);
        });
    };

    // --- delete / edit ---
    let delete_host = move |name: String| {
        leptos::task::spawn_local(async move {
            match invoke_delete_remote_host(name.clone()).await {
                Ok(()) => {
                    if app
                        .remote_connection
                        .get()
                        .is_some_and(|c| c.profile_name == name)
                    {
                        app.remote_connection.set(None);
                    }
                    if let Ok(list) = invoke_list_remote_hosts().await {
                        app.remote_hosts.set(list);
                    }
                    scans.update(|m| {
                        m.remove(&name);
                    });
                    selected.update(|s| {
                        s.remove(&name);
                    });
                }
                Err(e) => error.set(Some(format!("Failed to delete host: {e}"))),
            }
        });
    };
    let open_add = move |_| {
        editing.set(None);
        modal_open.set(true);
    };
    let open_edit = move |profile: RemoteHostProfile| {
        editing.set(Some(profile));
        modal_open.set(true);
    };
    let on_modal_close = move |_: ()| {
        modal_open.set(false);
        editing.set(None);
        load_hosts();
    };

    // --- per-host connection state ---
    let conn_state_for = move |name: String| -> HostConnState {
        if connecting_host.get().as_deref() == Some(name.as_str()) {
            return HostConnState::Connecting;
        }
        match app.remote_connection.get() {
            Some(c) if c.profile_name == name => HostConnState::Connected(c.user),
            _ => HostConnState::Disconnected,
        }
    };

    view! {
        <div class="hosts-page">
            <div class="hosts-header">
                <h1>"Hosts"</h1>
                <p class="hosts-subtitle">"Scan and manage the machines you reach over SSH."</p>
            </div>

            <Show when=move || error.get().is_some()>
                <div class="error-banner" role="alert">{move || error.get().unwrap_or_default()}</div>
            </Show>

            // --- action bar ---
            <div class="hosts-actions">
                <button
                    class="btn btn-primary"
                    on:click=scan_selected
                    disabled=move || scanning.get() || selected.get().is_empty()
                >
                    {move || if scanning.get() {
                        "Scanning\u{2026}".to_string()
                    } else {
                        format!("Scan Selected ({})", selected.get().len())
                    }}
                </button>
                <button class="btn btn-secondary" on:click=open_add>"Add Host"</button>
                <button class="hosts-adhoc-toggle" on:click=move |_| adhoc_open.update(|o| *o = !*o)>
                    {move || if adhoc_open.get() { "Hide ad-hoc target" } else { "Add ad-hoc target" }}
                </button>
                <span class="hosts-count">
                    {move || {
                        let count = app.remote_hosts.get().len() + adhoc.get().len();
                        format!("{} host{}", count, if count == 1 { "" } else { "s" })
                    }}
                </span>
            </div>

            <Show when=move || adhoc_open.get()>
                <div class="hosts-adhoc-input">
                    <input
                        type="text"
                        placeholder="user@host[:port]"
                        aria-label="Ad-hoc SSH target"
                        prop:value=adhoc_draft
                        on:input=move |ev| adhoc_draft.set(input_value(&ev))
                        on:keydown=move |ev| if ev.key() == "Enter" { ev.prevent_default(); add_adhoc(); }
                    />
                    <button class="btn btn-secondary" on:click=move |_| add_adhoc()
                        disabled=move || adhoc_draft.get().trim().is_empty()>"Add"</button>
                    <Show when=move || adhoc_error.get().is_some()>
                        <span class="error-banner" role="alert">{move || adhoc_error.get().unwrap_or_default()}</span>
                    </Show>
                </div>
            </Show>

            <Show when=move || scanning.get()>
                <p class="hosts-progress" aria-live="polite">
                    {move || format!("{} of {} finished", progress.get().len(), expected.get().len())}
                </p>
            </Show>

            // --- inventory ---
            {move || {
                let hosts = app.remote_hosts.get();
                let adhoc_list = adhoc.get();
                if hosts.is_empty() && adhoc_list.is_empty() {
                    return view! {
                        <div class="hosts-empty empty-state">
                            <p class="empty-state-title">"No hosts yet"</p>
                            <p class="empty-state-hint">"These are machines you reach over SSH."</p>
                            <ol class="hosts-empty-steps">
                                <li>"Add a host with its SSH details."</li>
                                <li>"Connect or scan it."</li>
                                <li>"Review its posture and roll out hardening."</li>
                            </ol>
                            <button class="btn btn-primary" on:click=open_add>"Add Host"</button>
                        </div>
                    }.into_any();
                }
                view! {
                    <div class="hosts-list">
                        <div class="hosts-list-head">
                            <button class="hosts-select-all" on:click=select_all>"Select all"</button>
                        </div>
                        {hosts.into_iter().map(|h| {
                            let key = h.name.clone();
                            let detail = format!(
                                "{}@{}:{}",
                                h.user.clone().unwrap_or_else(|| "root".to_string()), h.hostname, h.port
                            );
                            row_view(
                                key.clone(), h.name.clone(), detail, Some(h.clone()),
                                scans, selected, expanded, progress, scanning.into(), conn_state_for,
                                toggle_select, toggle_expand, connect, disconnect, session_scan,
                                open_edit, delete_host, remove_adhoc,
                            )
                        }).collect_view()}
                        {adhoc_list.into_iter().map(|t| {
                            row_view(
                                t.clone(), t.clone(), t.clone(), None,
                                scans, selected, expanded, progress, scanning.into(), conn_state_for,
                                toggle_select, toggle_expand, connect, disconnect, session_scan,
                                open_edit, delete_host, remove_adhoc,
                            )
                        }).collect_view()}
                    </div>
                }.into_any()
            }}

            // --- add/edit modal ---
            <Show when=move || modal_open.get()>
                <div class="modal-backdrop">
                    <div class="modal" role="dialog" aria-modal="true" aria-label="Host details">
                        <HostForm existing=editing.get() on_close=on_modal_close />
                    </div>
                </div>
            </Show>
        </div>
    }
}

/// Builds one `HostRow` with per-key derived signals, keeping the saved-host
/// and ad-hoc row loops DRY (both wire the same props). The handler closures
/// arrive by value and are `Copy` (they capture only `Copy` signals); the
/// `Send + Sync` bounds are what `Callback::new` and `Signal::derive` demand,
/// satisfied because those captured signals are themselves `Send + Sync`.
#[allow(clippy::too_many_arguments)]
fn row_view(
    key: String,
    label: String,
    detail: String,
    profile: Option<RemoteHostProfile>,
    scans: RwSignal<HashMap<String, FleetHostScan>>,
    selected: RwSignal<HashSet<String>>,
    expanded: RwSignal<Option<String>>,
    progress: RwSignal<HashMap<String, bool>>,
    scanning: Signal<bool>,
    conn_state_for: impl Fn(String) -> HostConnState + Copy + Send + Sync + 'static,
    toggle_select: impl Fn(String) + Copy + Send + Sync + 'static,
    toggle_expand: impl Fn(String) + Copy + Send + Sync + 'static,
    connect: impl Fn(String) + Copy + Send + Sync + 'static,
    disconnect: impl Fn(String) + Copy + Send + Sync + 'static,
    session_scan: impl Fn(String) + Copy + Send + Sync + 'static,
    open_edit: impl Fn(RemoteHostProfile) + Copy + Send + Sync + 'static,
    delete_host: impl Fn(String) + Copy + Send + Sync + 'static,
    remove_adhoc: impl Fn(String) + Copy + Send + Sync + 'static,
) -> impl IntoView {
    let k = key.clone();
    let scan = Signal::derive(move || scans.get().get(&k).cloned());
    let k = key.clone();
    let sel = Signal::derive(move || selected.get().contains(&k));
    let k = key.clone();
    let exp = Signal::derive(move || expanded.get().as_deref() == Some(k.as_str()));
    let k = key.clone();
    let prog = Signal::derive(move || progress.get().get(&k).copied());
    let k = key.clone();
    let conn = Signal::derive(move || conn_state_for(k.clone()));

    let profile_edit = profile.clone();
    view! {
        <HostRow
            key=key.clone()
            label=label
            detail=detail
            profile=profile.clone()
            scan=scan
            selected=sel
            expanded=exp
            progress=prog
            scanning=scanning
            conn=conn
            on_toggle_select={let k = key.clone(); Callback::new(move |_| toggle_select(k.clone()))}
            on_toggle_expand={let k = key.clone(); Callback::new(move |_| toggle_expand(k.clone()))}
            on_connect={let k = key.clone(); Callback::new(move |_| connect(k.clone()))}
            on_disconnect={let k = key.clone(); Callback::new(move |_| disconnect(k.clone()))}
            on_scan={let k = key.clone(); Callback::new(move |_| session_scan(k.clone()))}
            on_edit={let p = profile_edit.clone(); Callback::new(move |_| if let Some(p) = p.clone() { open_edit(p); })}
            on_delete={let k = key.clone(); Callback::new(move |_| delete_host(k.clone()))}
            on_remove_adhoc={let k = key.clone(); Callback::new(move |_| remove_adhoc(k.clone()))}
        />
    }
}
