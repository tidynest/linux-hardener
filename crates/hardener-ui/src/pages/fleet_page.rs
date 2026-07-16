//! Fleet page — scan several inventory hosts at once (read-only posture).

use crate::components::{AdhocHostInput, Card, FleetTable};
use crate::tauri_bindings::{invoke_fleet_scan, invoke_list_remote_hosts, listen_event};
use crate::types::FleetHostScan;
use hardener_types::remote::{FLEET_PROGRESS_EVENT, FleetProgress, RemoteHostProfile};
use leptos::prelude::*;
use std::collections::{HashMap, HashSet};

/// Read-only fleet scan: pick saved hosts, scan them concurrently, view each
/// host's severity posture.
#[component]
pub fn FleetPage() -> impl IntoView {
    let hosts = RwSignal::new(Vec::<RemoteHostProfile>::new());
    let selected = RwSignal::new(HashSet::<String>::new());
    let adhoc = RwSignal::new(Vec::<String>::new());
    let results = RwSignal::new(Vec::<FleetHostScan>::new());
    let scanning = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);
    // Live progress: the hosts of the running scan, and per-host completion
    // (true = that host failed). Filled by fleet-progress events; purely
    // cosmetic — the scan's outcome is the awaited invoke result.
    let expected = RwSignal::new(Vec::<String>::new());
    let progress = RwSignal::new(HashMap::<String, bool>::new());

    // Load saved inventory hosts on mount.
    leptos::task::spawn_local(async move {
        match invoke_list_remote_hosts().await {
            Ok(list) => hosts.set(list),
            Err(e) => error.set(Some(e)),
        }
    });

    let toggle = move |name: String| {
        selected.update(|s| {
            if !s.remove(&name) {
                s.insert(name);
            }
        });
    };

    let scan = move |_| {
        let names: Vec<String> = selected.get().into_iter().collect();
        let targets = adhoc.get();
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
            // Best-effort live updates; browser mode just keeps the plain
            // spinner. The subscription drops (unlistens) when the scan ends.
            let _subscription = listen_event::<FleetProgress, _>(FLEET_PROGRESS_EVENT, move |p| {
                progress.update(|m| {
                    m.insert(p.host, p.failed);
                });
            })
            .await
            .ok();
            match invoke_fleet_scan(names, targets, None).await {
                Ok(r) => results.set(r),
                Err(e) => error.set(Some(e)),
            }
            scanning.set(false);
        });
    };

    view! {
        <div class="fleet-page">
            <Card title="Fleet Scan".to_string()>
                <p class="fleet-intro">
                    "Select hosts and scan them concurrently for a read-only severity overview."
                </p>
                <Show when=move || error.get().is_some()>
                    <div class="error-banner" role="alert">
                        {move || error.get().unwrap_or_default()}
                    </div>
                </Show>
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
                                let name_for_check = name.clone();
                                let checked = move || selected.get().contains(&name_for_check);
                                let on_toggle = {
                                    let name = name.clone();
                                    move |_| toggle(name.clone())
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
                <AdhocHostInput adhoc=adhoc />
                <button
                    class="btn-primary"
                    on:click=scan
                    disabled=move || {
                        scanning.get() || (selected.get().is_empty() && adhoc.get().is_empty())
                    }
                >
                    {move || if scanning.get() { "Scanning\u{2026}" } else { "Scan selected" }}
                </button>
                <Show when=move || scanning.get()>
                    <div class="fleet-progress" aria-live="polite">
                        <p>
                            {move || {
                                format!(
                                    "{} of {} hosts finished",
                                    progress.get().len(),
                                    expected.get().len(),
                                )
                            }}
                        </p>
                        <ul class="fleet-progress-list">
                            {move || {
                                expected
                                    .get()
                                    .into_iter()
                                    .map(|host| {
                                        let (glyph, state) = match progress
                                            .with(|m| m.get(&host).copied())
                                        {
                                            None => ("\u{2026}", "pending"),
                                            Some(false) => ("\u{2713}", "ok"),
                                            Some(true) => ("\u{2717}", "failed"),
                                        };
                                        view! {
                                            <li class=format!(
                                                "fleet-progress-{state}",
                                            )>{format!("{glyph} {host}")}</li>
                                        }
                                    })
                                    .collect_view()
                            }}
                        </ul>
                    </div>
                </Show>
                <FleetTable scans=results />
            </Card>
        </div>
    }
}
