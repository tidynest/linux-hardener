//! Fleet page — scan several inventory hosts at once (read-only posture).

use crate::components::{AdhocHostInput, Card, FleetTable};
use crate::tauri_bindings::{invoke_fleet_scan, invoke_list_remote_hosts};
use crate::types::FleetHostScan;
use hardener_types::remote::RemoteHostProfile;
use leptos::prelude::*;
use std::collections::HashSet;

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
        scanning.set(true);
        error.set(None);
        leptos::task::spawn_local(async move {
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
                <FleetTable scans=results />
            </Card>
        </div>
    }
}
