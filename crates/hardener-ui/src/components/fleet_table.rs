//! Fleet scan results table — one row per host, expandable to its findings.

use crate::components::FindingsGrid;
use crate::types::{Finding, FleetHostScan, FleetHostStatus};
use leptos::prelude::*;
use std::sync::Arc;

/// Toggles which host row is expanded (accordion: one open at a time).
fn toggle_expanded(expanded: RwSignal<Option<String>>, host: &str) {
    expanded.update(|cur| {
        *cur = if cur.as_deref() == Some(host) {
            None
        } else {
            Some(host.to_string())
        };
    });
}

/// Renders fleet scan results: a row per host with severity tallies, expandable
/// to that host's findings (reusing `FindingsGrid`). Failed hosts show the error.
#[component]
pub fn FleetTable(#[prop(into)] scans: Signal<Vec<FleetHostScan>>) -> impl IntoView {
    let expanded = RwSignal::new(None::<String>);

    view! {
        <section class="fleet-table">
            {move || {
                let scans = scans.get();
                if scans.is_empty() {
                    return view! {
                        <p class="empty-state">"No fleet scan yet. Select hosts and scan."</p>
                    }
                    .into_any();
                }
                view! {
                    <table class="findings-table" role="grid">
                        <thead>
                            <tr role="row">
                                <th role="columnheader">"Host"</th>
                                <th role="columnheader">"Status"</th>
                                <th role="columnheader">"Critical"</th>
                                <th role="columnheader">"High"</th>
                                <th role="columnheader">"Medium"</th>
                                <th role="columnheader">"Low"</th>
                                <th role="columnheader">"Info"</th>
                            </tr>
                        </thead>
                        <tbody>
                            {scans
                                .into_iter()
                                .map(|scan| {
                                    let host = scan.host_name.clone();
                                    let findings: Arc<Vec<Finding>> = Arc::new(
                                        scan.scan_results
                                            .iter()
                                            .flat_map(|r| r.scan_findings.iter().cloned())
                                            .collect(),
                                    );
                                    let (status_text, status_class, failed) = match &scan.status {
                                        FleetHostStatus::Ok => ("OK".to_string(), "fleet-ok", false),
                                        FleetHostStatus::Failed(e) => {
                                            (format!("Failed: {e}"), "fleet-failed", true)
                                        }
                                    };
                                    let t = scan.tallies;
                                    let host_expanded = host.clone();
                                    let is_expanded =
                                        move || expanded.get().as_deref() == Some(host_expanded.as_str());
                                    let host_click = host.clone();
                                    let host_key = host.clone();
                                    // Keyboard handler: Enter/Space to toggle expansion.
                                    let on_keydown = move |ev: web_sys::KeyboardEvent| {
                                        if failed {
                                            return;
                                        }
                                        match ev.key().as_str() {
                                            "Enter" | " " => {
                                                ev.prevent_default();
                                                toggle_expanded(expanded, &host_key);
                                            }
                                            _ => {}
                                        }
                                    };
                                    view! {
                                        <tr
                                            role="row"
                                            class="fleet-row"
                                            class:fleet-row-expandable=move || !failed
                                            tabindex=if failed { "-1" } else { "0" }
                                            on:click=move |_| {
                                                if !failed {
                                                    toggle_expanded(expanded, &host_click);
                                                }
                                            }
                                            on:keydown=on_keydown
                                        >
                                            <td>{host.clone()}</td>
                                            <td class={status_class}>{status_text}</td>
                                            <td>{t.critical}</td>
                                            <td>{t.high}</td>
                                            <td>{t.medium}</td>
                                            <td>{t.low}</td>
                                            <td>{t.info}</td>
                                        </tr>
                                        <Show when=move || is_expanded() && !failed>
                                            {
                                                let findings = Arc::clone(&findings);
                                                view! {
                                                    <tr class="fleet-detail-row">
                                                        <td colspan="7">
                                                            <FindingsGrid findings=Signal::derive(move || {
                                                                (*findings).clone()
                                                            }) />
                                                        </td>
                                                    </tr>
                                                }
                                            }
                                        </Show>
                                    }
                                })
                                .collect::<Vec<_>>()}
                        </tbody>
                    </table>
                }
                .into_any()
            }}
        </section>
    }
}
