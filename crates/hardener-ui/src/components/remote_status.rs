//! Right panel showing connection status, scan controls, and remote scan results.
//!
//! Displays three states:
//! - **Disconnected**: empty placeholder prompting the user to connect.
//! - **Connected**: host info banner, Run Scan / Disconnect buttons.
//! - **Results**: findings table (severity badge, plugin, title) once a scan completes.

use crate::components::SeverityBadge;
use crate::state::AppState;
use crate::tauri_bindings;
use leptos::prelude::*;

/// Right-side panel for the Remote page.
///
/// Reacts to `AppState.remote_connection` to switch between the empty
/// placeholder and the connected view. When connected, provides scan
/// and disconnect actions and renders remote findings in a table that
/// mirrors the local `FindingsGrid` layout.
#[component]
pub fn RemoteStatus() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // --- Handlers ---

    let on_scan = move |_| {
        app_state.is_remote_scanning.set(true);
        leptos::task::spawn_local(async move {
            match tauri_bindings::invoke_remote_scan(None).await {
                Ok(results) => app_state.remote_scan_results.set(results),
                Err(e) => {
                    app_state
                        .error_message
                        .set(Some(format!("Remote scan failed: {}", e)));
                }
            }
            app_state.is_remote_scanning.set(false);
        });
    };

    let on_disconnect = move |_| {
        leptos::task::spawn_local(async move {
            if let Err(e) = tauri_bindings::invoke_disconnect_remote().await {
                app_state
                    .error_message
                    .set(Some(format!("Disconnect failed: {}", e)));
                return;
            }
            app_state.remote_connection.set(None);
            app_state.remote_scan_results.set(Vec::new());
        });
    };

    // --- Derived signals ---

    let total_findings = move || {
        app_state
            .remote_scan_results
            .get()
            .iter()
            .map(|r| r.scan_findings.len())
            .sum::<usize>()
    };

    let has_results = move || total_findings() > 0;

    view! {
        <Show
            when=move || app_state.remote_connection.get().is_some()
            fallback=move || view! {
                <div class="remote-empty">
                    <div class="remote-empty-icon">"Select a host and connect to start remote scanning."</div>
                </div>
            }
        >
            // Connected state
            {move || {
                let conn = app_state.remote_connection.get();
                let (profile, host, user) = conn
                    .map(|c| (c.profile_name, c.host, c.user))
                    .unwrap_or_default();

                view! {
                    <div class="remote-connected-header">
                        <div class="remote-connected-info">
                            <span class="remote-connected-label">{format!("Connected as {}", user)}</span>
                            <span class="remote-connected-host">{format!("{} ({})", profile, host)}</span>
                        </div>
                        <div class="remote-connected-actions">
                            <button
                                class="btn btn-primary btn-small"
                                on:click=on_scan
                                disabled=move || app_state.is_remote_scanning.get()
                            >
                                {move || if app_state.is_remote_scanning.get() { "Scanning..." } else { "Run Scan" }}
                            </button>
                            <button
                                class="btn btn-secondary btn-small"
                                on:click=on_disconnect
                            >
                                "Disconnect"
                            </button>
                        </div>
                    </div>

                    <Show when=has_results fallback=|| ()>
                        <div class="remote-results">
                            <p class="remote-results-title">
                                {move || format!("{} findings", total_findings())}
                            </p>
                            <table class="findings-table">
                                <thead>
                                    <tr>
                                        <th>"Severity"</th>
                                        <th>"Plugin"</th>
                                        <th>"Title"</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {move || {
                                        app_state.remote_scan_results.get().iter().flat_map(|r| {
                                            let plugin = r.scan_plugin_id.to_string();
                                            r.scan_findings.iter().map(move |f| {
                                                let title = f.finding_title.clone();
                                                let severity = f.finding_severity;
                                                let plugin = plugin.clone();
                                                view! {
                                                    <tr class="finding-row">
                                                        <td><SeverityBadge severity=severity /></td>
                                                        <td>{plugin}</td>
                                                        <td>{title}</td>
                                                    </tr>
                                                }
                                            }).collect::<Vec<_>>()
                                        }).collect::<Vec<_>>()
                                    }}
                                </tbody>
                            </table>
                        </div>
                    </Show>
                }
            }}
        </Show>
    }
}
