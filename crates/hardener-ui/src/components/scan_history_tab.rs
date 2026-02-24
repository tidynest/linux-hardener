//! Scan history tab for the Analysis page.
//!
//! Displays past scan sessions with metadata and drill-down capability.

use crate::state::AppState;
use crate::tauri_bindings::{invoke_get_scan_history, invoke_get_scan_session};
use crate::types::ScanSessionInfo;
use leptos::prelude::*;

/// Scan history tab showing past scan sessions.
#[component]
pub fn ScanHistoryTab() -> impl IntoView {
    let app_state = expect_context::<AppState>();
    let sessions = RwSignal::new(Vec::<ScanSessionInfo>::new());
    let is_loading = RwSignal::new(false);

    // Load history on mount
    let load_history = move || {
        is_loading.set(true);
        leptos::task::spawn_local(async move {
            match invoke_get_scan_history(Some(20)).await {
                Ok(history) => sessions.set(history),
                Err(e) => {
                    web_sys::console::error_1(
                        &format!("Failed to load scan history: {}", e).into(),
                    );
                }
            }
            is_loading.set(false);
        });
    };

    load_history();

    // Load a session's results into the main app state
    let load_session = move |session_id: String| {
        leptos::task::spawn_local(async move {
            match invoke_get_scan_session(session_id).await {
                Ok(results) => {
                    app_state.scan_results.set(results);
                }
                Err(e) => {
                    web_sys::console::error_1(&format!("Failed to load session: {}", e).into());
                    app_state
                        .error_message
                        .set(Some(format!("Failed to load session: {}", e)));
                }
            }
        });
    };

    view! {
        <div class="scan-history-tab">
            <div class="history-header">
                <button
                    class="btn btn-secondary btn-small"
                    on:click=move |_| load_history()
                    disabled=move || is_loading.get()
                >
                    {move || if is_loading.get() { "Loading..." } else { "Refresh" }}
                </button>
            </div>

            <Show
                when=move || !sessions.get().is_empty()
                fallback=move || {
                    if is_loading.get() {
                        view! {
                            <div class="empty-state">
                                <p class="empty-state-title">"Loading scan history..."</p>
                            </div>
                        }.into_any()
                    } else {
                        view! {
                            <div class="empty-state">
                                <p class="empty-state-title">"No scan history yet"</p>
                                <p class="empty-state-hint">"Run a scan to see history here."</p>
                            </div>
                        }.into_any()
                    }
                }
            >
                <table>
                    <thead>
                        <tr>
                            <th>"Date"</th>
                            <th>"Status"</th>
                            <th>"Findings"</th>
                            <th>"Plugins"</th>
                            <th>"Actions"</th>
                        </tr>
                    </thead>
                    <tbody>
                        {move || sessions.get().iter().map(|s| {
                            let started = s.started_at.clone();
                            let status = s.status.clone();
                            let findings = s.total_findings;
                            let plugins = s.total_plugins;
                            let session_id = s.session_id.clone();

                            let status_class = match status.as_str() {
                                "completed" => "status-success",
                                "failed" => "status-error",
                                _ => "status-running",
                            };

                            view! {
                                <tr>
                                    <td>{started}</td>
                                    <td>
                                        <span class=format!("status-badge {}", status_class)>
                                            {status}
                                        </span>
                                    </td>
                                    <td>{findings}</td>
                                    <td>{plugins}</td>
                                    <td>
                                        <button
                                            class="btn btn-secondary btn-small"
                                            on:click=move |_| load_session(session_id.clone())
                                        >
                                            "Load"
                                        </button>
                                    </td>
                                </tr>
                            }
                        }).collect::<Vec<_>>()}
                    </tbody>
                </table>
            </Show>
        </div>
    }
}
