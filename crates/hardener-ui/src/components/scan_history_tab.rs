//! Scan history tab for the Analysis page.
//!
//! A date-grouped vertical timeline reusing the Phase 2b checkpoint rail.
//! Each node is one past scan session; Load pulls that session's results into
//! the app state and switches to the Findings tab. Completed sessions read
//! neutral; a failed session is red with Load disabled.

use crate::state::AppState;
use crate::tauri_bindings::{invoke_get_scan_history, invoke_get_scan_session};
use crate::types::ScanSessionInfo;
use crate::utils::{checkpoint_time, group_sessions_by_date};
use leptos::prelude::*;

/// Scan history tab. `active_tab` is the Analysis page's tab signal, switched
/// to 0 (Findings) after a session is loaded.
#[component]
pub fn ScanHistoryTab(active_tab: RwSignal<usize>) -> impl IntoView {
    let app_state = expect_context::<AppState>();
    let sessions = RwSignal::new(Vec::<ScanSessionInfo>::new());
    let is_loading = RwSignal::new(false);

    let load_history = move || {
        is_loading.set(true);
        leptos::task::spawn_local(async move {
            match invoke_get_scan_history(Some(20)).await {
                Ok(history) => sessions.set(history),
                Err(e) => {
                    web_sys::console::error_1(&format!("Failed to load scan history: {e}").into())
                }
            }
            is_loading.set(false);
        });
    };

    load_history();

    let load_session = move |session_id: String| {
        leptos::task::spawn_local(async move {
            match invoke_get_scan_session(session_id).await {
                Ok(results) => {
                    app_state.scan_results.set(results);
                    active_tab.set(0);
                }
                Err(e) => {
                    web_sys::console::error_1(&format!("Failed to load session: {e}").into());
                    app_state
                        .error_message
                        .set(Some(format!("Failed to load session: {e}")));
                }
            }
        });
    };

    view! {
        <div class="scan-history-tab">
            <div class="checkpoint-controls">
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
                <ol class="timeline">
                    {move || {
                        let all = sessions.get();
                        let latest_id = all.first().map(|s| s.session_id.clone());
                        group_sessions_by_date(&all).into_iter().map(|(date, group)| {
                            let latest_id = latest_id.clone();
                            view! {
                                <li class="timeline-group">
                                    <p class="timeline-date">{date}</p>
                                    <ol class="timeline-nodes">
                                        {group.into_iter().map(|s| {
                                            let is_latest = latest_id.as_deref() == Some(s.session_id.as_str());
                                            let is_failed = s.status == "failed";
                                            let time = checkpoint_time(&s.started_at).to_string();
                                            let meta = format!(
                                                "{} findings across {} checks",
                                                s.total_findings, s.total_plugins,
                                            );
                                            let session_id = s.session_id.clone();
                                            let dot_cls = if is_failed {
                                                "timeline-dot timeline-dot-failed"
                                            } else if is_latest {
                                                "timeline-dot timeline-dot-latest"
                                            } else {
                                                "timeline-dot"
                                            };
                                            let status_cls = if is_failed {
                                                "timeline-status failed"
                                            } else {
                                                "timeline-status"
                                            };
                                            let status_text = if is_failed { "Failed" } else { "Completed" };
                                            view! {
                                                <li class="timeline-node">
                                                    <span class=dot_cls></span>
                                                    <div class="timeline-body">
                                                        <div class="timeline-head">
                                                            <span class="timeline-name">{time}</span>
                                                            {is_latest.then(|| view! {
                                                                <span class="timeline-latest-pill">"Latest"</span>
                                                            })}
                                                            <span class=status_cls>{status_text}</span>
                                                        </div>
                                                        <div class="timeline-meta">{meta}</div>
                                                        <div class="timeline-actions">
                                                            <button
                                                                class="btn btn-secondary btn-small"
                                                                disabled=is_failed
                                                                on:click=move |_| load_session(session_id.clone())
                                                            >
                                                                "Load"
                                                            </button>
                                                        </div>
                                                    </div>
                                                </li>
                                            }
                                        }).collect::<Vec<_>>()}
                                    </ol>
                                </li>
                            }
                        }).collect::<Vec<_>>()
                    }}
                </ol>
            </Show>
        </div>
    }
}
