//! Sidebar component listing saved remote host profiles.
//!
//! Displays saved hosts with connect, edit, and delete actions.
//! The connected host is visually highlighted. An "Add Host" button
//! at the bottom triggers the parent's edit callback with `None`.

use crate::state::AppState;
use crate::tauri_bindings::{
    invoke_connect_remote, invoke_delete_remote_host, invoke_list_remote_hosts,
};
use hardener_types::remote::{RemoteConnectionInfo, RemoteConnectionStatus, RemoteHostProfile};
use leptos::prelude::*;

/// Sidebar list of saved remote host profiles.
///
/// Loads profiles on mount and provides connect, edit, and delete actions
/// per entry. The currently connected host receives an active highlight.
#[component]
pub fn HostList(#[prop(into)] on_edit: Callback<Option<RemoteHostProfile>>) -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Reload host list from backend into AppState.
    let load_hosts = move || {
        leptos::task::spawn_local(async move {
            match invoke_list_remote_hosts().await {
                Ok(hosts) => app_state.remote_hosts.set(hosts),
                Err(e) => {
                    web_sys::console::error_1(&format!("Failed to load hosts: {}", e).into());
                    app_state
                        .error_message
                        .set(Some(format!("Failed to load hosts: {}", e)));
                }
            }
        });
    };

    // Load on mount
    load_hosts();

    // Connect handler — establishes SSH connection and stores info in AppState.
    let handle_connect = move |profile: RemoteHostProfile| {
        let name = profile.name.clone();
        let hostname = profile.hostname.clone();
        app_state.is_connecting.set(true);

        leptos::task::spawn_local(async move {
            match invoke_connect_remote(name.clone()).await {
                Ok(RemoteConnectionStatus::Connected { host, user }) => {
                    app_state.remote_connection.set(Some(RemoteConnectionInfo {
                        profile_name: name,
                        host,
                        user,
                    }));
                }
                Ok(RemoteConnectionStatus::Failed { error }) => {
                    web_sys::console::error_1(&format!("Connection failed: {}", error).into());
                    app_state.error_message.set(Some(format!(
                        "Connection to {} failed: {}",
                        hostname, error
                    )));
                }
                Err(e) => {
                    web_sys::console::error_1(&format!("Connect error: {}", e).into());
                    app_state
                        .error_message
                        .set(Some(format!("Connection error: {}", e)));
                }
            }
            app_state.is_connecting.set(false);
        });
    };

    // Delete handler — removes profile and reloads list.
    let handle_delete = move |name: String| {
        leptos::task::spawn_local(async move {
            match invoke_delete_remote_host(name.clone()).await {
                Ok(()) => {
                    // If the deleted host was connected, clear connection state
                    if let Some(ref conn) = app_state.remote_connection.get()
                        && conn.profile_name == name
                    {
                        app_state.remote_connection.set(None);
                    }
                    // Reload list
                    if let Ok(hosts) = invoke_list_remote_hosts().await {
                        app_state.remote_hosts.set(hosts);
                    }
                }
                Err(e) => {
                    web_sys::console::error_1(&format!("Delete failed: {}", e).into());
                    app_state
                        .error_message
                        .set(Some(format!("Failed to delete host: {}", e)));
                }
            }
        });
    };

    view! {
        <div class="host-list">
            <h3 class="host-list-title">"Saved Hosts"</h3>

            <Show
                when=move || !app_state.remote_hosts.get().is_empty()
                fallback=|| view! {
                    <div class="empty-state">
                        <p class="empty-state-title">"No saved hosts"</p>
                        <p class="empty-state-hint">"Add a remote host to begin scanning."</p>
                    </div>
                }
            >
                <ul class="host-entries">
                    {move || {
                        let connection = app_state.remote_connection.get();
                        app_state.remote_hosts.get().iter().map(|profile| {
                            let name = profile.name.clone();
                            let hostname = profile.hostname.clone();
                            let user_display = profile.user.clone().unwrap_or_else(|| "root".to_string());
                            let port = profile.port;
                            let is_active = connection.as_ref().is_some_and(|c| c.profile_name == name);

                            // Clone values for closures
                            let connect_profile = profile.clone();
                            let edit_profile = profile.clone();
                            let delete_name = name.clone();

                            let entry_class = if is_active {
                                "host-entry host-entry--active"
                            } else {
                                "host-entry"
                            };

                            view! {
                                <li class=entry_class>
                                    <div class="host-entry-info">
                                        <span class="host-entry-name">{name}</span>
                                        <span class="host-entry-detail">
                                            {format!("{}@{}:{}", user_display, hostname, port)}
                                        </span>
                                    </div>
                                    <div class="host-entry-actions">
                                        <button
                                            class="btn btn-primary btn-small"
                                            on:click={
                                                let profile = connect_profile.clone();
                                                move |_| handle_connect(profile.clone())
                                            }
                                            disabled=move || app_state.is_connecting.get() || is_active
                                        >
                                            {if is_active { "Connected" } else { "Connect" }}
                                        </button>
                                        <button
                                            class="btn btn-secondary btn-small"
                                            on:click={
                                                let profile = edit_profile.clone();
                                                let on_edit = on_edit.clone();
                                                move |_| on_edit.run(Some(profile.clone()))
                                            }
                                        >
                                            "Edit"
                                        </button>
                                        <button
                                            class="btn btn-danger btn-small"
                                            on:click={
                                                let name = delete_name.clone();
                                                move |_| handle_delete(name.clone())
                                            }
                                        >
                                            "Delete"
                                        </button>
                                    </div>
                                </li>
                            }
                        }).collect::<Vec<_>>()
                    }}
                </ul>
            </Show>

            <button
                class="btn btn-secondary host-add-button"
                on:click={
                    let on_edit = on_edit.clone();
                    move |_| on_edit.run(None)
                }
            >
                "Add Host"
            </button>
        </div>
    }
}
