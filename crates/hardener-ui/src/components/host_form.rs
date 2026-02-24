//! Form component for adding or editing a remote host profile.

use crate::state::AppState;
use crate::tauri_bindings::{invoke_list_remote_hosts, invoke_save_remote_host};
use hardener_types::remote::RemoteHostProfile;
use leptos::prelude::*;

/// Modal-style form for creating or editing a remote host profile.
///
/// Pre-fills fields when editing an existing profile. Validates that name
/// and hostname are non-empty before saving. After a successful save the
/// host list is reloaded and the parent is notified via `on_close`.
#[component]
pub fn HostForm(
    /// Existing profile to edit (None = add new).
    #[prop(optional)]
    existing: Option<RemoteHostProfile>,
    /// Callback when form is submitted or cancelled.
    #[prop(into)]
    on_close: Callback<()>,
) -> impl IntoView {
    let app_state = expect_context::<AppState>();
    let is_edit = existing.is_some();

    // Form field signals, pre-filled from existing profile when editing.
    let name = RwSignal::new(
        existing.as_ref().map_or(String::new(), |p| p.name.clone()),
    );
    let hostname = RwSignal::new(
        existing.as_ref().map_or(String::new(), |p| p.hostname.clone()),
    );
    let user = RwSignal::new(
        existing.as_ref().and_then(|p| p.user.clone()).unwrap_or_default(),
    );
    let port = RwSignal::new(
        existing.as_ref().map_or(22u16, |p| p.port),
    );
    let key_file = RwSignal::new(
        existing.as_ref().and_then(|p| p.key_file.clone()).unwrap_or_default(),
    );
    let host_key_checking = RwSignal::new(
        existing.as_ref().map_or(true, |p| p.host_key_checking),
    );
    let is_saving = RwSignal::new(false);

    let is_valid = move || {
        !name.get().trim().is_empty() && !hostname.get().trim().is_empty()
    };

    // Build profile from current field values, save, reload, close.
    let handle_submit = move |_| {
        let profile = RemoteHostProfile {
            name: name.get().trim().to_string(),
            hostname: hostname.get().trim().to_string(),
            user: {
                let u = user.get();
                if u.trim().is_empty() { None } else { Some(u.trim().to_string()) }
            },
            port: port.get(),
            key_file: {
                let k = key_file.get();
                if k.trim().is_empty() { None } else { Some(k.trim().to_string()) }
            },
            host_key_checking: host_key_checking.get(),
        };

        is_saving.set(true);

        leptos::task::spawn_local(async move {
            match invoke_save_remote_host(profile).await {
                Ok(()) => {
                    if let Ok(hosts) = invoke_list_remote_hosts().await {
                        app_state.remote_hosts.set(hosts);
                    }
                    on_close.run(());
                }
                Err(e) => {
                    web_sys::console::error_1(
                        &format!("Failed to save host: {}", e).into(),
                    );
                    app_state
                        .error_message
                        .set(Some(format!("Failed to save host: {}", e)));
                }
            }
            is_saving.set(false);
        });
    };

    view! {
        <div class="host-form">
            <h3>{if is_edit { "Edit Host" } else { "Add Host" }}</h3>

            <div class="form-field">
                <label for="host-name">"Display Name"</label>
                <input
                    id="host-name"
                    type="text"
                    class="input-text"
                    placeholder="e.g. web-01"
                    prop:value=move || name.get()
                    on:input=move |ev| name.set(event_target_value(&ev))
                />
            </div>

            <div class="form-field">
                <label for="host-hostname">"Hostname / IP"</label>
                <input
                    id="host-hostname"
                    type="text"
                    class="input-text"
                    placeholder="e.g. 192.168.1.10"
                    prop:value=move || hostname.get()
                    on:input=move |ev| hostname.set(event_target_value(&ev))
                />
            </div>

            <div class="form-field">
                <label for="host-user">"SSH User (optional)"</label>
                <input
                    id="host-user"
                    type="text"
                    class="input-text"
                    placeholder="root"
                    prop:value=move || user.get()
                    on:input=move |ev| user.set(event_target_value(&ev))
                />
            </div>

            <div class="form-field">
                <label for="host-port">"Port"</label>
                <input
                    id="host-port"
                    type="number"
                    class="input-text"
                    min="1"
                    max="65535"
                    prop:value=move || port.get().to_string()
                    on:input=move |ev| {
                        if let Ok(p) = event_target_value(&ev).parse::<u16>() {
                            port.set(p);
                        }
                    }
                />
            </div>

            <div class="form-field">
                <label for="host-key-file">"Key File (optional)"</label>
                <input
                    id="host-key-file"
                    type="text"
                    class="input-text"
                    placeholder="~/.ssh/id_ed25519"
                    prop:value=move || key_file.get()
                    on:input=move |ev| key_file.set(event_target_value(&ev))
                />
            </div>

            <div class="form-field form-field-checkbox">
                <label>
                    <input
                        type="checkbox"
                        checked=move || host_key_checking.get()
                        on:change=move |_| host_key_checking.update(|v| *v = !*v)
                    />
                    " Verify host key (recommended)"
                </label>
            </div>

            <div class="form-actions">
                <button
                    class="btn btn-primary"
                    on:click=handle_submit
                    disabled=move || is_saving.get() || !is_valid()
                >
                    {move || if is_saving.get() { "Saving..." } else { "Save" }}
                </button>
                <button
                    class="btn btn-secondary"
                    on:click=move |_| on_close.run(())
                    disabled=move || is_saving.get()
                >
                    "Cancel"
                </button>
            </div>
        </div>
    }
}
