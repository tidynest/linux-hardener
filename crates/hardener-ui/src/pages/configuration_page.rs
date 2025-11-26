use crate::state::AppState;
use crate::tauri_bindings::invoke_apply;

use leptos::prelude::*;
use tracing::error;

/// Configuration page for selecting security profiles and enabling/disabling plugins.
///
/// Allows users to choose from preset security profiles (Baseline, Secure, High Security)
/// or manually toggle individual plugins. The "Apply Changes" button triggers the
/// hardening process.
#[component]
pub fn ConfigurationPage() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Local signals for configuration state
    let selected_profile = RwSignal::new("secure".to_string());

    // Individual plugin toggles (8 plugins total)
    let kernel_enabled = RwSignal::new(true);
    let ssh_enabled = RwSignal::new(true);
    let firewall_enabled = RwSignal::new(true);
    let pam_enabled = RwSignal::new(true);
    let services_enabled = RwSignal::new(true);
    let audit_enabled = RwSignal::new(false);
    let permissions_enabled = RwSignal::new(false);
    let mac_enabled = RwSignal::new(false);

    // Update plugin toggles when profile changes
    let update_profile = move |profile: &str| {
        selected_profile.set(profile.to_string());

        match profile {
            "baseline" => {
                kernel_enabled.set(false);
                ssh_enabled.set(true);
                firewall_enabled.set(true);
                pam_enabled.set(false);
                services_enabled.set(false);
                audit_enabled.set(false);
                permissions_enabled.set(false);
                mac_enabled.set(false);
            }
            "secure" => {
                kernel_enabled.set(true);
                ssh_enabled.set(true);
                firewall_enabled.set(true);
                pam_enabled.set(true);
                services_enabled.set(true);
                audit_enabled.set(false);
                permissions_enabled.set(false);
                mac_enabled.set(false);
            }
            "high_security" => {
                kernel_enabled.set(true);
                ssh_enabled.set(true);
                firewall_enabled.set(true);
                pam_enabled.set(true);
                services_enabled.set(true);
                audit_enabled.set(true);
                permissions_enabled.set(true);
                mac_enabled.set(true);
            }
            _ => {}
        }
    };

    // Handle "Apply Changes" button click
    let handle_apply = move |_| {
        app_state.is_applying.set(true);

        // Build list of enabled plugin IDs
        let mut plugin_ids = Vec::new();
        if kernel_enabled.get() {
            plugin_ids.push("kernel-hardening".to_string());
        }
        if ssh_enabled.get() {
            plugin_ids.push("ssh-hardening".to_string());
        }
        if firewall_enabled.get() {
            plugin_ids.push("firewall-hardening".to_string());
        }

        if pam_enabled.get() {
            plugin_ids.push("pam-hardening".to_string());
        }
        if services_enabled.get() {
            plugin_ids.push("service-minimisation".to_string());
        }

        if audit_enabled.get() {
            plugin_ids.push("audit-hardening".to_string());
        }
        if permissions_enabled.get() {
            plugin_ids.push("permissions-hardening".to_string());
        }
        if mac_enabled.get() {
            plugin_ids.push("mac-hardening".to_string());
        }

        // Spawn async task to call backend
        leptos::task::spawn_local(async move {
            match invoke_apply(plugin_ids).await {
                Ok(results) => {
                    app_state.apply_results.set(results);
                }
                Err(e) => {
                    error!("Apply failed: {}", e);
                }
            }
            app_state.is_applying.set(false);
        })
    };

    view! {
        <article class="configuration-page">
            <h1>"Configuration"</h1>

        <section class="profile-selector">
            <h2>"Security Profile"</h2>
                <fieldset>
                    <legend>"Choose a preset configuration"</legend>

                    <label>
                        <input
                            type="radio"
                            name="profile"
                            value="baseline"
                            checked=move || selected_profile.get() == "baseline"
                            on:change=move |_| update_profile("baseline")
                        />
                        <strong>"Baseline"</strong>" - Essential security only (SSH, Firewall)"
                    </label>

                    <label>
                        <input
                            type="radio"
                            name="profile"
                            value="secure"
                            checked=move || selected_profile.get() == "secure"
                            on:change=move |_| update_profile("secure")
                        />
                        <strong>"Secure"</strong>" - Recommended for most systems"
                    </label>

                    <label>
                        <input
                            type="radio"
                            name="profile"
                            value="high_security"
                            checked=move || selected_profile.get() == "high_security"
                            on:change=move |_| update_profile("high_security")
                        />
                        <strong>"High Security"</strong>" - Maximum hardening (all plugins)"
                    </label>
                </fieldset>
            </section>

            <section class="plugin-toggles">
                <h2>"Individual Plugin Control"</h2>
                <fieldset>
                    <legend>"Enable or disable specific plugins"</legend>

                    <label><input type="checkbox" prop:checked=move ||
    kernel_enabled.get() on:change=move |ev|
    kernel_enabled.set(event_target_checked(&ev)) />" Kernel Hardening"</label>
                    <label><input type="checkbox" prop:checked=move ||
    ssh_enabled.get() on:change=move |ev|
    ssh_enabled.set(event_target_checked(&ev)) />" SSH Hardening"</label>
                    <label><input type="checkbox" prop:checked=move ||
    firewall_enabled.get() on:change=move |ev|
    firewall_enabled.set(event_target_checked(&ev)) />" Firewall"</label>
                    <label><input type="checkbox" prop:checked=move ||
    pam_enabled.get() on:change=move |ev|
    pam_enabled.set(event_target_checked(&ev)) />" PAM Authentication"</label>
                    <label><input type="checkbox" prop:checked=move ||
    services_enabled.get() on:change=move |ev|
    services_enabled.set(event_target_checked(&ev)) />" Service Minimisation"</label>
                    <label><input type="checkbox" prop:checked=move ||
    audit_enabled.get() on:change=move |ev|
    audit_enabled.set(event_target_checked(&ev)) />" Audit Rules"</label>
                    <label><input type="checkbox" prop:checked=move ||
    permissions_enabled.get() on:change=move |ev|
    permissions_enabled.set(event_target_checked(&ev)) />" File Permissions"</label>
                    <label><input type="checkbox" prop:checked=move ||
    mac_enabled.get() on:change=move |ev|
    mac_enabled.set(event_target_checked(&ev)) />" MAC System Hardening"</label>
                </fieldset>
            </section>

            <section class="apply-section">
                <Show
                    when=move || !app_state.is_applying.get()
                    fallback=|| view! { <p>"Applying changes..."</p> }
                >
                    <button on:click=handle_apply class="apply-button">"Apply Changes"</button>
                </Show>
                <nav class="apply-navigation">
                    <a href="/results">"View Previous Results"</a>
                    <a href="/checkpoints">"Manage Checkpoints"</a>
                </nav>
            </section>
        </article>
    }
}
