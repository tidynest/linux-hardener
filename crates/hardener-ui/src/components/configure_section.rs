//! Configure section for the Hardening page.
//!
//! Contains profile selection, plugin toggles, and apply controls.

use crate::state::AppState;
use crate::tauri_bindings::invoke_apply;
use leptos::prelude::*;

/// Plugin definition with ID and display name.
struct PluginDef {
    id: &'static str,
    name: &'static str,
}

const PLUGINS: &[PluginDef] = &[
    PluginDef {
        id: "kernel",
        name: "Kernel Hardening",
    },
    PluginDef {
        id: "ssh",
        name: "SSH Hardening",
    },
    PluginDef {
        id: "firewall",
        name: "Firewall",
    },
    PluginDef {
        id: "pam",
        name: "PAM Authentication",
    },
    PluginDef {
        id: "services",
        name: "Service Minimisation",
    },
    PluginDef {
        id: "audit",
        name: "Audit Rules",
    },
    PluginDef {
        id: "permissions",
        name: "File Permissions",
    },
    PluginDef {
        id: "mac",
        name: "MAC System",
    },
];

/// Configure section with profiles and plugin toggles.
#[component]
pub fn ConfigureSection() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Profile presets
    let selected_profile = RwSignal::new("secure".to_string());

    // Individual plugin states
    let plugin_states: Vec<(String, RwSignal<bool>)> = PLUGINS
        .iter()
        .map(|p| {
            let enabled = matches!(p.id, "kernel" | "ssh" | "firewall" | "pam" | "services");
            (p.id.to_string(), RwSignal::new(enabled))
        })
        .collect();

    // Update plugins based on profile selection
    let update_profile = {
        let plugin_states = plugin_states.clone();
        std::sync::Arc::new(move |profile: &str| {
            selected_profile.set(profile.to_string());

            let enabled_plugins: Vec<&str> = match profile {
                "baseline" => vec!["ssh", "firewall"],
                "secure" => vec!["kernel", "ssh", "firewall", "pam", "services"],
                "high" => PLUGINS.iter().map(|p| p.id).collect(),
                _ => vec![],
            };

            for (id, signal) in &plugin_states {
                signal.set(enabled_plugins.contains(&id.as_str()));
            }
        })
    };

    // Get enabled plugin IDs for apply
    let get_enabled_plugins = {
        let plugin_states = plugin_states.clone();
        move || {
            plugin_states
                .iter()
                .filter(|(_, signal)| signal.get())
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>()
        }
    };

    // Apply handler
    let on_apply = move |_| {
        let plugins = get_enabled_plugins();
        if plugins.is_empty() {
            return;
        }

        app_state.is_applying.set(true);

        leptos::task::spawn_local(async move {
            match invoke_apply(plugins).await {
                Ok(results) => {
                    app_state.apply_results.update(|r| r.extend(results));
                }
                Err(e) => {
                    web_sys::console::error_1(&format!("Apply failed: {}", e).into());
                }
            }
            app_state.is_applying.set(false);
        });
    };

    view! {
        <div class="configure-section">
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
                            on:change={
                                let update = update_profile.clone();
                                move |_| update("baseline")
                            }
                        />
                        "Baseline (SSH + Firewall only)"
                    </label>

                    <label>
                        <input
                            type="radio"
                            name="profile"
                            value="secure"
                            checked=move || selected_profile.get() == "secure"
                            on:change={
                                let update = update_profile.clone();
                                move |_| update("secure")
                            }
                        />
                        "Secure (Recommended - 5 plugins)"
                    </label>

                    <label>
                        <input
                            type="radio"
                            name="profile"
                            value="high"
                            checked=move || selected_profile.get() == "high"
                            on:change={
                                let update = update_profile.clone();
                                move |_| update("high")
                            }
                        />
                        "High Security (All 8 plugins)"
                    </label>
                </fieldset>
            </section>

            <section class="plugin-toggles">
                <h2>"Plugin Control"</h2>
                <div class="plugin-grid">
                    {plugin_states.iter().enumerate().map(|(i, (_, signal))| {
                        let plugin = &PLUGINS[i];
                        let name = plugin.name;
                        let signal = *signal;

                        view! {
                            <label class="framework-checkbox">
                                <input
                                    type="checkbox"
                                    checked=move || signal.get()
                                    on:change=move |_| {
                                        signal.update(|v| *v = !*v);
                                        selected_profile.set("custom".to_string());
                                    }
                                />
                                {name}
                            </label>
                        }
                    }).collect::<Vec<_>>()}
                </div>
            </section>

            <section class="apply-controls">
                <button
                    class="btn btn-primary btn-large apply-button"
                    on:click=on_apply
                    disabled=move || app_state.is_applying.get()
                >
                    {move || if app_state.is_applying.get() {
                        "Applying..."
                    } else {
                        "Apply Hardening"
                    }}
                </button>
            </section>
        </div>
    }
}
