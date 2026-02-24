//! Configure section for the Hardening page.
//!
//! Contains profile selection, plugin toggles, and apply controls.

use crate::components::{Card, ConfigFileCard, HeadingLevel};
use crate::state::AppState;
use crate::tauri_bindings::{invoke_apply, invoke_apply_dry_run};
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

    // Individual plugin states - stored for access across closures
    let plugin_states: Vec<(String, RwSignal<bool>)> = PLUGINS
        .iter()
        .map(|p| {
            let enabled = matches!(p.id, "kernel" | "ssh" | "firewall" | "pam" | "services");
            (p.id.to_string(), RwSignal::new(enabled))
        })
        .collect();
    let plugin_states = StoredValue::new(plugin_states);

    // Update plugins based on profile selection
    let update_profile = std::sync::Arc::new(move |profile: &str| {
        selected_profile.set(profile.to_string());

        let enabled_plugins: Vec<&str> = match profile {
            "baseline" => vec!["ssh", "firewall"],
            "secure" => vec!["kernel", "ssh", "firewall", "pam", "services"],
            "high" => PLUGINS.iter().map(|p| p.id).collect(),
            _ => vec![],
        };

        plugin_states.with_value(|states| {
            for (id, signal) in states {
                signal.set(enabled_plugins.contains(&id.as_str()));
            }
        });
    });

    // Get enabled plugin IDs for apply
    let get_enabled_plugins = move || {
        plugin_states.with_value(|states| {
            states
                .iter()
                .filter(|(_, signal)| signal.get())
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>()
        })
    };

    // Preview handler - runs dry-run and shows preview panel
    let on_preview = move |_| {
        let plugins = get_enabled_plugins();
        if plugins.is_empty() {
            return;
        }

        app_state.is_previewing.set(true);
        app_state.show_preview.set(false);

        leptos::task::spawn_local(async move {
            match invoke_apply_dry_run(plugins).await {
                Ok(results) => {
                    app_state.preview_results.set(results);
                    app_state.show_preview.set(true);
                }
                Err(e) => {
                    web_sys::console::error_1(&format!("Preview failed: {}", e).into());
                    app_state
                        .error_message
                        .set(Some(format!("Preview failed: {}", e)));
                }
            }
            app_state.is_previewing.set(false);
        });
    };

    // Cancel preview - hides preview panel
    let on_cancel_preview = move |_| {
        app_state.show_preview.set(false);
        app_state.preview_results.set(Vec::new());
    };

    // Confirm and apply - runs actual apply after preview
    let on_confirm_apply = move |_| {
        let plugins = get_enabled_plugins();
        if plugins.is_empty() {
            return;
        }

        app_state.is_applying.set(true);
        app_state.show_preview.set(false);

        leptos::task::spawn_local(async move {
            match invoke_apply(plugins).await {
                Ok(results) => {
                    app_state.apply_results.update(|r| r.extend(results));
                    app_state.preview_results.set(Vec::new());
                }
                Err(e) => {
                    web_sys::console::error_1(&format!("Apply failed: {}", e).into());
                    app_state
                        .error_message
                        .set(Some(format!("Apply failed: {}", e)));
                }
            }
            app_state.is_applying.set(false);
        });
    };

    view! {
        <div class="configure-section">
            <p class="section-guidance">
                "Select a security profile below, or toggle individual plugins. "
                "Higher security profiles may affect system usability. "
                "A checkpoint is created before changes are applied, allowing rollback if needed."
            </p>
            <ConfigFileCard />
            <Card title="Security Profile" title_level=HeadingLevel::H2 class="profile-selector">
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
            </Card>

            <Card title="Plugin Control" title_level=HeadingLevel::H2 class="plugin-toggles">
                <div class="plugin-grid">
                    {plugin_states.with_value(|states| {
                        states.iter().enumerate().map(|(i, (_, signal))| {
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
                        }).collect::<Vec<_>>()
                    })}
                </div>
            </Card>

            <Card class="apply-controls">
                <button
                    class="btn btn-primary btn-large"
                    on:click=on_preview
                    disabled=move || app_state.is_previewing.get() || app_state.is_applying.get()
                >
                    {move || if app_state.is_previewing.get() {
                        "Generating Preview..."
                    } else {
                        "Preview Changes"
                    }}
                </button>
            </Card>

            // Preview panel - shown after dry-run completes
            <Show when=move || app_state.show_preview.get()>
                <Card title="Preview Changes" title_level=HeadingLevel::H2 class="preview-panel">
                    <p class="preview-warning">
                        "Review the changes below before applying. A checkpoint will be created for rollback."
                    </p>

                    <div class="preview-changes">
                        {move || {
                            let results = app_state.preview_results.get();
                            if results.is_empty() {
                                view! { <p class="empty-state">"No changes to preview."</p> }.into_any()
                            } else {
                                results.iter().map(|report| {
                                    let plugin_id = report.validation_report_plugin_id.as_str().to_string();
                                    let changes = report.validation_report_estimated_changes.clone();
                                    let change_count = changes.len();

                                    view! {
                                        <div class="preview-plugin">
                                            <h4 class="preview-plugin-name">
                                                {plugin_id}
                                                <span class="preview-change-count">
                                                    {format!("({} change{})", change_count, if change_count == 1 { "" } else { "s" })}
                                                </span>
                                            </h4>
                                            <ul class="preview-change-list">
                                                {changes.iter().map(|change| {
                                                    view! { <li>{change.clone()}</li> }
                                                }).collect::<Vec<_>>()}
                                            </ul>
                                        </div>
                                    }
                                }).collect::<Vec<_>>().into_any()
                            }
                        }}
                    </div>

                    <div class="preview-actions">
                        <button
                            class="btn btn-secondary"
                            on:click=on_cancel_preview
                        >
                            "Cancel"
                        </button>
                        <button
                            class="btn btn-primary"
                            on:click=on_confirm_apply
                            disabled=move || app_state.is_applying.get()
                        >
                            {move || if app_state.is_applying.get() {
                                "Applying..."
                            } else {
                                "Confirm & Apply"
                            }}
                        </button>
                    </div>
                </Card>
            </Show>
        </div>
    }
}
