//! Schedule configuration section — enable/disable, cron schedule, plugins, severity.

use crate::state::AppState;
use crate::tauri_bindings;
use leptos::prelude::*;

/// Cron presets with display labels and 6-field cron expressions.
const SCHEDULE_PRESETS: &[(&str, &str)] = &[
    ("Daily at 2:00 AM", "0 0 2 * * *"),
    ("Every 6 hours", "0 0 */6 * * *"),
    ("Every 12 hours", "0 0 */12 * * *"),
    ("Weekly on Monday", "0 0 2 * * Mon"),
];

/// All available plugin IDs for the checkbox group.
const PLUGIN_IDS: &[&str] = &[
    "kernel", "ssh", "firewall", "pam", "services", "audit", "permissions", "mac",
];

/// Schedule configuration form.
///
/// Provides an enabled toggle, preset/custom cron schedule selector, plugin
/// checkboxes, and a minimum severity dropdown. An `Effect` syncs local form
/// signals from the global `scheduler_config` whenever it loads or changes.
/// The save handler merges schedule fields back into the existing config,
/// preserving the notification section untouched.
#[component]
pub fn ScheduleSection() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Local form state — populated from loaded config via Effect
    let enabled = RwSignal::new(false);
    let selected_preset = RwSignal::new(String::new());
    let custom_cron = RwSignal::new(String::new());
    let selected_plugins = RwSignal::new(Vec::<String>::new());
    let min_severity = RwSignal::new("medium".to_string());
    let save_status = RwSignal::new(None::<(bool, String)>);

    // Sync local state when config loads
    Effect::new(move || {
        if let Some(config) = app_state.scheduler_config.get() {
            enabled.set(config.enabled);
            min_severity.set(config.min_severity.clone());
            selected_plugins.set(config.plugins.clone());

            // Match schedule to a preset or set custom
            let preset_match = SCHEDULE_PRESETS
                .iter()
                .find(|(_, cron)| *cron == config.schedule);
            if let Some((label, _)) = preset_match {
                selected_preset.set(label.to_string());
            } else {
                selected_preset.set("Custom".to_string());
                custom_cron.set(config.schedule.clone());
            }
        }
    });

    // Derive the effective cron expression from preset or custom
    let effective_cron = move || {
        let preset = selected_preset.get();
        if preset == "Custom" {
            return custom_cron.get();
        }
        SCHEDULE_PRESETS
            .iter()
            .find(|(label, _)| *label == preset.as_str())
            .map(|(_, cron)| cron.to_string())
            .unwrap_or_default()
    };

    // Save handler — merges schedule fields into existing config, preserving notifications
    let handle_save = move |_| {
        let cron = effective_cron();
        let plugins = selected_plugins.get_untracked();
        let severity = min_severity.get_untracked();
        let is_enabled = enabled.get_untracked();
        let base_config = app_state.scheduler_config.get_untracked().unwrap_or_default();

        app_state.is_saving_scheduler.set(true);
        save_status.set(None);

        leptos::task::spawn_local(async move {
            let mut config = base_config;
            config.enabled = is_enabled;
            config.schedule = cron;
            config.plugins = plugins;
            config.min_severity = severity;

            match tauri_bindings::invoke_save_scheduler_config(config.clone()).await {
                Ok(path) => {
                    app_state.scheduler_config.set(Some(config));
                    save_status.set(Some((true, format!("Schedule saved to {path}"))));
                }
                Err(e) => {
                    save_status.set(Some((false, format!("Failed to save: {e}"))));
                }
            }
            app_state.is_saving_scheduler.set(false);
        });
    };

    // Toggle plugin in selection
    let toggle_plugin = move |plugin_id: String| {
        selected_plugins.update(|plugins| {
            if let Some(pos) = plugins.iter().position(|p| p == &plugin_id) {
                plugins.remove(pos);
            } else {
                plugins.push(plugin_id);
            }
        });
    };

    view! {
        <div class="schedule-section">
            // Enabled toggle
            <div class="form-row">
                <label class="toggle-label">
                    <input
                        type="checkbox"
                        class="toggle-input"
                        prop:checked=move || enabled.get()
                        on:change=move |event| {
                            use leptos::wasm_bindgen::JsCast;
                            let checked = event
                                .target()
                                .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
                                .map(|el| el.checked())
                                .unwrap_or(false);
                            enabled.set(checked);
                        }
                    />
                    "Enable scheduled scanning"
                </label>
            </div>

            // Schedule preset dropdown
            <div class="form-row">
                <label class="form-label">"Schedule"</label>
                <select
                    class="form-select"
                    prop:value=move || selected_preset.get()
                    on:change=move |event| {
                        use leptos::wasm_bindgen::JsCast;
                        let value = event
                            .target()
                            .and_then(|t| t.dyn_into::<web_sys::HtmlSelectElement>().ok())
                            .map(|el| el.value())
                            .unwrap_or_default();
                        selected_preset.set(value);
                    }
                >
                    {SCHEDULE_PRESETS
                        .iter()
                        .map(|(label, _)| {
                            view! { <option value=*label>{*label}</option> }
                        })
                        .collect::<Vec<_>>()}
                    <option value="Custom">"Custom"</option>
                </select>
                <span class="form-hint">
                    {move || {
                        let cron = effective_cron();
                        if cron.is_empty() {
                            String::new()
                        } else {
                            format!("Cron: {cron}")
                        }
                    }}
                </span>
            </div>

            // Custom cron input (visible only when Custom is selected)
            <Show when=move || selected_preset.get() == "Custom">
                <div class="form-row">
                    <label class="form-label">"Cron expression"</label>
                    <input
                        type="text"
                        class="form-input"
                        placeholder="0 0 2 * * *"
                        prop:value=move || custom_cron.get()
                        on:input=move |event| {
                            use leptos::wasm_bindgen::JsCast;
                            let value = event
                                .target()
                                .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
                                .map(|el| el.value())
                                .unwrap_or_default();
                            custom_cron.set(value);
                        }
                    />
                    <span class="form-hint">"Format: sec min hour day month weekday"</span>
                </div>
            </Show>

            // Plugin selection checkboxes
            <div class="form-row">
                <label class="form-label">"Plugins"</label>
                <span class="form-hint">"Leave all unchecked to scan every plugin"</span>
                <div class="plugin-checkboxes">
                    {PLUGIN_IDS
                        .iter()
                        .map(|id| {
                            let id_owned = id.to_string();
                            let id_for_check = id_owned.clone();
                            let id_for_toggle = id_owned.clone();
                            view! {
                                <label class="checkbox-label">
                                    <input
                                        type="checkbox"
                                        prop:checked=move || {
                                            selected_plugins.get().contains(&id_for_check)
                                        }
                                        on:change=move |_| toggle_plugin(id_for_toggle.clone())
                                    />
                                    {id_owned}
                                </label>
                            }
                        })
                        .collect::<Vec<_>>()}
                </div>
            </div>

            // Minimum severity dropdown
            <div class="form-row">
                <label class="form-label">"Minimum severity"</label>
                <select
                    class="form-select"
                    prop:value=move || min_severity.get()
                    on:change=move |event| {
                        use leptos::wasm_bindgen::JsCast;
                        let value = event
                            .target()
                            .and_then(|t| t.dyn_into::<web_sys::HtmlSelectElement>().ok())
                            .map(|el| el.value())
                            .unwrap_or_default();
                        min_severity.set(value);
                    }
                >
                    <option value="critical">"Critical"</option>
                    <option value="high">"High"</option>
                    <option value="medium">"Medium"</option>
                    <option value="low">"Low"</option>
                    <option value="info">"Info"</option>
                </select>
            </div>

            // Save status
            <Show when=move || save_status.get().is_some()>
                {move || {
                    save_status.get().map(|(ok, msg)| {
                        let class = if ok {
                            "test-result test-result--success"
                        } else {
                            "test-result test-result--failure"
                        };
                        view! { <div class=class>{msg}</div> }
                    })
                }}
            </Show>

            // Save button
            <div class="form-actions">
                <button
                    class="btn btn-primary"
                    on:click=handle_save
                    disabled=move || app_state.is_saving_scheduler.get()
                >
                    {move || {
                        if app_state.is_saving_scheduler.get() {
                            "Saving..."
                        } else {
                            "Save Schedule"
                        }
                    }}
                </button>
            </div>
        </div>
    }
}
