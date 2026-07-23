//! Schedule configuration section (presentational): reads/writes the shared
//! `SchedulerForm`; the page owns the config sync and the single Save. The
//! custom cron lives behind an Advanced disclosure and overrides the preset
//! when non-empty (see `utils::effective_schedule_cron`).

use crate::components::form_helpers;
use crate::state::SchedulerForm;
use crate::utils::SCHEDULE_PRESETS;
use leptos::prelude::*;

/// All available plugin ids for the checkbox group.
const PLUGIN_IDS: &[&str] = &[
    "kernel",
    "ssh",
    "firewall",
    "pam",
    "services",
    "audit",
    "permissions",
    "mac",
];

#[component]
pub fn ScheduleSection(form: SchedulerForm) -> impl IntoView {
    let toggle_plugin = move |plugin_id: String| {
        form.selected_plugins.update(|plugins| {
            if let Some(pos) = plugins.iter().position(|p| p == &plugin_id) {
                plugins.remove(pos);
            } else {
                plugins.push(plugin_id);
            }
        });
    };

    view! {
        <div class="schedule-section">
            <label class="toggle-switch">
                <input
                    type="checkbox"
                    class="toggle-switch-input"
                    prop:checked=move || form.enabled.get()
                    on:change=move |ev| form.enabled.set(form_helpers::checkbox_checked(&ev))
                />
                <span class="toggle-switch-track" aria-hidden="true"></span>
                <span class="toggle-switch-label">"Enable scheduled scanning"</span>
            </label>

            <div class="form-row">
                <label class="form-label">"Schedule"</label>
                <select
                    class="form-select"
                    prop:value=move || form.selected_preset.get()
                    on:change=move |ev| form.selected_preset.set(form_helpers::select_value(&ev))
                >
                    {SCHEDULE_PRESETS
                        .iter()
                        .map(|(label, _)| view! { <option value=*label>{*label}</option> })
                        .collect::<Vec<_>>()}
                </select>
            </div>

            <div class="form-row">
                <label class="form-label">"Plugins"</label>
                <span class="form-hint">"Leave all unchecked to scan every plugin"</span>
                <div class="plugin-checkboxes" role="group" aria-label="Scan plugins">
                    {PLUGIN_IDS
                        .iter()
                        .map(|id| {
                            let id_owned = id.to_string();
                            let id_check = id_owned.clone();
                            let id_toggle = id_owned.clone();
                            view! {
                                <label class="checkbox-label">
                                    <input
                                        type="checkbox"
                                        prop:checked=move || {
                                            form.selected_plugins.get().contains(&id_check)
                                        }
                                        on:change=move |_| toggle_plugin(id_toggle.clone())
                                    />
                                    {id_owned}
                                </label>
                            }
                        })
                        .collect::<Vec<_>>()}
                </div>
            </div>

            <div class="form-row">
                <label class="form-label">"Minimum severity"</label>
                <select
                    class="form-select"
                    prop:value=move || form.min_severity.get()
                    on:change=move |ev| form.min_severity.set(form_helpers::select_value(&ev))
                >
                    <option value="critical">"Critical"</option>
                    <option value="high">"High"</option>
                    <option value="medium">"Medium"</option>
                    <option value="low">"Low"</option>
                    <option value="info">"Info"</option>
                </select>
            </div>

            <div class="scheduler-advanced">
                <button
                    type="button"
                    class="scheduler-advanced-summary"
                    aria-expanded=move || form.advanced_open.get().to_string()
                    on:click=move |_| form.advanced_open.update(|o| *o = !*o)
                >
                    <span
                        class="scheduler-advanced-chev"
                        class:open=move || form.advanced_open.get()
                        aria-hidden="true"
                    ></span>
                    "Advanced: Custom Schedule"
                </button>
                <Show when=move || form.advanced_open.get()>
                    <div class="form-row">
                        <input
                            type="text"
                            class="form-input"
                            placeholder="0 0 2 * * *"
                            prop:value=move || form.custom_cron.get()
                            on:input=move |ev| form.custom_cron.set(form_helpers::input_value(&ev))
                        />
                        <span class="form-hint">
                            "Format: sec min hour day month weekday. A custom cron overrides the preset above."
                        </span>
                        <Show when=move || !form.custom_cron.get().is_empty()>
                            <span class="scheduler-override-note">"Custom schedule active"</span>
                        </Show>
                    </div>
                </Show>
            </div>
        </div>
    }
}
