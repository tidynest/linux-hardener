//! Schedule configuration section (presentational): reads/writes the shared
//! `SchedulerForm`; the page owns the config sync and the single Save. The
//! custom cron lives behind an Advanced disclosure and overrides the preset
//! when non-empty (see `utils::effective_schedule_cron`).

use crate::components::configure_section::plugin_display_name;
use crate::components::form_helpers;
use crate::state::SchedulerForm;
use crate::utils::SCHEDULE_PRESETS;
use leptos::prelude::*;

/// All available plugin ids for the checkbox group.
///
/// These are the ids the plugins actually declare, which is what the scheduler
/// stores and now checks its selection against. They were short names here
/// (`kernel`, `ssh`) that no plugin answers to; nothing rejected them, because
/// `is_plugin_enabled` returns true for an unknown id, so a schedule saved from
/// this screen recorded plugins that do not exist.
///
/// These are values, not labels: the checkbox text comes from
/// [`plugin_display_name`], so this screen and Hardening name the same eight
/// areas the same way. `tests::every_plugin_id_resolves_to_a_display_name` is
/// what fails if the two tables drift apart.
const PLUGIN_IDS: &[&str] = &[
    "kernel-hardening",
    "ssh-hardening",
    "firewall-hardening",
    "pam-hardening",
    "service-minimisation",
    "audit-hardening",
    "permissions-hardening",
    "mac-hardening",
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

            // Everything below is fully interactive while scanning is off, with
            // nothing to say so. The note deliberately states what the toggle
            // does NOT: that the settings survive being saved in this state, so
            // an operator configuring a paused schedule knows the work is kept.
            //
            // Two tidier-looking fixes were rejected. `disabled` on these
            // controls is the honest semantics and is exempt from the contrast
            // rules, but it makes adjusting a paused schedule mean enabling it
            // first, and leaving scanning switched on by accident is a worse
            // outcome than an untidy form. Dimming them lowers the real
            // contrast of text that is still editable, which trades one
            // accessibility problem for another.
            <Show when=move || !form.enabled.get()>
                <p class="scheduler-override-note">
                    "These settings are saved, but not used while scanning is off."
                </p>
            </Show>

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
                // Surfaced regardless of whether Advanced is open: a non-empty
                // custom cron always overrides the preset above (see
                // `utils::effective_schedule_cron`), so collapsing Advanced
                // must never hide that the preset select is a no-op.
                <Show when=move || !form.custom_cron.get().is_empty()>
                    <span class="scheduler-override-note">"Custom schedule active"</span>
                </Show>
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
                                    // The id is the VALUE, never the label. It
                                    // was both, so this screen read
                                    // `service-minimisation` where Hardening
                                    // reads "Service Minimisation" for the same
                                    // checkbox. Shared table, one set of names.
                                    {plugin_display_name(&id_owned)}
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
                    </div>
                </Show>
            </div>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two tables are keyed differently on purpose: `PLUGIN_IDS` holds full
    /// registry ids and `PLUGINS` holds short prefixes, joined by `starts_with`.
    /// A rename on either side leaves the join silently returning the fallback,
    /// which renders as "Unknown area" on a live checkbox and is exactly what a
    /// green suite would otherwise let through.
    #[test]
    fn every_plugin_id_resolves_to_a_display_name() {
        // Top level, and not merely a guard against the loop running zero
        // times: eight is what the registry declares, so a short list is a
        // hardening area an operator can no longer schedule at all.
        assert_eq!(PLUGIN_IDS.len(), 8, "the registry declares eight areas");
        for id in PLUGIN_IDS {
            assert_ne!(
                plugin_display_name(id),
                "Unknown area",
                "{id} has no entry in configure_section::PLUGINS"
            );
        }
    }

    /// Two ids collapsing onto one name would give the group two identical
    /// checkboxes, which reads as a duplicate rather than as a broken join, so
    /// the check above cannot see it.
    #[test]
    fn display_names_are_distinct() {
        let mut names: Vec<&str> = PLUGIN_IDS
            .iter()
            .map(|id| plugin_display_name(id))
            .collect();
        names.sort_unstable();
        let total = names.len();
        names.dedup();
        assert_eq!(total, names.len(), "two plugin ids share a display name");
    }
}
