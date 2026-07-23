//! Scheduler configuration page: schedule + notifications, one lifted form,
//! one Save. Owns the `SchedulerForm` bundle, the sole config-sync `Effect`,
//! and the single save handler; the two sections are presentational over the
//! bundle.

use crate::components::{NotificationSection, ScheduleSection};
use crate::state::{AppState, SchedulerForm};
use crate::tauri_bindings;
use crate::utils::{SCHEDULE_PRESETS, effective_schedule_cron, preset_label_for_cron};
use leptos::prelude::*;

#[component]
pub fn SchedulerPage() -> impl IntoView {
    let app_state = expect_context::<AppState>();
    let form = SchedulerForm::new();
    let save_status = RwSignal::new(None::<(bool, String)>);

    // Load config on mount.
    leptos::task::spawn_local(async move {
        match tauri_bindings::invoke_get_scheduler_config().await {
            Ok(config) => app_state.scheduler_config.set(Some(config)),
            Err(e) => {
                web_sys::console::warn_1(&format!("Failed to load scheduler config: {e}").into());
            }
        }
    });

    // The sole sync Effect: populate the whole bundle from the loaded config.
    Effect::new(move || {
        if let Some(config) = app_state.scheduler_config.get() {
            form.enabled.set(config.enabled);
            // An empty stored severity would leave the select unmatched (blank);
            // keep the form's "medium" default in that case.
            if !config.min_severity.is_empty() {
                form.min_severity.set(config.min_severity.clone());
            }
            form.selected_plugins.set(config.plugins.clone());

            // A schedule matching a preset selects it. A non-empty schedule
            // matching no preset is a real custom cron - keep the first preset
            // as the visible fallback, fill the custom field, and auto-open
            // Advanced. An empty schedule (a brand-new config) is not a custom
            // schedule: fall back to the first preset with Advanced closed.
            match preset_label_for_cron(&config.schedule) {
                Some(label) => {
                    form.selected_preset.set(label.to_string());
                    form.custom_cron.set(String::new());
                    form.advanced_open.set(false);
                }
                None => {
                    let has_custom = !config.schedule.is_empty();
                    form.selected_preset.set(SCHEDULE_PRESETS[0].0.to_string());
                    form.custom_cron.set(if has_custom {
                        config.schedule.clone()
                    } else {
                        String::new()
                    });
                    form.advanced_open.set(has_custom);
                }
            }

            let notif = config.notifications;
            form.email_enabled.set(notif.email.enabled);
            form.email_recipients.set(notif.email.recipients.join(", "));
            form.email_from.set(notif.email.from_address);
            form.webhook_enabled.set(notif.webhooks.enabled);
            form.webhook_url.set(notif.webhooks.url);
            form.webhook_format.set(notif.webhooks.format);
        }
    });

    // Single Save: snapshot the whole bundle, merge into the config, save once.
    let handle_save = move |_| {
        let cron = effective_schedule_cron(
            &form.selected_preset.get_untracked(),
            &form.custom_cron.get_untracked(),
        );
        let plugins = form.selected_plugins.get_untracked();
        let severity = form.min_severity.get_untracked();
        let is_enabled = form.enabled.get_untracked();
        let recipients: Vec<String> = form
            .email_recipients
            .get_untracked()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let is_email = form.email_enabled.get_untracked();
        let from = form.email_from.get_untracked();
        let is_webhook = form.webhook_enabled.get_untracked();
        let url = form.webhook_url.get_untracked();
        let webhook_format = form.webhook_format.get_untracked();
        let mut config = app_state
            .scheduler_config
            .get_untracked()
            .unwrap_or_default();

        app_state.is_saving_scheduler.set(true);
        save_status.set(None);

        leptos::task::spawn_local(async move {
            config.enabled = is_enabled;
            config.schedule = cron;
            config.plugins = plugins;
            config.min_severity = severity;
            config.notifications.email.enabled = is_email;
            config.notifications.email.recipients = recipients;
            config.notifications.email.from_address = from;
            config.notifications.webhooks.enabled = is_webhook;
            config.notifications.webhooks.url = url;
            config.notifications.webhooks.format = webhook_format;

            match tauri_bindings::invoke_save_scheduler_config(config.clone()).await {
                Ok(path) => {
                    app_state.scheduler_config.set(Some(config));
                    save_status.set(Some((true, format!("Saved to {path}"))));
                }
                Err(e) => save_status.set(Some((false, format!("Failed to save: {e}")))),
            }
            app_state.is_saving_scheduler.set(false);
        });
    };

    view! {
        <div class="scheduler-page">
            <div class="scheduler-header">
                <h1 class="scheduler-title">"Scheduler"</h1>
                <p class="scheduler-subtitle">
                    "Run scans automatically and send the results where you need them."
                </p>
            </div>

            <section class="scheduler-block">
                <h2 class="scheduler-block-title">"Schedule"</h2>
                <ScheduleSection form=form />
            </section>

            <section class="scheduler-block">
                <h2 class="scheduler-block-title">"Notifications"</h2>
                <NotificationSection form=form />
            </section>

            <div class="scheduler-save-bar">
                // Always-present live region so the save result is announced
                // when it appears (a region that only mounts with its content
                // is not reliably read by screen readers).
                <div class="scheduler-save-region" role="status" aria-live="polite">
                    {move || {
                        save_status
                            .get()
                            .map(|(ok, msg)| {
                                let class = if ok {
                                    "scheduler-save-status is-ok"
                                } else {
                                    "scheduler-save-status is-fail"
                                };
                                view! { <span class=class>{msg}</span> }
                            })
                    }}
                </div>
                <button
                    class="btn btn-primary"
                    on:click=handle_save
                    disabled=move || app_state.is_saving_scheduler.get()
                >
                    {move || {
                        if app_state.is_saving_scheduler.get() { "Saving..." } else { "Save" }
                    }}
                </button>
            </div>
        </div>
    }
}
