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

    // The sole sync Effect: populate the whole bundle from the loaded config,
    // ONCE, and record that it has happened so the form below can wait for it.
    //
    // The waiting is the fix, and it took a wrong answer first. The load above
    // resolves 150 ms or more after mount, so a form rendered immediately is
    // interactive before it has its data, and the hydration then lands on top
    // of whatever the operator has already done: switch scheduled scanning on
    // in that window and it silently switches itself back off. `T-SCHED-07`
    // caught exactly that on opensuse on 2026-08-21, and it read as a fault of
    // that distribution only because the window is a coin flip, five others
    // having won it. Refusing to hydrate TWICE does not help, because the
    // damage is done by the first and only hydration; a form that cannot be
    // edited before its data exists is what actually closes it.
    //
    // The once-guard is kept for the second writer rather than the first.
    // Save also sets `scheduler_config`, from a value built out of this very
    // form, so re-hydrating from it was always a no-op - but it is a no-op
    // only for as long as nothing is edited between the save being sent and
    // its result landing, which is the same race one layer along.
    let hydrated = RwSignal::new(false);
    Effect::new(move || {
        if let Some(config) = app_state.scheduler_config.get()
            && !hydrated.get_untracked()
        {
            hydrated.set(true);
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

            // Nothing editable exists until the config has landed. The header
            // above stays, so the page is never blank and the route still
            // identifies itself; what waits is only what the load owns.
            //
            // The hint reuses `.empty-state-hint` rather than introducing a
            // colour: that pairing is already weighed by the contrast suite,
            // and a new class here would be a fresh unmeasured one.
            <Show
                when=move || hydrated.get()
                fallback=|| {
                    view! {
                        <p class="empty-state-hint" role="status" aria-live="polite">
                            "Loading configuration..."
                        </p>
                    }
                }
            >
                <section class="scheduler-block">
                    <h2 class="scheduler-block-title">"Schedule"</h2>
                    <ScheduleSection form=form />
                </section>

                <section class="scheduler-block">
                    <h2 class="scheduler-block-title">"Notifications"</h2>
                    <NotificationSection form=form />
                </section>
            </Show>

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
                // Disabled rather than hidden before the load lands, so the
                // save bar keeps its shape and its live region. Saving in that
                // window would write the form's empty defaults over the real
                // config, which is the same race as the one above and costs
                // more: it reaches the file rather than the screen.
                <button
                    class="btn btn-primary"
                    on:click=handle_save
                    disabled=move || app_state.is_saving_scheduler.get() || !hydrated.get()
                >
                    {move || {
                        if app_state.is_saving_scheduler.get() { "Saving..." } else { "Save" }
                    }}
                </button>
            </div>
        </div>
    }
}
