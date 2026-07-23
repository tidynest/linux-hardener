//! Notification configuration section (presentational): email + webhook
//! toggle-reveal fields over the shared `SchedulerForm`, plus the contextual
//! Test Notification action. The page owns the config sync and the single Save;
//! only the test handler lives here.

use crate::components::form_helpers;
use crate::state::{AppState, SchedulerForm};
use crate::tauri_bindings;
use leptos::prelude::*;

#[component]
pub fn NotificationSection(form: SchedulerForm) -> impl IntoView {
    let app_state = expect_context::<AppState>();
    let test_result = RwSignal::new(None::<(bool, String)>);

    let handle_test = move |_| {
        app_state.is_testing_notification.set(true);
        test_result.set(None);
        leptos::task::spawn_local(async move {
            match tauri_bindings::invoke_test_notification().await {
                Ok(result) => test_result.set(Some((result.success, result.message))),
                Err(e) => test_result.set(Some((false, format!("Request failed: {e}")))),
            }
            app_state.is_testing_notification.set(false);
        });
    };

    view! {
        <div class="notification-section">
            <h3 class="subsection-title">"Email"</h3>
            <label class="toggle-switch">
                <input
                    type="checkbox"
                    class="toggle-switch-input"
                    prop:checked=move || form.email_enabled.get()
                    on:change=move |ev| form.email_enabled.set(form_helpers::checkbox_checked(&ev))
                />
                <span class="toggle-switch-track" aria-hidden="true"></span>
                <span class="toggle-switch-label">"Enable email notifications"</span>
            </label>
            <Show when=move || form.email_enabled.get()>
                <div class="form-row">
                    <label class="form-label">"Recipients"</label>
                    <input
                        type="text"
                        class="form-input"
                        placeholder="admin@example.com, ops@example.com"
                        prop:value=move || form.email_recipients.get()
                        on:input=move |ev| form.email_recipients.set(form_helpers::input_value(&ev))
                    />
                    <span class="form-hint">"Comma-separated email addresses"</span>
                </div>
                <div class="form-row">
                    <label class="form-label">"From address"</label>
                    <input
                        type="text"
                        class="form-input"
                        placeholder="hardener@example.com"
                        prop:value=move || form.email_from.get()
                        on:input=move |ev| form.email_from.set(form_helpers::input_value(&ev))
                    />
                </div>
            </Show>

            <h3 class="subsection-title">"Webhook"</h3>
            <label class="toggle-switch">
                <input
                    type="checkbox"
                    class="toggle-switch-input"
                    prop:checked=move || form.webhook_enabled.get()
                    on:change=move |ev| form.webhook_enabled.set(form_helpers::checkbox_checked(&ev))
                />
                <span class="toggle-switch-track" aria-hidden="true"></span>
                <span class="toggle-switch-label">"Enable webhook notifications"</span>
            </label>
            <Show when=move || form.webhook_enabled.get()>
                <div class="form-row">
                    <label class="form-label">"Endpoint URL"</label>
                    <input
                        type="url"
                        class="form-input"
                        placeholder="https://hooks.slack.com/services/..."
                        prop:value=move || form.webhook_url.get()
                        on:input=move |ev| form.webhook_url.set(form_helpers::input_value(&ev))
                    />
                </div>
                <div class="form-row">
                    <label class="form-label">"Format"</label>
                    <select
                        class="form-select"
                        prop:value=move || form.webhook_format.get()
                        on:change=move |ev| form.webhook_format.set(form_helpers::select_value(&ev))
                    >
                        <option value="generic">"Generic JSON"</option>
                        <option value="slack">"Slack"</option>
                        <option value="discord">"Discord"</option>
                    </select>
                </div>
            </Show>

            <div class="notification-actions">
                <button
                    class="btn btn-secondary"
                    on:click=handle_test
                    disabled=move || app_state.is_testing_notification.get()
                >
                    {move || {
                        if app_state.is_testing_notification.get() {
                            "Sending..."
                        } else {
                            "Test Notification"
                        }
                    }}
                </button>
                <Show when=move || test_result.get().is_some()>
                    {move || {
                        test_result
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
                </Show>
            </div>
        </div>
    }
}
