//! Notification configuration section — email, webhook, and test button.

use crate::state::AppState;
use crate::tauri_bindings;
use leptos::prelude::*;

/// Notification configuration form with email and webhook subsections.
///
/// Each channel has an enabled toggle that conditionally reveals its
/// detail fields. Recipients are displayed as a comma-separated string
/// in the text input and split into a `Vec<String>` on save.
///
/// The save handler merges notification fields into the existing config,
/// preserving the schedule section untouched. A "Send Test Notification"
/// button dispatches `invoke_test_notification()` and shows success or
/// failure inline via `test_result_message`.
#[component]
pub fn NotificationSection() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Local form signals
    let email_enabled = RwSignal::new(false);
    let email_recipients = RwSignal::new(String::new());
    let email_from = RwSignal::new(String::new());
    let webhook_enabled = RwSignal::new(false);
    let webhook_url = RwSignal::new(String::new());
    let webhook_format = RwSignal::new("generic".to_string());
    let test_result_message = RwSignal::new(None::<(bool, String)>);
    let save_status = RwSignal::new(None::<(bool, String)>);

    // Sync from loaded config
    Effect::new(move || {
        if let Some(config) = app_state.scheduler_config.get() {
            let notif = config.notifications;
            email_enabled.set(notif.email.enabled);
            email_recipients.set(notif.email.recipients.join(", "));
            email_from.set(notif.email.from_address);
            webhook_enabled.set(notif.webhooks.enabled);
            webhook_url.set(notif.webhooks.url);
            webhook_format.set(notif.webhooks.format);
        }
    });

    // Save handler — merges notification fields into existing config, preserving schedule
    let handle_save = move |_| {
        app_state.is_saving_scheduler.set(true);
        save_status.set(None);

        // Snapshot all form signals before entering async (avoids reactive tracking warnings)
        let recipients: Vec<String> = email_recipients
            .get_untracked()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let is_email_enabled = email_enabled.get_untracked();
        let from = email_from.get_untracked();
        let is_webhook_enabled = webhook_enabled.get_untracked();
        let url = webhook_url.get_untracked();
        let format = webhook_format.get_untracked();
        let mut config = app_state
            .scheduler_config
            .get_untracked()
            .unwrap_or_default();

        leptos::task::spawn_local(async move {
            config.notifications.email.enabled = is_email_enabled;
            config.notifications.email.recipients = recipients;
            config.notifications.email.from_address = from;
            config.notifications.webhooks.enabled = is_webhook_enabled;
            config.notifications.webhooks.url = url;
            config.notifications.webhooks.format = format;

            match tauri_bindings::invoke_save_scheduler_config(config.clone()).await {
                Ok(path) => {
                    app_state.scheduler_config.set(Some(config));
                    save_status.set(Some((true, format!("Notifications saved to {path}"))));
                }
                Err(e) => {
                    save_status.set(Some((false, format!("Failed to save: {e}"))));
                }
            }
            app_state.is_saving_scheduler.set(false);
        });
    };

    // Test notification handler
    let handle_test = move |_| {
        app_state.is_testing_notification.set(true);
        test_result_message.set(None);

        leptos::task::spawn_local(async move {
            match tauri_bindings::invoke_test_notification().await {
                Ok(result) => {
                    test_result_message.set(Some((result.success, result.message)));
                }
                Err(e) => {
                    test_result_message.set(Some((false, format!("Request failed: {e}"))));
                }
            }
            app_state.is_testing_notification.set(false);
        });
    };

    view! {
        <div class="notification-section">
            // --- Email ---
            <h3 class="subsection-title">"Email"</h3>

            <div class="form-row">
                <label class="toggle-label">
                    <input
                        type="checkbox"
                        class="toggle-input"
                        prop:checked=move || email_enabled.get()
                        on:change=move |event| {
                            use leptos::wasm_bindgen::JsCast;
                            let checked = event
                                .target()
                                .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
                                .map(|el| el.checked())
                                .unwrap_or(false);
                            email_enabled.set(checked);
                        }
                    />
                    "Enable email notifications"
                </label>
            </div>

            <Show when=move || email_enabled.get()>
                <div class="form-row">
                    <label class="form-label">"Recipients"</label>
                    <input
                        type="text"
                        class="form-input"
                        placeholder="admin@example.com, ops@example.com"
                        prop:value=move || email_recipients.get()
                        on:input=move |event| {
                            use leptos::wasm_bindgen::JsCast;
                            let value = event
                                .target()
                                .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
                                .map(|el| el.value())
                                .unwrap_or_default();
                            email_recipients.set(value);
                        }
                    />
                    <span class="form-hint">"Comma-separated email addresses"</span>
                </div>
                <div class="form-row">
                    <label class="form-label">"From address"</label>
                    <input
                        type="text"
                        class="form-input"
                        placeholder="hardener@example.com"
                        prop:value=move || email_from.get()
                        on:input=move |event| {
                            use leptos::wasm_bindgen::JsCast;
                            let value = event
                                .target()
                                .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
                                .map(|el| el.value())
                                .unwrap_or_default();
                            email_from.set(value);
                        }
                    />
                </div>
            </Show>

            // --- Webhook ---
            <h3 class="subsection-title">"Webhook"</h3>

            <div class="form-row">
                <label class="toggle-label">
                    <input
                        type="checkbox"
                        class="toggle-input"
                        prop:checked=move || webhook_enabled.get()
                        on:change=move |event| {
                            use leptos::wasm_bindgen::JsCast;
                            let checked = event
                                .target()
                                .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
                                .map(|el| el.checked())
                                .unwrap_or(false);
                            webhook_enabled.set(checked);
                        }
                    />
                    "Enable webhook notifications"
                </label>
            </div>

            <Show when=move || webhook_enabled.get()>
                <div class="form-row">
                    <label class="form-label">"Endpoint URL"</label>
                    <input
                        type="url"
                        class="form-input"
                        placeholder="https://hooks.slack.com/services/..."
                        prop:value=move || webhook_url.get()
                        on:input=move |event| {
                            use leptos::wasm_bindgen::JsCast;
                            let value = event
                                .target()
                                .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
                                .map(|el| el.value())
                                .unwrap_or_default();
                            webhook_url.set(value);
                        }
                    />
                </div>
                <div class="form-row">
                    <label class="form-label">"Format"</label>
                    <select
                        class="form-select"
                        prop:value=move || webhook_format.get()
                        on:change=move |event| {
                            use leptos::wasm_bindgen::JsCast;
                            let value = event
                                .target()
                                .and_then(|t| t.dyn_into::<web_sys::HtmlSelectElement>().ok())
                                .map(|el| el.value())
                                .unwrap_or_default();
                            webhook_format.set(value);
                        }
                    >
                        <option value="generic">"Generic JSON"</option>
                        <option value="slack">"Slack"</option>
                        <option value="discord">"Discord"</option>
                    </select>
                </div>
            </Show>

            // Status messages
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
            <Show when=move || test_result_message.get().is_some()>
                {move || {
                    test_result_message.get().map(|(success, message)| {
                        let class = if success {
                            "test-result test-result--success"
                        } else {
                            "test-result test-result--failure"
                        };
                        view! { <div class=class>{message}</div> }
                    })
                }}
            </Show>

            // --- Actions ---
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
                            "Save Notifications"
                        }
                    }}
                </button>
                <button
                    class="btn btn-accent"
                    on:click=handle_test
                    disabled=move || app_state.is_testing_notification.get()
                >
                    {move || {
                        if app_state.is_testing_notification.get() {
                            "Sending..."
                        } else {
                            "\u{25B6} Test Notification"
                        }
                    }}
                </button>
            </div>
        </div>
    }
}
