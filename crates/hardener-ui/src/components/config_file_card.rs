//! Config file picker for the Hardening page's "Advanced (optional)"
//! disclosure.
//!
//! Lets the user select a custom TOML config file via text input
//! or native file dialog, with inline validation feedback. Presentation
//! only: no card framing of its own, since the surrounding disclosure
//! already provides the box.

use crate::state::AppState;
use crate::tauri_bindings::{invoke_pick_config_file, invoke_validate_config, tauri_available};
use leptos::prelude::*;

/// Config file picker with text input, browse button, and validation status.
#[component]
pub fn ConfigFileCard() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    let input_value = RwSignal::new(String::new());
    let is_validating = RwSignal::new(false);

    // Validate a path and update AppState.
    // All captured signals are Copy, so this closure is Copy too.
    let validate_path = move |path: String| {
        if path.trim().is_empty() {
            app_state.config_path.set(None);
            app_state.config_summary.set(None);
            return;
        }

        is_validating.set(true);
        let path_clone = path.clone();
        leptos::task::spawn_local(async move {
            match invoke_validate_config(path_clone.clone()).await {
                Ok(summary) => {
                    app_state.config_path.set(Some(path_clone));
                    app_state.config_summary.set(Some(summary));
                }
                Err(e) => {
                    app_state.config_path.set(Some(path_clone.clone()));
                    app_state
                        .config_summary
                        .set(Some(crate::types::ConfigSummary {
                            config_path: path_clone,
                            config_is_valid: false,
                            config_error: Some(e),
                            config_enabled_plugins: Vec::new(),
                            config_directive_count: 0,
                            config_exception_count: 0,
                        }));
                }
            }
            is_validating.set(false);
        });
    };

    let on_blur = move |_| {
        validate_path(input_value.get_untracked());
    };

    let on_keydown = move |ev: web_sys::KeyboardEvent| {
        if ev.key() == "Enter" {
            ev.prevent_default();
            validate_path(input_value.get_untracked());
        }
    };

    let on_browse = move |_| {
        leptos::task::spawn_local(async move {
            match invoke_pick_config_file().await {
                Ok(Some(path)) => {
                    input_value.set(path.clone());
                    validate_path(path);
                }
                Ok(None) => {}
                Err(e) => {
                    web_sys::console::error_1(&format!("File dialog error: {}", e).into());
                }
            }
        });
    };

    let on_clear = move |_| {
        input_value.set(String::new());
        app_state.config_path.set(None);
        app_state.config_summary.set(None);
    };

    let status_view = move || {
        if is_validating.get() {
            return view! { <span class="config-status config-validating">"Validating..."</span> }
                .into_any();
        }

        match app_state.config_summary.get() {
            None => {
                view! { <span class="config-status config-default">"Using the built in defaults"</span> }
                    .into_any()
            }
            Some(summary) if summary.config_is_valid => {
                let plugin_count = summary.config_enabled_plugins.len();
                let directives = summary.config_directive_count;
                let exceptions = summary.config_exception_count;
                let text = format!(
                    "{} plugin{} \u{00b7} {} directive{} \u{00b7} {} exception{}",
                    plugin_count,
                    if plugin_count == 1 { "" } else { "s" },
                    directives,
                    if directives == 1 { "" } else { "s" },
                    exceptions,
                    if exceptions == 1 { "" } else { "s" },
                );
                view! {
                    <span class="config-status config-valid">
                        <span class="config-status-icon">{"\u{2713}"}</span>
                        " Valid \u{00b7} "
                        {text}
                    </span>
                }
                .into_any()
            }
            Some(summary) => {
                let error = summary.config_error.unwrap_or_default();
                view! {
                    <span class="config-status config-invalid">
                        <span class="config-status-icon">{"\u{2717}"}</span>
                        " "
                        {error}
                    </span>
                }
                .into_any()
            }
        }
    };

    view! {
        <div class="config-file-fields">
            <div class="config-file-row">
                <input
                    type="text"
                    class="config-file-input"
                    placeholder="path to a .toml config file"
                    prop:value=move || input_value.get()
                    on:input=move |ev| {
                        input_value.set(event_target_value(&ev));
                    }
                    on:blur=on_blur
                    on:keydown=on_keydown
                />
                <Show when=move || tauri_available()>
                    <button class="btn btn-secondary config-browse-btn" on:click=on_browse>
                        "Browse"
                    </button>
                </Show>
            </div>
            <div class="config-status-row">
                {status_view}
                <Show when=move || app_state.config_path.get().is_some()>
                    <button class="btn-link config-clear-btn" on:click=on_clear>
                        "Clear"
                    </button>
                </Show>
            </div>
        </div>
    }
}
