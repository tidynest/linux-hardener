# Scheduler UI Implementation Plan

**Goal:** Add a Scheduler page to the GUI for configuring scan schedules and notifications.

**Architecture:** WASM-safe types in `hardener-types`, Tauri IPC reads/writes the `[scheduler]` section of config.toml, Leptos page with two Card sections (schedule + notifications). Config is round-tripped via `toml::from_str` / `toml::to_string_pretty` using a wrapper struct that preserves the scheduler section.

**Tech Stack:** Leptos (WASM), Tauri v2 IPC, serde/toml, hardener-types, hardener-scheduler

---

## Task 1: WASM-safe Scheduler Types in hardener-types

The `SchedulerConfig` in `hardener-scheduler` depends on `PathBuf`, `libc`, `HashMap` — too heavy for WASM. We need a lightweight mirror in `hardener-types` that the frontend can deserialise.

**Files:**
- Create: `crates/hardener-types/src/scheduler.rs`
- Modify: `crates/hardener-types/src/lib.rs:13` — add `pub mod scheduler;`

**Step 1: Create the WASM-safe scheduler types**

In `crates/hardener-types/src/scheduler.rs`:

```rust
//! Scheduler configuration types shared between backend and WASM frontend.

use serde::{Deserialize, Serialize};

/// Schedule configuration for the GUI.
///
/// Mirrors the fields from `hardener-scheduler::SchedulerConfig` that
/// the frontend needs, without native-only dependencies like PathBuf.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct SchedulerUiConfig {
    pub enabled: bool,
    pub schedule: String,
    pub plugins: Vec<String>,
    pub min_severity: String,
    pub notifications: NotificationUiConfig,
}

/// Notification settings for the GUI.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct NotificationUiConfig {
    pub notify_min_severity: String,
    pub email: EmailUiConfig,
    pub webhooks: WebhookUiConfig,
}

/// Email notification settings (GUI subset — no SMTP internals).
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct EmailUiConfig {
    pub enabled: bool,
    pub recipients: Vec<String>,
    pub from_address: String,
}

/// Webhook notification settings (single endpoint for GUI).
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct WebhookUiConfig {
    pub enabled: bool,
    pub url: String,
    pub format: String,
}

/// Result of a test notification attempt.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TestNotificationResult {
    pub success: bool,
    pub message: String,
}
```

**Step 2: Register the module**

In `crates/hardener-types/src/lib.rs`, after line 13 (`pub mod remote;`), add:

```rust
pub mod scheduler;
```

**Step 3: Verify WASM compilation**

Run: `cargo check -p hardener-types --target wasm32-unknown-unknown`
Expected: compiles clean (no PathBuf, no native deps)

**Step 4: Commit**

```
feat(types): add WASM-safe scheduler UI config types
```

---

## Task 2: Tauri IPC Commands — get, save, test

Three new commands in the Tauri backend that read/write the `[scheduler]` section of `config.toml` and dispatch a test notification.

**Files:**
- Modify: `src-tauri/src/commands.rs` — add `get_scheduler_config`, `save_scheduler_config`, `test_notification`
- Modify: `src-tauri/src/main.rs` — register the 3 new commands
- Modify: `src-tauri/Cargo.toml` — add `hardener-scheduler` dependency (for config types and notification dispatcher)

**Step 1: Add hardener-scheduler dependency to Tauri**

In `src-tauri/Cargo.toml`, add to `[dependencies]`:

```toml
hardener-scheduler = { path = "../crates/hardener-scheduler" }
```

And `hardener-types`:

```toml
hardener-types = { path = "../crates/hardener-types" }
```

(Check if `hardener-types` is already present — it may be pulled transitively.)

**Step 2: Add a helper to get the config file path**

In `src-tauri/src/commands.rs`, add near `hosts_config_path()` (around line 34):

```rust
/// Returns the path to the main hardener config file.
fn hardener_config_path() -> Result<std::path::PathBuf, String> {
    // User config takes priority
    let user_config = dirs::config_dir()
        .map(|p| p.join("linux-hardener").join("config.toml"));
    if let Some(ref path) = user_config
        && path.exists()
    {
        return Ok(path.clone());
    }

    // System config fallback
    let system_config = std::path::PathBuf::from("/etc/linux-hardener/config.toml");
    if system_config.exists() {
        return Ok(system_config);
    }

    // Return user config path even if it doesn't exist yet (for creation)
    user_config.ok_or_else(|| "Cannot determine config directory".to_string())
}
```

**Step 3: Add `get_scheduler_config` command**

```rust
/// Reads the [scheduler] section from config.toml and returns it as SchedulerUiConfig.
#[tauri::command]
pub async fn get_scheduler_config() -> Result<hardener_types::scheduler::SchedulerUiConfig, String> {
    let path = hardener_config_path()?;
    if !path.exists() {
        return Ok(hardener_types::scheduler::SchedulerUiConfig::default());
    }

    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read config: {e}"))?;

    // Parse just the scheduler section using a wrapper struct
    #[derive(serde::Deserialize)]
    struct ConfigFile {
        #[serde(default)]
        scheduler: hardener_types::scheduler::SchedulerUiConfig,
    }

    let config: ConfigFile = toml::from_str(&content)
        .map_err(|e| format!("Failed to parse config: {e}"))?;

    Ok(config.scheduler)
}
```

**Step 4: Add `save_scheduler_config` command**

This needs to update only the `[scheduler]` section without disturbing the rest of the file. Use `toml_edit` for surgical editing, or re-serialise the entire file. Since the project doesn't use `toml_edit` yet, the simpler approach is to parse the whole file, update the scheduler section, and re-write.

Add `toml_edit` to `src-tauri/Cargo.toml`:

```toml
toml_edit = "0.22"
```

```rust
/// Saves the scheduler section to config.toml without disturbing other sections.
#[tauri::command]
pub async fn save_scheduler_config(
    config: hardener_types::scheduler::SchedulerUiConfig,
) -> Result<(), String> {
    let path = hardener_config_path()?;

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config directory: {e}"))?;
    }

    // Load existing file or start empty
    let content = if path.exists() {
        std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read config: {e}"))?
    } else {
        String::new()
    };

    // Parse into toml_edit document (preserves formatting and other sections)
    let mut document: toml_edit::DocumentMut = content.parse()
        .map_err(|e| format!("Failed to parse config: {e}"))?;

    // Serialise the scheduler section and merge it in
    let scheduler_toml = toml::to_string(&config)
        .map_err(|e| format!("Failed to serialise scheduler config: {e}"))?;
    let scheduler_table: toml_edit::DocumentMut = scheduler_toml.parse()
        .map_err(|e| format!("Failed to parse scheduler TOML: {e}"))?;

    document["scheduler"] = scheduler_table.as_item().clone();

    std::fs::write(&path, document.to_string())
        .map_err(|e| format!("Failed to write config: {e}"))
}
```

**Step 5: Add `test_notification` command**

```rust
/// Sends a test notification through all enabled channels.
#[tauri::command]
pub async fn test_notification() -> Result<hardener_types::scheduler::TestNotificationResult, String> {
    use hardener_scheduler::notification::NotificationDispatcher;
    use hardener_scheduler::runner::ScanSummary;

    // Load current scheduler config (native version for dispatcher)
    let path = hardener_config_path()?;
    let scheduler_config = if path.exists() {
        let content = std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read config: {e}"))?;

        #[derive(serde::Deserialize)]
        struct ConfigFile {
            #[serde(default)]
            scheduler: hardener_scheduler::SchedulerConfig,
        }

        let config: ConfigFile = toml::from_str(&content)
            .map_err(|e| format!("Failed to parse config: {e}"))?;
        config.scheduler
    } else {
        hardener_scheduler::SchedulerConfig::default()
    };

    // Build a test summary
    let summary = ScanSummary {
        session_id: "test-notification".into(),
        host: hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".into()),
        plugins_scanned: vec!["test".into()],
        total_findings: 1,
        critical_count: 0,
        high_count: 1,
        medium_count: 0,
        low_count: 0,
        info_count: 0,
        json_path: None,
        json_hash: None,
        had_errors: false,
    };

    let dispatcher = NotificationDispatcher::new(&scheduler_config.notifications);
    match dispatcher.dispatch(&summary).await {
        Ok(()) => Ok(hardener_types::scheduler::TestNotificationResult {
            success: true,
            message: "Test notification sent successfully".into(),
        }),
        Err(e) => Ok(hardener_types::scheduler::TestNotificationResult {
            success: false,
            message: format!("Notification failed: {e}"),
        }),
    }
}
```

**Step 6: Register commands in main.rs**

In `src-tauri/src/main.rs`, add to the import list (line 4-8):

```rust
get_scheduler_config, save_scheduler_config, test_notification,
```

Add to the `generate_handler![]` array (line 22-43):

```rust
get_scheduler_config,
save_scheduler_config,
test_notification,
```

**Step 7: Verify native compilation**

Run: `cargo check -p hardener-tauri`
Expected: compiles clean

**Step 8: Commit**

```
feat(tauri): add scheduler config IPC commands
```

---

## Task 3: WASM Bindings for Scheduler Commands

Wire the three new Tauri commands into the WASM binding layer.

**Files:**
- Modify: `crates/hardener-ui/src/tauri_bindings.rs:341` — add 3 new functions
- Modify: `crates/hardener-ui/src/types.rs:1` — re-export scheduler types

**Step 1: Add type re-exports**

In `crates/hardener-ui/src/types.rs`, add after the existing `hardener_types` re-export block (line 6):

```rust
pub use hardener_types::scheduler::{
    SchedulerUiConfig, NotificationUiConfig, EmailUiConfig, WebhookUiConfig, TestNotificationResult,
};
```

**Step 2: Add binding functions**

At the end of `crates/hardener-ui/src/tauri_bindings.rs` (after line 340), add:

```rust
// === Scheduler Configuration Bindings ===

/// Invokes the get_scheduler_config Tauri command.
///
/// Returns the current scheduler configuration from config.toml.
pub async fn invoke_get_scheduler_config() -> Result<SchedulerUiConfig, String> {
    let result = invoke_command("get_scheduler_config", JsValue::NULL).await?;
    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise scheduler config: {}", e))
}

/// Invokes the save_scheduler_config Tauri command.
///
/// Persists scheduler configuration to the [scheduler] section of config.toml.
pub async fn invoke_save_scheduler_config(config: SchedulerUiConfig) -> Result<(), String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "config": config,
    }))
    .map_err(|e| format!("Failed to serialise scheduler config: {}", e))?;
    invoke_command("save_scheduler_config", args).await?;
    Ok(())
}

/// Invokes the test_notification Tauri command.
///
/// Sends a test notification through all enabled channels.
pub async fn invoke_test_notification() -> Result<TestNotificationResult, String> {
    let result = invoke_command("test_notification", JsValue::NULL).await?;
    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise test result: {}", e))
}
```

Import the types at top of file (line 6-9), adding:

```rust
use crate::types::{SchedulerUiConfig, TestNotificationResult};
```

**Step 3: Verify WASM compilation**

Run: `cargo check -p hardener-ui --target wasm32-unknown-unknown`
Expected: compiles clean

**Step 4: Commit**

```
feat(ui): add WASM bindings for scheduler IPC commands
```

---

## Task 4: AppState Signals for Scheduler

Add scheduler-specific signals to AppState.

**Files:**
- Modify: `crates/hardener-ui/src/state/mod.rs:2` — import `SchedulerUiConfig`
- Modify: `crates/hardener-ui/src/state/mod.rs:12-55` — add 3 new signals
- Modify: `crates/hardener-ui/src/state/mod.rs:58-79` — add defaults

**Step 1: Add import**

In `crates/hardener-ui/src/state/mod.rs`, line 1, add to the import:

```rust
use crate::types::{..., SchedulerUiConfig};
```

**Step 2: Add signals to AppState struct** (after line 54, `is_remote_scanning`)

```rust
    /// Loaded scheduler configuration from config.toml.
    pub scheduler_config: RwSignal<Option<SchedulerUiConfig>>,
    /// Whether scheduler config is being saved.
    pub is_saving_scheduler: RwSignal<bool>,
    /// Whether a test notification is in progress.
    pub is_testing_notification: RwSignal<bool>,
```

**Step 3: Add defaults** (after line 77, `is_remote_scanning: RwSignal::new(false)`)

```rust
            scheduler_config: RwSignal::new(None),
            is_saving_scheduler: RwSignal::new(false),
            is_testing_notification: RwSignal::new(false),
```

**Step 4: Verify compilation**

Run: `cargo check -p hardener-ui --target wasm32-unknown-unknown`
Expected: compiles clean

**Step 5: Commit**

```
feat(ui): add scheduler config signals to AppState
```

---

## Task 5: SchedulerPage Component

The main page with two Card sections.

**Files:**
- Create: `crates/hardener-ui/src/pages/scheduler_page.rs`
- Modify: `crates/hardener-ui/src/pages/mod.rs` — add module + re-export

**Step 1: Create the page component**

In `crates/hardener-ui/src/pages/scheduler_page.rs`:

```rust
//! Scheduler configuration page — manage scan schedules and notifications.

use crate::components::Card;
use crate::components::{NotificationSection, ScheduleSection};
use crate::state::AppState;
use crate::tauri_bindings;
use leptos::prelude::*;

/// Scheduler page with two sections: schedule and notifications.
/// Loads config on mount, provides save handler to child components.
#[component]
pub fn SchedulerPage() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Load scheduler config on mount
    leptos::task::spawn_local(async move {
        match tauri_bindings::invoke_get_scheduler_config().await {
            Ok(config) => app_state.scheduler_config.set(Some(config)),
            Err(e) => {
                web_sys::console::warn_1(
                    &format!("Failed to load scheduler config: {e}").into(),
                );
            }
        }
    });

    view! {
        <div class="scheduler-page">
            <Card title="Schedule".to_string()>
                <ScheduleSection />
            </Card>
            <Card title="Notifications".to_string()>
                <NotificationSection />
            </Card>
        </div>
    }
}
```

**Step 2: Register in pages/mod.rs**

Add to `crates/hardener-ui/src/pages/mod.rs`:

```rust
pub mod scheduler_page;
pub use scheduler_page::SchedulerPage;
```

**Step 3: Commit** (will fail to compile until Task 6 — that's expected, commit after Task 6)

---

## Task 6: ScheduleSection Component

The schedule configuration form: enabled toggle, preset dropdown, custom cron, plugin checkboxes, severity dropdown.

**Files:**
- Create: `crates/hardener-ui/src/components/schedule_section.rs`

**Step 1: Create the component**

```rust
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
#[component]
pub fn ScheduleSection() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Local form state — populated from loaded config via Effect
    let enabled = RwSignal::new(false);
    let selected_preset = RwSignal::new(String::new());
    let custom_cron = RwSignal::new(String::new());
    let selected_plugins = RwSignal::new(Vec::<String>::new());
    let min_severity = RwSignal::new("medium".to_string());

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

    // Save handler
    let handle_save = move |_| {
        let cron = effective_cron();
        let plugins = selected_plugins.get();
        let severity = min_severity.get();
        let is_enabled = enabled.get();

        app_state.is_saving_scheduler.set(true);

        leptos::task::spawn_local(async move {
            // Build config, preserving notification section from current state
            let mut config = app_state
                .scheduler_config
                .get()
                .unwrap_or_default();
            config.enabled = is_enabled;
            config.schedule = cron;
            config.plugins = plugins;
            config.min_severity = severity;

            match tauri_bindings::invoke_save_scheduler_config(config.clone()).await {
                Ok(()) => app_state.scheduler_config.set(Some(config)),
                Err(e) => {
                    app_state
                        .error_message
                        .set(Some(format!("Failed to save schedule: {e}")));
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
```

**Step 2: Commit** (combined with Task 7 — both components needed before page compiles)

---

## Task 7: NotificationSection Component

Email config, webhook config, and test button.

**Files:**
- Create: `crates/hardener-ui/src/components/notification_section.rs`

**Step 1: Create the component**

```rust
//! Notification configuration section — email, webhook, and test button.

use crate::state::AppState;
use crate::tauri_bindings;
use leptos::prelude::*;

/// Notification configuration form with email, webhook, and test button.
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

    // Sync from loaded config
    Effect::new(move || {
        if let Some(config) = app_state.scheduler_config.get() {
            let notif = &config.notifications;
            email_enabled.set(notif.email.enabled);
            email_recipients.set(notif.email.recipients.join(", "));
            email_from.set(notif.email.from_address.clone());
            webhook_enabled.set(notif.webhooks.enabled);
            webhook_url.set(notif.webhooks.url.clone());
            webhook_format.set(notif.webhooks.format.clone());
        }
    });

    // Save handler
    let handle_save = move |_| {
        app_state.is_saving_scheduler.set(true);

        let recipients: Vec<String> = email_recipients
            .get()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        leptos::task::spawn_local(async move {
            let mut config = app_state.scheduler_config.get().unwrap_or_default();
            config.notifications.email.enabled = email_enabled.get();
            config.notifications.email.recipients = recipients;
            config.notifications.email.from_address = email_from.get();
            config.notifications.webhooks.enabled = webhook_enabled.get();
            config.notifications.webhooks.url = webhook_url.get();
            config.notifications.webhooks.format = webhook_format.get();

            match tauri_bindings::invoke_save_scheduler_config(config.clone()).await {
                Ok(()) => app_state.scheduler_config.set(Some(config)),
                Err(e) => {
                    app_state
                        .error_message
                        .set(Some(format!("Failed to save notifications: {e}")));
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
                    class="btn btn-secondary"
                    on:click=handle_test
                    disabled=move || app_state.is_testing_notification.get()
                >
                    {move || {
                        if app_state.is_testing_notification.get() {
                            "Sending..."
                        } else {
                            "Send Test Notification"
                        }
                    }}
                </button>
            </div>

            // Test result message
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
        </div>
    }
}
```

**Step 2: Register both new components in components/mod.rs**

Add to `crates/hardener-ui/src/components/mod.rs`:

```rust
mod notification_section;
mod schedule_section;

pub use notification_section::NotificationSection;
pub use schedule_section::ScheduleSection;
```

**Step 3: Verify WASM compilation**

Run: `cargo check -p hardener-ui --target wasm32-unknown-unknown`
Expected: compiles clean

**Step 4: Commit**

```
feat(ui): add ScheduleSection and NotificationSection components
```

---

## Task 8: Routing and Navigation

Wire the SchedulerPage into the router and nav bar.

**Files:**
- Modify: `crates/hardener-ui/src/lib.rs:15` — import SchedulerPage
- Modify: `crates/hardener-ui/src/lib.rs:60` — add nav link
- Modify: `crates/hardener-ui/src/lib.rs:94` — add route

**Step 1: Add import** (line 15)

Change:
```rust
use pages::{AnalysisPage, DashboardPage, HardeningPage, RemotePage};
```
To:
```rust
use pages::{AnalysisPage, DashboardPage, HardeningPage, RemotePage, SchedulerPage};
```

**Step 2: Add nav link** (after line 60, the Remote link)

```rust
<li><A href="/scheduler">"Scheduler"</A></li>
```

**Step 3: Add route** (after line 94, the remote route)

```rust
<Route path=StaticSegment("scheduler") view=SchedulerPage/>
```

**Step 4: Verify WASM compilation**

Run: `cargo check -p hardener-ui --target wasm32-unknown-unknown`
Expected: compiles clean

**Step 5: Commit**

```
feat(ui): add Scheduler page route and navigation link
```

---

## Task 9: CSS Styles for Scheduler Page

Add styles for the scheduler form components.

**Files:**
- Modify: `crates/hardener-ui/styles.css` — append scheduler styles

**Step 1: Add styles**

Append to the end of `crates/hardener-ui/styles.css`:

```css
/* ---- Scheduler Page ---- */

.scheduler-page {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.schedule-section,
.notification-section {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.subsection-title {
  font-size: 1rem;
  font-weight: 600;
  color: var(--text-primary);
  margin: 0.5rem 0 0;
  padding-top: 0.75rem;
  border-top: 1px solid var(--border);
}

.form-row {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.form-label {
  font-size: 0.875rem;
  font-weight: 500;
  color: var(--text-secondary);
}

.form-input,
.form-select {
  padding: 0.5rem 0.75rem;
  background: var(--bg-tertiary);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text-primary);
  font-size: 0.875rem;
  font-family: inherit;
  max-width: 400px;
}

.form-input:focus,
.form-select:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 2px var(--accent-muted);
}

.form-hint {
  font-size: 0.75rem;
  color: var(--text-muted);
}

.toggle-label {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  cursor: pointer;
  font-size: 0.875rem;
  color: var(--text-primary);
}

.toggle-input {
  accent-color: var(--accent);
}

.plugin-checkboxes {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
}

.checkbox-label {
  display: flex;
  align-items: center;
  gap: 0.375rem;
  font-size: 0.8125rem;
  color: var(--text-secondary);
  cursor: pointer;
}

.form-actions {
  display: flex;
  gap: 0.75rem;
  margin-top: 0.5rem;
}

.test-result {
  padding: 0.5rem 0.75rem;
  border-radius: 6px;
  font-size: 0.8125rem;
}

.test-result--success {
  background: var(--severity-low-bg, rgba(46, 160, 67, 0.15));
  color: var(--severity-low, #3fb950);
  border: 1px solid var(--severity-low, #3fb950);
}

.test-result--failure {
  background: var(--severity-critical-bg, rgba(248, 81, 73, 0.15));
  color: var(--severity-critical, #f85149);
  border: 1px solid var(--severity-critical, #f85149);
}
```

**Step 2: Check for CSS class conflicts**

Grep styles.css for `.form-row`, `.form-label`, `.form-input`, etc. to check for existing definitions. If they already exist (e.g., from HostForm), the new styles may merge naturally or need scoping. If conflicts exist, prefix with `.scheduler-page` or `.schedule-section`.

**Step 3: Commit**

```
feat(ui): add scheduler page styles
```

---

## Task 10: Tauri Mock for GUI Testing

Add mock handlers for the 3 new scheduler commands.

**Files:**
- Modify: `gui-tests/tauri-mock.js` — add handlers before the `default:` case (around line 545)

**Step 1: Add mock state and handlers**

Near the top of the mock (with other state variables), add:

```javascript
let schedulerConfig = {
  enabled: false,
  schedule: '0 0 2 * * *',
  plugins: [],
  min_severity: 'medium',
  notifications: {
    notify_min_severity: '',
    email: { enabled: false, recipients: [], from_address: '' },
    webhooks: { enabled: false, url: '', format: 'generic' },
  },
};
```

Before the `default:` case, add:

```javascript
      // ---- Scheduler Commands ----

      case 'get_scheduler_config':
        return schedulerConfig;

      case 'save_scheduler_config': {
        const cfg = args && args.config;
        if (cfg) schedulerConfig = cfg;
        return null;
      }

      case 'test_notification':
        return { success: true, message: 'Test notification sent successfully' };
```

**Step 2: Commit**

```
feat(test): add scheduler IPC mocks to tauri-mock.js
```

---

## Task 11: Documentation Updates

Update ROADMAP, CHANGELOG, and FILE_MAP.

**Files:**
- Modify: `docs/ROADMAP.md` — mark Scheduler UI complete
- Modify: `docs/CHANGELOG.md` — add entry
- Modify: `docs/FILE_MAP.md` — add new files (if this file exists)

**Step 1: Update ROADMAP**

Change `Scheduler UI | P3 | ⬜` to `Scheduler UI | P3 | ✅ Complete`

**Step 2: Update CHANGELOG**

Add under today's date:

```markdown
### Added
- Scheduler configuration UI page with cron presets and custom expressions
- Notification setup (email recipients, webhook endpoint with Slack/Discord/Generic)
- Test notification button for verifying delivery
- WASM-safe scheduler types in hardener-types
- 3 new Tauri IPC commands: get_scheduler_config, save_scheduler_config, test_notification
```

**Step 3: Update FILE_MAP** (if it exists)

Add new files:
```
crates/hardener-types/src/scheduler.rs         — WASM-safe scheduler config types
crates/hardener-ui/src/pages/scheduler_page.rs — Scheduler page component
crates/hardener-ui/src/components/schedule_section.rs     — Schedule config form
crates/hardener-ui/src/components/notification_section.rs — Notification config form
```

**Step 4: Commit**

```
docs: update roadmap and changelog for scheduler UI
```

---

## Task 12: Final Verification

**Step 1: Run all Rust tests**

Run: `cargo test --workspace`
Expected: all tests pass (400+)

**Step 2: Run clippy**

Run: `cargo clippy --workspace -- -D clippy::unwrap_used`
Expected: no warnings

**Step 3: Check WASM build**

Run: `cargo check -p hardener-ui --target wasm32-unknown-unknown`
Expected: compiles clean

**Step 4: Check native build**

Run: `cargo check -p hardener-tauri`
Expected: compiles clean
