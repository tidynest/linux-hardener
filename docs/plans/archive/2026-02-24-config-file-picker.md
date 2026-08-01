# Config File Picker Implementation Plan

> **Archived.** Historical record, possibly superseded by later work. Retained for history.

**Goal:** Add a config file picker to the Hardening page so users can select a custom TOML config file, equivalent to the CLI `--config FILE` flag.

**Architecture:** New WASM-safe `ConfigSummary` type in `hardener-types`. Two new Tauri commands (`validate_config`, `pick_config_file`). One new Leptos component (`ConfigFileCard`) on the Hardening page. Config path stored in `AppState` and threaded through to scan/apply/rollback commands. `tauri-plugin-dialog` provides the native file picker.

**Tech Stack:** Rust, Tauri v2, Leptos/WASM, `tauri-plugin-dialog`, `ConfigLoader`

---

### Task 1: Add `ConfigSummary` type to `hardener-types`

**Files:**
- Create: `crates/hardener-types/src/config_picker.rs`
- Modify: `crates/hardener-types/src/lib.rs`

**Step 1: Create the type file**

In `crates/hardener-types/src/config_picker.rs`:

```rust
//! Types for the config file picker UI.

use serde::{Deserialize, Serialize};

/// Summary of a validated configuration file.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ConfigSummary {
    /// Path to the config file that was validated.
    pub config_path: String,
    /// Whether the file parsed successfully.
    pub config_is_valid: bool,
    /// Parse error message (None if valid).
    pub config_error: Option<String>,
    /// Names of plugins that are enabled in this config.
    pub config_enabled_plugins: Vec<String>,
    /// Total directive count across all plugin sections.
    pub config_directive_count: u32,
    /// Total exception count across all plugin sections.
    pub config_exception_count: u32,
}
```

**Step 2: Register module in lib.rs**

Add to `crates/hardener-types/src/lib.rs` after the `pub mod scheduler;` line:

```rust
pub mod config_picker;
pub use config_picker::*;
```

**Step 3: Verify it compiles**

Run: `cargo check -p hardener-types`
Expected: success, no errors

Run: `cargo check -p hardener-types --target wasm32-unknown-unknown`
Expected: success (WASM-safe)

**Step 4: Commit**

```bash
git add crates/hardener-types/src/config_picker.rs crates/hardener-types/src/lib.rs
git commit -m "feat(types): add ConfigSummary for config file picker"
```

---

### Task 2: Add `tauri-plugin-dialog` dependency

**Files:**
- Modify: `src-tauri/Cargo.toml`
- Modify: `src-tauri/src/main.rs`
- Modify: `src-tauri/capabilities/default.json`

**Step 1: Add dependency to src-tauri/Cargo.toml**

Add to `[dependencies]` section:

```toml
tauri-plugin-dialog = "2"
```

**Step 2: Register plugin in main.rs**

In `src-tauri/src/main.rs`, add `.plugin(tauri_plugin_dialog::init())` to the builder chain, before `.invoke_handler(...)`:

```rust
tauri::Builder::default()
    .plugin(tauri_plugin_dialog::init())
    .manage(RemoteState { ... })
    .invoke_handler(...)
```

**Step 3: Add dialog permission to capabilities**

In `src-tauri/capabilities/default.json`, add to the `permissions` array:

```json
"dialog:default"
```

**Step 4: Verify it compiles**

Run: `cargo check -p linux-hardener-desktop`
Expected: success

**Step 5: Commit**

```bash
git add src-tauri/Cargo.toml src-tauri/src/main.rs src-tauri/capabilities/default.json
git commit -m "chore: add tauri-plugin-dialog for native file picker"
```

---

### Task 3: Add `validate_config` and `pick_config_file` Tauri commands

**Files:**
- Modify: `src-tauri/src/commands.rs`
- Modify: `src-tauri/src/main.rs`

**Step 1: Add validate_config command**

In `src-tauri/src/commands.rs`, add after the existing imports at the top (ensure `hardener_core::ConfigLoader` is imported), then add near the other Tauri commands:

```rust
use hardener_types::ConfigSummary;
```

```rust
/// Validates a config file and returns a summary of its contents.
///
/// Parses the TOML file using ConfigLoader and counts plugins,
/// directives, and exceptions. Returns error details if invalid.
#[tauri::command]
pub async fn validate_config(path: String) -> Result<ConfigSummary, String> {
    use hardener_core::ConfigLoader;

    let file_path = std::path::PathBuf::from(&path);

    if !file_path.exists() {
        return Ok(ConfigSummary {
            config_path: path,
            config_is_valid: false,
            config_error: Some("File not found".to_string()),
            ..Default::default()
        });
    }

    let loader = ConfigLoader::new()
        .skip_defaults()
        .with_cli_config(file_path);

    match loader.load() {
        Ok(config) => {
            let plugin_sections = [
                ("kernel", &config.kernel),
                ("ssh", &config.ssh),
                ("firewall", &config.firewall),
                ("pam", &config.pam),
                ("services", &config.services),
                ("audit", &config.audit),
                ("permissions", &config.permissions),
                ("mac", &config.mac),
            ];

            let enabled_plugins: Vec<String> = plugin_sections
                .iter()
                .filter(|(_, pc)| pc.enabled)
                .map(|(name, _)| (*name).to_string())
                .collect();

            let directive_count: u32 = plugin_sections
                .iter()
                .map(|(_, pc)| (pc.directives.len() + pc.custom_directives.len()) as u32)
                .sum();

            let exception_count: u32 = plugin_sections
                .iter()
                .map(|(_, pc)| pc.exceptions.len() as u32)
                .sum();

            Ok(ConfigSummary {
                config_path: path,
                config_is_valid: true,
                config_error: None,
                config_enabled_plugins: enabled_plugins,
                config_directive_count: directive_count,
                config_exception_count: exception_count,
            })
        }
        Err(e) => Ok(ConfigSummary {
            config_path: path,
            config_is_valid: false,
            config_error: Some(e.to_string()),
            ..Default::default()
        }),
    }
}
```

**Step 2: Add pick_config_file command**

```rust
/// Opens a native file dialog for selecting a TOML config file.
///
/// Returns the selected file path, or None if the dialog was cancelled.
#[tauri::command]
pub async fn pick_config_file(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;

    let file_path = app
        .dialog()
        .file()
        .add_filter("TOML Config", &["toml"])
        .set_title("Select Configuration File")
        .blocking_pick_file();

    Ok(file_path.map(|p| p.path.to_string_lossy().to_string()))
}
```

**Step 3: Register commands in main.rs**

In `src-tauri/src/main.rs`, add `pick_config_file` and `validate_config` to both the import and the `generate_handler![]` macro.

**Step 4: Verify it compiles**

Run: `cargo check -p linux-hardener-desktop`
Expected: success

**Step 5: Commit**

```bash
git add src-tauri/src/commands.rs src-tauri/src/main.rs
git commit -m "feat(tauri): add validate_config and pick_config_file commands"
```

---

### Task 4: Add WASM bindings and AppState signals

**Files:**
- Modify: `crates/hardener-ui/src/tauri_bindings.rs`
- Modify: `crates/hardener-ui/src/state/mod.rs`

**Step 1: Add WASM bindings**

In `crates/hardener-ui/src/tauri_bindings.rs`, add `ConfigSummary` to the imports from `crate::types`, then add at the bottom (before the last closing line or after the scheduler section):

```rust
// === Config File Picker Bindings ===

/// Invokes the validate_config Tauri command.
///
/// Validates a TOML config file and returns a summary of its contents.
pub async fn invoke_validate_config(path: String) -> Result<ConfigSummary, String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "path": path,
    }))
    .map_err(|e| format!("Failed to serialise arguments: {}", e))?;

    let result = invoke_command("validate_config", args).await?;

    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise config summary: {}", e))
}

/// Invokes the pick_config_file Tauri command.
///
/// Opens a native file dialog for selecting a TOML config file.
pub async fn invoke_pick_config_file() -> Result<Option<String>, String> {
    let result = invoke_command("pick_config_file", JsValue::NULL).await?;

    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise file path: {}", e))
}
```

**Step 2: Add signals to AppState**

In `crates/hardener-ui/src/state/mod.rs`:

Add `ConfigSummary` to the imports from `crate::types`.

Add two fields to `AppState` struct (after `is_testing_notification`):

```rust
/// Path to a custom config file (None = use default config cascade).
pub config_path: RwSignal<Option<String>>,
/// Validation summary of the loaded config file.
pub config_summary: RwSignal<Option<ConfigSummary>>,
```

Add to the `Default` impl:

```rust
config_path: RwSignal::new(None),
config_summary: RwSignal::new(None),
```

**Step 3: Verify it compiles**

Run: `cargo check -p hardener-ui --target wasm32-unknown-unknown`
Expected: success

**Step 4: Commit**

```bash
git add crates/hardener-ui/src/tauri_bindings.rs crates/hardener-ui/src/state/mod.rs
git commit -m "feat(ui): add config picker WASM bindings and AppState signals"
```

---

### Task 5: Create `ConfigFileCard` component

**Files:**
- Create: `crates/hardener-ui/src/components/config_file_card.rs`
- Modify: `crates/hardener-ui/src/components/mod.rs`

**Step 1: Create the component**

In `crates/hardener-ui/src/components/config_file_card.rs`:

```rust
//! Config file picker card for the Hardening page.
//!
//! Lets the user select a custom TOML config file via text input
//! or native file dialog, with inline validation feedback.

use crate::components::{Card, HeadingLevel};
use crate::state::AppState;
use crate::tauri_bindings::{invoke_pick_config_file, invoke_validate_config, tauri_available};
use leptos::prelude::*;

/// Config file picker with text input, browse button, and validation status.
#[component]
pub fn ConfigFileCard() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Local input value (mirrors app_state.config_path for the text field)
    let input_value = RwSignal::new(String::new());
    let is_validating = RwSignal::new(false);

    // Validate a path and update AppState
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
                    app_state.config_summary.set(Some(crate::types::ConfigSummary {
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

    // Handle blur / Enter on text input
    let on_blur = move |_| {
        let path = input_value.get_untracked();
        validate_path(path);
    };

    let on_keydown = move |ev: web_sys::KeyboardEvent| {
        if ev.key() == "Enter" {
            ev.prevent_default();
            let path = input_value.get_untracked();
            validate_path(path);
        }
    };

    // Browse button handler
    let on_browse = move |_| {
        leptos::task::spawn_local(async move {
            match invoke_pick_config_file().await {
                Ok(Some(path)) => {
                    input_value.set(path.clone());
                    validate_path(path);
                }
                Ok(None) => {} // Cancelled
                Err(e) => {
                    web_sys::console::error_1(&format!("File dialog error: {}", e).into());
                }
            }
        });
    };

    // Clear button handler
    let on_clear = move |_| {
        input_value.set(String::new());
        app_state.config_path.set(None);
        app_state.config_summary.set(None);
    };

    // Status line rendering
    let status_view = move || {
        if is_validating.get() {
            return view! { <span class="config-status config-validating">"Validating..."</span> }
                .into_any();
        }

        match app_state.config_summary.get() {
            None => {
                view! { <span class="config-status config-default">"Using default configuration"</span> }
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
        <Card title="Configuration File" title_level=HeadingLevel::H2 class="config-file-card">
            <div class="config-file-row">
                <input
                    type="text"
                    class="config-file-input"
                    placeholder="Using default configuration"
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
        </Card>
    }
}
```

**Step 2: Register in components/mod.rs**

Add to `crates/hardener-ui/src/components/mod.rs`:

```rust
mod config_file_card;
```

And the pub use:

```rust
pub use config_file_card::ConfigFileCard;
```

**Step 3: Verify it compiles**

Run: `cargo check -p hardener-ui --target wasm32-unknown-unknown`
Expected: success

**Step 4: Commit**

```bash
git add crates/hardener-ui/src/components/config_file_card.rs crates/hardener-ui/src/components/mod.rs
git commit -m "feat(ui): add ConfigFileCard component for config picker"
```

---

### Task 6: Wire ConfigFileCard into ConfigureSection

**Files:**
- Modify: `crates/hardener-ui/src/components/configure_section.rs`

**Step 1: Add ConfigFileCard to the view**

In `crates/hardener-ui/src/components/configure_section.rs`:

Add `ConfigFileCard` to the import from `crate::components`.

Insert `<ConfigFileCard />` in the view, between the `<p class="section-guidance">` and `<Card title="Security Profile" ...>`.

**Step 2: Verify it compiles**

Run: `cargo check -p hardener-ui --target wasm32-unknown-unknown`
Expected: success

**Step 3: Commit**

```bash
git add crates/hardener-ui/src/components/configure_section.rs
git commit -m "feat(ui): wire ConfigFileCard into Hardening page"
```

---

### Task 7: Thread config path through backend commands

**Files:**
- Modify: `src-tauri/src/commands.rs`
- Modify: `crates/hardener-ui/src/tauri_bindings.rs`
- Modify: `crates/hardener-ui/src/components/configure_section.rs`

This task connects the stored config path to the actual scan/apply/rollback operations.

**Step 1: Add `config_path` parameter to Tauri commands**

Modify the signatures of `run_scan`, `run_apply`, `run_apply_dry_run`, and `run_rollback` in `src-tauri/src/commands.rs` to accept an optional config path:

For `run_scan(plugin_ids, config_path)`:
- Add parameter: `config_path: Option<String>`
- When `config_path` is `Some(path)`, create a `ConfigLoader` with `.with_cli_config(PathBuf::from(path))` and call `.load()` to get a `HardenerConfig`
- Use `config.is_plugin_enabled()` to filter plugins and `config.get_plugin_config()` to pass per-plugin config

For `run_apply(plugin_ids, config_path)`:
- Add parameter: `config_path: Option<String>`
- When `Some(path)`, push `"--config"` and the path into the CLI args before calling `run_privileged_command`

For `run_apply_dry_run(plugin_ids, config_path)`:
- Add parameter: `config_path: Option<String>`
- When `Some(path)`, push `"--config"` and the path into the CLI args

For `run_rollback(checkpoint_id, config_path)`:
- Add parameter: `config_path: Option<String>`
- When `Some(path)`, push `"--config"` and the path into the CLI args

**Step 2: Update WASM bindings to pass config_path**

In `crates/hardener-ui/src/tauri_bindings.rs`, update `invoke_scan`, `invoke_apply`, `invoke_apply_dry_run`, and `invoke_rollback` to accept an `Option<String>` config_path and include it in the serialised args as `"configPath"`.

**Step 3: Update ConfigureSection to pass config_path**

In `crates/hardener-ui/src/components/configure_section.rs`, update the `on_preview` and `on_confirm_apply` handlers to read `app_state.config_path.get_untracked()` and pass it to the updated invoke functions.

**Step 4: Verify it compiles**

Run: `cargo check -p linux-hardener-desktop`
Expected: success

Run: `cargo check -p hardener-ui --target wasm32-unknown-unknown`
Expected: success

**Step 5: Run existing tests**

Run: `cargo test`
Expected: all pass (no regressions from Optional parameter additions)

**Step 6: Commit**

```bash
git add src-tauri/src/commands.rs crates/hardener-ui/src/tauri_bindings.rs crates/hardener-ui/src/components/configure_section.rs
git commit -m "feat: thread config path through scan, apply, dry-run, rollback"
```

---

### Task 8: Add CSS styles for ConfigFileCard

**Files:**
- Modify: `crates/hardener-ui/styles.css`

**Step 1: Add styles**

Add to `crates/hardener-ui/styles.css` (near the existing `.configure-section` or `.scheduler-page` styles):

```css
/* Config File Picker */
.config-file-card { margin-bottom: var(--space-md); }

.config-file-row {
    display: flex;
    gap: var(--space-sm);
    align-items: center;
}

.config-file-input {
    flex: 1;
    padding: var(--space-xs) var(--space-sm);
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    font-family: var(--font-mono);
    font-size: 0.875rem;
    transition: border-color var(--transition-fast);
}

.config-file-input:focus {
    outline: none;
    border-color: var(--color-accent);
    box-shadow: 0 0 0 2px rgba(var(--color-accent-rgb, 59, 130, 246), 0.15);
}

.config-file-input::placeholder {
    color: var(--text-muted);
    font-family: var(--font-body);
    font-style: italic;
}

.config-browse-btn { white-space: nowrap; }

.config-status-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-top: var(--space-xs);
    min-height: 1.5rem;
}

.config-status {
    font-size: 0.8125rem;
}

.config-default { color: var(--text-muted); }
.config-validating { color: var(--text-secondary); }

.config-valid {
    color: var(--color-success, #22c55e);
}

.config-valid .config-status-icon {
    font-weight: bold;
}

.config-invalid {
    color: var(--color-error, #ef4444);
}

.config-invalid .config-status-icon {
    font-weight: bold;
}

.config-clear-btn {
    background: none;
    border: none;
    color: var(--text-secondary);
    cursor: pointer;
    font-size: 0.8125rem;
    padding: 0;
    text-decoration: underline;
    transition: color var(--transition-fast);
}

.config-clear-btn:hover {
    color: var(--text-primary);
}
```

**Step 2: Verify it compiles**

Run: `cargo check -p hardener-ui --target wasm32-unknown-unknown`
Expected: success (CSS is separate, but checking WASM ensures nothing broke)

**Step 3: Commit**

```bash
git add crates/hardener-ui/styles.css
git commit -m "style: add CSS for config file picker card"
```

---

### Task 9: Add mock handler and update GUI tests

**Files:**
- Modify: `gui-tests/tauri-mock.js`

**Step 1: Add mock handlers**

In `gui-tests/tauri-mock.js`, add cases to the invoke handler for `validate_config` and `pick_config_file`:

```javascript
case 'validate_config':
    return {
        config_path: args.path,
        config_is_valid: true,
        config_error: null,
        config_enabled_plugins: ['kernel', 'ssh', 'firewall', 'pam', 'services', 'audit', 'permissions', 'mac'],
        config_directive_count: 3,
        config_exception_count: 1,
    };

case 'pick_config_file':
    return '/home/user/.config/linux-hardener/config.toml';
```

**Step 2: Commit**

```bash
git add gui-tests/tauri-mock.js
git commit -m "test: add config picker mock handlers for GUI tests"
```

---

### Task 10: Update documentation and ROADMAP

**Files:**
- Modify: `ROADMAP.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/FILE_MAP.md`

**Step 1: Mark Config file picker complete in ROADMAP.md**

Change the Config file picker row status from `⬜ Pending` to `✅ Complete`.

**Step 2: Add CHANGELOG entry**

Add under the latest `### Added` section:

```markdown
- **Config File Picker**: GUI equivalent of CLI `--config FILE` flag on Hardening page
  - Text input + native file dialog (Browse button) via `tauri-plugin-dialog`
  - Inline validation with one-line summary (plugin count, directives, exceptions)
  - Config path threaded through scan, apply, dry-run, and rollback commands
  - `ConfigSummary` type in `hardener-types` for WASM-safe validation results
```

**Step 3: Update FILE_MAP.md**

Add the new file entry for `config_file_card.rs` and `config_picker.rs`.

**Step 4: Commit**

```bash
git add ROADMAP.md CHANGELOG.md docs/FILE_MAP.md
git commit -m "docs: mark config file picker complete, update changelog and file map"
```

---

## Task Dependency Graph

```
Task 1 (types) ──────────┐
Task 2 (dialog dep) ─────┤
                          ├── Task 3 (Tauri commands) ── Task 7 (thread config)
Task 1 ───────────────────┤                                     │
                          ├── Task 4 (WASM + AppState) ─────────┤
                          │                                     │
                          └── Task 5 (component) ── Task 6 (wire) ── Task 8 (CSS)
                                                                │
                                                          Task 9 (mock)
                                                                │
                                                          Task 10 (docs)
```

Tasks 1 and 2 are independent and can run in parallel. Tasks 3-6 depend on both. Task 7 depends on 3-6. Tasks 8-10 follow linearly.
