# Remote Scanning UI — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a "Remote" page to the GUI that lets users save SSH host profiles, connect to remote machines, and run security scans over SSH.

**Architecture:** Tauri backend holds an `SshExecutor` in managed state. GUI sends connection details via IPC, Tauri connects and holds the session, then runs scans through it using the existing `PluginManager::scan()` pipeline. Results are standard `Vec<ScanResult>` — existing findings rendering works unchanged.

**Tech Stack:** Rust, Tauri v2, Leptos/WASM, openssh crate, TOML config, hardener-types

**Design doc:** `docs/plans/2026-02-24-remote-scanning-ui-design.md`

---

## Task 1: Remote types in hardener-types

**Files:**
- Create: `crates/hardener-types/src/remote.rs`
- Modify: `crates/hardener-types/src/lib.rs`

**Step 1: Create remote types module**

In `crates/hardener-types/src/remote.rs`:

```rust
//! Types for remote SSH scanning.

use serde::{Deserialize, Serialize};

/// A saved SSH host profile for remote scanning.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RemoteHostProfile {
    /// Display name (e.g., "web-01").
    pub name: String,
    /// Hostname or IP address.
    pub hostname: String,
    /// SSH username. None uses current system user.
    pub user: Option<String>,
    /// SSH port (default 22).
    #[serde(default = "default_port")]
    pub port: u16,
    /// Path to SSH private key. None uses SSH agent.
    pub key_file: Option<String>,
    /// Whether to verify remote host key (default true).
    #[serde(default = "default_true")]
    pub host_key_checking: bool,
}

fn default_port() -> u16 {
    22
}

fn default_true() -> bool {
    true
}

/// TOML file structure for saved host profiles.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HostsConfig {
    #[serde(default)]
    pub hosts: Vec<RemoteHostProfile>,
}

/// Result of an SSH connection attempt.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RemoteConnectionStatus {
    /// Successfully connected.
    Connected { host: String, user: String },
    /// Connection failed.
    Failed { error: String },
}

/// Active connection info for the UI.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemoteConnectionInfo {
    pub profile_name: String,
    pub host: String,
    pub user: String,
}
```

**Step 2: Register module in lib.rs**

In `crates/hardener-types/src/lib.rs`, add after line 11 (`pub use chrono::{DateTime, Utc};`):

```rust
pub mod remote;
pub use remote::*;
```

**Step 3: Verify it compiles**

Run: `cargo check -p hardener-types`
Expected: compiles cleanly

**Step 4: Commit**

```
feat(types): add remote SSH scanning types
```

---

## Task 2: TOML host profile persistence in Tauri

**Files:**
- Modify: `src-tauri/Cargo.toml` (add `toml` dependency)
- Modify: `src-tauri/src/commands.rs` (add 3 host management commands)
- Modify: `src-tauri/src/main.rs` (register commands + managed state)

**Step 1: Add toml dependency**

In `src-tauri/Cargo.toml`, add to `[dependencies]`:

```toml
toml = "0.8"
```

**Step 2: Add RemoteState and host persistence helpers**

In `src-tauri/src/commands.rs`, add at the top (with existing imports):

```rust
use hardener_types::remote::{HostsConfig, RemoteConnectionInfo, RemoteConnectionStatus, RemoteHostProfile};
use std::sync::Mutex;
```

Then add the `RemoteState` struct and helpers:

```rust
/// Managed state for remote SSH connections.
pub struct RemoteState {
    pub active_connection: Mutex<Option<ActiveConnection>>,
}

pub struct ActiveConnection {
    pub executor: std::sync::Arc<hardener_core::SshExecutor>,
    pub info: RemoteConnectionInfo,
}

/// Returns the path to the hosts config file (~/.config/linux-hardener/hosts.toml).
fn hosts_config_path() -> Result<std::path::PathBuf, String> {
    let config_dir = dirs::config_dir()
        .ok_or_else(|| "Cannot determine config directory".to_string())?
        .join("linux-hardener");
    std::fs::create_dir_all(&config_dir)
        .map_err(|e| format!("Failed to create config directory: {}", e))?;
    Ok(config_dir.join("hosts.toml"))
}

/// Loads host profiles from TOML config file.
fn load_hosts_config() -> Result<HostsConfig, String> {
    let path = hosts_config_path()?;
    if !path.exists() {
        return Ok(HostsConfig::default());
    }
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read hosts config: {}", e))?;
    toml::from_str(&content)
        .map_err(|e| format!("Failed to parse hosts config: {}", e))
}

/// Saves host profiles to TOML config file.
fn save_hosts_config(config: &HostsConfig) -> Result<(), String> {
    let path = hosts_config_path()?;
    let content = toml::to_string_pretty(config)
        .map_err(|e| format!("Failed to serialise hosts config: {}", e))?;
    std::fs::write(&path, content)
        .map_err(|e| format!("Failed to write hosts config: {}", e))
}
```

**Step 3: Implement 3 host management commands**

```rust
#[tauri::command]
pub async fn list_remote_hosts() -> Result<Vec<RemoteHostProfile>, String> {
    let config = load_hosts_config()?;
    Ok(config.hosts)
}

#[tauri::command]
pub async fn save_remote_host(profile: RemoteHostProfile) -> Result<(), String> {
    let mut config = load_hosts_config()?;
    // Upsert: replace existing profile with same name, or append
    if let Some(existing) = config.hosts.iter_mut().find(|h| h.name == profile.name) {
        *existing = profile;
    } else {
        config.hosts.push(profile);
    }
    save_hosts_config(&config)
}

#[tauri::command]
pub async fn delete_remote_host(name: String) -> Result<(), String> {
    let mut config = load_hosts_config()?;
    config.hosts.retain(|h| h.name != name);
    save_hosts_config(&config)
}
```

**Step 4: Register in main.rs**

In `src-tauri/src/main.rs`:

Add to imports (after existing `use commands::{...}`):

```rust
use commands::{
    // ... existing imports ...
    list_remote_hosts, save_remote_host, delete_remote_host,
    RemoteState,
};
```

Add `.manage()` before `.invoke_handler()`:

```rust
.manage(RemoteState {
    active_connection: std::sync::Mutex::new(None),
})
```

Add to `generate_handler![]`:

```rust
list_remote_hosts,
save_remote_host,
delete_remote_host,
```

**Step 5: Verify it compiles**

Run: `cargo check -p hardener-tauri` (or whatever the Tauri crate is named)
Expected: compiles cleanly

**Step 6: Commit**

```
feat(tauri): add host profile CRUD commands with TOML persistence
```

---

## Task 3: SSH connect/disconnect commands

**Files:**
- Modify: `src-tauri/src/commands.rs` (add connect, disconnect commands)
- Modify: `src-tauri/src/main.rs` (register 2 commands)

**Step 1: Implement connect_remote**

In `src-tauri/src/commands.rs`:

```rust
#[tauri::command]
pub async fn connect_remote(
    name: String,
    state: tauri::State<'_, RemoteState>,
) -> Result<RemoteConnectionStatus, String> {
    // Load profile by name
    let config = load_hosts_config()?;
    let profile = config
        .hosts
        .iter()
        .find(|h| h.name == name)
        .ok_or_else(|| format!("Host profile '{}' not found", name))?
        .clone();

    // Build SshConfig from profile
    let ssh_config = hardener_core::SshConfig {
        host: profile.hostname.clone(),
        port: profile.port,
        user: profile.user.clone(),
        identity_file: profile.key_file.clone(),
        known_hosts: if profile.host_key_checking {
            openssh::KnownHosts::Strict
        } else {
            openssh::KnownHosts::Accept
        },
        connect_timeout: std::time::Duration::from_secs(30),
    };

    // Attempt connection
    match hardener_core::SshExecutor::connect(ssh_config).await {
        Ok(executor) => {
            let user_display = profile.user.clone().unwrap_or_else(whoami::username);
            let info = RemoteConnectionInfo {
                profile_name: name,
                host: profile.hostname.clone(),
                user: user_display.clone(),
            };
            let mut connection = state.active_connection.lock()
                .map_err(|e| format!("Lock error: {}", e))?;
            *connection = Some(ActiveConnection {
                executor: std::sync::Arc::new(executor),
                info,
            });
            Ok(RemoteConnectionStatus::Connected {
                host: profile.hostname,
                user: user_display,
            })
        }
        Err(e) => Ok(RemoteConnectionStatus::Failed {
            error: format!("{}", e),
        }),
    }
}
```

**Step 2: Implement disconnect_remote**

```rust
#[tauri::command]
pub async fn disconnect_remote(
    state: tauri::State<'_, RemoteState>,
) -> Result<(), String> {
    let mut connection = state.active_connection.lock()
        .map_err(|e| format!("Lock error: {}", e))?;
    *connection = None;
    Ok(())
}
```

**Step 3: Check if `whoami` and `openssh` are in Tauri deps**

`openssh` is used via `hardener-core` (re-exported `KnownHosts`). Add `whoami` and check if `openssh` types are accessible. If `KnownHosts` isn't re-exported from `hardener-core`, add:

In `src-tauri/Cargo.toml`:
```toml
openssh = { workspace = true }
whoami = "1"
```

If `whoami` is already in the workspace, use `{ workspace = true }`.

**Step 4: Register in main.rs**

Add to imports and `generate_handler![]`:

```rust
connect_remote, disconnect_remote,
```

**Step 5: Verify it compiles**

Run: `cargo check -p hardener-tauri`
Expected: compiles cleanly (may need openssh/whoami dep adjustments)

**Step 6: Commit**

```
feat(tauri): add SSH connect/disconnect commands with managed state
```

---

## Task 4: Remote scan command

**Files:**
- Modify: `src-tauri/src/commands.rs` (add run_remote_scan)
- Modify: `src-tauri/src/main.rs` (register command)

**Step 1: Implement run_remote_scan**

In `src-tauri/src/commands.rs`:

```rust
#[tauri::command]
pub async fn run_remote_scan(
    plugin_ids: Option<Vec<String>>,
    state: tauri::State<'_, RemoteState>,
) -> Result<Vec<ScanResult>, String> {
    // Get active connection
    let executor = {
        let connection = state.active_connection.lock()
            .map_err(|e| format!("Lock error: {}", e))?;
        match connection.as_ref() {
            Some(conn) => conn.executor.clone(),
            None => return Err("No active remote connection".to_string()),
        }
    };
    // Release the lock before async work

    // Create context with SSH executor
    let context = hardener_core::Context::with_executor(executor);
    let registry = create_plugin_registry();

    // Determine which plugins to scan
    let plugins_to_scan: Vec<_> = if let Some(ref ids) = plugin_ids {
        if ids.is_empty() {
            registry.execution_order()
        } else {
            registry
                .execution_order()
                .into_iter()
                .filter(|p| ids.contains(&p.metadata().id.as_str().to_string()))
                .collect()
        }
    } else {
        registry.execution_order()
    };

    // Run scan (same pipeline as local)
    let mut results = Vec::new();
    for plugin in &plugins_to_scan {
        match plugin.scan(&context).await {
            Ok(result) => results.push(result),
            Err(e) => {
                tracing::error!("Remote scan error for {}: {}", plugin.metadata().name, e);
                results.push(ScanResult {
                    plugin_id: plugin.metadata().id.clone(),
                    plugin_name: plugin.metadata().name.clone(),
                    findings: vec![],
                    passed: false,
                    score: 0.0,
                    error: Some(format!("{}", e)),
                });
            }
        }
    }

    Ok(results)
}
```

Note: The exact `ScanResult` construction on error may need adjustment to match the struct's actual fields. Check `hardener-types` for the exact field names and adapt.

**Step 2: Register in main.rs**

Add `run_remote_scan` to imports and `generate_handler![]`.

**Step 3: Verify it compiles**

Run: `cargo check -p hardener-tauri`
Expected: compiles cleanly. May need to adjust `ScanResult` error field construction.

**Step 4: Commit**

```
feat(tauri): add run_remote_scan command using SshExecutor
```

---

## Task 5: WASM bindings for remote commands

**Files:**
- Modify: `crates/hardener-ui/src/tauri_bindings.rs` (add 6 invoke functions)

**Step 1: Add type imports**

At the top of `tauri_bindings.rs`, add to the existing imports from `crate::types`:

```rust
use hardener_types::remote::{RemoteConnectionStatus, RemoteHostProfile};
```

**Step 2: Add 6 binding functions**

Append to `tauri_bindings.rs` (following existing pattern):

```rust
// === Remote Scanning Bindings ===

pub async fn invoke_list_remote_hosts() -> Result<Vec<RemoteHostProfile>, String> {
    let result = invoke_command("list_remote_hosts", JsValue::NULL).await?;
    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise remote hosts: {}", e))
}

pub async fn invoke_save_remote_host(profile: RemoteHostProfile) -> Result<(), String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "profile": profile,
    }))
    .map_err(|e| format!("Failed to serialise profile: {}", e))?;
    invoke_command("save_remote_host", args).await?;
    Ok(())
}

pub async fn invoke_delete_remote_host(name: String) -> Result<(), String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "name": name,
    }))
    .map_err(|e| format!("Failed to serialise name: {}", e))?;
    invoke_command("delete_remote_host", args).await?;
    Ok(())
}

pub async fn invoke_connect_remote(name: String) -> Result<RemoteConnectionStatus, String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "name": name,
    }))
    .map_err(|e| format!("Failed to serialise name: {}", e))?;
    let result = invoke_command("connect_remote", args).await?;
    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise connection status: {}", e))
}

pub async fn invoke_disconnect_remote() -> Result<(), String> {
    invoke_command("disconnect_remote", JsValue::NULL).await?;
    Ok(())
}

pub async fn invoke_remote_scan(plugin_ids: Option<Vec<String>>) -> Result<Vec<ScanResult>, String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "pluginIds": plugin_ids,
    }))
    .map_err(|e| format!("Failed to serialise scan args: {}", e))?;
    let result = invoke_command("run_remote_scan", args).await?;
    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise remote scan results: {}", e))
}
```

**Step 3: Verify it compiles**

Run: `cargo check -p hardener-ui --target wasm32-unknown-unknown`
Expected: compiles cleanly

**Step 4: Commit**

```
feat(ui): add WASM bindings for 6 remote scanning IPC commands
```

---

## Task 6: AppState remote signals

**Files:**
- Modify: `crates/hardener-ui/src/state/mod.rs` (add 5 signals)

**Step 1: Add import**

At line 1 of `state/mod.rs`, add `RemoteConnectionInfo` to the imports. Since it's in `hardener_types::remote`, add:

```rust
use hardener_types::remote::RemoteConnectionInfo;
use hardener_types::remote::RemoteHostProfile;
```

**Step 2: Add 5 signals to AppState**

After `error_message` field (line 43), add:

```rust
    /// Saved remote host profiles.
    pub remote_hosts: RwSignal<Vec<RemoteHostProfile>>,
    /// Currently active remote connection info (None = disconnected).
    pub remote_connection: RwSignal<Option<RemoteConnectionInfo>>,
    /// Results from the most recent remote scan.
    pub remote_scan_results: RwSignal<Vec<ScanResult>>,
    /// Whether an SSH connection attempt is in progress.
    pub is_connecting: RwSignal<bool>,
    /// Whether a remote scan is currently running.
    pub is_remote_scanning: RwSignal<bool>,
```

**Step 3: Add defaults**

In the `Default` impl, after `error_message` init (line 61), add:

```rust
            remote_hosts: RwSignal::new(Vec::new()),
            remote_connection: RwSignal::new(None),
            remote_scan_results: RwSignal::new(Vec::new()),
            is_connecting: RwSignal::new(false),
            is_remote_scanning: RwSignal::new(false),
```

**Step 4: Verify it compiles**

Run: `cargo check -p hardener-ui --target wasm32-unknown-unknown`
Expected: compiles cleanly

**Step 5: Commit**

```
feat(ui): add remote scanning signals to AppState
```

---

## Task 7: Remote page — skeleton + routing

**Files:**
- Create: `crates/hardener-ui/src/pages/remote_page.rs`
- Modify: `crates/hardener-ui/src/pages/mod.rs` (register + export)
- Modify: `crates/hardener-ui/src/lib.rs` (add route + nav link)

**Step 1: Create RemotePage skeleton**

In `crates/hardener-ui/src/pages/remote_page.rs`:

```rust
//! Remote scanning page — manage SSH hosts and scan remote systems.

use crate::components::Card;
use crate::state::AppState;
use leptos::prelude::*;

/// Remote scanning page with two-panel layout:
/// left panel for saved hosts, right panel for connection status and scan results.
#[component]
pub fn RemotePage() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    view! {
        <div class="remote-page">
            <Card title="Remote Scanning".to_string()>
                <div class="remote-layout">
                    <aside class="remote-sidebar">
                        <p class="empty-state-text">"Host list will go here."</p>
                    </aside>
                    <section class="remote-main">
                        <p class="empty-state-text">"Select a host or add a new one to get started."</p>
                    </section>
                </div>
            </Card>
        </div>
    }
}
```

**Step 2: Register in pages/mod.rs**

Add to `crates/hardener-ui/src/pages/mod.rs`:

```rust
pub mod remote_page;
pub use remote_page::RemotePage;
```

**Step 3: Add route and nav link in lib.rs**

In `crates/hardener-ui/src/lib.rs`:

Update import (line 15):
```rust
use pages::{AnalysisPage, DashboardPage, HardeningPage, RemotePage};
```

Add nav link after "Hardening" (line 59):
```rust
<li><A href="/remote">"Remote"</A></li>
```

Add route after hardening route (line 92):
```rust
<Route path=StaticSegment("remote") view=RemotePage/>
```

**Step 4: Add basic CSS**

In `crates/hardener-ui/styles.css`, append:

```css
/* === Remote Scanning Page === */

.remote-page {
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
}

.remote-layout {
    display: grid;
    grid-template-columns: 280px 1fr;
    gap: var(--space-lg);
    min-height: 400px;
}

.remote-sidebar {
    border-right: 1px solid var(--border-color);
    padding-right: var(--space-md);
}

.remote-main {
    min-width: 0;
}

@media (max-width: 768px) {
    .remote-layout {
        grid-template-columns: 1fr;
    }
    .remote-sidebar {
        border-right: none;
        border-bottom: 1px solid var(--border-color);
        padding-right: 0;
        padding-bottom: var(--space-md);
    }
}
```

**Step 5: Verify it compiles**

Run: `cargo check -p hardener-ui --target wasm32-unknown-unknown`
Expected: compiles cleanly

**Step 6: Commit**

```
feat(ui): add Remote page skeleton with routing and navigation
```

---

## Task 8: HostList component

**Files:**
- Create: `crates/hardener-ui/src/components/host_list.rs`
- Modify: `crates/hardener-ui/src/components/mod.rs` (register + export)

**Step 1: Create HostList component**

In `crates/hardener-ui/src/components/host_list.rs`:

```rust
//! Sidebar component listing saved remote host profiles.

use crate::state::AppState;
use crate::tauri_bindings;
use hardener_types::remote::RemoteHostProfile;
use leptos::prelude::*;

#[component]
pub fn HostList(
    /// Callback when user wants to add/edit a host.
    #[prop(into)]
    on_edit: Callback<Option<RemoteHostProfile>>,
) -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Load hosts on mount
    leptos::task::spawn_local(async move {
        if let Ok(hosts) = tauri_bindings::invoke_list_remote_hosts().await {
            app_state.remote_hosts.set(hosts);
        }
    });

    let on_connect = move |name: String| {
        let app_state = app_state;
        app_state.is_connecting.set(true);
        leptos::task::spawn_local(async move {
            match tauri_bindings::invoke_connect_remote(name).await {
                Ok(status) => {
                    match status {
                        hardener_types::remote::RemoteConnectionStatus::Connected { host, user } => {
                            app_state.remote_connection.set(Some(
                                hardener_types::remote::RemoteConnectionInfo {
                                    profile_name: host.clone(),
                                    host,
                                    user,
                                },
                            ));
                        }
                        hardener_types::remote::RemoteConnectionStatus::Failed { error } => {
                            app_state.error_message.set(Some(format!("Connection failed: {}", error)));
                        }
                    }
                }
                Err(e) => {
                    app_state.error_message.set(Some(format!("Connection error: {}", e)));
                }
            }
            app_state.is_connecting.set(false);
        });
    };

    let on_delete = move |name: String| {
        let app_state = app_state;
        leptos::task::spawn_local(async move {
            if let Err(e) = tauri_bindings::invoke_delete_remote_host(name).await {
                app_state.error_message.set(Some(format!("Delete failed: {}", e)));
                return;
            }
            // Reload host list
            if let Ok(hosts) = tauri_bindings::invoke_list_remote_hosts().await {
                app_state.remote_hosts.set(hosts);
            }
        });
    };

    view! {
        <div class="host-list">
            <h3 class="host-list-title">"Saved Hosts"</h3>
            <Show
                when=move || !app_state.remote_hosts.get().is_empty()
                fallback=|| view! {
                    <p class="empty-state-text">"No saved hosts yet."</p>
                }
            >
                <ul class="host-entries">
                    <For
                        each=move || app_state.remote_hosts.get()
                        key=|host| host.name.clone()
                        children=move |host: RemoteHostProfile| {
                            let name = host.name.clone();
                            let display = format!(
                                "{}@{}",
                                host.user.as_deref().unwrap_or("(agent)"),
                                host.hostname
                            );
                            let connect_name = name.clone();
                            let delete_name = name.clone();
                            let edit_host = host.clone();
                            let on_connect = on_connect.clone();
                            let on_delete = on_delete.clone();
                            let on_edit = on_edit.clone();
                            let is_connected = move || {
                                app_state.remote_connection.get()
                                    .as_ref()
                                    .map_or(false, |c| c.profile_name == name)
                            };

                            view! {
                                <li class="host-entry" class:host-entry--active=is_connected>
                                    <div class="host-entry-info">
                                        <span class="host-entry-name">{name.clone()}</span>
                                        <span class="host-entry-detail">{display}</span>
                                    </div>
                                    <div class="host-entry-actions">
                                        <button
                                            class="btn btn-primary btn-small"
                                            on:click={
                                                let on_connect = on_connect.clone();
                                                let connect_name = connect_name.clone();
                                                move |_| on_connect(connect_name.clone())
                                            }
                                            disabled=move || app_state.is_connecting.get()
                                        >
                                            {move || if is_connected() { "Reconnect" } else { "Connect" }}
                                        </button>
                                        <button
                                            class="btn btn-secondary btn-small"
                                            on:click={
                                                let on_edit = on_edit.clone();
                                                let edit_host = edit_host.clone();
                                                move |_| on_edit.run(Some(edit_host.clone()))
                                            }
                                        >
                                            "Edit"
                                        </button>
                                        <button
                                            class="btn btn-danger btn-small"
                                            on:click={
                                                let on_delete = on_delete.clone();
                                                let delete_name = delete_name.clone();
                                                move |_| on_delete(delete_name.clone())
                                            }
                                        >
                                            "Delete"
                                        </button>
                                    </div>
                                </li>
                            }
                        }
                    />
                </ul>
            </Show>
            <button
                class="btn btn-secondary host-add-button"
                on:click=move |_| on_edit.run(None)
            >
                "+ Add Host"
            </button>
        </div>
    }
}
```

Note: The exact Leptos `Callback`, `For`, `Show`, and closure patterns may need adaptation based on the Leptos version in use. Check existing components (e.g., `configure_section.rs`, `history_section.rs`) for the exact API.

**Step 2: Register in components/mod.rs**

Add to `crates/hardener-ui/src/components/mod.rs`:

```rust
mod host_list;
pub use host_list::HostList;
```

**Step 3: Add CSS for host list**

Append to `crates/hardener-ui/styles.css`:

```css
/* --- Host List Sidebar --- */

.host-list-title {
    font-size: 1rem;
    font-weight: 600;
    margin-bottom: var(--space-sm);
    color: var(--text-primary);
}

.host-entries {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
}

.host-entry {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
    padding: var(--space-sm);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-sm, 6px);
    background: var(--bg-secondary);
    transition: border-color var(--transition-fast);
}

.host-entry:hover {
    border-color: var(--color-accent);
}

.host-entry--active {
    border-color: var(--color-accent);
    background: var(--bg-tertiary, var(--bg-secondary));
}

.host-entry-info {
    display: flex;
    flex-direction: column;
}

.host-entry-name {
    font-weight: 600;
    font-size: 0.9rem;
    color: var(--text-primary);
}

.host-entry-detail {
    font-size: 0.8rem;
    color: var(--text-muted);
    font-family: var(--font-mono);
}

.host-entry-actions {
    display: flex;
    gap: var(--space-xs);
    flex-wrap: wrap;
}

.host-add-button {
    width: 100%;
    margin-top: var(--space-sm);
}
```

**Step 4: Verify it compiles**

Run: `cargo check -p hardener-ui --target wasm32-unknown-unknown`
Expected: compiles cleanly

**Step 5: Commit**

```
feat(ui): add HostList sidebar component with connect/edit/delete
```

---

## Task 9: HostForm component

> **User contribution opportunity:** The form validation logic is a good candidate for the user to implement — there are trade-offs around which fields to validate and how strictly.

**Files:**
- Create: `crates/hardener-ui/src/components/host_form.rs`
- Modify: `crates/hardener-ui/src/components/mod.rs` (register + export)

**Step 1: Create HostForm component**

In `crates/hardener-ui/src/components/host_form.rs`:

```rust
//! Form component for adding or editing a remote host profile.

use crate::state::AppState;
use crate::tauri_bindings;
use hardener_types::remote::RemoteHostProfile;
use leptos::prelude::*;

#[component]
pub fn HostForm(
    /// Existing profile to edit (None = add new).
    #[prop(optional)]
    existing: Option<RemoteHostProfile>,
    /// Callback when form is submitted or cancelled.
    #[prop(into)]
    on_close: Callback<()>,
) -> impl IntoView {
    let app_state = expect_context::<AppState>();
    let is_edit = existing.is_some();

    let name = RwSignal::new(existing.as_ref().map_or(String::new(), |p| p.name.clone()));
    let hostname = RwSignal::new(existing.as_ref().map_or(String::new(), |p| p.hostname.clone()));
    let user = RwSignal::new(existing.as_ref().and_then(|p| p.user.clone()).unwrap_or_default());
    let port = RwSignal::new(existing.as_ref().map_or(22u16, |p| p.port));
    let key_file = RwSignal::new(existing.as_ref().and_then(|p| p.key_file.clone()).unwrap_or_default());
    let host_key_checking = RwSignal::new(existing.as_ref().map_or(true, |p| p.host_key_checking));
    let is_saving = RwSignal::new(false);

    // TODO(user): implement validate_form() — see design doc for field constraints
    let is_valid = move || {
        !name.get().trim().is_empty() && !hostname.get().trim().is_empty()
    };

    let on_submit = move |_| {
        if !is_valid() {
            return;
        }
        is_saving.set(true);
        let profile = RemoteHostProfile {
            name: name.get().trim().to_string(),
            hostname: hostname.get().trim().to_string(),
            user: {
                let u = user.get();
                if u.trim().is_empty() { None } else { Some(u.trim().to_string()) }
            },
            port: port.get(),
            key_file: {
                let k = key_file.get();
                if k.trim().is_empty() { None } else { Some(k.trim().to_string()) }
            },
            host_key_checking: host_key_checking.get(),
        };
        let on_close = on_close.clone();
        leptos::task::spawn_local(async move {
            match tauri_bindings::invoke_save_remote_host(profile).await {
                Ok(()) => {
                    // Reload hosts
                    if let Ok(hosts) = tauri_bindings::invoke_list_remote_hosts().await {
                        app_state.remote_hosts.set(hosts);
                    }
                    on_close.run(());
                }
                Err(e) => {
                    app_state.error_message.set(Some(format!("Save failed: {}", e)));
                }
            }
            is_saving.set(false);
        });
    };

    view! {
        <div class="host-form">
            <h3>{if is_edit { "Edit Host" } else { "Add Host" }}</h3>
            <div class="form-field">
                <label for="host-name">"Display Name"</label>
                <input
                    id="host-name"
                    type="text"
                    class="input-text"
                    placeholder="e.g. web-01"
                    prop:value=move || name.get()
                    on:input=move |ev| name.set(event_target_value(&ev))
                />
            </div>
            <div class="form-field">
                <label for="host-hostname">"Hostname / IP"</label>
                <input
                    id="host-hostname"
                    type="text"
                    class="input-text"
                    placeholder="e.g. 192.168.1.10"
                    prop:value=move || hostname.get()
                    on:input=move |ev| hostname.set(event_target_value(&ev))
                />
            </div>
            <div class="form-field">
                <label for="host-user">"Username (optional)"</label>
                <input
                    id="host-user"
                    type="text"
                    class="input-text"
                    placeholder="Uses current user if empty"
                    prop:value=move || user.get()
                    on:input=move |ev| user.set(event_target_value(&ev))
                />
            </div>
            <div class="form-field">
                <label for="host-port">"Port"</label>
                <input
                    id="host-port"
                    type="number"
                    class="input-text"
                    min="1"
                    max="65535"
                    prop:value=move || port.get().to_string()
                    on:input=move |ev| {
                        if let Ok(p) = event_target_value(&ev).parse::<u16>() {
                            port.set(p);
                        }
                    }
                />
            </div>
            <div class="form-field">
                <label for="host-key">"Key File Path (optional)"</label>
                <input
                    id="host-key"
                    type="text"
                    class="input-text"
                    placeholder="Uses SSH agent if empty"
                    prop:value=move || key_file.get()
                    on:input=move |ev| key_file.set(event_target_value(&ev))
                />
            </div>
            <div class="form-field form-field-checkbox">
                <label>
                    <input
                        type="checkbox"
                        checked=move || host_key_checking.get()
                        on:change=move |_| host_key_checking.update(|v| *v = !*v)
                    />
                    " Verify host key (recommended)"
                </label>
            </div>
            <div class="form-actions">
                <button
                    class="btn btn-primary"
                    on:click=on_submit
                    disabled=move || is_saving.get() || !is_valid()
                >
                    {move || if is_saving.get() { "Saving..." } else { "Save" }}
                </button>
                <button
                    class="btn btn-secondary"
                    on:click={
                        let on_close = on_close.clone();
                        move |_| on_close.run(())
                    }
                >
                    "Cancel"
                </button>
            </div>
        </div>
    }
}
```

**Step 2: Register in components/mod.rs**

```rust
mod host_form;
pub use host_form::HostForm;
```

**Step 3: Add CSS for host form**

Append to `crates/hardener-ui/styles.css`:

```css
/* --- Host Form --- */

.host-form {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    padding: var(--space-md);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-sm, 6px);
    background: var(--bg-secondary);
}

.host-form h3 {
    margin: 0 0 var(--space-xs);
    font-size: 1rem;
    color: var(--text-primary);
}

.form-field {
    display: flex;
    flex-direction: column;
    gap: var(--space-2xs, 4px);
}

.form-field label {
    font-size: 0.85rem;
    font-weight: 500;
    color: var(--text-secondary);
}

.form-field-checkbox label {
    display: flex;
    align-items: center;
    gap: var(--space-xs);
    font-size: 0.9rem;
    color: var(--text-primary);
    cursor: pointer;
}

.form-actions {
    display: flex;
    gap: var(--space-sm);
    margin-top: var(--space-xs);
}
```

**Step 4: Verify it compiles**

Run: `cargo check -p hardener-ui --target wasm32-unknown-unknown`

**Step 5: Commit**

```
feat(ui): add HostForm component for adding/editing host profiles
```

---

## Task 10: RemoteStatus component

**Files:**
- Create: `crates/hardener-ui/src/components/remote_status.rs`
- Modify: `crates/hardener-ui/src/components/mod.rs` (register + export)

**Step 1: Create RemoteStatus component**

In `crates/hardener-ui/src/components/remote_status.rs`:

```rust
//! Right panel showing connection status, scan controls, and remote scan results.

use crate::components::SeverityBadge;
use crate::state::AppState;
use crate::tauri_bindings;
use leptos::prelude::*;

#[component]
pub fn RemoteStatus() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    let on_scan = move |_| {
        app_state.is_remote_scanning.set(true);
        leptos::task::spawn_local(async move {
            match tauri_bindings::invoke_remote_scan(None).await {
                Ok(results) => {
                    app_state.remote_scan_results.set(results);
                }
                Err(e) => {
                    app_state.error_message.set(Some(format!("Remote scan failed: {}", e)));
                }
            }
            app_state.is_remote_scanning.set(false);
        });
    };

    let on_disconnect = move |_| {
        leptos::task::spawn_local(async move {
            if let Err(e) = tauri_bindings::invoke_disconnect_remote().await {
                app_state.error_message.set(Some(format!("Disconnect failed: {}", e)));
                return;
            }
            app_state.remote_connection.set(None);
            app_state.remote_scan_results.set(Vec::new());
        });
    };

    let total_findings = move || {
        app_state.remote_scan_results.get()
            .iter()
            .map(|r| r.findings.len())
            .sum::<usize>()
    };

    view! {
        <div class="remote-status">
            <Show
                when=move || app_state.remote_connection.get().is_some()
                fallback=move || view! {
                    <div class="remote-empty">
                        <div class="remote-empty-icon">"🌐"</div>
                        <p>"Select a host and connect to start remote scanning."</p>
                    </div>
                }
            >
                {move || {
                    let conn = app_state.remote_connection.get().unwrap();
                    view! {
                        <div class="remote-connected">
                            <div class="remote-connected-header">
                                <div class="remote-connected-info">
                                    <span class="remote-connected-label">"Connected to"</span>
                                    <span class="remote-connected-host">
                                        {format!("{}@{}", conn.user, conn.host)}
                                    </span>
                                </div>
                                <div class="remote-connected-actions">
                                    <button
                                        class="btn btn-primary"
                                        on:click=on_scan
                                        disabled=move || app_state.is_remote_scanning.get()
                                    >
                                        {move || if app_state.is_remote_scanning.get() {
                                            "Scanning..."
                                        } else {
                                            "Run Scan"
                                        }}
                                    </button>
                                    <button
                                        class="btn btn-secondary"
                                        on:click=on_disconnect
                                        disabled=move || app_state.is_remote_scanning.get()
                                    >
                                        "Disconnect"
                                    </button>
                                </div>
                            </div>

                            // Show scan results if available
                            <Show when=move || !app_state.remote_scan_results.get().is_empty()>
                                <div class="remote-results">
                                    <h4 class="remote-results-title">
                                        {move || format!("Scan Results — {} findings", total_findings())}
                                    </h4>
                                    <table class="findings-table">
                                        <thead>
                                            <tr>
                                                <th>"Plugin"</th>
                                                <th>"Finding"</th>
                                                <th>"Severity"</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <For
                                                each=move || {
                                                    app_state.remote_scan_results.get()
                                                        .iter()
                                                        .flat_map(|r| {
                                                            let plugin = r.plugin_name.clone();
                                                            r.findings.iter().map(move |f| {
                                                                (plugin.clone(), f.clone())
                                                            }).collect::<Vec<_>>()
                                                        })
                                                        .collect::<Vec<_>>()
                                                }
                                                key=|(plugin, finding)| format!("{}-{}", plugin, finding.title)
                                                children=move |(plugin, finding)| {
                                                    view! {
                                                        <tr>
                                                            <td>{plugin}</td>
                                                            <td>{finding.title.clone()}</td>
                                                            <td><SeverityBadge severity=finding.severity/></td>
                                                        </tr>
                                                    }
                                                }
                                            />
                                        </tbody>
                                    </table>
                                </div>
                            </Show>
                        </div>
                    }
                }}
            </Show>
        </div>
    }
}
```

Note: The exact field names on `ScanResult` and `Finding` (e.g., `findings`, `title`, `severity`, `plugin_name`) must match the actual types in `hardener-types`. Check and adapt accordingly.

**Step 2: Register in components/mod.rs**

```rust
mod remote_status;
pub use remote_status::RemoteStatus;
```

**Step 3: Add CSS**

Append to `crates/hardener-ui/styles.css`:

```css
/* --- Remote Status Panel --- */

.remote-empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: var(--space-2xl);
    color: var(--text-muted);
    text-align: center;
}

.remote-empty-icon {
    font-size: 2.5rem;
    margin-bottom: var(--space-sm);
}

.remote-connected-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: var(--space-sm) var(--space-md);
    background: var(--bg-secondary);
    border: 1px solid var(--color-accent);
    border-radius: var(--radius-sm, 6px);
    margin-bottom: var(--space-md);
}

.remote-connected-info {
    display: flex;
    flex-direction: column;
}

.remote-connected-label {
    font-size: 0.8rem;
    color: var(--text-muted);
}

.remote-connected-host {
    font-family: var(--font-mono);
    font-weight: 600;
    color: var(--color-accent);
}

.remote-connected-actions {
    display: flex;
    gap: var(--space-sm);
}

.remote-results {
    margin-top: var(--space-md);
}

.remote-results-title {
    font-size: 1rem;
    font-weight: 600;
    margin-bottom: var(--space-sm);
    color: var(--text-primary);
}
```

**Step 4: Verify it compiles**

Run: `cargo check -p hardener-ui --target wasm32-unknown-unknown`

**Step 5: Commit**

```
feat(ui): add RemoteStatus panel with scan trigger and results table
```

---

## Task 11: Wire RemotePage with child components

**Files:**
- Modify: `crates/hardener-ui/src/pages/remote_page.rs` (replace skeleton with full layout)

**Step 1: Update RemotePage to use HostList, HostForm, RemoteStatus**

Replace the skeleton in `remote_page.rs` with the full two-panel layout that toggles between host list and form, and shows RemoteStatus on the right.

The page should manage:
- `show_form: RwSignal<bool>` — whether to show add/edit form
- `editing_host: RwSignal<Option<RemoteHostProfile>>` — host being edited

When `show_form` is true, show `HostForm` instead of `HostList` in the sidebar.

Load remote hosts on mount via `invoke_list_remote_hosts()`.

**Step 2: Verify it compiles**

Run: `cargo check -p hardener-ui --target wasm32-unknown-unknown`

**Step 3: Commit**

```
feat(ui): wire RemotePage with HostList, HostForm, and RemoteStatus
```

---

## Task 12: Build and visual test

**Step 1: Build WASM**

Run: `trunk build --release` (or the project's WASM build command)
Expected: builds successfully

**Step 2: Build Tauri**

Run: `cargo build -p hardener-tauri` (or `cargo tauri build`)
Expected: builds successfully

**Step 3: Run native tests**

Run: `cargo test`
Expected: all existing tests pass (no regressions)

**Step 4: Visual smoke test**

Launch the app, navigate to the Remote page, verify:
- Page renders with two-panel layout
- "Add Host" button opens the form
- Form fields work (text input, checkbox, port number)
- Saving a host persists to `~/.config/linux-hardener/hosts.toml`
- Host appears in the sidebar after save
- Connect button triggers SSH connection attempt

**Step 5: Commit**

```
feat: complete remote scanning UI — host management + SSH scan
```

---

## Task 13: Update documentation

**Files:**
- Modify: `ROADMAP.md` (mark Remote scanning UI as complete)
- Modify: `CHANGELOG.md` (if it exists)

**Step 1: Update ROADMAP.md**

Change the Remote scanning UI row from `Pending` to `Complete`:

```
| Remote scanning UI | `--ssh` flags | P3 | ✅ Complete |
```

**Step 2: Commit**

```
docs: mark remote scanning UI as complete in roadmap
```

---

## Summary

| Task | Description | Estimated complexity |
|------|-------------|---------------------|
| 1 | Remote types in hardener-types | Small |
| 2 | TOML host persistence + 3 CRUD commands | Medium |
| 3 | SSH connect/disconnect commands | Medium |
| 4 | Remote scan command | Medium |
| 5 | WASM bindings (6 functions) | Small |
| 6 | AppState signals (5 fields) | Small |
| 7 | RemotePage skeleton + routing | Small |
| 8 | HostList component | Medium |
| 9 | HostForm component | Medium |
| 10 | RemoteStatus component | Medium |
| 11 | Wire page with children | Small |
| 12 | Build + visual test | Medium |
| 13 | Documentation update | Small |

**Total: 13 tasks, ~5 new files, ~7 modified files**
