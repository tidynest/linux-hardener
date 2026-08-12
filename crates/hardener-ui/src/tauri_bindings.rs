//! Tauri command bindings for invoking backend functions from WASM.
//!
//! These bindings use wasm-bindgen to call Tauri's JavaScript invoke API.
//! In browser mode (without Tauri), all commands return errors gracefully.

use crate::types::{
    ApplyOutcome, ApplyResult, CheckpointDetail, CheckpointList, ComplianceReport, ConfigSummary,
    FleetHostScan, PluginMetadata, RollbackOutcome, RollbackResult, ScanResult, ScanSessionInfo,
    SchedulerUiConfig, TestNotificationResult, WrittenException,
};
use hardener_types::ValidationReport;
use hardener_types::remote::{HostSessionInfo, RemoteConnectionStatus, RemoteHostProfile};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "core"], js_name = invoke, catch)]
    async fn tauri_invoke(cmd: &str, args: JsValue) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "event"], js_name = listen, catch)]
    async fn tauri_event_listen(
        event: &str,
        handler: &js_sys::Function,
    ) -> Result<JsValue, JsValue>;
}

/// Active Tauri event subscription. Dropping it unsubscribes and releases the
/// handler closure: hold it for as long as events should be received.
pub struct EventSubscription {
    unlisten: js_sys::Function,
    _handler: Closure<dyn FnMut(JsValue)>,
}

impl Drop for EventSubscription {
    fn drop(&mut self) {
        let _ = self.unlisten.call0(&JsValue::NULL);
    }
}

/// Subscribes to a Tauri event, deserialising each event's `payload` into `T`
/// and passing it to `on_event`. Errors in browser mode (no Tauri runtime):
/// callers treat live updates as best-effort and fall back gracefully.
pub async fn listen_event<T, F>(event: &str, mut on_event: F) -> Result<EventSubscription, String>
where
    T: serde::de::DeserializeOwned,
    F: FnMut(T) + 'static,
{
    if !tauri_available() {
        return Err("Tauri not available (running in browser mode)".to_string());
    }
    let handler = Closure::wrap(Box::new(move |raw: JsValue| {
        let payload = js_sys::Reflect::get(&raw, &JsValue::from_str("payload")).unwrap_or(raw);
        if let Ok(value) = serde_wasm_bindgen::from_value::<T>(payload) {
            on_event(value);
        }
    }) as Box<dyn FnMut(JsValue)>);
    let unlisten = tauri_event_listen(event, handler.as_ref().unchecked_ref())
        .await
        .map_err(|e| format!("Failed to listen for {event}: {e:?}"))?;
    let unlisten: js_sys::Function = unlisten
        .dyn_into()
        .map_err(|_| format!("listen({event}) did not return an unlisten function"))?;
    Ok(EventSubscription {
        unlisten,
        _handler: handler,
    })
}

/// Check if Tauri runtime is available (running in desktop app vs browser).
#[wasm_bindgen(
    inline_js = "export function is_tauri_available() { return typeof window.__TAURI__ !== 'undefined'; }"
)]
extern "C" {
    fn is_tauri_available() -> bool;
}

/// Returns true if running inside Tauri desktop app, false if in browser.
pub fn tauri_available() -> bool {
    is_tauri_available()
}

/// Helper to invoke Tauri commands with proper error handling.
/// Returns an error immediately if Tauri is not available.
async fn invoke_command(cmd: &str, args: JsValue) -> Result<JsValue, String> {
    if !tauri_available() {
        return Err("Tauri not available (running in browser mode)".to_string());
    }

    match tauri_invoke(cmd, args).await {
        Ok(result) => Ok(result),
        Err(err) => {
            // Extract error message from JsValue
            let error_msg = if let Some(s) = err.as_string() {
                s
            } else {
                format!("{:?}", err)
            };
            Err(format!("Tauri command '{}' failed: {}", cmd, error_msg))
        }
    }
}

/// Invokes the run_scan Tauri command with an optional plugin filter and config path.
///
/// Pass an empty vec to scan all plugins, or specific IDs to scan a subset.
/// Pass a config path to use a custom configuration file.
pub async fn invoke_scan(
    plugin_ids: Vec<String>,
    config_path: Option<String>,
) -> Result<Vec<ScanResult>, String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "pluginIds": if plugin_ids.is_empty() { None } else { Some(plugin_ids) },
        "configPath": config_path,
    }))
    .map_err(|e| format!("Failed to serialise arguments: {}", e))?;

    let result = invoke_command("run_scan", args).await?;

    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise scan result: {}", e))
}

/// Invokes the run_deep_scan Tauri command: a pkexec-elevated scan whose
/// results match `sudo hardener scan`. One polkit prompt per invocation.
pub async fn invoke_deep_scan(
    plugin_ids: Vec<String>,
    config_path: Option<String>,
) -> Result<Vec<ScanResult>, String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "pluginIds": if plugin_ids.is_empty() { None } else { Some(plugin_ids) },
        "configPath": config_path,
    }))
    .map_err(|e| format!("Failed to serialise arguments: {}", e))?;

    let result = invoke_command("run_deep_scan", args).await?;

    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise scan result: {}", e))
}

/// Invokes the run_apply Tauri command.
///
/// Applies hardening changes for the specified plugins.
/// Pass a config path to use a custom configuration file.
pub async fn invoke_apply(
    plugin_ids: Vec<String>,
    config_path: Option<String>,
) -> Result<Vec<ApplyResult>, String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "pluginIds": plugin_ids,
        "configPath": config_path,
    }))
    .map_err(|e| format!("Failed to serialise arguments: {}", e))?;

    let result = invoke_command("run_apply", args).await?;

    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise apply results: {}", e))
}

/// Invokes the run_apply_dry_run Tauri command.
///
/// Performs a dry-run preview of hardening changes without modifying the system.
/// Pass a config path to use a custom configuration file.
pub async fn invoke_apply_dry_run(
    plugin_ids: Vec<String>,
    config_path: Option<String>,
) -> Result<Vec<ValidationReport>, String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "pluginIds": plugin_ids,
        "configPath": config_path,
    }))
    .map_err(|e| format!("Failed to serialise arguments: {}", e))?;

    let result = invoke_command("run_apply_dry_run", args).await?;

    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise arguments: {}", e))
}

/// Invokes the generate_compliance_report Tauri command
///
/// Generates compliance reports for the specified frameworks.
pub async fn invoke_generate_report(
    frameworks: Vec<String>,
) -> Result<Vec<ComplianceReport>, String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "frameworks": frameworks,
    }))
    .map_err(|e| format!("Failed to serialise arguments: {}", e))?;

    let result = invoke_command("generate_compliance_report", args).await?;

    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise generate compliance reports: {}", e))
}

/// Invokes the export_compliance_report Tauri command.
///
/// Generates reports, formats them, and saves to a file.
/// Returns the final file path used.
pub async fn invoke_export_report(
    frameworks: Vec<String>,
    format: String,
    output_path: Option<String>,
) -> Result<String, String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "frameworks": frameworks,
        "format": format,
        "outputPath": output_path,
    }))
    .map_err(|e| format!("Failed to serialise arguments: {}", e))?;

    let result = invoke_command("export_compliance_report", args).await?;

    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise export path: {}", e))
}

/// Invokes the get_latest_scan Tauri command.
///
/// Retrieves the most recent persisted scan results from the database.
/// Returns None if no completed scans exist.
pub async fn invoke_get_latest_scan() -> Result<Option<Vec<ScanResult>>, String> {
    let result = invoke_command("get_latest_scan", JsValue::NULL).await?;

    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise latest scan: {}", e))
}

/// Invokes the get_checkpoints Tauri command.
///
/// Retrieves all available system checkpoints for rollback, together with
/// whether the root-owned system database could be read. A list that silently
/// omits a source is indistinguishable from a complete one, so the caller
/// needs both halves.
pub async fn invoke_get_checkpoints() -> Result<CheckpointList, String> {
    let result = invoke_command("get_checkpoints", JsValue::NULL).await?;

    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise checkpoints: {}", e))
}

/// Invokes the create_checkpoint Tauri command.
///
/// Creates a manual checkpoint of the current system state.
/// Requires root privileges (prompts for password via polkit).
/// Returns the new checkpoint's ID.
pub async fn invoke_create_checkpoint(name: String) -> Result<String, String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "name": name,
    }))
    .map_err(|e| format!("Failed to serialise arguments: {}", e))?;

    let result = invoke_command("create_checkpoint", args).await?;

    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise checkpoint id: {}", e))
}

/// Invokes the delete_checkpoint Tauri command.
///
/// Deletes a checkpoint by ID. Tries user DB first, then system DB via pkexec.
pub async fn invoke_delete_checkpoint(checkpoint_id: String) -> Result<bool, String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "checkpointId": checkpoint_id,
    }))
    .map_err(|e| format!("Failed to serialise arguments: {}", e))?;

    let result = invoke_command("delete_checkpoint", args).await?;

    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise delete result: {}", e))
}

/// Invokes the get_scan_history Tauri command.
///
/// Returns recent scan session metadata (no results data).
pub async fn invoke_get_scan_history(limit: Option<i32>) -> Result<Vec<ScanSessionInfo>, String> {
    let args = match limit {
        Some(n) => serde_wasm_bindgen::to_value(&serde_json::json!({ "limit": n }))
            .map_err(|e| format!("Failed to serialise arguments: {}", e))?,
        None => JsValue::NULL,
    };

    let result = invoke_command("get_scan_history", args).await?;

    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise scan history: {}", e))
}

/// Invokes the get_scan_session Tauri command.
///
/// Returns full scan results for a specific session.
pub async fn invoke_get_scan_session(session_id: String) -> Result<Vec<ScanResult>, String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "sessionId": session_id,
    }))
    .map_err(|e| format!("Failed to serialise arguments: {}", e))?;

    let result = invoke_command("get_scan_session", args).await?;

    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise scan session: {}", e))
}

/// Invokes the get_checkpoint_detail Tauri command.
///
/// Returns detailed checkpoint information including captured files.
pub async fn invoke_get_checkpoint_detail(
    checkpoint_id: String,
) -> Result<CheckpointDetail, String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "checkpointId": checkpoint_id,
    }))
    .map_err(|e| format!("Failed to serialise arguments: {}", e))?;

    let result = invoke_command("get_checkpoint_detail", args).await?;

    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise checkpoint detail: {}", e))
}

/// Invokes the run_rollback Tauri command.
///
/// Restores system state to the specified checkpoint. Takes no config path:
/// `rollback` consults no policy, and the one that used to be sent reached the
/// CLI after the `--` separator, where clap read it as a second positional and
/// refused the command outright.
pub async fn invoke_rollback(checkpoint_id: String) -> Result<RollbackResult, String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "checkpointId": checkpoint_id,
    }))
    .map_err(|e| format!("Failed to serialise arguments: {}", e))?;

    let result = invoke_command("run_rollback", args).await?;

    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise rollback result: {}", e))
}

// === Remote Scanning Bindings ===

/// Invokes the list_remote_hosts Tauri command.
///
/// Returns all saved remote host profiles.
pub async fn invoke_list_remote_hosts() -> Result<Vec<RemoteHostProfile>, String> {
    let result = invoke_command("list_remote_hosts", JsValue::NULL).await?;
    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise remote hosts: {}", e))
}

/// Invokes the save_remote_host Tauri command.
///
/// Persists a remote host profile to the configuration file.
pub async fn invoke_save_remote_host(profile: RemoteHostProfile) -> Result<(), String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "profile": profile,
    }))
    .map_err(|e| format!("Failed to serialise profile: {}", e))?;
    invoke_command("save_remote_host", args).await?;
    Ok(())
}

/// Invokes the delete_remote_host Tauri command.
///
/// Removes a remote host profile by name.
pub async fn invoke_delete_remote_host(name: String) -> Result<(), String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "name": name,
    }))
    .map_err(|e| format!("Failed to serialise name: {}", e))?;
    invoke_command("delete_remote_host", args).await?;
    Ok(())
}

/// Invokes the connect_remote Tauri command.
///
/// Establishes an SSH connection to the named remote host.
pub async fn invoke_connect_remote(name: String) -> Result<RemoteConnectionStatus, String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "name": name,
    }))
    .map_err(|e| format!("Failed to serialise name: {}", e))?;
    let result = invoke_command("connect_remote", args).await?;
    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise connection status: {}", e))
}

/// Invokes the disconnect_remote Tauri command.
///
/// Closes the active SSH connection.
pub async fn invoke_disconnect_remote() -> Result<(), String> {
    invoke_command("disconnect_remote", JsValue::NULL).await?;
    Ok(())
}

/// Invokes the run_remote_scan Tauri command.
///
/// Runs a hardening scan on the connected remote host.
/// Pass plugin IDs to scan a subset, or None to scan all.
pub async fn invoke_remote_scan(
    plugin_ids: Option<Vec<String>>,
) -> Result<Vec<ScanResult>, String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "pluginIds": plugin_ids,
    }))
    .map_err(|e| format!("Failed to serialise scan args: {}", e))?;
    let result = invoke_command("run_remote_scan", args).await?;
    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise remote scan results: {}", e))
}

/// Invokes the run_fleet_scan Tauri command.
///
/// Scans the named inventory hosts plus ad-hoc `user@host[:port]` targets
/// concurrently and returns each host's severity posture. Pass plugin IDs to
/// scan a subset, or None for all.
pub async fn invoke_fleet_scan(
    host_names: Vec<String>,
    adhoc: Vec<String>,
    plugin_ids: Option<Vec<String>>,
) -> Result<Vec<FleetHostScan>, String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "hostNames": host_names,
        "adhoc": adhoc,
        "pluginIds": plugin_ids,
    }))
    .map_err(|e| format!("Failed to serialise fleet scan args: {}", e))?;
    let result = invoke_command("run_fleet_scan", args).await?;
    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise fleet scan results: {}", e))
}

/// Invokes run_fleet_apply. `execute = false` is a dry-run preview; an empty
/// `plugins` vector applies all plugins.
pub async fn invoke_fleet_apply(
    hosts: Vec<String>,
    adhoc: Vec<String>,
    plugins: Vec<String>,
    execute: bool,
) -> Result<Vec<ApplyOutcome>, String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "hosts": hosts, "adhoc": adhoc, "plugins": plugins, "execute": execute,
    }))
    .map_err(|e| format!("Failed to serialise fleet apply args: {}", e))?;
    let result = invoke_command("run_fleet_apply", args).await?;
    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise fleet apply results: {}", e))
}

/// Invokes run_fleet_rollback. `execute = false` previews; an empty `plugins`
/// vector rolls back all plugins.
pub async fn invoke_fleet_rollback(
    hosts: Vec<String>,
    adhoc: Vec<String>,
    plugins: Vec<String>,
    execute: bool,
) -> Result<Vec<RollbackOutcome>, String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "hosts": hosts, "adhoc": adhoc, "plugins": plugins, "execute": execute,
    }))
    .map_err(|e| format!("Failed to serialise fleet rollback args: {}", e))?;
    let result = invoke_command("run_fleet_rollback", args).await?;
    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise fleet rollback results: {}", e))
}

/// Invokes get_host_history: persisted per-host scan sessions from the
/// scheduler database (written by CLI batch/scheduled scans), newest first.
pub async fn invoke_get_host_history(
    host: String,
    limit: Option<u32>,
) -> Result<Vec<HostSessionInfo>, String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "host": host, "limit": limit,
    }))
    .map_err(|e| format!("Failed to serialise host history args: {}", e))?;
    let result = invoke_command("get_host_history", args).await?;
    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise host history: {}", e))
}

/// Invokes list_plugins for the plugin selector.
pub async fn invoke_list_plugins() -> Result<Vec<PluginMetadata>, String> {
    let result = invoke_command("list_plugins", JsValue::NULL).await?;
    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise plugin list: {}", e))
}

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
pub async fn invoke_save_scheduler_config(config: SchedulerUiConfig) -> Result<String, String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "config": config,
    }))
    .map_err(|e| format!("Failed to serialise scheduler config: {}", e))?;
    let result = invoke_command("save_scheduler_config", args).await?;
    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise save path: {}", e))
}

/// Invokes the test_notification Tauri command.
///
/// Sends a test notification through all enabled channels.
pub async fn invoke_test_notification() -> Result<TestNotificationResult, String> {
    let result = invoke_command("test_notification", JsValue::NULL).await?;
    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise test result: {}", e))
}

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

// === Policy Exception Bindings ===

/// Invokes add_policy_exception: writes a documented deviation for one finding.
///
/// Sends no value. The CLI behind this re-reads the host and pins what it
/// observes, so a row that has been open for days cannot write a stale pin.
pub async fn invoke_add_policy_exception(
    plugin_id: String,
    exception_key: String,
    reason: String,
    approved_by: Option<String>,
    ticket: Option<String>,
    expires: Option<String>,
) -> Result<WrittenException, String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "pluginId": plugin_id,
        "exceptionKey": exception_key,
        "reason": reason,
        "approvedBy": approved_by,
        "ticket": ticket,
        "expires": expires,
    }))
    .map_err(|e| format!("Failed to serialise arguments: {}", e))?;

    let result = invoke_command("add_policy_exception", args).await?;

    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise written exception: {}", e))
}

/// Invokes remove_policy_exception.
pub async fn invoke_remove_policy_exception(
    plugin_id: String,
    exception_key: String,
) -> Result<(), String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "pluginId": plugin_id,
        "exceptionKey": exception_key,
    }))
    .map_err(|e| format!("Failed to serialise arguments: {}", e))?;

    invoke_command("remove_policy_exception", args)
        .await
        .map(|_| ())
}
