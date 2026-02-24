//! Tauri command bindings for invoking backend functions from WASM.
//!
//! These bindings use wasm-bindgen to call Tauri's JavaScript invoke API.
//! In browser mode (without Tauri), all commands return errors gracefully.

use crate::types::{
    ApplyResult, CheckpointDetail, CheckpointInfo, ComplianceReport, ConfigSummary,
    PluginMetadata, RollbackResult, ScanResult, ScanSessionInfo, SchedulerUiConfig,
    TestNotificationResult,
};
use hardener_types::ValidationReport;
use hardener_types::remote::{RemoteConnectionStatus, RemoteHostProfile};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "core"], js_name = invoke, catch)]
    async fn tauri_invoke(cmd: &str, args: JsValue) -> Result<JsValue, JsValue>;
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

/// Invokes the run_scan Tauri command with an optional plugin filter.
///
/// Pass an empty vec to scan all plugins, or specific IDs to scan a subset.
pub async fn invoke_scan(plugin_ids: Vec<String>) -> Result<Vec<ScanResult>, String> {
    let args = if plugin_ids.is_empty() {
        JsValue::NULL
    } else {
        serde_wasm_bindgen::to_value(&serde_json::json!({
            "pluginIds": plugin_ids,
        }))
        .map_err(|e| format!("Failed to serialise arguments: {}", e))?
    };

    let result = invoke_command("run_scan", args).await?;

    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise scan result: {}", e))
}

/// Invokes the run_apply Tauri command.
///
/// Applies hardening changes for the specified plugins.
pub async fn invoke_apply(plugin_ids: Vec<String>) -> Result<Vec<ApplyResult>, String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "plugin_ids": plugin_ids,
    }))
    .map_err(|e| format!("Failed to serialise arguments: {}", e))?;

    let result = invoke_command("run_apply", args).await?;

    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise apply results: {}", e))
}

/// Invokes the run_apply_dry_run Tauri command.
///
/// Performs a dry-run preview of hardening changes without modifying the system.
pub async fn invoke_apply_dry_run(
    plugin_ids: Vec<String>,
) -> Result<Vec<ValidationReport>, String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "plugin_ids": plugin_ids,
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
/// Retrieves all available system checkpoints for rollback.
pub async fn invoke_get_checkpoints() -> Result<Vec<CheckpointInfo>, String> {
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
pub async fn invoke_get_scan_history(
    limit: Option<i32>,
) -> Result<Vec<ScanSessionInfo>, String> {
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

/// Invokes the list_plugins Tauri command.
///
/// Returns metadata for all available hardening plugins.
pub async fn invoke_list_plugins() -> Result<Vec<PluginMetadata>, String> {
    let result = invoke_command("list_plugins", JsValue::NULL).await?;

    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise plugin list: {}", e))
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
/// Restores system state to the specified checkpoint.
pub async fn invoke_rollback(checkpoint_id: String) -> Result<RollbackResult, String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "checkpoint_id": checkpoint_id,
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
pub async fn invoke_remote_scan(plugin_ids: Option<Vec<String>>) -> Result<Vec<ScanResult>, String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "pluginIds": plugin_ids,
    }))
    .map_err(|e| format!("Failed to serialise scan args: {}", e))?;
    let result = invoke_command("run_remote_scan", args).await?;
    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise remote scan results: {}", e))
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
