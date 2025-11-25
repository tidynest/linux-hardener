//! Tauri command bindings for invoking backend functions from WASM.
//!
//! These bindings use wasm-bindgen to call Tauri's JavaScript invoke API.

#[allow(unused_macros)]
use crate::types::{ApplyResult, ScanResult};

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "core"], js_name = invoke)]
    async fn tauri_invoke(cmd: &str, args: JsValue) -> JsValue;
}

/// Invokes the run_scan Tauri command.
///
/// Returns scan results from all registered plugins.
pub async fn invoke_scan() -> Result<Vec<ScanResult>, String> {
    let result = tauri_invoke("run_scan", JsValue::NULL).await;

    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise scan result: {}", e))
}

/// Invokes the run_apply Tauri command.
///
/// Applies hardening changes for the specified plugins.
pub async fn invoke_apply(plugin_ids: Vec<String>
) -> Result<Vec<ApplyResult>, String> {
    let args = serde_wasm_bindgen::to_value(&serde_json::json!({
        "plugin_ids": plugin_ids,
    }))
    .map_err(|e| format!("Failed to serialise arguments: {}", e))?;

    let result = tauri_invoke("run_apply", args).await;

    serde_wasm_bindgen::from_value(result)
        .map_err(|e| format!("Failed to deserialise apply results: {}", e))
}
