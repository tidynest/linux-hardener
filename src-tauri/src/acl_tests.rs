//! Runtime verification for SAM-039: application commands are individually
//! deniable through the capability ACL.
//!
//! `tauri::test::mock_context` ships an empty resolved ACL with
//! `has_app_acl = false`, which would skip the app-command check entirely,
//! the opposite of the production build, where the `AppManifest` in
//! `build.rs` switches enforcement on. These tests install an authority
//! mirroring production (`has_app_acl = true` plus an explicit allow-list)
//! and drive invokes through the same `on_message` path the webview uses.

use std::collections::BTreeMap;

use tauri::WebviewWindow;
use tauri::ipc::{CallbackFn, InvokeBody, RuntimeAuthority};
use tauri::test::{
    INVOKE_KEY, MockRuntime, get_ipc_response, mock_builder, mock_context, noop_assets,
};
use tauri::utils::acl::ExecutionContext;
use tauri::utils::acl::resolved::Resolved;
use tauri::webview::InvokeRequest;

/// Builds a mock app whose ACL grants exactly `granted`, like a
/// `capabilities/default.json` stripped down to those permissions.
fn mock_webview(granted: &[&str]) -> (tauri::App<MockRuntime>, WebviewWindow<MockRuntime>) {
    let mut context = mock_context(noop_assets());
    let mut authority = RuntimeAuthority::new(
        BTreeMap::new(),
        Resolved {
            has_app_acl: true,
            ..Default::default()
        },
    );
    for command in granted {
        authority.__allow_command((*command).to_string(), ExecutionContext::Local);
    }
    *context.runtime_authority_mut() = authority;

    let app = mock_builder()
        .invoke_handler(tauri::generate_handler![
            crate::commands::run_apply,
            crate::commands::validate_config
        ])
        .build(context)
        .expect("failed to build mock app");
    let webview = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
        .build()
        .expect("failed to build mock webview");
    (app, webview)
}

fn invoke(
    webview: &WebviewWindow<MockRuntime>,
    cmd: &str,
    body: serde_json::Value,
) -> Result<tauri::ipc::InvokeResponseBody, serde_json::Value> {
    get_ipc_response(
        webview,
        InvokeRequest {
            cmd: cmd.into(),
            callback: CallbackFn(0),
            error: CallbackFn(1),
            url: "tauri://localhost".parse().expect("static URL"),
            body: InvokeBody::Json(body),
            headers: Default::default(),
            invoke_key: INVOKE_KEY.to_string(),
        },
    )
}

/// A command whose `allow-*` permission is absent must be rejected by the
/// ACL layer itself, before argument deserialisation or the command body.
#[test]
fn ungranted_command_is_rejected_by_acl() {
    let (_app, webview) = mock_webview(&["validate_config"]);

    let err = invoke(&webview, "run_apply", serde_json::json!({}))
        .expect_err("run_apply must be rejected without allow-run-apply");

    let message = err.to_string();
    assert!(
        message.contains("not allowed"),
        "expected an ACL rejection, got: {message}"
    );
}

/// Positive control: a granted command passes the ACL and reaches its
/// handler (the missing file yields an invalid-config summary, not an error).
#[test]
fn granted_command_reaches_the_handler() {
    let (_app, webview) = mock_webview(&["validate_config"]);

    let response = invoke(
        &webview,
        "validate_config",
        serde_json::json!({ "path": "/tmp/hardener-acl-test-missing.toml" }),
    );

    assert!(
        response.is_ok(),
        "granted command must reach the handler, got: {response:?}"
    );
}
