//! Split from the former flat `commands.rs` along the seams its test files
//! had already named. Shared plumbing lives in the parent; each domain here
//! keeps its own commands and their private helpers.

use super::*;

/// The argument vector for `hardener exception add`.
///
/// Separated from the command so the flag construction is testable without a
/// pkexec prompt: an optional field that became an empty flag would write an
/// empty approver into the operator's configuration, and nothing downstream
/// could tell that from one they typed.
pub(crate) fn exception_add_args<'a>(
    plugin_id: &'a str,
    exception_key: &'a str,
    reason: &'a str,
    approved_by: Option<&'a str>,
    ticket: Option<&'a str>,
    expires: Option<&'a str>,
) -> Vec<&'a str> {
    let mut args = vec![
        "--format",
        "json",
        "exception",
        "add",
        plugin_id,
        exception_key,
        "--reason",
        reason,
    ];
    for (flag, field) in [
        ("--approved-by", approved_by),
        ("--ticket", ticket),
        ("--expires", expires),
    ] {
        // Blank counts as absent, not as a flag paired with an empty string:
        // `Some("")` reaches here whenever the caller trims a field and hands
        // back an empty string rather than `None`, and `--ticket ""` would
        // write an empty ticket into the operator's config.
        if let Some(supplied) = field.filter(|s| !s.trim().is_empty()) {
            args.push(flag);
            args.push(supplied);
        }
    }
    args
}

/// Writes a policy exception for one finding, as root.
///
/// The desktop sends the plugin id, the key and the operator's text, and
/// nothing describing the host: the CLI re-reads the host and pins the value it
/// observes. A key that no live finding carries is refused there, which is also
/// why no allow-list is needed here.
#[tauri::command]
pub async fn add_policy_exception(
    plugin_id: String,
    exception_key: String,
    reason: String,
    approved_by: Option<String>,
    ticket: Option<String>,
    expires: Option<String>,
) -> Result<hardener_types::WrittenException, String> {
    let _guard = PrivilegedOpGuard::acquire()?;
    validate_plugin_ids(std::slice::from_ref(&plugin_id))?;
    validate_ipc_string(&exception_key, "exception_key")?;
    validate_ipc_string(&reason, "reason")?;
    for (field, name) in [
        (&approved_by, "approved_by"),
        (&ticket, "ticket"),
        (&expires, "expires"),
    ] {
        if let Some(text) = field {
            validate_ipc_string(text, name)?;
        }
    }
    if reason.trim().is_empty() {
        return Err("A reason is required: an undocumented deviation is what an exception exists to prevent.".to_string());
    }

    let args = exception_add_args(
        &plugin_id,
        &exception_key,
        &reason,
        approved_by.as_deref(),
        ticket.as_deref(),
        expires.as_deref(),
    );

    let output = run_privileged_command(&args).await.map_err(safe_err)?;
    serde_json::from_str(&output).map_err(|e| {
        safe_err(format!(
            "Could not read what the exception write reported: {e}"
        ))
    })
}

/// Removes a policy exception, as root.
#[tauri::command]
pub async fn remove_policy_exception(
    plugin_id: String,
    exception_key: String,
) -> Result<(), String> {
    let _guard = PrivilegedOpGuard::acquire()?;
    validate_plugin_ids(std::slice::from_ref(&plugin_id))?;
    validate_ipc_string(&exception_key, "exception_key")?;

    run_privileged_command(&[
        "--format",
        "json",
        "exception",
        "remove",
        &plugin_id,
        &exception_key,
    ])
    .await
    .map(|_| ())
    .map_err(safe_err)
}
