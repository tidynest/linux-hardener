// Mock data is available for development/testing but not currently used
#[allow(dead_code)]
mod mock_data;

use crate::types::ApplyResult;

/// Whether an error string returned from a privileged Tauri command
/// represents the user dismissing the pkexec authentication prompt, rather
/// than a genuine failure.
///
/// Errors cross the Tauri IPC boundary as plain strings, so this matches on
/// the fixed text emitted by `PrivilegedCommandError::AuthCancelled`'s
/// `Display` impl in `src-tauri/src/commands.rs`. If that text changes, this
/// must be updated to match.
pub fn is_auth_cancelled(err: &str) -> bool {
    err.contains("Authentication cancelled")
}

/// Builds the "N changes made[, K failed][, M skipped]" phrase the apply
/// summaries render. Counts come from the `ApplyResult` helpers, so the
/// number next to "made" only ever counts successes and skips never absorb
/// failures.
pub fn apply_change_summary(result: &ApplyResult) -> String {
    let mut summary = format!("{} changes made", result.applied_change_count());
    let failed = result.failed_change_count();
    let skipped = result.skipped_change_count();
    if failed > 0 {
        summary.push_str(&format!(", {failed} failed"));
    }
    if skipped > 0 {
        summary.push_str(&format!(", {skipped} skipped"));
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Change, ChangeType, PluginId};

    fn change(change_type: ChangeType, success: bool) -> Change {
        Change {
            change_description: "test".to_string(),
            change_type,
            change_success: success,
            change_error: None,
        }
    }

    fn apply_result(changes: Vec<Change>) -> ApplyResult {
        ApplyResult {
            apply_plugin_id: PluginId::new("test"),
            apply_success: true,
            apply_changes: changes,
            apply_checkpoint_id: None,
            apply_error: None,
        }
    }

    #[test]
    fn apply_change_summary_reports_failures_and_skips() {
        let result = apply_result(vec![
            change(ChangeType::KernelParameter, true),
            change(ChangeType::KernelParameter, false),
            change(ChangeType::KernelParameter, false),
            change(ChangeType::Skipped, true),
        ]);
        assert_eq!(
            apply_change_summary(&result),
            "1 changes made, 2 failed, 1 skipped"
        );
    }

    #[test]
    fn apply_change_summary_plain_when_all_succeed() {
        let result = apply_result(vec![
            change(ChangeType::ConfigFile, true),
            change(ChangeType::ConfigFile, true),
        ]);
        assert_eq!(apply_change_summary(&result), "2 changes made");
    }

    #[test]
    fn is_auth_cancelled_matches_backend_text() {
        assert!(is_auth_cancelled(
            "Authentication cancelled. Root privileges are required for this operation."
        ));
    }

    #[test]
    fn is_auth_cancelled_rejects_other_errors() {
        assert!(!is_auth_cancelled("Command failed: exit status 1"));
        assert!(!is_auth_cancelled("No Polkit authentication agent found."));
        assert!(!is_auth_cancelled(""));
    }
}
