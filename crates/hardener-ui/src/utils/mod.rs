// Mock data is available for development/testing but not currently used
#[allow(dead_code)]
mod mock_data;

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

#[cfg(test)]
mod tests {
    use super::*;

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
