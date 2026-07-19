//! Error types for the Linux hardening tool
//!
//! Provides comprehensive error handling across all operations

use thiserror::Error;

/// Main error type for hardening operations.
///
/// This enum covers all error scenarios that can occur during
/// scanning, applying changes, and managing system state.
#[derive(Error, Debug)]
pub enum HardeningError {
    /// Configuration file or parameter is invalid.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Database error variant
    #[error("Database error: {0}")]
    Database(String),

    /// Dependency resolution failed (circular dependencies, missing plugins, etc.).
    #[error("Dependency error: {0}")]
    Dependency(String),

    /// An executor operation failed.
    #[error("Executor error: {0}")]
    Executor(String),

    /// Notification delivery failed.
    #[error("Notification error: {0}")]
    Notification(String),

    /// Package manager operation failed.
    #[error("Package manager error: {0}")]
    PackageManager(String),

    /// Plugin operation failed.
    #[error("Plugin error: {0}")]
    Plugin(String),

    /// Insufficient privileges for the requested operation.
    #[error("Insufficient privileges: {0}")]
    Privilege(String),

    /// Rollback operation failed
    #[error("Rollback error: {0}")]
    Rollback(String),

    /// Serialisation or deserialisation operation failed.
    #[error("Serialisation error: {0}")]
    Serialisation(#[from] serde_json::Error),

    /// State management or checkpoint operation failed.
    #[error("State management error: {0}")]
    State(String),

    /// A system-level I/O error occurred.
    #[error("System error: {0}")]
    System(#[from] std::io::Error),

    /// The detected Linux distribution is not supported.
    #[error("Distribution not supported: {0}")]
    UnsupportedDistro(String),

    /// Validation of configuration or system state failed.
    #[error("Validation error: {0}")]
    Validation(String),
}

impl From<anyhow::Error> for HardeningError {
    fn from(err: anyhow::Error) -> Self {
        err.downcast::<HardeningError>()
            .unwrap_or_else(|err| HardeningError::Executor(err.to_string()))
    }
}

/// Result type alias using HardeningError.
pub type Result<T> = std::result::Result<T, HardeningError>;

/// True when an error message indicates a privilege failure rather than a
/// genuine absence or malfunction. Matches the strings the kernel, nft,
/// auditctl and sshd surface for unprivileged callers.
pub fn message_indicates_permission_denied(message: &str) -> bool {
    message.contains("Permission denied")
        || message.contains("permission denied")
        || message.contains("Operation not permitted")
        || message.contains("must be root")
        || message.contains("requires root")
}

/// True when an SSH connect failure names an authentication or agent problem
/// (bad or absent key, no usable agent) rather than a network fault. Drives the
/// ssh-agent/key hint shown to the user; a network failure (connection refused,
/// timeout, no route, name resolution) must never match, so a real network
/// outage is never mislabelled as an auth issue. Matches the case-insensitive
/// signatures the ssh client prints to stderr on authentication failure.
pub fn message_indicates_ssh_auth_failure(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("permission denied")
        || message.contains("publickey")
        || message.contains("authentication")
        || message.contains("could not open a connection to your authentication agent")
        || message.contains("no such identity")
}

/// True when the error chain indicates the operation failed for lack of
/// privileges: an io `PermissionDenied` anywhere in the chain, or a cause
/// whose message names a privilege failure (command stderr paths).
pub fn is_permission_denied(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        if let Some(io) = cause.downcast_ref::<std::io::Error>()
            && io.kind() == std::io::ErrorKind::PermissionDenied
        {
            return true;
        }
        message_indicates_permission_denied(&cause.to_string())
    })
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use anyhow::Context;

    use super::*;

    #[test]
    fn detects_io_permission_denied_through_anyhow_chain() {
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let err =
            anyhow::Error::new(io).context("Failed to read file /etc/security/pwquality.conf");
        assert!(is_permission_denied(&err));
    }

    #[test]
    fn detects_permission_strings() {
        assert!(message_indicates_permission_denied(
            "nft: Permission denied"
        ));
        assert!(message_indicates_permission_denied(
            "Operation not permitted"
        ));
        assert!(message_indicates_permission_denied(
            "You must be root to run this"
        ));
        assert!(!message_indicates_permission_denied(
            "No such file or directory"
        ));
    }

    #[test]
    fn not_found_is_not_permission_denied() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let err = anyhow::Error::new(io).context("Failed to read file /etc/nothing");
        assert!(!is_permission_denied(&err));
    }

    #[test]
    fn detects_ssh_auth_failure_signatures() {
        // The strings ssh prints to stderr when a key/agent is the problem.
        assert!(message_indicates_ssh_auth_failure(
            "root@host: Permission denied (publickey)."
        ));
        assert!(message_indicates_ssh_auth_failure(
            "Permission denied (publickey,password)"
        ));
        assert!(message_indicates_ssh_auth_failure(
            "Could not open a connection to your authentication agent."
        ));
        assert!(message_indicates_ssh_auth_failure(
            "Load key \"/x\": no such identity"
        ));
        // Case-insensitive.
        assert!(message_indicates_ssh_auth_failure(
            "PERMISSION DENIED (PUBLICKEY)"
        ));
    }

    #[test]
    fn network_failures_are_not_ssh_auth_failures() {
        // A genuine network fault must never be mislabelled as an auth problem.
        assert!(!message_indicates_ssh_auth_failure(
            "connect to host 10.0.0.5 port 22: Connection refused"
        ));
        assert!(!message_indicates_ssh_auth_failure(
            "connect to host 10.0.0.5 port 22: Connection timed out"
        ));
        assert!(!message_indicates_ssh_auth_failure(
            "connect to host 10.0.0.5 port 22: No route to host"
        ));
        assert!(!message_indicates_ssh_auth_failure(
            "ssh: Could not resolve hostname bogus: Name or service not known"
        ));
    }
}
