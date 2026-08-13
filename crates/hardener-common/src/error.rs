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

    /// The operator named something that does not exist.
    ///
    /// Distinct from every variant around it, and the distinction is the point:
    /// those all say the tool failed at something, and this one says the tool
    /// worked and the answer is no. Rolling back to a checkpoint id that was
    /// never created is not a database malfunction, and reporting it as one
    /// sent an operator to look at the database. The CLI walk caught exactly
    /// that: `Database error: no rows returned by a query that expected to
    /// return at least one row`, which names neither what was missing nor what
    /// to do about it.
    ///
    /// The payload carries the whole noun phrase and the remedy, because
    /// "Not found: " reads as a prefix rather than as a sentence opener.
    #[error("Not found: {0}")]
    NotFound(String),

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
/// auditctl, ufw and sshd surface for unprivileged callers.
///
/// Every entry is a wording some tool actually prints, and that is the whole
/// discipline here: this predicate decides whether an operator is told to try
/// again as root, so a string nothing emits adds no coverage and a string too
/// general matches failures privilege cannot fix. `need to be root` is ufw's,
/// and it is here because the firewall plugin used to fabricate
/// "(permission denied)" for every ufw failure rather than propagate the real
/// stderr. That made a broken ufw install indistinguishable from a refusal, and
/// removing the fabrication made this the only thing standing between the
/// genuine case and silence.
pub fn message_indicates_permission_denied(message: &str) -> bool {
    message.contains("Permission denied")
        || message.contains("permission denied")
        || message.contains("Operation not permitted")
        || message.contains("must be root")
        || message.contains("need to be root")
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
mod tests;
