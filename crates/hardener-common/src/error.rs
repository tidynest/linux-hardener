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

/// Result type alias using HardeningError.
pub type Result<T> = std::result::Result<T, HardeningError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_config() {
        let err = HardeningError::Config("invalid setting".to_string());
        assert_eq!(format!("{}", err), "Configuration error: invalid setting");
    }

    #[test]
    fn test_error_display_database() {
        let err = HardeningError::Database("connection failed".to_string());
        assert_eq!(format!("{}", err), "Database error: connection failed");
    }

    #[test]
    fn test_error_display_dependency() {
        let err = HardeningError::Dependency("circular dependency".to_string());
        assert_eq!(format!("{}", err), "Dependency error: circular dependency");
    }

    #[test]
    fn test_error_display_package_manager() {
        let err = HardeningError::PackageManager("apt failed".to_string());
        assert_eq!(format!("{}", err), "Package manager error: apt failed");
    }

    #[test]
    fn test_error_display_plugin() {
        let err = HardeningError::Plugin("scan failed".to_string());
        assert_eq!(format!("{}", err), "Plugin error: scan failed");
    }

    #[test]
    fn test_error_display_privilege() {
        let err = HardeningError::Privilege("root required".to_string());
        assert_eq!(format!("{}", err), "Insufficient privileges: root required");
    }

    #[test]
    fn test_error_display_rollback() {
        let err = HardeningError::Rollback("checkpoint not found".to_string());
        assert_eq!(format!("{}", err), "Rollback error: checkpoint not found");
    }

    #[test]
    fn test_error_display_state() {
        let err = HardeningError::State("corrupted state".to_string());
        assert_eq!(
            format!("{}", err),
            "State management error: corrupted state"
        );
    }

    #[test]
    fn test_error_display_unsupported_distro() {
        let err = HardeningError::UnsupportedDistro("BSD".to_string());
        assert_eq!(format!("{}", err), "Distribution not supported: BSD");
    }

    #[test]
    fn test_error_display_validation() {
        let err = HardeningError::Validation("invalid input".to_string());
        assert_eq!(format!("{}", err), "Validation error: invalid input");
    }

    #[test]
    fn test_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: HardeningError = io_err.into();
        assert!(format!("{}", err).contains("file not found"));
    }

    #[test]
    fn test_error_debug() {
        let err = HardeningError::Config("test".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("Config"));
    }
}
