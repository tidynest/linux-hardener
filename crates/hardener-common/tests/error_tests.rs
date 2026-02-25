use hardener_common::error::HardeningError;

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
fn test_error_display_notification() {
    let err = HardeningError::Notification("SMTP connection refused".to_string());
    assert_eq!(
        format!("{}", err),
        "Notification error: SMTP connection refused"
    );
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
