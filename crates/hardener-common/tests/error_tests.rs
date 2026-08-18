use hardener_common::error::HardeningError;
use std::collections::HashSet;

/// The whole rendering each variant must produce for the payload it carries.
///
/// The match is exhaustive on purpose: a fifteenth `HardeningError` variant
/// fails to compile here rather than silently joining the untested set. The
/// category prefixes are written out rather than derived from `error.rs`, so a
/// prefix that is deleted, reworded or misspelt fails the assertion instead of
/// moving with it.
fn expected_rendering(err: &HardeningError) -> String {
    match err {
        HardeningError::Config(cause) => format!("Configuration error: {cause}"),
        HardeningError::Database(cause) => format!("Database error: {cause}"),
        HardeningError::Dependency(cause) => format!("Dependency error: {cause}"),
        HardeningError::Executor(cause) => format!("Executor error: {cause}"),
        HardeningError::Notification(cause) => format!("Notification error: {cause}"),
        HardeningError::NotFound(cause) => format!("Not found: {cause}"),
        HardeningError::Plugin(cause) => format!("Plugin error: {cause}"),
        HardeningError::Privilege(cause) => format!("Insufficient privileges: {cause}"),
        HardeningError::Rollback(cause) => format!("Rollback error: {cause}"),
        HardeningError::Serialisation(cause) => format!("Serialisation error: {cause}"),
        HardeningError::State(cause) => format!("State management error: {cause}"),
        HardeningError::System(cause) => format!("System error: {cause}"),
        HardeningError::UnsupportedDistro(cause) => format!("Distribution not supported: {cause}"),
        HardeningError::Validation(cause) => format!("Validation error: {cause}"),
    }
}

/// One value per variant. `Serialisation` and `System` are built through the
/// `#[from]` conversions rather than constructed directly, because that is the
/// only way either is ever reached, and a sweep over variant names has already
/// missed `System` for that reason once.
fn one_of_each_variant() -> Vec<HardeningError> {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
    let json_err = serde_json::from_str::<serde_json::Value>("{").unwrap_err();

    vec![
        HardeningError::Config("invalid setting".to_string()),
        HardeningError::Database("connection failed".to_string()),
        HardeningError::Dependency("circular dependency".to_string()),
        HardeningError::Executor("ssh channel closed".to_string()),
        HardeningError::Notification("SMTP connection refused".to_string()),
        HardeningError::NotFound("checkpoint 42; run `hardener list` to see them".to_string()),
        HardeningError::Plugin("scan failed".to_string()),
        HardeningError::Privilege("root required".to_string()),
        HardeningError::Rollback("checkpoint not found".to_string()),
        json_err.into(),
        HardeningError::State("corrupted state".to_string()),
        io_err.into(),
        HardeningError::UnsupportedDistro("BSD".to_string()),
        HardeningError::Validation("invalid input".to_string()),
    ]
}

#[test]
fn every_variant_renders_with_its_category_prefix() {
    let cases = one_of_each_variant();

    let distinct: HashSet<_> = cases.iter().map(std::mem::discriminant).collect();
    assert_eq!(
        distinct.len(),
        cases.len(),
        "the same variant appears twice, so one arm of expected_rendering is unexercised"
    );

    for err in &cases {
        assert_eq!(err.to_string(), expected_rendering(err));
    }
}

#[test]
fn anyhow_without_a_hardening_error_inside_becomes_executor() {
    let err: HardeningError = anyhow::anyhow!("ssh channel closed").into();
    assert_eq!(err.to_string(), "Executor error: ssh channel closed");
}

#[test]
fn anyhow_carrying_a_hardening_error_keeps_its_own_variant() {
    let err: HardeningError =
        anyhow::Error::from(HardeningError::NotFound("checkpoint 42".to_string())).into();
    assert_eq!(err.to_string(), "Not found: checkpoint 42");
}

#[test]
fn test_error_debug() {
    let err = HardeningError::Config("test".to_string());
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("Config"));
}
