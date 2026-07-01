//! PAM plugin tests using MockExecutor.
//!
//! These tests verify plugin behavior without touching real PAM configuration.

use hardener_common::types::{PluginId, Severity};
use hardener_core::{
    Context, MockExecutor, PluginConfig, PolicyException, SystemExecutor, plugin::HardeningPlugin,
};
use hardener_plugins::PamHardeningPlugin;
use std::sync::Arc;

/// Creates a mock executor with secure PAM configuration.
fn secure_pam_executor() -> MockExecutor {
    MockExecutor::new()
        // pwquality.conf uses "key = value" format
        .with_file(
            "/etc/security/pwquality.conf",
            r#"# Password Quality Configuration
minlen 14
dcredit -1
ucredit -1
lcredit -1
ocredit -1
maxrepeat 3
"#,
        )
        // login.defs uses space-separated format
        .with_file(
            "/etc/login.defs",
            r#"# Login defaults
PASS_MAX_DAYS 90
PASS_MIN_DAYS 1
PASS_WARN_AGE 7
"#,
        )
        // faillock.conf: deny=3 is stricter than the threshold of 5 — compliant
        .with_file("/etc/security/faillock.conf", "deny = 3\n")
        // pwhistory.conf: remember=10 exceeds the minimum of 5 — compliant
        .with_file("/etc/security/pwhistory.conf", "remember = 10\n")
}

/// Creates a mock executor with insecure PAM configuration.
fn insecure_pam_executor() -> MockExecutor {
    MockExecutor::new()
        .with_file(
            "/etc/security/pwquality.conf",
            r#"# Default password quality
minlen 8
# No complexity requirements set
"#,
        )
        .with_file(
            "/etc/login.defs",
            r#"# Default login settings
PASS_MAX_DAYS 99999
PASS_MIN_DAYS 0
PASS_WARN_AGE 7
"#,
        )
}

/// Creates a mock executor with missing PAM config files.
fn missing_pam_config_executor() -> MockExecutor {
    MockExecutor::new()
    // No files - both configs will fail to read
}

/// Creates a mock executor with partial configuration.
fn partial_pam_executor() -> MockExecutor {
    MockExecutor::new()
        // pwquality.conf exists but missing some settings
        .with_file(
            "/etc/security/pwquality.conf",
            r#"minlen 14
dcredit -1
# Missing ucredit, lcredit, ocredit, maxrepeat
"#,
        )
        // login.defs has some secure settings
        .with_file(
            "/etc/login.defs",
            r#"PASS_MAX_DAYS 90
PASS_MIN_DAYS 0
PASS_WARN_AGE 7
"#,
        )
}

#[tokio::test]
async fn test_pam_scan_secure_config_no_findings() {
    let executor = secure_pam_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PamHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success, "secure PAM scan should succeed");
    assert_eq!(result.scan_plugin_id, PluginId::from("pam-hardening"));
    assert!(
        result.scan_findings.is_empty(),
        "Secure PAM config should have no findings, but got: {:?}",
        result
            .scan_findings
            .iter()
            .map(|f| &f.finding_title)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_pam_scan_insecure_config_finds_issues() {
    let executor = insecure_pam_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PamHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success, "insecure PAM scan should succeed");
    assert!(
        !result.scan_findings.is_empty(),
        "insecure PAM config should have findings"
    );

    let finding_ids: Vec<_> = result
        .scan_findings
        .iter()
        .map(|f| f.finding_id.as_str())
        .collect();

    // Should find minlen is too short
    assert!(
        finding_ids.contains(&"pam-minlen"),
        "Should flag weak minlen"
    );

    // Should find missing complexity requirements
    assert!(
        finding_ids.contains(&"pam-dcredit") || finding_ids.contains(&"pam-ucredit"),
        "Should flag missing complexity"
    );

    // Should find PASS_MAX_DAYS is too long
    assert!(
        finding_ids.contains(&"pam-PASS_MAX_DAYS"),
        "should flag PASS_MAX_DAYS, got: {finding_ids:?}"
    );

    // Should find PASS_MIN_DAYS is 0
    assert!(
        finding_ids.contains(&"pam-PASS_MIN_DAYS"),
        "should flag PASS_MIN_DAYS, got: {finding_ids:?}"
    );
}

#[tokio::test]
async fn test_pam_scan_missing_configs_flags_all() {
    let executor = missing_pam_config_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PamHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(
        result.scan_success,
        "scan with missing configs should succeed"
    );
    // All directives should be flagged as "not set"
    assert!(
        !result.scan_findings.is_empty(),
        "missing configs should produce findings"
    );

    // All findings should have "not set" as current value
    for finding in &result.scan_findings {
        assert_eq!(
            finding.finding_current_value, "not set",
            "Missing config should show 'not set' for {}",
            finding.finding_id
        );
    }
}

#[tokio::test]
async fn test_pam_scan_partial_config() {
    let executor = partial_pam_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PamHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success, "partial PAM scan should succeed");

    let finding_ids: Vec<_> = result
        .scan_findings
        .iter()
        .map(|f| f.finding_id.as_str())
        .collect();

    // minlen and dcredit are set correctly - should NOT be flagged
    assert!(
        !finding_ids.contains(&"pam-minlen"),
        "correctly set minlen should not be flagged"
    );
    assert!(
        !finding_ids.contains(&"pam-dcredit"),
        "correctly set dcredit should not be flagged"
    );

    // ucredit, lcredit, ocredit, maxrepeat are missing - should be flagged
    assert!(
        finding_ids.contains(&"pam-ucredit"),
        "missing ucredit should be flagged"
    );
    assert!(
        finding_ids.contains(&"pam-lcredit"),
        "missing lcredit should be flagged"
    );
    assert!(
        finding_ids.contains(&"pam-ocredit"),
        "missing ocredit should be flagged"
    );
    assert!(
        finding_ids.contains(&"pam-maxrepeat"),
        "missing maxrepeat should be flagged"
    );

    // PASS_MIN_DAYS is wrong (0 vs 1) - should be flagged
    assert!(
        finding_ids.contains(&"pam-PASS_MIN_DAYS"),
        "wrong PASS_MIN_DAYS should be flagged"
    );
}

#[tokio::test]
async fn test_pam_scan_finding_structure() {
    let executor = MockExecutor::new()
        .with_file("/etc/security/pwquality.conf", "minlen 8\n")
        .with_file("/etc/login.defs", "");

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PamHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    // Find minlen finding
    let minlen_finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "pam-minlen")
        .expect("Should have minlen finding");

    assert_eq!(minlen_finding.finding_current_value, "8");
    assert_eq!(minlen_finding.finding_recommended_value, "14");
    assert_eq!(minlen_finding.finding_severity, Severity::High);
    assert!(
        minlen_finding.finding_title.contains("minlen"),
        "finding title should mention minlen, got: {}",
        minlen_finding.finding_title
    );
    assert!(
        !minlen_finding.finding_compliance.is_empty(),
        "minlen finding should have compliance mappings"
    );
}

#[tokio::test]
async fn test_pam_scan_compliance_mappings() {
    let executor = insecure_pam_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PamHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    // minlen should have CIS 5.3.1 mapping
    let minlen_finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "pam-minlen")
        .expect("Should have minlen finding");

    assert!(
        !minlen_finding.finding_compliance.is_empty(),
        "minlen finding should have compliance mappings"
    );
    assert!(
        minlen_finding.finding_compliance[0]
            .compliance_control_id
            .starts_with("5.3"),
        "minlen compliance control should start with 5.3, got: {}",
        minlen_finding.finding_compliance[0].compliance_control_id
    );
}

#[tokio::test]
async fn test_pam_scan_severity_levels() {
    let executor = insecure_pam_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PamHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    // minlen should be High severity
    if let Some(minlen) = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "pam-minlen")
    {
        assert_eq!(minlen.finding_severity, Severity::High);
    }

    // maxrepeat should be Low severity (if missing)
    if let Some(maxrepeat) = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "pam-maxrepeat")
    {
        assert_eq!(maxrepeat.finding_severity, Severity::Low);
    }

    // dcredit/ucredit/lcredit/ocredit should be Medium severity
    if let Some(dcredit) = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "pam-dcredit")
    {
        assert_eq!(dcredit.finding_severity, Severity::Medium);
    }
}

#[tokio::test]
async fn test_pam_validate() {
    // PAM validate checks config file access and estimates changes
    let executor = MockExecutor::new()
        .with_file("/etc/security/pwquality.conf", "minlen 8\n")
        .with_file("/etc/login.defs", "PASS_MAX_DAYS 99999\n");

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PamHardeningPlugin::new();
    let config = hardener_core::PluginConfig::default();

    let result = plugin.validate(&ctx, &config).await.unwrap();

    // Should have estimated changes
    assert!(
        !result.validation_report_estimated_changes.is_empty(),
        "validation should produce estimated changes"
    );
}

#[tokio::test]
async fn test_pam_scan_logs_file_reads() {
    let executor = MockExecutor::new()
        .with_file("/etc/security/pwquality.conf", "minlen 14")
        .with_file("/etc/login.defs", "PASS_MAX_DAYS 90");

    let ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = PamHardeningPlugin::new();

    let _ = plugin.scan(&ctx).await;

    let log = executor.log();

    // Should have read both config files
    assert!(
        log.files_read
            .iter()
            .any(|p| p.to_str().unwrap().contains("pwquality")),
        "Should read pwquality.conf"
    );
    assert!(
        log.files_read
            .iter()
            .any(|p| p.to_str().unwrap().contains("login.defs")),
        "Should read login.defs"
    );
}

#[tokio::test]
async fn test_pam_scan_duration_recorded() {
    let executor = secure_pam_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PamHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(
        result.scan_duration_us > 0,
        "scan duration should be recorded"
    );
}

#[tokio::test]
async fn test_pam_metadata() {
    let plugin = PamHardeningPlugin::new();
    let metadata = plugin.metadata();

    assert_eq!(metadata.plugin_id, PluginId::from("pam-hardening"));
    assert_eq!(metadata.plugin_name, "PAM Authentication Hardening");
}

#[tokio::test]
async fn test_pam_scan_with_remote_executor() {
    let executor = MockExecutor::new()
        .remote()
        .with_description("ssh://admin@server.example.com")
        .with_file("/etc/security/pwquality.conf", "minlen 8\n")
        .with_file("/etc/login.defs", "PASS_MAX_DAYS 99999\n");

    assert!(
        executor.is_remote(),
        "remote executor should report as remote"
    );

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PamHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success, "remote PAM scan should succeed");
    // Should find issues on remote system
    assert!(
        !result.scan_findings.is_empty(),
        "insecure remote PAM config should have findings"
    );
}

#[tokio::test]
async fn test_pam_scan_whitespace_handling() {
    // Test that the parser handles space-separated format (which is what Auto format expects)
    let executor = MockExecutor::new()
        .with_file(
            "/etc/security/pwquality.conf",
            r#"minlen 14
dcredit -1
ucredit -1
lcredit -1
ocredit -1
maxrepeat 3
"#,
        )
        .with_file(
            "/etc/login.defs",
            r#"PASS_MAX_DAYS 90
PASS_MIN_DAYS 1
PASS_WARN_AGE 7
"#,
        )
        .with_file("/etc/security/faillock.conf", "deny = 3\n")
        .with_file("/etc/security/pwhistory.conf", "remember = 10\n");

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PamHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(
        result.scan_success,
        "whitespace-variant scan should succeed"
    );
    // All secure values should be recognized
    assert!(
        result.scan_findings.is_empty(),
        "Secure config should parse correctly, but got: {:?}",
        result
            .scan_findings
            .iter()
            .map(|f| &f.finding_id)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_pam_apply_respects_directives() {
    let executor = insecure_pam_executor();
    let mut ctx = Context::with_executor(Arc::new(executor));
    let plugin = PamHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config
        .directives
        .insert("minlen".to_string(), "20".to_string());

    let result = plugin.apply(&mut ctx, &config).await.unwrap();

    // The directive-overridden value should appear in the change description
    let minlen_change = result
        .apply_changes
        .iter()
        .find(|c| c.change_description.contains("minlen"));
    assert!(minlen_change.is_some(), "should have a minlen change");
    assert!(
        minlen_change
            .expect("checked above")
            .change_description
            .contains("20"),
        "expected directive value '20', got: {}",
        minlen_change.expect("checked above").change_description
    );

    // Other directives should still use baseline values
    let dcredit_change = result
        .apply_changes
        .iter()
        .find(|c| c.change_description.contains("dcredit"));
    assert!(dcredit_change.is_some(), "should have a dcredit change");
    assert!(
        dcredit_change
            .expect("checked above")
            .change_description
            .contains("-1"),
        "non-overridden directive should use baseline"
    );
}

#[tokio::test]
async fn test_pam_apply_skips_exceptions() {
    let executor = insecure_pam_executor();
    let mut ctx = Context::with_executor(Arc::new(executor));
    let plugin = PamHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "minlen".to_string(),
        PolicyException {
            value: "8".to_string(),
            allowed: true,
            reason: "Legacy application requires short passwords".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let result = plugin.apply(&mut ctx, &config).await.unwrap();

    // Should have a "skipped" change for minlen
    let skipped = result.apply_changes.iter().find(|c| {
        c.change_description.contains("skipped") && c.change_description.contains("minlen")
    });
    assert!(skipped.is_some(), "should have a skipped change for minlen");
    assert!(
        skipped
            .expect("checked above")
            .change_description
            .contains("Legacy application"),
    );

    // Should NOT have a "Set minlen" change (it was skipped)
    assert!(
        !result
            .apply_changes
            .iter()
            .any(|c| c.change_description.contains("Set minlen")),
        "should not have a 'Set minlen' change when excepted"
    );
}

#[tokio::test]
async fn test_pam_validate_skips_exceptions() {
    let executor = MockExecutor::new()
        .with_file("/etc/security/pwquality.conf", "minlen 8\n")
        .with_file("/etc/login.defs", "PASS_MAX_DAYS 99999\n");

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PamHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "minlen".to_string(),
        PolicyException {
            value: "8".to_string(),
            allowed: true,
            reason: "Legacy application".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let report = plugin.validate(&ctx, &config).await.unwrap();

    // minlen should NOT appear in estimated changes
    assert!(
        !report
            .validation_report_estimated_changes
            .iter()
            .any(|c| c.contains("minlen")),
        "excepted directive should not appear in estimated changes"
    );

    // Other directives should still appear
    assert!(
        report
            .validation_report_estimated_changes
            .iter()
            .any(|c| c.contains("dcredit")),
        "non-excepted directives should still appear"
    );
}
