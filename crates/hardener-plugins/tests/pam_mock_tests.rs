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
        // faillock.conf: deny=3 is stricter than the threshold of 5, compliant
        .with_file("/etc/security/faillock.conf", "deny = 3\n")
        // pwhistory.conf: remember=10 exceeds the minimum of 5, compliant
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

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

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

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

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

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

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

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

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

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

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

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

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

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

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

    let _ = plugin.scan(&ctx, &PluginConfig::default()).await;

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

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

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

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

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

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

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

/// No-loosen contract for threshold directives (CIS 5.3.2/5.3.3): when
/// faillock/pwhistory already hold a STRICTER value than the compliant boundary,
/// apply must leave them untouched, never rewrite `deny = 3` up to `deny = 5`.
#[tokio::test]
async fn test_pam_apply_never_loosens_stricter_thresholds() {
    // deny = 3 is stricter than the boundary of 5; remember = 10 exceeds the
    // minimum of 5. Both are already compliant and must not be rewritten.
    let executor = Arc::new(
        secure_pam_executor()
            .with_file("/etc/security/faillock.conf", "deny = 3\n")
            .with_file("/etc/security/pwhistory.conf", "remember = 10\n"),
    );
    let mut ctx = Context::with_executor(executor.clone());
    let plugin = PamHardeningPlugin::new();

    let result = plugin
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .unwrap();

    // The virtual filesystem must still hold the stricter values verbatim.
    let files = executor.files();
    assert_eq!(
        files
            .get(std::path::Path::new("/etc/security/faillock.conf"))
            .map(String::as_str),
        Some("deny = 3\n"),
        "apply must not loosen a stricter faillock deny"
    );
    assert_eq!(
        files
            .get(std::path::Path::new("/etc/security/pwhistory.conf"))
            .map(String::as_str),
        Some("remember = 10\n"),
        "apply must not loosen a stricter pwhistory remember"
    );

    // There must be no "Set deny"/"Set remember" write, and the skip should be
    // recorded as an "already meets threshold" success change.
    assert!(
        !result
            .apply_changes
            .iter()
            .any(|c| c.change_description.starts_with("Set deny")
                || c.change_description.starts_with("Set remember")),
        "apply must not emit a write change for already-compliant thresholds"
    );
    for name in ["deny", "remember"] {
        assert!(
            result.apply_changes.iter().any(|c| {
                c.change_success
                    && c.change_description
                        .contains(&format!("{} already meets threshold", name))
            }),
            "expected an 'already meets threshold' change for {name}"
        );
    }
}

/// Complementary to the no-loosen test: a LOOSER (or unset) threshold must be
/// tightened to the compliant boundary on apply.
#[tokio::test]
async fn test_pam_apply_tightens_looser_thresholds() {
    let executor = Arc::new(
        secure_pam_executor()
            .with_file("/etc/security/faillock.conf", "deny = 10\n")
            .with_file("/etc/security/pwhistory.conf", "remember = 2\n"),
    );
    let mut ctx = Context::with_executor(executor.clone());
    let plugin = PamHardeningPlugin::new();

    plugin
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .unwrap();

    let files = executor.files();
    let faillock = files
        .get(std::path::Path::new("/etc/security/faillock.conf"))
        .cloned()
        .unwrap_or_default();
    let pwhistory = files
        .get(std::path::Path::new("/etc/security/pwhistory.conf"))
        .cloned()
        .unwrap_or_default();
    assert!(
        faillock.contains("deny = 5"),
        "looser deny should be tightened to the boundary 5, got: {faillock}"
    );
    assert!(
        pwhistory.contains("remember = 5"),
        "too-small remember should be raised to the boundary 5, got: {pwhistory}"
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

/// A stale exception (documented value no longer matches the host) must not
/// suppress hardening: apply must treat it as if there were no exception.
#[tokio::test]
async fn apply_ignores_exception_whose_value_does_not_match() {
    let executor = insecure_pam_executor();
    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = PamHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "minlen".to_string(),
        PolicyException {
            value: "99".to_string(),
            allowed: true,
            reason: "Stale exception".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let result = plugin.apply(&mut ctx, &config).await.unwrap();

    assert!(
        !result
            .apply_changes
            .iter()
            .any(|c| c.change_description.contains("Stale exception")),
        "a non-matching exception must not produce a skipped change"
    );
    assert!(
        result
            .apply_changes
            .iter()
            .any(|c| c.change_description.contains("Set minlen")),
        "the directive must actually be hardened once the stale exception is ignored, got: {:?}",
        result.apply_changes
    );
}

#[tokio::test]
async fn scan_honours_directive_override() {
    // deny = 3 is compliant against the built-in boundary of 5, but a
    // directive override that tightens the boundary to 2 makes the same
    // value violate -> a finding appears even though the host already
    // meets the hardcoded baseline. The override must be clamped through
    // the same path apply uses, never compared against the raw baseline.
    let executor = secure_pam_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PamHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config
        .directives
        .insert("deny".to_string(), "2".to_string());

    let result = plugin.scan(&ctx, &config).await.unwrap();

    let finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "pam-deny")
        .unwrap_or_else(|| {
            panic!(
                "stricter directive should surface a finding, got: {:?}",
                result
                    .scan_findings
                    .iter()
                    .map(|f| &f.finding_id)
                    .collect::<Vec<_>>()
            )
        });

    // Target-dependent field must reflect the clamped override (2), not the
    // hardcoded baseline (5) - otherwise the finding would self-contradict
    // by recommending a value the host already exceeds.
    assert_eq!(
        finding.finding_recommended_value, "2",
        "recommended value should reflect the directive override, not the baseline"
    );
}

#[tokio::test]
async fn scan_annotates_valid_exception() {
    // minlen = 8 violates the baseline of 14, and carries a valid exception:
    // exceptions annotate findings, they never drop them, so the finding
    // stays present and carries the exception annotation.
    let executor = insecure_pam_executor();
    let ctx = Context::with_executor(Arc::new(executor));
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

    let result = plugin.scan(&ctx, &config).await.unwrap();

    let finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "pam-minlen")
        .expect("non-compliant directive should still produce a finding");
    assert!(
        finding.finding_policy_exception.is_some(),
        "finding should be annotated with the valid exception"
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

/// A stale exception (documented value no longer matches the host) must not
/// remove the directive from validate's preview.
#[tokio::test]
async fn validate_ignores_exception_whose_value_does_not_match() {
    let executor = MockExecutor::new()
        .with_file("/etc/security/pwquality.conf", "minlen 8\n")
        .with_file("/etc/login.defs", "PASS_MAX_DAYS 99999\n");

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PamHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "minlen".to_string(),
        PolicyException {
            value: "99".to_string(),
            allowed: true,
            reason: "Stale exception".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let report = plugin.validate(&ctx, &config).await.unwrap();

    assert!(
        report
            .validation_report_estimated_changes
            .iter()
            .any(|c| c.contains("minlen")),
        "a non-matching exception must leave the directive in the preview, got: {:?}",
        report.validation_report_estimated_changes
    );
}

/// State-aware apply: a fully compliant host gets no file rewrites and no
/// backups; every directive is reported as an already-set Skipped no-op, so
/// the applied count is honestly zero.
#[tokio::test]
async fn pam_apply_all_compliant_writes_nothing_and_makes_no_backups() {
    let executor = Arc::new(secure_pam_executor());
    let mut ctx = Context::with_executor(executor.clone());
    let plugin = PamHardeningPlugin::new();

    let result = plugin
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert!(result.apply_success, "compliant apply should succeed");

    let log = executor.log();
    assert!(
        log.files_written.is_empty(),
        "no file should be rewritten on a compliant host, got: {:?}",
        log.files_written
    );
    assert!(
        !log.commands_executed.iter().any(|(prog, _)| prog == "cp"),
        "no backup should be created on a compliant host, got: {:?}",
        log.commands_executed
    );

    // Every pwquality/login.defs directive reports an already-set Skipped line.
    for name in ["minlen", "PASS_MAX_DAYS"] {
        assert!(
            result.apply_changes.iter().any(|c| c.is_skipped()
                && c.change_success
                && c.change_description.contains(name)
                && c.change_description.contains("already set")),
            "expected an already-set Skipped change for {name}, got: {:?}",
            result.apply_changes
        );
    }
    assert_eq!(
        result.applied_change_count(),
        0,
        "a compliant host must count zero applied changes"
    );
}

/// State-aware apply: one drifted pwquality directive causes exactly one file
/// rewrite and exactly one backup; login.defs is left completely untouched.
#[tokio::test]
async fn pam_apply_one_drifted_rewrites_one_file_with_one_backup() {
    use std::time::{SystemTime, UNIX_EPOCH};

    // minlen drifted to 8; everything else compliant.
    let mut executor = secure_pam_executor().with_file(
        "/etc/security/pwquality.conf",
        "minlen 8\ndcredit -1\nucredit -1\nlcredit -1\nocredit -1\nmaxrepeat 3\n",
    );
    // The backup path embeds a unix timestamp; register the cp for a small
    // clock window (same idiom as the SSH mock tests).
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for t in now..now + 3 {
        let backup = format!("/etc/security/pwquality.conf.backup-{t}");
        executor = executor.with_command(
            "cp",
            &["/etc/security/pwquality.conf", &backup],
            hardener_core::CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        );
    }
    let executor = Arc::new(executor);
    let mut ctx = Context::with_executor(executor.clone());
    let plugin = PamHardeningPlugin::new();

    let result = plugin
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .unwrap();

    let log = executor.log();
    assert_eq!(
        log.files_written.len(),
        1,
        "exactly one file should be rewritten, got: {:?}",
        log.files_written
    );
    assert_eq!(
        log.files_written[0].0.to_str().unwrap(),
        "/etc/security/pwquality.conf"
    );
    assert!(
        log.files_written[0].1.contains("minlen = 14"),
        "rewrite must fix the drifted directive, got: {}",
        log.files_written[0].1
    );
    assert_eq!(
        log.commands_executed
            .iter()
            .filter(|(prog, _)| prog == "cp")
            .count(),
        1,
        "exactly one backup should be created, got: {:?}",
        log.commands_executed
    );

    // The drifted directive is a real change; a compliant one is Skipped.
    assert!(
        result
            .apply_changes
            .iter()
            .any(|c| !c.is_skipped() && c.change_description.contains("Set minlen = 14")),
        "drifted minlen must be a real change, got: {:?}",
        result.apply_changes
    );
    assert!(
        result.apply_changes.iter().any(|c| c.is_skipped()
            && c.change_description.contains("dcredit")
            && c.change_description.contains("already set")),
        "compliant dcredit must be a Skipped no-op, got: {:?}",
        result.apply_changes
    );
}

/// State-aware validate: a fully compliant host lists zero pending directives;
/// every checked directive is tallied in `validation_report_compliant_count`.
#[tokio::test]
async fn pam_validate_all_compliant_lists_no_pending_changes() {
    let executor = secure_pam_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PamHardeningPlugin::new();

    let report = plugin
        .validate(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert!(
        report.validation_report_estimated_changes.is_empty(),
        "a fully compliant host has no pending changes, got: {:?}",
        report.validation_report_estimated_changes
    );
    assert_eq!(
        report.validation_report_compliant_count, 11,
        "all 11 directives must be counted as already compliant, not listed as pending"
    );
}

/// State-aware validate: one drifted directive is listed with its current and
/// target values; the rest are summarised as compliant.
#[tokio::test]
async fn pam_validate_one_drifted_lists_exactly_that_directive() {
    let executor = secure_pam_executor().with_file(
        "/etc/security/pwquality.conf",
        "minlen 8\ndcredit -1\nucredit -1\nlcredit -1\nocredit -1\nmaxrepeat 3\n",
    );
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PamHardeningPlugin::new();

    let report = plugin
        .validate(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    let pending = &report.validation_report_estimated_changes;
    assert_eq!(
        pending.len(),
        1,
        "exactly one directive should be pending, got: {pending:?}"
    );
    assert!(
        pending[0].contains("minlen") && pending[0].contains('8') && pending[0].contains("14"),
        "pending line must show current and target, got: {}",
        pending[0]
    );
    assert_eq!(
        report.validation_report_compliant_count, 10,
        "the other 10 directives must be counted as already compliant"
    );
}

/// State-aware validate must not assert false facts without privileges: a
/// root-only pwquality.conf (stat succeeds, read denied) must yield
/// conditional requires-root lines, never a confident "(currently not set)".
#[tokio::test]
async fn pam_validate_reports_requires_root_when_pwquality_is_root_only() {
    let executor = MockExecutor::new()
        // File exists (stat succeeds) but reading it needs root.
        .with_file("/etc/security/pwquality.conf", "minlen 14\n")
        .with_read_permission_denied("/etc/security/pwquality.conf")
        .with_file(
            "/etc/login.defs",
            "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\n",
        )
        .with_file("/etc/security/faillock.conf", "deny = 3\n")
        .with_file("/etc/security/pwhistory.conf", "remember = 10\n");
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PamHardeningPlugin::new();

    let report = plugin
        .validate(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert!(
        !report
            .validation_report_estimated_changes
            .iter()
            .any(|c| c.contains("(currently not set)")),
        "an unreadable file must never be claimed 'not set', got: {:?}",
        report.validation_report_estimated_changes
    );
    let minlen_line = report
        .validation_report_estimated_changes
        .iter()
        .find(|c| c.contains("minlen"))
        .expect("minlen must still be listed");
    assert!(
        minlen_line.contains("requires root"),
        "unreadable pwquality directives must use the requires-root wording, got: {minlen_line}"
    );
}

/// Scan reads the effective faillock/pwhistory value from inline pam.d args
/// when the /etc/security/*.conf file is empty or absent, because inline args
/// override the .conf at runtime.
#[tokio::test]
async fn pam_scan_reads_inline_pamd_override() {
    // Case A: faillock.conf absent, inline deny=3 in system-auth → compliant (3 ≤ 5).
    let executor_compliant = Arc::new(
        MockExecutor::new()
            .with_file(
                "/etc/security/pwquality.conf",
                "minlen 14\ndcredit -1\nucredit -1\nlcredit -1\nocredit -1\nmaxrepeat 3\n",
            )
            .with_file(
                "/etc/login.defs",
                "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\n",
            )
            .with_file("/etc/security/pwhistory.conf", "remember = 10\n")
            // faillock.conf is intentionally absent; deny configured inline below
            .with_file(
                "/etc/pam.d/system-auth",
                "auth required pam_faillock.so preauth silent deny=3\n",
            ),
    );
    let ctx = Context::with_executor(executor_compliant);
    let plugin = PamHardeningPlugin::new();
    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    assert!(
        !result
            .scan_findings
            .iter()
            .any(|f| f.finding_id == "pam-deny"),
        "inline deny=3 (≤5) should not produce a deny finding, got: {:?}",
        result
            .scan_findings
            .iter()
            .map(|f| &f.finding_id)
            .collect::<Vec<_>>()
    );

    // Case B: inline deny=10 (> 5) → non-compliant, finding expected.
    let executor_non_compliant = Arc::new(
        MockExecutor::new()
            .with_file(
                "/etc/security/pwquality.conf",
                "minlen 14\ndcredit -1\nucredit -1\nlcredit -1\nocredit -1\nmaxrepeat 3\n",
            )
            .with_file(
                "/etc/login.defs",
                "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\n",
            )
            .with_file("/etc/security/pwhistory.conf", "remember = 10\n")
            .with_file(
                "/etc/pam.d/system-auth",
                "auth required pam_faillock.so preauth silent deny=10\n",
            ),
    );
    let ctx2 = Context::with_executor(executor_non_compliant);
    let result2 = plugin.scan(&ctx2, &PluginConfig::default()).await.unwrap();

    assert!(
        result2
            .scan_findings
            .iter()
            .any(|f| f.finding_id == "pam-deny"),
        "inline deny=10 (>5) should produce a deny finding"
    );
}

/// When a non-compliant value is set inline in the PAM stack, apply must NOT
/// write to the .conf (a silent no-op) and must report the manual action.
#[tokio::test]
async fn pam_apply_refuses_inline_pamd_override() {
    let executor = Arc::new(
        MockExecutor::new()
            .with_file(
                "/etc/security/pwquality.conf",
                "minlen 14\ndcredit -1\nucredit -1\nlcredit -1\nocredit -1\nmaxrepeat 3\n",
            )
            .with_file(
                "/etc/login.defs",
                "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\n",
            )
            // faillock.conf empty; the inline arg is what counts
            .with_file("/etc/security/faillock.conf", "")
            .with_file("/etc/security/pwhistory.conf", "remember = 10\n")
            // Non-compliant inline: deny=10 overrides the .conf at runtime
            .with_file(
                "/etc/pam.d/system-auth",
                "auth required pam_faillock.so preauth silent deny=10\n",
            ),
    );
    let mut ctx = Context::with_executor(executor.clone());
    let plugin = PamHardeningPlugin::new();

    let result = plugin
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .unwrap();

    // (a) faillock.conf must NOT have been written with a new deny value.
    assert!(
        !result
            .apply_changes
            .iter()
            .any(|c| { c.change_description.contains("Set deny") && c.change_success }),
        "apply must not emit a successful 'Set deny' change when deny is inline"
    );

    // (b) There must be a failed change whose description mentions the PAM stack
    //     and a manual edit.
    let inline_change = result
        .apply_changes
        .iter()
        .find(|c| !c.change_success && c.change_description.contains("deny"));
    assert!(
        inline_change.is_some(),
        "apply must emit a failed change for inline deny, got: {:?}",
        result.apply_changes
    );
    let inline_change = inline_change.unwrap();
    assert!(
        inline_change.change_description.contains("PAM stack")
            || inline_change.change_description.contains("pam.d")
            || inline_change.change_description.contains("manually"),
        "failed change should mention the PAM stack or manual edit, got: {}",
        inline_change.change_description
    );
    assert!(
        !result.apply_success,
        "apply_success must be false when an inline override blocks auto-remediation"
    );
}

/// A root-only pwquality.conf must not read as an empty file: that would
/// falsely flag every directive as "not set" on a hardened, unprivileged
/// scan. The permission failure surfaces as unchecked instead.
#[tokio::test]
async fn pam_scan_reports_unchecked_not_findings_when_pwquality_is_root_only() {
    let mock = MockExecutor::new()
        .with_read_permission_denied("/etc/security/pwquality.conf")
        .with_file("/etc/login.defs", "PASS_MAX_DAYS 365\n");
    let ctx = Context::with_executor(Arc::new(mock));
    let result = PamHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    // No false "not set" findings for pwquality directives.
    assert!(
        !result
            .scan_findings
            .iter()
            .any(|f| f.finding_id == "pam-minlen"),
        "minlen must not be flagged when the file is unreadable"
    );
    // Every pwquality directive appears as unchecked instead.
    let unchecked_ids: Vec<&str> = result
        .scan_unchecked
        .iter()
        .map(|u| u.unchecked_check_id.as_str())
        .collect();
    assert!(unchecked_ids.contains(&"pam-minlen"));
    assert!(unchecked_ids.contains(&"pam-dcredit"));
    assert!(result.scan_success);
}

/// Root-only faillock/pwhistory confs with no inline pam.d override must
/// surface their threshold directives as unchecked, not as "not set" findings.
#[tokio::test]
async fn pam_scan_reports_unchecked_when_threshold_confs_are_root_only() {
    let mock = MockExecutor::new()
        .with_file(
            "/etc/security/pwquality.conf",
            "minlen 14\ndcredit -1\nucredit -1\nlcredit -1\nocredit -1\nmaxrepeat 3\n",
        )
        .with_file(
            "/etc/login.defs",
            "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\n",
        )
        .with_read_permission_denied("/etc/security/faillock.conf")
        .with_read_permission_denied("/etc/security/pwhistory.conf");
    let ctx = Context::with_executor(Arc::new(mock));
    let result = PamHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    let finding_ids: Vec<&str> = result
        .scan_findings
        .iter()
        .map(|f| f.finding_id.as_str())
        .collect();
    assert!(
        !finding_ids.contains(&"pam-deny") && !finding_ids.contains(&"pam-remember"),
        "root-only threshold confs must not produce 'not set' findings, got: {finding_ids:?}"
    );

    let unchecked_ids: Vec<&str> = result
        .scan_unchecked
        .iter()
        .map(|u| u.unchecked_check_id.as_str())
        .collect();
    assert!(
        unchecked_ids.contains(&"pam-deny"),
        "deny must be unchecked, got: {unchecked_ids:?}"
    );
    assert!(
        unchecked_ids.contains(&"pam-remember"),
        "remember must be unchecked, got: {unchecked_ids:?}"
    );
    assert!(result.scan_success);
}

/// An inline pam.d override wins outright even when the backing
/// /etc/security conf is root-only: the directive is evaluated from the
/// inline value (world-readable) and never lands in scan_unchecked.
#[tokio::test]
async fn pam_scan_inline_override_wins_over_permission_denied_conf() {
    // Inline deny=10 (> 5) is non-compliant, so an evaluation from the inline
    // value must produce a genuine finding with that value, proving the
    // root-only faillock.conf was never needed.
    let mock = MockExecutor::new()
        .with_file(
            "/etc/security/pwquality.conf",
            "minlen 14\ndcredit -1\nucredit -1\nlcredit -1\nocredit -1\nmaxrepeat 3\n",
        )
        .with_file(
            "/etc/login.defs",
            "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\n",
        )
        .with_file("/etc/security/pwhistory.conf", "remember = 10\n")
        .with_read_permission_denied("/etc/security/faillock.conf")
        .with_file(
            "/etc/pam.d/system-auth",
            "auth required pam_faillock.so preauth silent deny=10\n",
        );
    let ctx = Context::with_executor(Arc::new(mock));
    let result = PamHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    let deny_finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "pam-deny")
        .expect("inline deny=10 (>5) must be evaluated and flagged");
    assert_eq!(
        deny_finding.finding_current_value, "10",
        "finding must carry the inline value"
    );
    assert!(
        !result
            .scan_unchecked
            .iter()
            .any(|u| u.unchecked_check_id == "pam-deny"),
        "deny must not be unchecked when the inline override supplies its value"
    );
    assert!(result.scan_success);
}

/// Apply honours a stricter per-host override (clamped so it never loosens).
#[tokio::test]
async fn pam_apply_honours_stricter_override() {
    // Case A: config override deny→"3", conf has deny=5 → apply should write deny=3.
    let executor_tighten = Arc::new(
        MockExecutor::new()
            .with_file(
                "/etc/security/pwquality.conf",
                "minlen 14\ndcredit -1\nucredit -1\nlcredit -1\nocredit -1\nmaxrepeat 3\n",
            )
            .with_file(
                "/etc/login.defs",
                "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\n",
            )
            .with_file("/etc/security/faillock.conf", "deny = 5\n")
            .with_file("/etc/security/pwhistory.conf", "remember = 10\n"),
    );
    let mut ctx_tighten = Context::with_executor(executor_tighten.clone());
    let plugin = PamHardeningPlugin::new();

    let mut config_tighten = PluginConfig::default();
    config_tighten
        .directives
        .insert("deny".to_string(), "3".to_string());

    plugin
        .apply(&mut ctx_tighten, &config_tighten)
        .await
        .unwrap();

    let files = executor_tighten.files();
    let faillock = files
        .get(std::path::Path::new("/etc/security/faillock.conf"))
        .cloned()
        .unwrap_or_default();
    assert!(
        faillock.contains("deny = 3"),
        "stricter override (deny→3) should be written, got: {faillock}"
    );

    // Case B: config override deny→"10" (looser than 5), conf has deny=5 (compliant) →
    //         apply must NOT write (override clamped to 5, already compliant).
    let executor_clamp = Arc::new(
        MockExecutor::new()
            .with_file(
                "/etc/security/pwquality.conf",
                "minlen 14\ndcredit -1\nucredit -1\nlcredit -1\nocredit -1\nmaxrepeat 3\n",
            )
            .with_file(
                "/etc/login.defs",
                "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\n",
            )
            .with_file("/etc/security/faillock.conf", "deny = 5\n")
            .with_file("/etc/security/pwhistory.conf", "remember = 10\n"),
    );
    let mut ctx_clamp = Context::with_executor(executor_clamp.clone());

    let mut config_clamp = PluginConfig::default();
    config_clamp
        .directives
        .insert("deny".to_string(), "10".to_string());

    let result_clamp = plugin.apply(&mut ctx_clamp, &config_clamp).await.unwrap();

    let files_clamp = executor_clamp.files();
    let faillock_clamp = files_clamp
        .get(std::path::Path::new("/etc/security/faillock.conf"))
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        faillock_clamp, "deny = 5\n",
        "looser override (deny→10) must be clamped; conf with deny=5 (already compliant) must not be rewritten"
    );
    assert!(
        result_clamp.apply_changes.iter().any(|c| {
            c.change_success
                && c.change_description
                    .contains("deny already meets threshold")
        }),
        "clamped looser override should produce an 'already meets threshold' change"
    );
}
