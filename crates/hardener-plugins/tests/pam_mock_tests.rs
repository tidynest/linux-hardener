//! PAM plugin tests using MockExecutor.
//!
//! These tests verify plugin behavior without touching real PAM configuration.

use hardener_common::types::{PluginId, Severity};
use hardener_core::{
    Change, Context, MockExecutor, PluginConfig, PolicyException, SystemExecutor,
    plugin::HardeningPlugin,
};
use hardener_plugins::PamHardeningPlugin;
use std::sync::Arc;

/// The secure fixture minus faillock.conf, so callers can model an absent or
/// unreadable faillock file without duplicating the other compliant directives.
fn secure_pam_executor_base() -> MockExecutor {
    MockExecutor::new()
        // pwquality.conf uses "key = value" format, which is also the form
        // apply writes: a compliant host in that form has nothing to rewrite.
        .with_file(
            "/etc/security/pwquality.conf",
            r#"# Password Quality Configuration
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
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
        // pwhistory.conf: remember=10 exceeds the minimum of 5, compliant
        .with_file("/etc/security/pwhistory.conf", "remember = 10\n")
}

/// Creates a mock executor with secure PAM configuration.
fn secure_pam_executor() -> MockExecutor {
    // faillock.conf: deny=3 is stricter than the threshold of 5, compliant
    secure_pam_executor_base().with_file("/etc/security/faillock.conf", "deny = 3\n")
}

/// Asserts that a file apply refused to rewrite is named by exactly one change,
/// the refusal, and that nothing recorded for it counts as a hardening success.
/// A directive that could not be written must record nothing of its own, or
/// "N change(s) applied" tallies writes that never happened.
fn assert_refusal_is_the_only_change(changes: &[Change], label: &str) {
    let named: Vec<&str> = changes
        .iter()
        .filter(|c| c.change_description.contains(label))
        .map(|c| c.change_description.as_str())
        .collect();
    assert_eq!(
        named.len(),
        1,
        "{label} must contribute exactly one change, the refusal, got: {named:?}"
    );
    assert!(
        !changes
            .iter()
            .any(|c| c.change_success && !c.is_skipped() && c.change_description.contains(label)),
        "no change for {label} may count as a hardening success, got: {named:?}"
    );
}

/// Registers the `cp` that `create_config_backup` issues for `path`, across a
/// three-second window so a clock tick between registration and call cannot
/// break the test.
fn with_backup_cp(mut executor: MockExecutor, path: &str) -> MockExecutor {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before the unix epoch")
        .as_secs();
    for t in now..now + 3 {
        let backup = format!("{path}.backup-{t}");
        executor = executor.with_command(
            "cp",
            &[path, &backup],
            hardener_core::CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        );
    }
    executor
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
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut executor = secure_pam_executor()
        .with_file("/etc/security/faillock.conf", "deny = 10\n")
        .with_file("/etc/security/pwhistory.conf", "remember = 2\n");
    // Both files are rewritten, and the backup path embeds a unix timestamp;
    // register cp for both across a small clock window.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for path in [
        "/etc/security/faillock.conf",
        "/etc/security/pwhistory.conf",
    ] {
        for t in now..now + 3 {
            let backup = format!("{path}.backup-{t}");
            executor = executor.with_command(
                "cp",
                &[path, &backup],
                hardener_core::CommandOutput {
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            );
        }
    }
    let executor = Arc::new(executor);
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

    // minlen drifted to 8; everything else compliant, in the form apply writes.
    let mut executor = secure_pam_executor().with_file(
        "/etc/security/pwquality.conf",
        "minlen = 8\ndcredit = -1\nucredit = -1\nlcredit = -1\nocredit = -1\nmaxrepeat = 3\n",
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

#[tokio::test]
async fn apply_refuses_to_rewrite_an_unreadable_security_conf() {
    // The file exists with a non-compliant value, so apply wants to rewrite it,
    // but its contents cannot be read. Merging directives into an empty buffer
    // would replace the host's file with ours, so the write must not happen.
    // The refusal is detected, and the function returns, before any backup is
    // attempted, so no `cp` is registered here: a registration that never runs
    // would misleadingly suggest that path is exercised.
    let path = "/etc/security/faillock.conf";
    let executor = secure_pam_executor()
        .with_file(path, "deny = 10\n")
        .with_read_permission_denied(path);
    let executor = Arc::new(executor);
    let mut ctx = Context::with_executor(executor.clone());
    let plugin = PamHardeningPlugin::new();

    let result = plugin
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("apply must run rather than abort");

    let log = executor.log();
    assert!(
        !log.files_written
            .iter()
            .any(|(written, _)| written.to_str() == Some(path)),
        "an unreadable config must never be rewritten, but got: {:?}",
        log.files_written
    );
    assert!(
        !result.apply_success,
        "refusing to harden a file must be reported, not silently swallowed"
    );
    assert!(
        result
            .apply_changes
            .iter()
            .any(|change| { !change.change_success && change.change_description.contains(path) }),
        "the refusal must be reported as a failed change naming {}, got: {:?}",
        path,
        result.apply_changes
    );
}

#[tokio::test]
async fn apply_still_creates_an_absent_security_conf() {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Guard against over-correction: a file that is simply not there has
    // genuinely unset directives and must still be created. Built from the
    // base fixture (no faillock.conf registration) rather than
    // `secure_pam_executor()`, which registers a compliant faillock.conf.
    let path = "/etc/security/faillock.conf";
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before the unix epoch")
        .as_secs();
    let mut executor = secure_pam_executor_base();
    for t in now..now + 3 {
        let backup = format!("{path}.backup-{t}");
        // A missing source cannot be backed up: this is what `cp` actually
        // does when the file is not there, and is why absence must skip the
        // backup rather than attempt and fail it.
        executor = executor.with_command(
            "cp",
            &[path, &backup],
            hardener_core::CommandOutput {
                stdout: String::new(),
                stderr: format!("cp: cannot stat '{path}': No such file or directory\n"),
                exit_code: 1,
            },
        );
    }
    let executor = Arc::new(executor);
    let mut ctx = Context::with_executor(executor.clone());
    let plugin = PamHardeningPlugin::new();

    plugin
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("apply must run");

    let log = executor.log();
    assert!(
        log.files_written
            .iter()
            .any(|(written, _)| written.to_str() == Some(path)),
        "an absent config must still be created, got: {:?}",
        log.files_written
    );
}

#[tokio::test]
async fn apply_refuses_to_rewrite_an_unreadable_pwquality() {
    // pwquality.conf exists with a drifted value, so apply wants to rewrite it,
    // but cannot read it. Rewriting would discard every directive the host has.
    // No `cp` is registered, for the reason given in
    // `apply_refuses_to_rewrite_an_unreadable_security_conf`: the refusal is
    // recorded at read time and every directive for the file is skipped, so no
    // backup is ever attempted, and a registration that cannot run would
    // misleadingly suggest that path is exercised.
    let path = "/etc/security/pwquality.conf";
    let executor = secure_pam_executor()
        .with_file(path, "minlen 8\n")
        .with_read_permission_denied(path);
    let executor = Arc::new(executor);
    let mut ctx = Context::with_executor(executor.clone());
    let plugin = PamHardeningPlugin::new();

    let result = plugin
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("apply must run rather than abort");

    let log = executor.log();
    assert!(
        !log.files_written
            .iter()
            .any(|(written, _)| written.to_str() == Some(path)),
        "an unreadable pwquality.conf must never be rewritten, got: {:?}",
        log.files_written
    );
    assert_refusal_is_the_only_change(&result.apply_changes, "pwquality.conf");
    assert!(
        !result.apply_success,
        "refusing to harden a file must be reported"
    );
}

/// Mirrors `apply_refuses_to_rewrite_an_unreadable_pwquality` for login.defs:
/// a genuinely distinct code path (its own read, its own write gate), so it
/// needs its own proof rather than relying on the pwquality coverage above.
#[tokio::test]
async fn apply_refuses_to_rewrite_an_unreadable_login_defs() {
    // No `cp` is registered here either: the refusal returns before any backup
    // is attempted, so a registration would only suggest a path that cannot run.
    let path = "/etc/login.defs";
    let executor = secure_pam_executor()
        .with_file(path, "PASS_MAX_DAYS 99999\n")
        .with_read_permission_denied(path);
    let executor = Arc::new(executor);
    let mut ctx = Context::with_executor(executor.clone());
    let plugin = PamHardeningPlugin::new();

    let result = plugin
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("apply must run rather than abort");

    let log = executor.log();
    assert!(
        !log.files_written
            .iter()
            .any(|(written, _)| written.to_str() == Some(path)),
        "an unreadable login.defs must never be rewritten, got: {:?}",
        log.files_written
    );
    assert_refusal_is_the_only_change(&result.apply_changes, "login.defs");
    assert!(
        !result.apply_success,
        "refusing to harden a file must be reported"
    );
}

/// Guard against over-correction on the other two files this task touches:
/// neither pwquality.conf nor login.defs is registered, so both are Absent
/// (a confirmed non-existence), which must still start from an empty buffer
/// and be created, exactly as before this fix, distinct from the refusal
/// above which requires a confirmed Unreadable classification.
#[tokio::test]
async fn apply_still_creates_absent_pwquality_and_login_defs() {
    let executor = Arc::new(missing_pam_config_executor());
    let mut ctx = Context::with_executor(executor.clone());
    let plugin = PamHardeningPlugin::new();

    plugin
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("apply must run");

    let log = executor.log();
    for path in ["/etc/security/pwquality.conf", "/etc/login.defs"] {
        assert!(
            log.files_written
                .iter()
                .any(|(written, _)| written.to_str() == Some(path)),
            "an absent {} must still be created, got: {:?}",
            path,
            log.files_written
        );
    }
}

/// `login.defs(5)` takes `NAME VALUE`; `=` is not part of its syntax. A host
/// hardened by an earlier release carries the proof in its own file: an
/// appended `PASS_MAX_DAYS = 90` the tools ignore, sitting below the live
/// `99999` it was meant to replace. Apply must rewrite the live line in the
/// syntax the file accepts, and clear the stale line it left behind.
#[tokio::test]
async fn apply_writes_login_defs_in_the_syntax_login_defs_accepts() {
    const REAL_LOGIN_DEFS: &str = "\
#\tPASS_MAX_DAYS\tMaximum number of days a password may be used.
#
PASS_MAX_DAYS\t99999
PASS_MIN_DAYS\t0
PASS_WARN_AGE\t7
PASS_MAX_DAYS = 90
";

    let path = "/etc/login.defs";
    // Everything else in the fixture is already compliant, so login.defs is the
    // only file this apply rewrites.
    let executor = Arc::new(with_backup_cp(
        secure_pam_executor().with_file(path, REAL_LOGIN_DEFS),
        path,
    ));
    let mut ctx = Context::with_executor(executor.clone());

    PamHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("apply must run");

    let log = executor.log();
    let written = &log
        .files_written
        .iter()
        .find(|(p, _)| p.to_str() == Some(path))
        .expect("login.defs must be rewritten")
        .1;

    let live: Vec<&str> = written
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter(|line| line.split_whitespace().next() == Some("PASS_MAX_DAYS"))
        .collect();
    assert_eq!(
        live.len(),
        1,
        "login.defs takes one definition per key, so the stale one must go:\n{written}"
    );
    assert_eq!(
        live[0].split_whitespace().collect::<Vec<_>>(),
        ["PASS_MAX_DAYS", "90"],
        "the live line must read `NAME VALUE`, with no `=`:\n{written}"
    );
    assert!(
        !written.contains("99999"),
        "the insecure value must no longer be in force:\n{written}"
    );
    assert!(
        !written.contains("PASS_MAX_DAYS = 90"),
        "`=` is not login.defs syntax:\n{written}"
    );
    assert!(
        written.contains("#\tPASS_MAX_DAYS\tMaximum number of days"),
        "the explanatory comment is documentation and must survive:\n{written}"
    );
}

/// A file that ends with a blank line is still a file with nothing to repair.
/// The writer joins the lines it was given, which drops a trailing blank, so
/// counting every line would read that as a dropped duplicate and rewrite a
/// compliant host's file for nothing.
#[tokio::test]
async fn apply_leaves_a_compliant_file_ending_in_a_blank_line_alone() {
    let path = "/etc/login.defs";
    let executor = Arc::new(with_backup_cp(
        secure_pam_executor().with_file(
            path,
            "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\n\n",
        ),
        path,
    ));
    let mut ctx = Context::with_executor(executor.clone());

    PamHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("apply must run");

    assert!(
        executor.log().files_written.is_empty(),
        "a compliant host must not be rewritten, got: {:?}",
        executor.log().files_written
    );
}

/// Clearing the line an earlier release appended cannot depend on the value
/// having drifted. `PASS_WARN_AGE 7` is the stock setting on most hosts and is
/// already the target, so the stale `PASS_WARN_AGE = 7` below it survived every
/// apply: the directive reported as already set and the writer never ran. The
/// file must converge to one definition instead.
#[tokio::test]
async fn apply_clears_a_stale_definition_whose_value_already_matches() {
    const LOGIN_DEFS: &str = "\
PASS_MAX_DAYS\t90
PASS_MIN_DAYS\t1
PASS_WARN_AGE\t7
PASS_WARN_AGE = 7
";

    let path = "/etc/login.defs";
    let executor = Arc::new(with_backup_cp(
        secure_pam_executor().with_file(path, LOGIN_DEFS),
        path,
    ));
    let mut ctx = Context::with_executor(executor.clone());

    PamHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("apply must run");

    let log = executor.log();
    let written = &log
        .files_written
        .iter()
        .find(|(p, _)| p.to_str() == Some(path))
        .expect("login.defs must be rewritten to clear the stale definition")
        .1;

    let live: Vec<&str> = written
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter(|line| line.split_whitespace().next() == Some("PASS_WARN_AGE"))
        .collect();
    assert_eq!(
        live.len(),
        1,
        "login.defs takes one definition per key, so the stale one must go:\n{written}"
    );
    assert_eq!(
        live[0].split_whitespace().collect::<Vec<_>>(),
        ["PASS_WARN_AGE", "7"],
        "the surviving line must read `NAME VALUE`, with no `=`:\n{written}"
    );
    assert!(
        written.contains("PASS_MAX_DAYS 90"),
        "a directive with nothing else to repair keeps its value, in the file's own syntax:\n{written}"
    );
}

/// The shape an earlier release left on a host where the key was absent or
/// commented out: it appended `NAME = VALUE`, so the file's only definition of
/// that key is in a syntax `login.defs(5)` does not define, carrying the value
/// the tool still targets today. Nothing about the file's line count changes
/// when the writer repairs it in place, so a skip that counts lines leaves the
/// host broken and green for ever. Apply must repair the line, and a second
/// apply must then find nothing to do.
#[tokio::test]
async fn apply_repairs_a_lone_definition_left_in_the_appended_syntax() {
    const APPENDED_ONLY: &str = "\
#PASS_MAX_DAYS\t99999
PASS_MIN_DAYS 1
PASS_WARN_AGE 7
PASS_MAX_DAYS = 90
";

    let path = "/etc/login.defs";
    let executor = Arc::new(with_backup_cp(
        secure_pam_executor().with_file(path, APPENDED_ONLY),
        path,
    ));
    let mut ctx = Context::with_executor(executor.clone());

    PamHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("apply must run");

    let log = executor.log();
    let written = log
        .files_written
        .iter()
        .find(|(p, _)| p.to_str() == Some(path))
        .expect("login.defs must be rewritten: its only definition is unreadable to shadow")
        .1
        .clone();

    assert!(
        written.contains("PASS_MAX_DAYS 90"),
        "the definition must be repaired to `NAME VALUE`:\n{written}"
    );
    assert!(
        !written.contains("PASS_MAX_DAYS = 90"),
        "`=` is not login.defs syntax:\n{written}"
    );
    let live: Vec<&str> = written
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter(|line| line.split_whitespace().next() == Some("PASS_MAX_DAYS"))
        .collect();
    assert_eq!(
        live.len(),
        1,
        "repairing the line must not add a second definition:\n{written}"
    );
    assert!(
        written.contains("#PASS_MAX_DAYS\t99999"),
        "the commented stock line is documentation and must survive:\n{written}"
    );

    // Second pass over what the first one wrote: the backup command stays
    // registered, so an empty write log means the repair converged, not that a
    // failed backup blocked the write.
    let second = Arc::new(with_backup_cp(
        secure_pam_executor().with_file(path, &written),
        path,
    ));
    let mut ctx = Context::with_executor(second.clone());

    PamHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("apply must run");

    assert!(
        second.log().files_written.is_empty(),
        "the repair must converge in one pass, got: {:?}",
        second.log().files_written
    );
}

/// The `pwquality.conf` analogue of the repair above. Its written form is
/// `key = value`; a lone definition already at the target value but left
/// bare-space separated must still be rewritten once to repair the
/// separator, and a second apply must then find nothing to do.
#[tokio::test]
async fn apply_repairs_a_lone_pwquality_definition_left_space_separated() {
    const SPACE_SEPARATED_MINLEN: &str = "\
# Password Quality Configuration
minlen 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
";

    let path = "/etc/security/pwquality.conf";
    let executor = Arc::new(with_backup_cp(
        secure_pam_executor().with_file(path, SPACE_SEPARATED_MINLEN),
        path,
    ));
    let mut ctx = Context::with_executor(executor.clone());

    PamHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("apply must run");

    let log = executor.log();
    let written = log
        .files_written
        .iter()
        .find(|(p, _)| p.to_str() == Some(path))
        .expect("pwquality.conf must be rewritten: minlen is space separated, not key = value")
        .1
        .clone();

    let live: Vec<&str> = written
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter(|line| line.split_whitespace().next() == Some("minlen"))
        .collect();
    assert_eq!(
        live.len(),
        1,
        "repairing the line must not add a second definition:\n{written}"
    );
    assert_eq!(
        live[0].split_whitespace().collect::<Vec<_>>(),
        ["minlen", "=", "14"],
        "the surviving line must read `key = value`:\n{written}"
    );

    // Second pass over what the first one wrote: the backup command stays
    // registered, so an empty write log means the repair converged, not that a
    // failed backup blocked the write.
    let second = Arc::new(with_backup_cp(
        secure_pam_executor().with_file(path, &written),
        path,
    ));
    let mut ctx = Context::with_executor(second.clone());

    PamHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("apply must run");

    assert!(
        second.log().files_written.is_empty(),
        "the repair must converge in one pass, got: {:?}",
        second.log().files_written
    );
}

/// The refusal is per file, not per run: one unreadable config must not stop
/// the other three being hardened, and must contribute exactly one change, the
/// refusal itself.
///
/// Built on a context with no checkpoint manager, which is the only place this
/// fallback is reachable. Where a manager is present, which is every path a
/// `hardener` command takes, the unreadable declared path fails the pre-apply
/// capture and aborts the whole apply before this loop runs.
#[tokio::test]
async fn apply_refuses_only_the_unreadable_file_and_hardens_the_rest() {
    let unreadable = "/etc/security/pwquality.conf";
    let written = [
        "/etc/login.defs",
        "/etc/security/faillock.conf",
        "/etc/security/pwhistory.conf",
    ];

    // Every file drifts, so apply wants to rewrite all four; only pwquality.conf
    // cannot be read.
    let mut executor = MockExecutor::new()
        .with_file(unreadable, "minlen 8\n")
        .with_read_permission_denied(unreadable)
        .with_file(
            "/etc/login.defs",
            "PASS_MAX_DAYS 99999\nPASS_MIN_DAYS 0\nPASS_WARN_AGE 7\n",
        )
        .with_file("/etc/security/faillock.conf", "deny = 10\n")
        .with_file("/etc/security/pwhistory.conf", "remember = 2\n");
    for path in written {
        executor = with_backup_cp(executor, path);
    }
    let executor = Arc::new(executor);
    let mut ctx = Context::with_executor(executor.clone());

    let result = PamHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("apply must run rather than abort");

    let log = executor.log();
    assert!(
        !log.files_written
            .iter()
            .any(|(path, _)| path.to_str() == Some(unreadable)),
        "the unreadable file must never be rewritten, got: {:?}",
        log.files_written
    );
    for path in written {
        assert!(
            log.files_written
                .iter()
                .any(|(p, _)| p.to_str() == Some(path)),
            "one unreadable file must not stop {} being hardened, got: {:?}",
            path,
            log.files_written
        );
    }

    assert_refusal_is_the_only_change(&result.apply_changes, "pwquality.conf");
    assert!(
        !result.apply_success,
        "refusing to harden a file must be reported, not silently swallowed"
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

/// Validate's `SecurityConf` estimate reuses the `observed` value already
/// computed for the exception check instead of reading the conf file a
/// second time. This pins down the "compliant" and "needs tightening"
/// wordings so that reuse can never silently change what an operator is
/// told.
#[tokio::test]
async fn pam_validate_security_conf_estimate_reuses_observed_value() {
    let executor = MockExecutor::new()
        .with_file(
            "/etc/security/pwquality.conf",
            "minlen 14\ndcredit -1\nucredit -1\nlcredit -1\nocredit -1\nmaxrepeat 3\n",
        )
        .with_file(
            "/etc/login.defs",
            "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\n",
        )
        // deny = 3 is stricter than the boundary of 5: compliant, no estimate line.
        .with_file("/etc/security/faillock.conf", "deny = 3\n")
        // remember = 2 is looser than the minimum of 5: needs tightening.
        .with_file("/etc/security/pwhistory.conf", "remember = 2\n");
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
            .any(|c| c.contains("deny")),
        "a compliant deny must not appear as a pending change, got: {:?}",
        report.validation_report_estimated_changes
    );
    let remember_line = report
        .validation_report_estimated_changes
        .iter()
        .find(|c| c.contains("remember"))
        .expect("looser remember must be listed");
    assert_eq!(
        remember_line, "remember will change: 2 -> 5",
        "wording must reflect the observed value and the clamped target"
    );
}

/// Complementary to the estimate test above: a `SecurityConf` file blocked by
/// privileges must say so, and must not promise a write.
///
/// This pinned `"deny <= 5 (current value requires root; applied only if
/// currently looser)"` until the promise in it was checked against what apply
/// does with the same host. `apply_refuses_to_rewrite_an_unreadable_security_conf`
/// asserts the file is never written, so the preview was describing a
/// conditional write no apply would attempt, and the two tests described one
/// host two ways. The wording asserted here is the one that matches.
#[tokio::test]
async fn pam_validate_security_conf_requires_root_when_faillock_is_root_only() {
    let executor = MockExecutor::new()
        .with_file(
            "/etc/security/pwquality.conf",
            "minlen 14\ndcredit -1\nucredit -1\nlcredit -1\nocredit -1\nmaxrepeat 3\n",
        )
        .with_file(
            "/etc/login.defs",
            "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\n",
        )
        .with_file("/etc/security/faillock.conf", "deny = 3\n")
        .with_read_permission_denied("/etc/security/faillock.conf")
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
            .any(|c| c.contains("deny") && c.contains("not set")),
        "an unreadable faillock.conf must never be claimed 'not set', got: {:?}",
        report.validation_report_estimated_changes
    );
    let deny_line = report
        .validation_report_estimated_changes
        .iter()
        .find(|c| c.contains("deny"))
        .expect("deny must still be listed");
    assert_eq!(
        deny_line,
        "deny will not be set to 5: /etc/security/faillock.conf could not be read \
         (current value requires root)",
        "the preview must name the file and must not promise a write apply refuses"
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
    // Registered as an existing file, then marked unreadable: a root-only
    // conf is still stat-able (its existence is not secret), only its
    // content is blocked, so the mock must reflect both facts for the
    // classifier's existence probe to land on Unreadable, not Absent.
    let mock = MockExecutor::new()
        .with_file("/etc/security/pwquality.conf", "minlen 14\n")
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
    // Both threshold confs are registered as existing files, then marked
    // unreadable, so the classifier's existence probe lands on Unreadable
    // rather than the Absent it would (wrongly) see for a path with no
    // metadata at all.
    let mock = MockExecutor::new()
        .with_file(
            "/etc/security/pwquality.conf",
            "minlen 14\ndcredit -1\nucredit -1\nlcredit -1\nocredit -1\nmaxrepeat 3\n",
        )
        .with_file(
            "/etc/login.defs",
            "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\n",
        )
        .with_file("/etc/security/faillock.conf", "deny = 3\n")
        .with_read_permission_denied("/etc/security/faillock.conf")
        .with_file("/etc/security/pwhistory.conf", "remember = 10\n")
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
        // Registered as well as denied: an unregistered path reads as absent,
        // which would model a host with no faillock.conf rather than the
        // root-only one this test is named for. The compliant deny = 3 it holds
        // is the value the finding must NOT carry, since the inline override
        // wins before this file is ever read.
        .with_file("/etc/security/faillock.conf", "deny = 3\n")
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
    use std::time::{SystemTime, UNIX_EPOCH};

    // Case A: config override deny→"3", conf has deny=5 → apply should write deny=3.
    let mut executor_tighten = MockExecutor::new()
        .with_file(
            "/etc/security/pwquality.conf",
            "minlen 14\ndcredit -1\nucredit -1\nlcredit -1\nocredit -1\nmaxrepeat 3\n",
        )
        .with_file(
            "/etc/login.defs",
            "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\n",
        )
        .with_file("/etc/security/faillock.conf", "deny = 5\n")
        .with_file("/etc/security/pwhistory.conf", "remember = 10\n");
    // deny drifts from 5 to 3, so faillock.conf is rewritten; the backup path
    // embeds a unix timestamp, so register cp across a small clock window.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for t in now..now + 3 {
        let backup = format!("/etc/security/faillock.conf.backup-{t}");
        executor_tighten = executor_tighten.with_command(
            "cp",
            &["/etc/security/faillock.conf", &backup],
            hardener_core::CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        );
    }
    let executor_tighten = Arc::new(executor_tighten);
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

/// A vendor `login.defs` of the shape openSUSE ships under `/usr/etc`. Only
/// the keys the assertions need are present; the real file sets 38.
const VENDOR_LOGIN_DEFS: &str = "\
UMASK           022
ENCRYPT_METHOD  yescrypt
PASS_MAX_DAYS   99999
PASS_MIN_DAYS   0
PASS_WARN_AGE   7
";

#[tokio::test]
async fn apply_materialises_the_vendor_file_before_editing_it() {
    // openSUSE keeps vendor configuration in /usr/etc and reserves /etc for
    // administrator overrides, and that override is whole-file rather than per
    // directive. Creating a three-directive /etc/login.defs therefore silences
    // every other key the vendor file sets, including ENCRYPT_METHOD and
    // UMASK. Hardening three settings by disabling the rest is not hardening,
    // so the vendor copy is carried over first and the managed directives are
    // edited into that copy.
    let executor = Arc::new(
        secure_pam_executor_base()
            .with_file("/etc/security/faillock.conf", "deny = 3\n")
            .without_file("/etc/login.defs")
            .with_file("/usr/etc/login.defs", VENDOR_LOGIN_DEFS)
            .with_command_program(
                "chmod",
                hardener_core::CommandOutput {
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            ),
    );
    let mut ctx = Context::with_executor(executor.clone());

    let result = PamHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("apply must run rather than abort");

    let log = executor.log();
    let written = log
        .files_written
        .iter()
        .find(|(path, _)| path.to_str() == Some("/etc/login.defs"))
        .map(|(_, content)| content.clone())
        .unwrap_or_else(|| {
            panic!(
                "login.defs must be written, not refused; wrote: {:?}",
                log.files_written
            )
        });
    for key in ["UMASK", "ENCRYPT_METHOD", "PASS_MIN_DAYS", "PASS_WARN_AGE"] {
        assert!(
            written.contains(key),
            "materialising must preserve every vendor key; {key} is missing from: {written}"
        );
    }
    assert!(
        written.contains("PASS_MAX_DAYS 90"),
        "the managed directive must still be applied to the copy: {written}"
    );
    assert!(
        result.apply_success,
        "the host is hardened and the vendor settings survive: {:?}",
        result.apply_changes
    );
}

#[tokio::test]
async fn a_materialised_file_wears_the_vendor_mode_not_the_temporary_file_s() {
    // update_file_atomically restores an *original* mode, and a file being
    // created has none, so it keeps whatever the temporary file had. That is
    // how the tool's /etc/security/pwquality.conf landed 0600 on openSUSE
    // against the vendor's 0644, and at 0600 pwscore and pwmake cannot read it
    // and silently fall back to their built-in defaults: a configuration that
    // appears to apply and does not.
    let executor = Arc::new(
        secure_pam_executor_base()
            .with_file("/etc/security/faillock.conf", "deny = 3\n")
            .without_file("/etc/login.defs")
            .with_file("/usr/etc/login.defs", VENDOR_LOGIN_DEFS)
            .with_command_program(
                "chmod",
                hardener_core::CommandOutput {
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            ),
    );
    let mut ctx = Context::with_executor(executor.clone());

    PamHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("apply must run");

    assert!(
        executor
            .log()
            .commands_executed
            .iter()
            .any(|(command, args)| {
                command == "chmod"
                    && args.iter().any(|a| a == "/etc/login.defs")
                    && args.iter().any(|a| a.contains("644"))
            }),
        "the created file must be given the vendor file's mode, commands: {:?}",
        executor.log().commands_executed
    );
}

#[tokio::test]
async fn apply_refuses_when_it_cannot_tell_whether_a_vendor_file_exists() {
    // Fail closed. A probe that errors is not evidence of absence, and
    // authorising the write on it would mask the vendor file exactly as
    // confidently as ignoring the layer altogether.
    let executor = secure_pam_executor_base()
        .with_file("/etc/security/faillock.conf", "deny = 3\n")
        .without_file("/etc/login.defs")
        .with_path_exists_error("/usr/etc/login.defs");
    let executor = Arc::new(executor);
    let mut ctx = Context::with_executor(executor.clone());
    let plugin = PamHardeningPlugin::new();

    let result = plugin
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("apply must run rather than abort");

    let log = executor.log();
    assert!(
        !log.files_written
            .iter()
            .any(|(written, _)| written.to_str() == Some("/etc/login.defs")),
        "an unverifiable vendor layer must not authorise the write, but apply wrote: {:?}",
        log.files_written
    );
    assert!(!result.apply_success, "the refusal must be reported");
    assert!(
        result.apply_changes.iter().any(|change| {
            !change.change_success && change.change_description.contains("could not be checked")
        }),
        "an indeterminate probe must read differently from a confirmed vendor file, got: {:?}",
        result.apply_changes
    );
}

#[tokio::test]
async fn apply_materialises_a_vendor_security_conf_before_editing_it() {
    // The same door, on the other file kind. faillock.conf is written through
    // the SecurityConf arm, which has its own read and its own write, so
    // handling login.defs alone would leave this one masking its vendor copy.
    // The vendor value breaches the threshold, so a write is genuinely wanted
    // and the vendor's other settings have to survive it.
    let executor = Arc::new(
        secure_pam_executor_base()
            .with_file(
                "/usr/etc/security/faillock.conf",
                "deny = 10\naudit\nsilent\n",
            )
            .with_command_program(
                "chmod",
                hardener_core::CommandOutput {
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            ),
    );
    let mut ctx = Context::with_executor(executor.clone());

    let result = PamHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("apply must run rather than abort");

    let log = executor.log();
    let written = log
        .files_written
        .iter()
        .find(|(path, _)| path.to_str() == Some("/etc/security/faillock.conf"))
        .map(|(_, content)| content.clone())
        .unwrap_or_else(|| {
            panic!(
                "faillock.conf must be written, not refused; wrote: {:?}",
                log.files_written
            )
        });
    for key in ["audit", "silent"] {
        assert!(
            written.contains(key),
            "the vendor's unmanaged settings must survive; {key} is missing from: {written}"
        );
    }
    assert!(
        written.contains("deny = 5"),
        "the managed directive must be clamped into the copy: {written}"
    );
    assert!(
        result.apply_success,
        "the host is hardened and the vendor settings survive: {:?}",
        result.apply_changes
    );
}

/// A vendor `login.defs` whose password-ageing keys already meet this tool's
/// targets, so a scan that reads the layer it lives in has nothing to report.
const COMPLIANT_VENDOR_LOGIN_DEFS: &str = "\
UMASK           022
ENCRYPT_METHOD  yescrypt
PASS_MAX_DAYS   90
PASS_MIN_DAYS   1
PASS_WARN_AGE   7
";

#[tokio::test]
async fn scan_reads_login_defs_from_the_vendor_layer() {
    // openSUSE ships no /etc/login.defs. Reading only that path made every
    // directive it sets read as unset, so the scan reported findings against a
    // host whose vendor file already held compliant values.
    let executor = Arc::new(
        secure_pam_executor()
            .without_file("/etc/login.defs")
            .with_file("/usr/etc/login.defs", COMPLIANT_VENDOR_LOGIN_DEFS),
    );
    let ctx = Context::with_executor(executor.clone());

    let result = PamHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .expect("scan runs");

    let reported: Vec<&str> = result
        .scan_findings
        .iter()
        .map(|f| f.finding_id.as_str())
        .collect();
    for key in ["PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_WARN_AGE"] {
        assert!(
            !reported.iter().any(|id| id.contains(key)),
            "the vendor file already sets a compliant {key}, so there is nothing to \
             report; got: {reported:?}"
        );
    }
}

#[tokio::test]
async fn scan_does_not_report_an_unreadable_login_defs_as_unset() {
    // A root-only /etc/login.defs is not an empty one. Folding the read failure
    // into an empty buffer made every directive it sets read as unset, so an
    // unprivileged scan reported findings against a host that is hardened.
    let executor = Arc::new(secure_pam_executor().with_read_permission_denied("/etc/login.defs"));
    let ctx = Context::with_executor(executor.clone());

    let result = PamHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .expect("scan runs");

    let reported: Vec<&str> = result
        .scan_findings
        .iter()
        .map(|f| f.finding_id.as_str())
        .collect();
    for key in ["PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_WARN_AGE"] {
        assert!(
            !reported.iter().any(|id| id.contains(key)),
            "a file this scan could not read must never be reported as unset; got: \
             {reported:?}"
        );
    }
    assert!(
        !result.scan_unchecked.is_empty(),
        "the privilege failure must surface as unchecked entries instead"
    );
}

#[tokio::test]
async fn an_inline_pam_argument_in_a_vendor_stack_file_is_honoured() {
    // pam.d layers per service file. A vendor system-auth with an inline deny=
    // overrides /etc/security/faillock.conf, so missing that layer makes the
    // tool report a threshold that is not the one in force.
    let executor = Arc::new(secure_pam_executor().with_file(
        "/usr/etc/pam.d/system-auth",
        "auth required pam_faillock.so deny=10\n",
    ));
    let ctx = Context::with_executor(executor.clone());

    let result = PamHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .expect("scan runs");

    assert!(
        result
            .scan_findings
            .iter()
            .any(|f| f.finding_id.contains("deny")),
        "deny=10 inline exceeds the threshold and is what sshd's PAM stack \
         actually enforces, so it must be reported; got: {:?}",
        result
            .scan_findings
            .iter()
            .map(|f| f.finding_id.as_str())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn a_compliant_vendor_security_conf_needs_neither_a_write_nor_a_refusal() {
    // Reading the layer the value lives in is what makes this case visible at
    // all. While the tool could only see /etc it read the directive as unset,
    // wanted to write, and the vendor-mask guard had to stop it; the host was
    // reported unsuccessful for being already compliant. Now the value is
    // observed, nothing needs writing, and there is nothing to refuse.
    let executor = Arc::new(secure_pam_executor_base().with_file(
        "/usr/etc/security/faillock.conf",
        "deny = 3\naudit\nsilent\n",
    ));
    let mut ctx = Context::with_executor(executor.clone());

    let result = PamHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("apply must run");

    assert!(
        !executor
            .log()
            .files_written
            .iter()
            .any(|(written, _)| written.to_str() == Some("/etc/security/faillock.conf")),
        "a compliant vendor value must not be copied into /etc, wrote: {:?}",
        executor.log().files_written
    );
    assert!(
        result.apply_success,
        "being already compliant is not a failure: {:?}",
        result.apply_changes
    );
}

#[tokio::test]
async fn scan_reports_vendor_keys_the_admin_file_masks() {
    // The override is whole-file, so an /etc/login.defs setting one key silences
    // every other key the vendor file sets. Nothing in the tool said so: the
    // scan read the file in force, found the directives it manages, and reported
    // a host whose ENCRYPT_METHOD and UMASK had quietly reverted to shadow's
    // built-in defaults as clean.
    //
    // It fires whoever caused the masking. An operator's hand-rolled file, a
    // vendor that adds a key in a later package, and an older release of this
    // tool all produce the same drift, and the scan cannot tell them apart.
    let executor = Arc::new(
        secure_pam_executor()
            .with_file("/etc/login.defs", "PASS_MAX_DAYS 90\n")
            .with_file("/usr/etc/login.defs", VENDOR_LOGIN_DEFS),
    );
    let ctx = Context::with_executor(executor.clone());

    let result = PamHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .expect("scan runs");

    let drift = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "pam-login-defs-masked-keys")
        .unwrap_or_else(|| {
            panic!(
                "a masked vendor key must be reported; got: {:?}",
                result
                    .scan_findings
                    .iter()
                    .map(|f| f.finding_id.as_str())
                    .collect::<Vec<_>>()
            )
        });

    for key in ["ENCRYPT_METHOD", "UMASK", "PASS_MIN_DAYS", "PASS_WARN_AGE"] {
        assert!(
            drift.finding_current_value.contains(key),
            "the finding must name every masked key; {key} is missing from: {}",
            drift.finding_current_value
        );
    }
    // PASS_MAX_DAYS is set in /etc, so the vendor's value is overridden rather
    // than lost. Listing it would turn every layered host into a wall of keys
    // that are working as intended, and would pass an implementation that
    // reports the vendor file's contents instead of the difference.
    assert!(
        !drift.finding_current_value.contains("PASS_MAX_DAYS"),
        "a key the admin file sets is overridden, not masked: {}",
        drift.finding_current_value
    );
    assert_eq!(
        drift.finding_severity,
        Severity::Medium,
        "masking a vendor login.defs was measured dropping password hashing to \
         DES on openSUSE, and the scheduler drops anything below Medium, so at \
         Low a fleet host with DES passwords would record nothing"
    );
    assert!(
        drift.finding_compliance.is_empty(),
        "no framework maps this, and a mapping would let it drive a control to \
         Fail: {:?}",
        drift.finding_compliance
    );
}

#[tokio::test]
async fn nothing_is_reported_when_the_admin_file_sets_every_vendor_key() {
    // Opposite direction: this passes against an implementation that never
    // reports anything, so it is not evidence of the fix. It is here to stop the
    // finding firing on the mere presence of a vendor file, which would put a
    // permanent Low on every openSUSE host that has taken a full copy.
    let executor = Arc::new(
        secure_pam_executor()
            .with_file("/etc/login.defs", VENDOR_LOGIN_DEFS)
            .with_file("/usr/etc/login.defs", VENDOR_LOGIN_DEFS),
    );
    let ctx = Context::with_executor(executor.clone());

    let result = PamHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .expect("scan runs");

    assert!(
        !result
            .scan_findings
            .iter()
            .any(|f| f.finding_id == "pam-login-defs-masked-keys"),
        "an admin file that keeps every vendor key masks nothing"
    );
}

#[tokio::test]
async fn scan_reports_masked_keys_in_every_layered_pam_conf_not_only_login_defs() {
    // The whole-file override is a property of the layering, not of login.defs.
    // /etc/security/{pwquality,faillock,pwhistory}.conf mask their /usr/etc
    // counterparts identically, and the drift check covered none of them, so a
    // hand-rolled pwquality.conf silenced every quality rule the vendor set and
    // the scan reported the host clean.
    //
    // All three in one test on purpose: the defect is that the check is wired to
    // one path rather than to the layering, so proving one file is fixed proves
    // nothing about the other two.
    let executor = Arc::new(
        secure_pam_executor()
            .with_file(
                "/usr/etc/security/pwquality.conf",
                "minlen = 8\ndifok = 5\nminclass = 4\n",
            )
            .with_file(
                "/usr/etc/security/faillock.conf",
                "deny = 5\nunlock_time = 900\neven_deny_root =\n",
            )
            .with_file(
                "/usr/etc/security/pwhistory.conf",
                "remember = 5\nenforce_for_root =\n",
            ),
    );
    let ctx = Context::with_executor(executor.clone());

    let result = PamHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .expect("scan runs");

    let seen: Vec<&str> = result
        .scan_findings
        .iter()
        .map(|f| f.finding_id.as_str())
        .collect();

    for (id, masked, overridden) in [
        (
            "pam-pwquality-conf-masked-keys",
            &["difok", "minclass"][..],
            "minlen",
        ),
        (
            "pam-faillock-conf-masked-keys",
            &["even_deny_root", "unlock_time"][..],
            "deny",
        ),
        (
            "pam-pwhistory-conf-masked-keys",
            &["enforce_for_root"][..],
            "remember",
        ),
    ] {
        let drift = result
            .scan_findings
            .iter()
            .find(|f| f.finding_id == id)
            .unwrap_or_else(|| panic!("{id} must be reported; got: {seen:?}"));

        // Compared key by key rather than by substring: `even_deny_root`
        // contains `deny`, so a `contains` check would call the masked key the
        // overridden one and fail against correct output.
        let named: Vec<&str> = drift.finding_current_value.split(", ").collect();
        assert_eq!(
            named, masked,
            "{id} must name exactly the keys the vendor sets and the admin file \
             does not"
        );
        // Set at both layers, so the vendor's value is overridden rather than
        // lost. Naming it would pass an implementation that lists the vendor
        // file's contents instead of the set difference.
        assert!(
            !named.contains(&overridden),
            "{id} must not name {overridden}, which the admin file sets: {}",
            drift.finding_current_value
        );
        assert_eq!(
            drift.finding_severity,
            Severity::Medium,
            "{id} must match the severity login.defs drift already carries, or \
             the scheduler drops it below its default min_severity"
        );
        // Guard, not evidence: this passes against the unfixed code too, since
        // the unfixed code emits no such finding at all. It is here so a later
        // edit cannot quietly map these to a framework control, which would let
        // a masked file drive that control to Fail on evidence no framework
        // asked for.
        assert!(
            drift.finding_compliance.is_empty(),
            "{id} must carry no compliance mapping: {:?}",
            drift.finding_compliance
        );
    }
}

#[tokio::test]
async fn validate_reports_the_layer_drift_scan_reports() {
    // `apply --dry-run` runs this path, and it is what an operator reads before
    // deciding to apply. It described the directives that would change and said
    // nothing about masked keys, so a host whose vendor settings had already
    // reverted previewed identically to one whose had not, and the operator
    // applied believing the preview was the whole story.
    //
    // Two files rather than one, because the point is that validate asks the
    // same shared question scan asks. A second hardcoded path would satisfy a
    // single-file assertion.
    let executor = Arc::new(
        secure_pam_executor()
            .with_file("/usr/etc/login.defs", VENDOR_LOGIN_DEFS)
            .with_file(
                "/usr/etc/security/pwquality.conf",
                "minlen = 8\ndifok = 5\n",
            ),
    );
    let ctx = Context::with_executor(executor.clone());

    let report = PamHardeningPlugin::new()
        .validate(&ctx, &PluginConfig::default())
        .await
        .expect("validate runs");

    let messages: Vec<&str> = report
        .validation_report_issues
        .iter()
        .map(|i| i.validation_issue_message.as_str())
        .collect();

    for (file, key) in [
        ("/etc/login.defs", "ENCRYPT_METHOD"),
        ("/etc/security/pwquality.conf", "difok"),
    ] {
        let issue = report
            .validation_report_issues
            .iter()
            .find(|i| {
                i.validation_issue_message.contains(file)
                    && i.validation_issue_message.contains("mask")
            })
            .unwrap_or_else(|| {
                panic!("validate must report {file} masking its vendor copy; got: {messages:?}")
            });
        assert!(
            issue.validation_issue_message.contains(key),
            "the issue for {file} must name the masked key {key}: {}",
            issue.validation_issue_message
        );
        assert_eq!(
            issue.validation_issue_severity,
            Severity::Medium,
            "drift is the same severity here as the finding scan reports for it"
        );
    }

    // Drift is not a pending change. apply deliberately does not import keys an
    // existing /etc file omits, so listing it here would inflate the change
    // count and promise a write that never happens, which is the defect this
    // preview already carries one arm over.
    assert!(
        !report
            .validation_report_estimated_changes
            .iter()
            .any(|c| c.contains("mask")),
        "masked keys are not a change apply will make: {:?}",
        report.validation_report_estimated_changes
    );
}

// === An unreadable PAM stack (M) ===

/// The first file `pamd_module_for("deny")` searches. An inline
/// `pam_faillock.so ... deny=N` here overrides `/etc/security/faillock.conf`
/// entirely, which is what makes an unreadable copy of it consequential.
const PAM_STACK_FILE: &str = "/etc/pam.d/system-auth";

/// A PAM stack this run could not read leaves the effective value unknown, and
/// unknown is not the same as compliant.
///
/// An inline argument on the module wins over the `.conf`, so a stack that
/// could not be read means the `.conf` value may not be the one in force. The
/// read folded that into the same answer as a stack positively confirmed to
/// carry no override, and the scan then reported the `.conf` value as the
/// host's own: a host whose stack says `deny=10` reads as compliant on the
/// strength of a `faillock.conf` nothing consults.
#[tokio::test]
async fn scan_reports_deny_unchecked_when_the_pam_stack_cannot_be_read() {
    let executor = Arc::new(
        secure_pam_executor()
            .with_file(PAM_STACK_FILE, "auth required pam_faillock.so deny=10\n")
            .with_read_permission_denied(PAM_STACK_FILE),
    );
    let ctx = Context::with_executor(executor.clone());

    let result = PamHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .expect("scan runs");

    assert!(
        result
            .scan_unchecked
            .iter()
            .any(|u| u.unchecked_check_id == "pam-deny"),
        "deny cannot be assessed while the stack that may override it is \
         unreadable, got unchecked: {:?} findings: {:?}",
        result
            .scan_unchecked
            .iter()
            .map(|u| &u.unchecked_check_id)
            .collect::<Vec<_>>(),
        result
            .scan_findings
            .iter()
            .map(|f| &f.finding_id)
            .collect::<Vec<_>>()
    );
}

/// Apply must not write a file whose value may already be overridden.
///
/// Writing `faillock.conf` while an inline `deny=` sits in the stack is a
/// silent no-op: the write succeeds, the change is recorded as applied, and
/// the host keeps enforcing the inline value. Apply already refuses when it
/// can see the inline argument. It could not see one it failed to read, so it
/// wrote the file and reported a success that changed nothing.
///
/// The backup command is registered across a small clock window so the write
/// is genuinely reachable. Without it the apply stops at a failed backup, and
/// the test passes for a reason that has nothing to do with the stack.
#[tokio::test]
async fn apply_refuses_to_write_the_conf_when_the_pam_stack_cannot_be_read() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let conf = "/etc/security/faillock.conf";
    let mut executor = secure_pam_executor_base()
        .with_file(conf, "deny = 10\n")
        .with_file(PAM_STACK_FILE, "auth required pam_faillock.so deny=10\n")
        .with_read_permission_denied(PAM_STACK_FILE);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for t in now..now + 3 {
        executor = executor.with_command(
            "cp",
            &[conf, &format!("{conf}.backup-{t}")],
            hardener_core::CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        );
    }
    let executor = Arc::new(executor);
    let mut ctx = Context::with_executor(executor.clone());

    let result = PamHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("apply must run rather than abort");

    assert!(
        !executor
            .log()
            .files_written
            .iter()
            .any(|(written, _)| written.to_str() == Some(conf)),
        "writing {conf} cannot take effect while an unread stack may override \
         it, but it was written: {:?}",
        executor.log().files_written
    );
    assert!(
        result
            .apply_changes
            .iter()
            .any(|c| !c.change_success && c.change_description.contains(PAM_STACK_FILE)),
        "the operator must learn which stack file could not be read, got: {:?}",
        result.apply_changes
    );
}
