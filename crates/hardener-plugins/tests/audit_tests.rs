//! Integration tests for Audit Hardening plugin

use hardener_core::{Context, PluginConfig, plugin::HardeningPlugin};
use hardener_plugins::AuditHardeningPlugin;

#[test]
fn test_audit_plugin_metadata() {
    let plugin = AuditHardeningPlugin::new();
    let metadata = plugin.metadata();

    assert_eq!(metadata.plugin_id.to_string(), "audit-hardening");
    assert_eq!(metadata.plugin_name, "Audit Rules Hardening");
    assert_eq!(metadata.plugin_version, env!("CARGO_PKG_VERSION"));
    assert!(metadata.plugin_description.contains("auditd"));
}

#[test]
fn test_audit_plugin_has_no_dependencies() {
    let plugin = AuditHardeningPlugin::new();
    let dependencies = plugin.dependencies();

    assert_eq!(
        dependencies.len(),
        0,
        "Audit plugin should have no dependencies"
    );
}

/// Declared environment smoke test. `Context::new()` hands the plugin a
/// `LocalExecutor`, so this runs against whatever host executes it, and it may
/// therefore assert only what is true on every host: the call completed, it
/// answered for this plugin, and it recorded how long it took. What the scan
/// finds on a host with auditd absent, disabled or partially ruled is covered
/// deterministically in `audit_mock_tests.rs`, where the fixture decides.
///
/// The per-finding structure checks that used to sit here ran inside a `for`
/// over `scan_findings`, so on a fully configured host the loop had no
/// iterations and the test exited 0 having asserted nothing about a finding.
/// `audit_mock_tests.rs:258` makes the same checks against a finding that is
/// guaranteed to exist. The `scan_success` assertion went with them: the scan
/// sets that field to the literal `true` at both of its return sites, so it
/// could not have failed.
#[tokio::test]
async fn audit_scan_host_smoke_test() {
    let plugin = AuditHardeningPlugin::new();
    let context = Context::new();

    // Completes even where auditd is not installed: that is a finding, not an
    // error, which is the graceful degradation this plugin promises.
    let scan_result = plugin
        .scan(&context, &PluginConfig::default())
        .await
        .expect("the audit scan reports a missing auditd as a finding, never as Err");

    assert_eq!(scan_result.scan_plugin_id.to_string(), "audit-hardening");
    assert!(
        scan_result.scan_duration_us > 0,
        "Scan duration should be captured"
    );
}

/// Declared environment smoke test, under the same `LocalExecutor` caveat as
/// the scan above: it runs against the executing host, so it may assert only
/// host-invariants.
///
/// It used to branch on `validation_report_is_valid` and assert in both arms,
/// so unlike the loops elsewhere in this file it did always assert something.
/// It still had to go. Which arm ran was decided by whether the executing host
/// has auditd installed, so the substantive claim (that some issue names
/// auditd) was only ever reached on a host without it, and the emptiness
/// claims in both arms are restatements of the constructor: validate sets
/// `validation_report_is_valid: issues.is_empty()`, so "valid implies no
/// issues" cannot fail whatever the host does. Both arms are covered against a
/// known host in `audit_mock_tests.rs:283` and `audit_mock_tests.rs:303`.
#[tokio::test]
async fn audit_validate_host_smoke_test() {
    let plugin = AuditHardeningPlugin::new();
    let context = Context::new();
    let config = PluginConfig::default();

    let validation_report = plugin
        .validate(&context, &config)
        .await
        .expect("audit validate reports an undeterminable auditd as an issue, never as Err");

    assert_eq!(
        validation_report.validation_report_plugin_id.to_string(),
        "audit-hardening"
    );
}

#[tokio::test]
#[ignore = "Requires root privileges and modifies system audit configuration"]
async fn test_audit_apply_requires_root() {
    let plugin = AuditHardeningPlugin::new();
    let mut context = Context::new();
    let config = PluginConfig::default();

    let result = plugin.apply(&mut context, &config).await;

    match result {
        // The per-change loop that used to follow is gone: it had no
        // iterations on a host where apply changed nothing, so the arm could
        // assert nothing beyond the plugin id. `audit_mock_tests.rs` asserts
        // on change descriptions throughout, against applies whose changes the
        // fixture guarantees.
        Ok(apply_result) => {
            assert_eq!(apply_result.apply_plugin_id.to_string(), "audit-hardening");
        }
        // The arm used to be empty, excused as "expected if not running as
        // root". Nothing runs this test except someone who deliberately asked
        // for it with `--ignored`, having read the `#[ignore]` reason saying it
        // needs root, so an `Err` here is a real failure and not an absent
        // privilege. Swallowing it let the one test covering apply exit 0
        // having asserted nothing at all.
        Err(e) => panic!("audit apply failed: {e}"),
    }
}
