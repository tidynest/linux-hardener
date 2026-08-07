//! Audit plugin tests using MockExecutor.
//!
//! These tests verify plugin behavior without touching real auditd.

mod common;

use common::test_checkpoint_manager;
use hardener_common::types::{PluginId, Severity};
use hardener_core::{
    CommandOutput, Context, ExceptionOutcome, FileMetadata, MockExecutor, PluginConfig,
    PolicyException, SystemExecutor, UncheckedBlocker, plugin::HardeningPlugin,
};
use hardener_plugins::AuditHardeningPlugin;
use hardener_types::DeclineReason;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

/// Creates a mock executor with auditd fully configured and running.
fn fully_configured_audit_executor() -> MockExecutor {
    MockExecutor::new()
        .with_command_exists("auditd", true)
        .with_command(
            "systemctl",
            &["is-enabled", "auditd"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "auditd"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        // All rules are configured
        .with_command(
            "auditctl",
            &["-l"],
            CommandOutput {
                stdout: r#"-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network-change
-w /etc/hosts -p wa -k network-change
-a always,exit -F arch=b64 -S chmod -k perm-mod
-a always,exit -F arch=b64 -S chown -k perm-mod
-w /usr/bin/sudo -p x -k privileged
-w /usr/bin/su -p x -k privileged
-a always,exit -F arch=b64 -S unlink -k delete
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
"#
                .to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
}

/// Creates a mock executor where auditd is not installed.
fn no_auditd_executor() -> MockExecutor {
    MockExecutor::new().with_command_exists("auditd", false)
}

/// Creates a mock executor where auditd is installed but not enabled/running.
fn auditd_disabled_executor() -> MockExecutor {
    MockExecutor::new()
        .with_command_exists("auditd", true)
        .with_command(
            "systemctl",
            &["is-enabled", "auditd"],
            CommandOutput {
                stdout: "disabled\n".to_string(),
                stderr: String::new(),
                exit_code: 1,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "auditd"],
            CommandOutput {
                stdout: "inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 3,
            },
        )
        .with_command(
            "auditctl",
            &["-l"],
            CommandOutput {
                stdout: "No rules\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
}

/// Creates a mock executor with auditd running but missing some rules.
fn partial_rules_executor() -> MockExecutor {
    MockExecutor::new()
        .with_command_exists("auditd", true)
        .with_command(
            "systemctl",
            &["is-enabled", "auditd"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "auditd"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        // Only identity rules configured, missing others
        .with_command(
            "auditctl",
            &["-l"],
            CommandOutput {
                stdout: r#"-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
"#
                .to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
}

#[tokio::test]
async fn test_audit_scan_fully_configured_no_findings() {
    let executor = fully_configured_audit_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = AuditHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    assert!(
        result.scan_success,
        "fully configured audit scan should succeed"
    );
    assert_eq!(result.scan_plugin_id, PluginId::new("audit-hardening"));
    assert!(
        result.scan_findings.is_empty(),
        "Fully configured audit should have no findings, but got: {:?}",
        result
            .scan_findings
            .iter()
            .map(|f| &f.finding_title)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_audit_scan_not_installed() {
    let executor = no_auditd_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = AuditHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    assert!(result.scan_success, "scan with no auditd should succeed");
    assert_eq!(result.scan_findings.len(), 1);

    let finding = &result.scan_findings[0];
    assert_eq!(finding.finding_id, "audit_not_installed");
    assert_eq!(finding.finding_severity, Severity::Critical);
    assert_eq!(finding.finding_current_value, "not installed");
}

#[tokio::test]
async fn test_audit_scan_disabled_and_stopped() {
    let executor = auditd_disabled_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = AuditHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    assert!(result.scan_success, "disabled auditd scan should succeed");

    let finding_ids: Vec<_> = result
        .scan_findings
        .iter()
        .map(|f| f.finding_id.as_str())
        .collect();

    // Should find auditd not enabled and not running
    assert!(
        finding_ids.contains(&"audit_not_enabled"),
        "should flag auditd not enabled, got: {finding_ids:?}"
    );
    assert!(
        finding_ids.contains(&"auditd_not_running"),
        "should flag auditd not running, got: {finding_ids:?}"
    );

    // Check severities
    let not_enabled = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "audit_not_enabled")
        .unwrap();
    assert_eq!(not_enabled.finding_severity, Severity::High);
}

#[tokio::test]
async fn test_audit_scan_missing_rules() {
    let executor = partial_rules_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = AuditHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    assert!(result.scan_success, "partial rules scan should succeed");

    let finding_ids: Vec<_> = result
        .scan_findings
        .iter()
        .map(|f| f.finding_id.as_str())
        .collect();

    // Should find missing rule categories
    // identity rules are present, but time-change, network-change, perm-mod,
    // privileged, delete, modules should be flagged
    assert!(
        finding_ids.iter().any(|id| id.contains("time_change")),
        "Should flag missing time-change rules"
    );
    assert!(
        finding_ids.iter().any(|id| id.contains("network_change")),
        "Should flag missing network-change rules"
    );
    assert!(
        finding_ids.iter().any(|id| id.contains("perm_mod")),
        "Should flag missing perm-mod rules"
    );

    // identity is present, should NOT be flagged
    // Note: The plugin checks for category name in the rule, so we need to verify
}

#[tokio::test]
async fn test_audit_scan_finding_structure() {
    let executor = no_auditd_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = AuditHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    let finding = &result.scan_findings[0];

    assert_eq!(finding.finding_id, "audit_not_installed");
    assert!(
        !finding.finding_compliance.is_empty(),
        "audit finding should have compliance mappings"
    );
    assert_eq!(
        finding.finding_compliance[0].compliance_control_id,
        "4.1.1.1"
    );
    assert!(
        !finding.finding_remediation_steps.is_empty(),
        "audit finding should have remediation steps"
    );
}

#[tokio::test]
async fn test_audit_validate_with_auditd() {
    let executor = partial_rules_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = AuditHardeningPlugin::new();
    let config = hardener_core::PluginConfig::default();

    let result = plugin.validate(&ctx, &config).await.unwrap();

    assert!(
        result.validation_report_is_valid,
        "validation with auditd should be valid"
    );
    // Should have estimated changes for missing rules
    assert!(
        !result.validation_report_estimated_changes.is_empty(),
        "partial rules should produce estimated changes"
    );
}

#[tokio::test]
async fn test_audit_validate_no_auditd() {
    let executor = no_auditd_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = AuditHardeningPlugin::new();
    let config = hardener_core::PluginConfig::default();

    let result = plugin.validate(&ctx, &config).await.unwrap();

    assert!(
        !result.validation_report_is_valid,
        "validation without auditd should be invalid"
    );
    assert!(
        !result.validation_report_issues.is_empty(),
        "validation without auditd should have issues"
    );

    let issue = &result.validation_report_issues[0];
    assert_eq!(issue.validation_issue_severity, Severity::Critical);
    assert!(
        issue.validation_issue_message.contains("auditd"),
        "issue should mention auditd, got: {}",
        issue.validation_issue_message
    );
}

#[tokio::test]
async fn test_audit_scan_duration_recorded() {
    let executor = fully_configured_audit_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = AuditHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    assert!(
        result.scan_duration_us > 0,
        "scan duration should be recorded"
    );
}

#[tokio::test]
async fn test_audit_scan_logs_commands() {
    let executor = partial_rules_executor();
    let ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = AuditHardeningPlugin::new();

    let _ = plugin.scan(&ctx, &PluginConfig::default()).await;

    let log = executor.log();

    // Should have executed systemctl and auditctl commands
    assert!(
        log.commands_executed
            .iter()
            .any(|(cmd, _)| cmd == "systemctl"),
        "Should execute systemctl"
    );
    assert!(
        log.commands_executed
            .iter()
            .any(|(cmd, _)| cmd == "auditctl"),
        "Should execute auditctl"
    );
}

#[tokio::test]
async fn test_audit_metadata() {
    let plugin = AuditHardeningPlugin::new();
    let metadata = plugin.metadata();

    assert_eq!(metadata.plugin_id, PluginId::new("audit-hardening"));
    assert_eq!(metadata.plugin_name, "Audit Rules Hardening");
}

#[tokio::test]
async fn test_audit_scan_with_remote_executor() {
    let executor = MockExecutor::new()
        .remote()
        .with_description("ssh://admin@server.example.com")
        .with_command_exists("auditd", true)
        .with_command(
            "systemctl",
            &["is-enabled", "auditd"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "auditd"],
            CommandOutput {
                stdout: "inactive\n".to_string(), // Not running on remote
                stderr: String::new(),
                exit_code: 3,
            },
        )
        .with_command(
            "auditctl",
            &["-l"],
            CommandOutput {
                stdout: "No rules\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        );

    assert!(
        executor.is_remote(),
        "remote executor should report as remote"
    );

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = AuditHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    assert!(result.scan_success, "remote audit scan should succeed");
    // Should find auditd not running on remote
    assert!(
        result
            .scan_findings
            .iter()
            .any(|f| f.finding_id == "auditd_not_running"),
        "should find auditd not running on remote, got: {:?}",
        result
            .scan_findings
            .iter()
            .map(|f| &f.finding_id)
            .collect::<Vec<_>>()
    );
}

/// Creates a mock executor simulating permission denied when running `auditctl -l`.
/// This is Bug E: auditctl requires root to list rules.
fn auditctl_permission_denied_executor() -> MockExecutor {
    MockExecutor::new()
        .with_command_exists("auditd", true)
        .with_command(
            "systemctl",
            &["is-enabled", "auditd"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "auditd"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        // auditctl -l fails with permission denied (needs root)
        .with_command(
            "auditctl",
            &["-l"],
            CommandOutput {
                stdout: String::new(),
                stderr: "You must be root to run this program.\n".to_string(),
                exit_code: 1,
            },
        )
}

/// BUG E TEST: This test exposes the false positive bug.
///
/// When `auditctl -l` fails due to permission denied, the plugin should NOT
/// report all 25 rules as "not configured" - it should either:
/// 1. Report "Unable to verify audit rules (permission denied)"
/// 2. Return scan_success=false with appropriate error
/// 3. Mark findings as "unknown" status instead of "not configured"
///
/// Currently this test will FAIL because the plugin incorrectly reports
/// all audit rules as missing when it can't check them due to permissions.
#[tokio::test]
async fn test_audit_scan_permission_denied_should_not_report_missing_rules() {
    let executor = auditctl_permission_denied_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = AuditHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    // auditd is installed, enabled, and running
    // But auditctl -l failed with permission denied

    // We should NOT have 25 "rule not configured" findings
    // because we don't actually know if the rules are configured or not
    let rule_findings: Vec<_> = result
        .scan_findings
        .iter()
        .filter(|f| {
            f.finding_id.contains("rule_") || f.finding_description.contains("not configured")
        })
        .collect();

    // BUG E: Currently this incorrectly reports ~25 findings for missing rules
    // The correct behaviour would be:
    // A) No rule findings (because we don't know the actual state)
    // B) scan_success = false with permission error
    // C) Findings that say "Unable to verify" (not "not configured")

    // This assertion documents the EXPECTED behaviour
    assert!(
        rule_findings.is_empty(),
        "BUG E: Permission denied on auditctl should NOT result in 'rule not configured' findings. \
         We cannot verify rules without root access. \
         Got {} findings: {:?}",
        rule_findings.len(),
        rule_findings
            .iter()
            .take(5)
            .map(|f| &f.finding_id)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_audit_apply_skips_exceptions() {
    // Auditd installed, enabled, running: apply writes rules file.
    // Exception on "modules" category: those 3 rules should be absent.
    //
    // The rules directory is registered here and in every other apply fixture
    // because the audit package ships it on nearly every host. Apply creates a
    // missing one before writing into it, so a fixture that left it out would
    // describe an unusual host and reach a mkdir instead of the write these
    // assertions are about. The hosts that genuinely lack it have their own
    // tests at the end of this file.
    let ok = CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    };
    let executor = MockExecutor::new()
        .with_command_exists("auditd", true)
        .with_command_exists("augenrules", true)
        .with_command(
            "systemctl",
            &["is-enabled", "auditd"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "auditd"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_directory("/etc/audit/rules.d")
        .with_command(
            "chmod",
            &["0640", "/etc/audit/rules.d/hardening.rules"],
            ok.clone(),
        )
        .with_command("augenrules", &["--load"], ok);

    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = AuditHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "modules".to_string(),
        PolicyException {
            value: "skip".to_string(),
            allowed: true,
            reason: "Module loading monitored by separate HIDS".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let result = plugin.apply(&mut ctx, &config).await.unwrap();

    // Should have a "skipped" change for modules category
    let skipped = result.apply_changes.iter().find(|c| {
        c.change_description.contains("skipped") && c.change_description.contains("modules")
    });
    assert!(
        skipped.is_some(),
        "should have a skipped change for modules category"
    );
    assert!(
        skipped
            .expect("checked above")
            .change_description
            .contains("HIDS"),
    );

    // Verify the written rules file does NOT contain module rules
    let log = executor.log();
    let rules_write = log
        .files_written
        .iter()
        .find(|(p, _)| p.to_str().unwrap().contains("hardening.rules"));
    assert!(rules_write.is_some(), "should have written rules file");
    let rules_content = &rules_write.expect("checked above").1;

    // "insmod", "rmmod", "modprobe" should NOT appear (they're the 3 module rules)
    assert!(
        !rules_content.contains("insmod"),
        "excepted module rules should not appear in rules file"
    );
    // Other categories should still appear
    assert!(
        rules_content.contains("identity"),
        "non-excepted categories should still appear"
    );
}

/// Builds a mock executor for the reload-failure scenarios: auditd is
/// installed, enabled and running, the rules file writes fine, but both
/// `augenrules --load` and the `systemctl restart auditd` fallback fail
/// (mirroring Arch, where the auditd unit ships `RefuseManualStop=yes` so
/// the systemctl leg is always refused). `auditctl -s` output is supplied
/// by the caller to select the immutable vs. non-immutable case.
fn reload_fails_executor(auditctl_status: CommandOutput) -> MockExecutor {
    let ok = CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    };
    MockExecutor::new()
        .with_command_exists("auditd", true)
        .with_command_exists("augenrules", true)
        .with_command(
            "systemctl",
            &["is-enabled", "auditd"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "auditd"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_directory("/etc/audit/rules.d")
        .with_command(
            "chmod",
            &["0640", "/etc/audit/rules.d/hardening.rules"],
            ok.clone(),
        )
        .with_command(
            "augenrules",
            &["--load"],
            CommandOutput {
                stdout: String::new(),
                stderr: "augenrules: failed to load rules\n".to_string(),
                exit_code: 1,
            },
        )
        .with_command(
            "systemctl",
            &["restart", "auditd"],
            CommandOutput {
                stdout: String::new(),
                stderr: "Failed to restart auditd.service: Operation refused, unit auditd.service may be requested by dependency only (it is configured to refuse manual start/stop).\n".to_string(),
                exit_code: 1,
            },
        )
        .with_command("auditctl", &["-s"], auditctl_status)
}

#[tokio::test]
async fn test_audit_apply_reload_immutable_becomes_skip() {
    // auditctl -s reports the kernel audit config is locked (-e 2): both
    // reload legs are dead until reboot, but this is not a plugin failure.
    let executor = reload_fails_executor(CommandOutput {
        stdout: "enabled 2\nfailure 1\npid 0\nrate_limit 0\n".to_string(),
        stderr: String::new(),
        exit_code: 0,
    });
    let mut ctx = Context::with_executor(Arc::new(executor));
    let plugin = AuditHardeningPlugin::new();
    let config = PluginConfig::default();

    let result = plugin.apply(&mut ctx, &config).await.unwrap();

    assert!(
        result.apply_success,
        "reload failure explained by immutable audit config must not fail the apply"
    );

    let reload_change = result
        .apply_changes
        .iter()
        .find(|c| c.change_description.to_lowercase().contains("reboot"))
        .expect("should record a reboot-required change");
    assert!(reload_change.is_skipped(), "must be a Skipped change");
    assert!(
        reload_change.change_success,
        "the skipped change itself must report success"
    );
    assert!(
        reload_change.change_description.contains("-e 2")
            || reload_change.change_description.contains("locked"),
        "description should explain the immutable audit config, got: {}",
        reload_change.change_description
    );
}

#[tokio::test]
async fn test_audit_apply_reload_failure_not_immutable_stays_failed() {
    // auditctl -s reports normal (non-immutable) enabled state: both reload
    // legs genuinely failed, so this must remain a real failure. The load
    // failure is NOT a "Rule exists" collision, so no flush may run and the
    // error must say the previously loaded rules are still active.
    let executor = reload_fails_executor(CommandOutput {
        stdout: "enabled 1\nfailure 1\npid 0\nrate_limit 0\n".to_string(),
        stderr: String::new(),
        exit_code: 0,
    });
    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = AuditHardeningPlugin::new();
    let config = PluginConfig::default();

    let result = plugin.apply(&mut ctx, &config).await.unwrap();

    assert!(
        !result.apply_success,
        "a genuinely broken reload (not immutable) must still fail the apply"
    );

    let reload_change = result
        .apply_changes
        .iter()
        .find(|c| {
            c.change_description
                .contains("Failed to reload audit rules")
        })
        .expect("should still record the reload failure");
    assert!(!reload_change.change_success);
    assert!(!reload_change.is_skipped());
    assert!(
        reload_change
            .change_error
            .as_deref()
            .is_some_and(|error| error.contains("still active")),
        "a no-flush failure must say the previous rules are still loaded, got: {:?}",
        reload_change.change_error
    );

    let log = executor.log();
    assert!(
        !log.commands_executed
            .iter()
            .any(|(cmd, args)| cmd == "auditctl" && args == &["-D".to_string()]),
        "a load failure without 'Rule exists' must never flush the kernel rule set"
    );
}

#[tokio::test]
async fn test_audit_apply_reload_failure_probe_exit_nonzero_stays_failed() {
    // The immutability probe itself fails (non-zero exit) but emits partial
    // stdout that happens to contain "enabled 2": untrusted output from a
    // failed probe must never downgrade a genuine reload failure to a skip.
    let executor = reload_fails_executor(CommandOutput {
        stdout: "enabled 2\n".to_string(),
        stderr: "auditctl: Operation not permitted\n".to_string(),
        exit_code: 1,
    });
    let mut ctx = Context::with_executor(Arc::new(executor));
    let plugin = AuditHardeningPlugin::new();
    let config = PluginConfig::default();

    let result = plugin.apply(&mut ctx, &config).await.unwrap();

    assert!(
        !result.apply_success,
        "a failed probe must not be trusted, even if its stdout says enabled 2"
    );

    let reload_change = result
        .apply_changes
        .iter()
        .find(|c| {
            c.change_description
                .contains("Failed to reload audit rules")
        })
        .expect("should still record the reload failure");
    assert!(!reload_change.change_success);
    assert!(!reload_change.is_skipped());
}

#[tokio::test]
async fn test_audit_apply_reload_success_unaffected() {
    // Happy path: augenrules succeeds, so the immutability probe must never
    // run and the existing success change is unchanged.
    let ok = CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    };
    let executor = MockExecutor::new()
        .with_command_exists("auditd", true)
        .with_command_exists("augenrules", true)
        .with_command(
            "systemctl",
            &["is-enabled", "auditd"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "auditd"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_directory("/etc/audit/rules.d")
        .with_command(
            "chmod",
            &["0640", "/etc/audit/rules.d/hardening.rules"],
            ok.clone(),
        )
        .with_command("augenrules", &["--load"], ok);

    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = AuditHardeningPlugin::new();
    let config = PluginConfig::default();

    let result = plugin.apply(&mut ctx, &config).await.unwrap();

    assert!(result.apply_success);
    let reload_change = result
        .apply_changes
        .iter()
        .find(|c| {
            c.change_description
                .contains("Loaded audit rules into running daemon")
        })
        .expect("should record the successful reload");
    assert!(reload_change.change_success);
    assert!(!reload_change.is_skipped());

    let log = executor.log();
    assert!(
        !log.commands_executed
            .iter()
            .any(|(cmd, args)| cmd == "auditctl" && args == &["-s".to_string()]),
        "the immutability probe must not run when reload succeeds"
    );
}

/// Common scaffold for the duplicate-collision retry scenarios: auditd
/// installed, enabled and running, augenrules present, rules directory
/// creatable. Callers register the `augenrules --load` sequence and the
/// `auditctl -D` flush outcome themselves.
fn reload_retry_executor() -> MockExecutor {
    let ok = CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    };
    MockExecutor::new()
        .with_command_exists("auditd", true)
        .with_command_exists("augenrules", true)
        .with_command(
            "systemctl",
            &["is-enabled", "auditd"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "auditd"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_directory("/etc/audit/rules.d")
        .with_command("chmod", &["0640", "/etc/audit/rules.d/hardening.rules"], ok)
}

/// The `augenrules --load` output seen on a re-apply: kernel-resident rules
/// from the previous load collide with the merged set.
fn rule_exists_failure() -> CommandOutput {
    CommandOutput {
        stdout: String::new(),
        stderr: "/usr/sbin/augenrules: Error sending add rule data request (Rule exists)\n\
                 There was an error in line 6 of /etc/audit/audit.rules\n"
            .to_string(),
        exit_code: 1,
    }
}

#[tokio::test]
async fn test_audit_apply_rule_exists_flushes_and_retries() {
    // Re-apply scenario: the first `augenrules --load` collides with the
    // kernel-resident rules from a previous apply ("Rule exists"). The
    // plugin must flush with `auditctl -D` and retry the load once, and
    // only in that order: load, flush, load.
    let ok = CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    };
    let executor = reload_retry_executor()
        .with_command_sequence(
            "augenrules",
            &["--load"],
            vec![rule_exists_failure(), ok.clone()],
        )
        .with_command("auditctl", &["-D"], ok);

    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = AuditHardeningPlugin::new();
    let config = PluginConfig::default();

    let result = plugin.apply(&mut ctx, &config).await.unwrap();

    assert!(
        result.apply_success,
        "re-apply must succeed after the retry"
    );

    let log = executor.log();
    let load_indices: Vec<usize> = log
        .commands_executed
        .iter()
        .enumerate()
        .filter(|(_, (cmd, args))| cmd == "augenrules" && args == &["--load".to_string()])
        .map(|(index, _)| index)
        .collect();
    let flush_index = log
        .commands_executed
        .iter()
        .position(|(cmd, args)| cmd == "auditctl" && args == &["-D".to_string()])
        .expect("auditctl -D should have run as the flush");
    assert_eq!(load_indices.len(), 2, "load should run exactly twice");
    assert!(
        load_indices[0] < flush_index && flush_index < load_indices[1],
        "order must be load, flush, load; got loads at {load_indices:?}, flush at {flush_index}"
    );
}

#[tokio::test]
async fn test_audit_apply_rule_exists_flush_failure_still_succeeds() {
    // The flush is best-effort: if `auditctl -D` itself errors but the
    // retried load succeeds anyway, the apply must succeed. The flush's
    // exit status is never allowed to affect the outcome.
    let ok = CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    };
    let executor = reload_retry_executor()
        .with_command_sequence("augenrules", &["--load"], vec![rule_exists_failure(), ok])
        .with_command(
            "auditctl",
            &["-D"],
            CommandOutput {
                stdout: String::new(),
                stderr: "Error deleting all rules\n".to_string(),
                exit_code: 1,
            },
        );

    let mut ctx = Context::with_executor(Arc::new(executor));
    let plugin = AuditHardeningPlugin::new();
    let config = PluginConfig::default();

    let result = plugin.apply(&mut ctx, &config).await.unwrap();

    assert!(
        result.apply_success,
        "a failed best-effort flush must not fail the apply when the retried load succeeds"
    );
    let reload_change = result
        .apply_changes
        .iter()
        .find(|c| {
            c.change_description
                .contains("Loaded audit rules into running daemon")
        })
        .expect("should still record the successful reload");
    assert!(reload_change.change_success);
}

#[tokio::test]
async fn test_audit_apply_rule_exists_retry_failure_discloses_flush() {
    // Both loads fail (the first with "Rule exists", so a flush happened in
    // between) and the systemctl fallback fails on a non-immutable host:
    // the failure must be preserved and its error must disclose that the
    // kernel rule set was flushed, naming the manual reload path, because
    // the host may now be running with no audit rules loaded.
    let executor = reload_retry_executor()
        .with_command_sequence(
            "augenrules",
            &["--load"],
            vec![
                rule_exists_failure(),
                CommandOutput {
                    stdout: String::new(),
                    stderr: "augenrules: failed to load rules\n".to_string(),
                    exit_code: 1,
                },
            ],
        )
        .with_command(
            "auditctl",
            &["-D"],
            CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["restart", "auditd"],
            CommandOutput {
                stdout: String::new(),
                stderr: "Failed to restart auditd.service\n".to_string(),
                exit_code: 1,
            },
        )
        .with_command(
            "auditctl",
            &["-s"],
            CommandOutput {
                stdout: "enabled 1\nfailure 1\npid 0\nrate_limit 0\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        );

    let mut ctx = Context::with_executor(Arc::new(executor));
    let plugin = AuditHardeningPlugin::new();
    let config = PluginConfig::default();

    let result = plugin.apply(&mut ctx, &config).await.unwrap();

    assert!(
        !result.apply_success,
        "a reload still failing after the flush-and-retry must fail the apply"
    );
    let reload_change = result
        .apply_changes
        .iter()
        .find(|c| {
            c.change_description
                .contains("Failed to reload audit rules")
        })
        .expect("should record the reload failure");
    let error = reload_change
        .change_error
        .as_deref()
        .expect("the failure must carry an error message");
    assert!(
        error.contains("may currently be unloaded") && error.contains("auditctl -R"),
        "the error must disclose the flush and the manual reload path, got: {error}"
    );
}

#[tokio::test]
async fn test_audit_validate_skips_exceptions() {
    // Partial rules (only identity); normally many missing.
    // Exception on "modules" should reduce the missing count.
    let executor = partial_rules_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = AuditHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "modules".to_string(),
        PolicyException {
            value: "skip".to_string(),
            allowed: true,
            reason: "Module loading monitored externally".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let report = plugin.validate(&ctx, &config).await.unwrap();

    // Without exception: partial_rules_executor has only identity rules.
    // All other categories are missing. With "modules" excepted, the 3 module
    // rules should be excluded from the missing count.
    let config_no_exception = PluginConfig::default();
    let report_no_exception = plugin.validate(&ctx, &config_no_exception).await.unwrap();

    // Both should have an "Add N audit-rules" entry
    let get_count = |changes: &[String]| -> Option<usize> {
        changes
            .iter()
            .find(|c| c.contains("audit-rules"))
            .and_then(|c| c.split_whitespace().nth(1))
            .and_then(|n| n.parse().ok())
    };

    let count_with = get_count(&report.validation_report_estimated_changes);
    let count_without = get_count(&report_no_exception.validation_report_estimated_changes);

    assert!(
        report
            .validation_report_exceptions
            .iter()
            .any(|l| l.contains("modules")),
        "an excepted category must still be previewed"
    );
    assert!(
        !report
            .validation_report_exceptions
            .iter()
            .any(|l| l.contains("skip")),
        "the advisory value was never compared against the host, so the preview \
         may not present it as the category's state: {:?}",
        report.validation_report_exceptions
    );

    assert!(
        count_with.is_some(),
        "should have audit-rules change with exception"
    );
    assert!(
        count_without.is_some(),
        "should have audit-rules change without exception"
    );
    assert!(
        count_with.expect("checked") < count_without.expect("checked"),
        "excepted category should reduce missing rule count: {} should be < {}",
        count_with.expect("checked"),
        count_without.expect("checked")
    );
}

#[tokio::test]
async fn test_audit_apply_is_idempotent_when_rules_file_already_matches() {
    // Mirrors the kernel persistent-config drift guard: a second apply on a
    // host whose /etc/audit/rules.d/hardening.rules already equals the desired
    // content must rewrite nothing, back up nothing and reload nothing, and
    // record exactly one Skipped "already up to date" change so a compliant
    // host reports zero applied changes instead of "2 change(s) applied".
    let ok = CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    };
    let executor = MockExecutor::new()
        .with_command_exists("auditd", true)
        .with_command_exists("augenrules", true)
        .with_command(
            "systemctl",
            &["is-enabled", "auditd"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "auditd"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_directory("/etc/audit/rules.d")
        .with_command(
            "chmod",
            &["0640", "/etc/audit/rules.d/hardening.rules"],
            ok.clone(),
        )
        .with_command("augenrules", &["--load"], ok);

    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = AuditHardeningPlugin::new();
    let config = PluginConfig::default();

    // First apply writes the rules file and reloads the running daemon.
    let first = plugin.apply(&mut ctx, &config).await.unwrap();
    assert!(first.apply_success, "first apply should succeed: {first:?}");
    assert!(
        first.applied_change_count() >= 1,
        "first apply must do real work (write + reload), got: {:?}",
        first.apply_changes
    );

    // Isolate the second apply's activity from the first.
    executor.clear_log();

    // Second apply: the file now matches the desired content byte-for-byte.
    let second = plugin.apply(&mut ctx, &config).await.unwrap();
    assert!(
        second.apply_success,
        "compliant re-apply should succeed: {second:?}"
    );
    assert_eq!(
        second.applied_change_count(),
        0,
        "a compliant re-apply must count zero applied changes, got: {:?}",
        second.apply_changes
    );

    // Exactly one Skipped "already up to date" change, nothing else counted.
    let up_to_date = second
        .apply_changes
        .iter()
        .find(|c| c.change_description.contains("already up to date"))
        .expect("should record an 'already up to date' skip");
    assert!(
        up_to_date.is_skipped(),
        "the up-to-date entry must be a Skipped change, got: {up_to_date:?}"
    );

    // No rewrite, no backup, no mkdir, no reload on the compliant re-apply.
    let log = executor.log();
    assert!(
        log.files_written.is_empty(),
        "no rules file may be rewritten when it already matches, wrote: {:?}",
        log.files_written
    );
    assert!(
        !log.commands_executed
            .iter()
            .any(|(cmd, _)| cmd == "augenrules"),
        "no reload may run on a compliant re-apply, commands: {:?}",
        log.commands_executed
    );
    assert!(
        !log.commands_executed.iter().any(|(cmd, _)| cmd == "cp"),
        "no backup may be created on a compliant re-apply, commands: {:?}",
        log.commands_executed
    );
    assert!(
        !log.commands_executed.iter().any(|(cmd, _)| cmd == "mkdir"),
        "no directory creation on a compliant re-apply, commands: {:?}",
        log.commands_executed
    );
}

#[tokio::test]
async fn test_audit_apply_rewrites_when_rules_file_read_fails() {
    // Fail-safe: if the current rules file cannot be read (permission/IO), the
    // apply must treat the content as drifted and write, never skip a needed
    // audit hardening because the current state was unknowable.
    let ok = CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    };
    let executor = MockExecutor::new()
        .with_command_exists("auditd", true)
        .with_command_exists("augenrules", true)
        .with_command(
            "systemctl",
            &["is-enabled", "auditd"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "auditd"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_directory("/etc/audit/rules.d")
        .with_command(
            "chmod",
            &["0640", "/etc/audit/rules.d/hardening.rules"],
            ok.clone(),
        )
        .with_command("augenrules", &["--load"], ok.clone())
        // A file that is present gets backed up before it is rewritten, and
        // the destination carries a timestamp, so the program is registered
        // rather than one exact argument list.
        .with_command_program("cp", ok)
        // The rules file exists but cannot be read (root-only, denied).
        .with_read_permission_denied("/etc/audit/rules.d/hardening.rules");

    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = AuditHardeningPlugin::new();
    let config = PluginConfig::default();

    let result = plugin.apply(&mut ctx, &config).await.unwrap();

    assert!(result.apply_success, "apply should succeed: {result:?}");
    let log = executor.log();
    assert!(
        log.files_written
            .iter()
            .any(|(p, _)| p.to_str().unwrap_or_default().contains("hardening.rules")),
        "an unreadable current file must fail safe toward writing, wrote: {:?}",
        log.files_written
    );
    assert!(
        log.commands_executed
            .iter()
            .any(|(cmd, args)| cmd == "augenrules" && args == &["--load".to_string()]),
        "a drifting/unknowable file must still reload the daemon, commands: {:?}",
        log.commands_executed
    );
}

#[tokio::test]
async fn scan_annotates_valid_exception() {
    // The "modules" rule category is missing and has a valid exception: the
    // finding is still reported but annotated. Audit has no directive
    // override, so there is no target value to assert here (mirrors
    // services_mock_tests::scan_annotates_valid_exception).
    let executor = auditd_disabled_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = AuditHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "modules".to_string(),
        PolicyException {
            value: "skip".to_string(),
            allowed: true,
            reason: "Module loading monitored by separate HIDS".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let result = plugin.scan(&ctx, &config).await.unwrap();

    let f = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "audit_rule_modules")
        .expect("missing modules rule should still produce a finding");
    assert!(
        f.is_policy_excepted(),
        "finding should be annotated with the valid exception"
    );

    // Daemon-state findings have no exception key: they must stay unannotated
    // even though this scan is exercising the same config's exception map.
    let daemon_finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "audit_not_enabled")
        .expect("disabled auditd should still produce a finding");
    assert!(
        !daemon_finding.is_policy_excepted(),
        "daemon-state findings have no exception key and stay unannotated"
    );
}

/// A presence check can only ever decline on expiry: there is no host value
/// to mismatch against, since the exception key already names the deviating
/// subsystem state. Silently falling back to `NotConfigured` here would look
/// identical to no exception having been written at all, and an operator
/// reading the report would believe their exception was honoured when it was
/// not.
#[tokio::test]
async fn an_audit_exception_that_has_expired_is_reported_as_declined() {
    let ctx = Context::with_executor(Arc::new(no_auditd_executor()));
    let plugin = AuditHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "auditd-present".to_string(),
        PolicyException {
            value: "absent".to_string(),
            allowed: true,
            reason: "auditing is collected off-host by the agent, JIRA-7731".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: Some("2020-01-01".to_string()),
        },
    );

    let result = plugin.scan(&ctx, &config).await.unwrap();

    let finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "audit_not_installed")
        .expect("the finding is still reported");

    match &finding.finding_exception {
        ExceptionOutcome::Declined(declined) => match &declined.exception_declined_reason {
            DeclineReason::Expired { expired_on } => {
                assert_eq!(expired_on, "2020-01-01");
            }
            other => panic!("expected an expiry, got {other:?}"),
        },
        other => panic!("expected Declined, got {other:?}"),
    }
}

/// The rules file names every path and syscall this host watches, so it is not
/// a world-readable file. A local create lands 0644 like any other
/// configuration file and a remote one lands whatever `tee` gives it, so the
/// mode is stated rather than inherited from whichever write path ran.
#[tokio::test]
async fn test_audit_rules_file_is_not_world_readable() {
    let ok = CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    };
    let executor = MockExecutor::new()
        .with_command_exists("auditd", true)
        .with_command_exists("augenrules", true)
        .with_command(
            "systemctl",
            &["is-enabled", "auditd"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "auditd"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_directory("/etc/audit/rules.d")
        .with_command(
            "chmod",
            &["0640", "/etc/audit/rules.d/hardening.rules"],
            ok.clone(),
        )
        .with_command("augenrules", &["--load"], ok);

    let mut ctx = Context::with_executor(Arc::new(executor.clone()));

    let result = AuditHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert!(result.apply_success, "{:?}", result.apply_changes);
    assert!(
        executor.log().commands_executed.iter().any(|(cmd, args)| {
            cmd == "chmod"
                && args
                    == &[
                        "0640".to_string(),
                        "/etc/audit/rules.d/hardening.rules".to_string(),
                    ]
        }),
        "the rules file must be given 0640; commands: {:?}",
        executor.log().commands_executed
    );
}

/// A mode that could not be set is recorded and does not stop the run: the
/// rules are loaded into the kernel either way, and refusing an apply over a
/// permission bit would leave the host less hardened for a lesser problem.
#[tokio::test]
async fn test_audit_rules_mode_failure_is_recorded_not_fatal() {
    let ok = CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    };
    let executor = MockExecutor::new()
        .with_command_exists("auditd", true)
        .with_command_exists("augenrules", true)
        .with_command(
            "systemctl",
            &["is-enabled", "auditd"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "auditd"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_directory("/etc/audit/rules.d")
        .with_command(
            "chmod",
            &["0640", "/etc/audit/rules.d/hardening.rules"],
            CommandOutput {
                stdout: String::new(),
                stderr: "chmod: changing permissions: Read-only file system\n".to_string(),
                exit_code: 1,
            },
        )
        .with_command("augenrules", &["--load"], ok);

    let mut ctx = Context::with_executor(Arc::new(executor.clone()));

    let result = AuditHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .unwrap();

    let mode_change = result
        .apply_changes
        .iter()
        .find(|c| c.change_description.contains("could not set its mode"))
        .expect("a mode that could not be set must be reported, not swallowed");
    assert!(!mode_change.change_success);
    assert!(
        mode_change.change_error.is_some(),
        "the failure must carry chmod's own words"
    );
    assert!(
        !result.apply_success,
        "an unreported gap is the thing to avoid; the run is not fully successful"
    );
    assert!(
        result.apply_changes.iter().any(|c| {
            c.change_description
                .contains("Loaded audit rules into running daemon")
                && c.change_success
        }),
        "the rules still load: the mode is a lesser problem than an unhardened host; changes: {:?}",
        result.apply_changes
    );
}

// =============================================================================
// The directory the rules file lives in
// =============================================================================

const RULES_DIR: &str = "/etc/audit/rules.d";
const RULES_FILE: &str = "/etc/audit/rules.d/hardening.rules";

/// A command that said its piece on **stderr**, which is what the name does not
/// say and what cost a reader minutes: the first argument is the error stream,
/// not the output one. Use [`spoken`] for a command whose answer is read.
fn command_output(stderr: &str, exit_code: i32) -> CommandOutput {
    CommandOutput {
        stdout: String::new(),
        stderr: stderr.to_string(),
        exit_code,
    }
}

/// A command that answered on stdout, for the probes that read the word rather
/// than the exit status.
///
/// The newline is added here because systemd prints one and every caller would
/// otherwise have to remember it. `is-enabled` is judged on its word, so a
/// fixture that answers with an empty stdout represents a host that cannot
/// exist.
fn spoken(stdout: &str, exit_code: i32) -> CommandOutput {
    CommandOutput {
        stdout: format!("{stdout}\n"),
        stderr: String::new(),
        exit_code,
    }
}

/// A host with auditd installed, enabled and running, whose reload and chmod
/// both succeed. Everything the apply needs except the rules directory, which
/// each test below describes for itself.
fn audit_apply_executor() -> MockExecutor {
    MockExecutor::new()
        .with_command_exists("auditd", true)
        .with_command_exists("augenrules", true)
        // Both answers carry the word systemd actually prints. They said
        // nothing but exit 0 until `is_auditd_enabled` began reading the word,
        // at which point a fixture representing "enabled" was answering with a
        // state no systemd emits, and these two tests failed on an enable the
        // fixture had never been asked to permit. A fixture that cannot occur
        // on a real host proves nothing about one.
        .with_command("systemctl", &["is-enabled", "auditd"], spoken("enabled", 0))
        .with_command("systemctl", &["is-active", "auditd"], spoken("active", 0))
        .with_command("chmod", &["0640", RULES_FILE], command_output("", 0))
        .with_command("augenrules", &["--load"], command_output("", 0))
}

/// How many times the apply asked for the audit rules directory to exist.
fn rules_mkdir_count(executor: &MockExecutor) -> usize {
    executor
        .log()
        .commands_executed
        .iter()
        .filter(|(command, args)| {
            command == "mkdir"
                && args.contains(&"-p".to_string())
                && args.contains(&RULES_DIR.to_string())
        })
        .count()
}

/// Whether the apply wrote the rules file.
fn wrote_the_rules_file(executor: &MockExecutor) -> bool {
    executor
        .log()
        .files_written
        .iter()
        .any(|(path, _)| path.to_str() == Some(RULES_FILE))
}

/// A mock whose successful `mkdir -p` actually creates the directory.
///
/// A plain `MockExecutor` answers `file_metadata` from a registry no command
/// ever touches, so a checkpoint taken after the mkdir records the directory
/// absent exactly as one taken before it would: the fixture cannot tell the two
/// placements apart, and an ordering test written on it passes either way. Here
/// the mkdir writes into the same virtual host the capture then reads, which is
/// what the real `mkdir` does, so the stored checkpoint row answers the ordering
/// question by itself.
struct MkdirCreatesTheDirectory {
    inner: Arc<MockExecutor>,
}

#[async_trait::async_trait]
impl SystemExecutor for MkdirCreatesTheDirectory {
    fn description(&self) -> String {
        self.inner.description()
    }

    fn is_remote(&self) -> bool {
        self.inner.is_remote()
    }

    async fn read_file(&self, path: &Path) -> anyhow::Result<String> {
        self.inner.read_file(path).await
    }

    async fn read_file_optional(&self, path: &Path) -> anyhow::Result<Option<String>> {
        self.inner.read_file_optional(path).await
    }

    async fn write_file(&self, path: &Path, content: &str) -> anyhow::Result<()> {
        self.inner.write_file(path, content).await
    }

    async fn path_exists(&self, path: &Path) -> anyhow::Result<bool> {
        self.inner.path_exists(path).await
    }

    /// Delegated rather than inherited, like the mock's own override: the
    /// provided body shells out to `readlink`, which no fixture registers.
    async fn read_link(&self, path: &Path) -> anyhow::Result<Option<String>> {
        self.inner.read_link(path).await
    }

    /// Delegated for the same reason as `read_link` above, and it has to be
    /// listed separately: a wrapper that forwards one and inherits the other
    /// runs a command no fixture registered, and fails for a reason that names
    /// neither the test nor the wrapper.
    async fn link_target_as_writer(&self, path: &Path) -> anyhow::Result<Option<PathBuf>> {
        self.inner.link_target_as_writer(path).await
    }

    async fn file_metadata(&self, path: &Path) -> anyhow::Result<FileMetadata> {
        self.inner.file_metadata(path).await
    }

    async fn read_dir(&self, path: &Path) -> anyhow::Result<Vec<PathBuf>> {
        self.inner.read_dir(path).await
    }

    /// Delegated for the same reason: the provided body probes through `sh`,
    /// which the fixtures answer with `with_command_exists` instead.
    async fn command_exists(&self, program: &str) -> anyhow::Result<bool> {
        self.inner.command_exists(program).await
    }

    async fn execute_command(&self, program: &str, args: &[&str]) -> anyhow::Result<CommandOutput> {
        let output = self.inner.execute_command(program, args).await?;

        // A `mkdir -p` that exited 0 has created the directory, so the mock's
        // filesystem has to show it from here on. A clone shares the registry
        // with `inner`, so this registration lands on the same virtual host.
        if program == "mkdir"
            && output.success()
            && let Some(dir) = args.iter().find(|arg| arg.starts_with('/'))
        {
            let _ = (*self.inner).clone().with_directory(dir);
        }

        Ok(output)
    }
}

/// The directory has to exist before the checkpoint, not merely before the
/// write.
///
/// This apply's checkpoint captures /etc/audit/rules.d, and `hardener-state`
/// stores an absent path with a zero mode, which a rollback reads as "remove
/// this". A directory created after that capture therefore turned a clean
/// rollback into a failure: the removal ran `rm -f` on a directory, which `rm`
/// refuses. Created before the capture, the row records it present and the
/// rollback restores its mode instead.
///
/// The assertion is on the stored row rather than on the order of two logged
/// calls, because the row is the thing the rollback later reads.
#[tokio::test]
async fn audit_apply_creates_the_rules_directory_before_the_checkpoint_captures_it() {
    // No directory registered: this is a host whose auditd install never
    // brought /etc/audit/rules.d with it.
    let mock = Arc::new(audit_apply_executor().with_command(
        "mkdir",
        &["-p", RULES_DIR],
        command_output("", 0),
    ));
    let executor = Arc::new(MkdirCreatesTheDirectory {
        inner: mock.clone(),
    });
    let mut ctx = Context::with_executor_and_checkpoint(executor, test_checkpoint_manager().await);

    let result = AuditHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("audit apply should not error");

    assert_eq!(
        rules_mkdir_count(&mock),
        1,
        "an absent rules directory must be created, commands: {:?}",
        mock.log().commands_executed
    );

    let checkpoint_id = result
        .apply_checkpoint_id
        .clone()
        .expect("the apply must take a checkpoint on a host with auditd");
    let (_, captured) = ctx
        .checkpoint_manager()
        .expect("the context carries a checkpoint manager")
        .get_checkpoint(&hardener_state::CheckpointId::new(checkpoint_id))
        .await
        .expect("the checkpoint just taken must be readable");
    let directory_row = captured
        .iter()
        .find(|state| state.file_path == RULES_DIR)
        .expect("the checkpoint captures the rules directory");

    assert_ne!(
        directory_row.file_permissions, 0,
        "the checkpoint must record the directory as present; a zero mode is what a \
         rollback reads as 'remove this', and removing a directory with `rm -f` fails. \
         Captured: {captured:?}"
    );
    assert!(
        wrote_the_rules_file(&mock),
        "the rules must still reach the file, writes: {:?}",
        mock.log().files_written
    );
    assert!(
        result.apply_success,
        "an apply that created the directory it needed succeeded, changes: {:?}",
        result.apply_changes
    );
}

/// A probe that cannot answer is not an answer. `path_exists` returns an error
/// for a directory it could not determine, and reading that as "it is there"
/// would skip the creation on exactly the host that needs it. `mkdir -p` on an
/// existing directory does nothing, so attempting it costs nothing.
#[tokio::test]
async fn audit_apply_creates_the_rules_directory_when_the_probe_cannot_answer() {
    let executor = Arc::new(
        audit_apply_executor()
            .with_path_exists_error(RULES_DIR)
            .with_command("mkdir", &["-p", RULES_DIR], command_output("", 0)),
    );
    let mut ctx = Context::with_executor(executor.clone());

    AuditHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("audit apply should not error");

    assert_eq!(
        rules_mkdir_count(&executor),
        1,
        "a probe that failed must be treated as may-be-missing, commands: {:?}",
        executor.log().commands_executed
    );
}

/// `execute_command` returns Ok for a command that ran and failed, so an
/// unchecked exit code would let a failed mkdir be followed by a write that
/// cannot land. The failure must be reported as a failed change carrying the
/// reason, because "Failed to write audit rules" alone tells the operator
/// nothing about the directory.
#[tokio::test]
async fn audit_apply_reports_why_the_rules_directory_could_not_be_created() {
    let executor = Arc::new(audit_apply_executor().with_command(
        "mkdir",
        &["-p", RULES_DIR],
        command_output(
            "mkdir: cannot create directory '/etc/audit/rules.d': Read-only file system\n",
            1,
        ),
    ));
    let mut ctx = Context::with_executor(executor.clone());

    let result = AuditHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("audit apply should not error");

    let failed = result
        .apply_changes
        .iter()
        .find(|change| !change.change_success)
        .expect("a failed mkdir must produce a failed change, not a silent success");
    assert!(
        failed
            .change_error
            .as_deref()
            .is_some_and(|reason| reason.contains("Read-only file system")),
        "the operator must be told why the directory could not be created, got: {:?}",
        failed.change_error
    );
    assert!(
        !wrote_the_rules_file(&executor),
        "a write into a directory that could not be created must not be attempted, \
         writes: {:?}",
        executor.log().files_written
    );
    assert!(
        !result.apply_success,
        "an apply whose rules never reached the disk has not succeeded"
    );
}

/// A host without the auditd package must be left exactly as it was found.
/// The directory belongs to that package, so creating it for a host that does
/// not have auditd would leave a stray directory behind, and there is nothing
/// to checkpoint either: the apply touches nothing.
#[tokio::test]
async fn audit_apply_touches_nothing_when_auditd_is_not_installed() {
    let executor = Arc::new(no_auditd_executor().with_command(
        "mkdir",
        &["-p", RULES_DIR],
        command_output("", 0),
    ));
    let mut ctx =
        Context::with_executor_and_checkpoint(executor.clone(), test_checkpoint_manager().await);

    let result = AuditHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("audit apply should not error");

    assert_eq!(
        rules_mkdir_count(&executor),
        0,
        "no directory may be created for a package that is not installed, commands: {:?}",
        executor.log().commands_executed
    );
    assert!(
        executor.log().files_written.is_empty(),
        "nothing may be written on a host without auditd, writes: {:?}",
        executor.log().files_written
    );
    assert!(
        result.apply_checkpoint_id.is_none(),
        "a host that is not touched is not checkpointed either, got: {:?}",
        result.apply_checkpoint_id
    );
}

/// The rules file the apply creates has to be named in the checkpoint, not
/// merely covered by the directory that holds it.
///
/// Capturing a directory emits a row for the directory and one per child that
/// is there at capture time, and on a host that never had this file there is no
/// such child, so nothing carried it. A rollback walks only the rows the
/// checkpoint holds, which left the hardening in place after an operator had
/// asked for it to be undone. Naming the path makes the capture store it absent
/// with a zero mode, which the restore reads as "remove this".
///
/// The assertion is on the stored row, because the row is what a later rollback
/// reads. It does not prove the removal itself: that belongs to the restore
/// side, which is exercised in `hardener-state`.
#[tokio::test]
async fn audit_apply_checkpoints_the_rules_file_it_is_about_to_create() {
    // The directory is there, courtesy of the auditd package, but the file is
    // not: this is the first apply this host has seen.
    let executor = Arc::new(audit_apply_executor().with_directory(RULES_DIR));
    let mut ctx =
        Context::with_executor_and_checkpoint(executor.clone(), test_checkpoint_manager().await);

    let result = AuditHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("audit apply should not error");

    assert!(
        wrote_the_rules_file(&executor),
        "the apply under test must have created the file, writes: {:?}",
        executor.log().files_written
    );

    let checkpoint_id = result
        .apply_checkpoint_id
        .clone()
        .expect("the apply must take a checkpoint on a host with auditd");
    let (_, captured) = ctx
        .checkpoint_manager()
        .expect("the context carries a checkpoint manager")
        .get_checkpoint(&hardener_state::CheckpointId::new(checkpoint_id))
        .await
        .expect("the checkpoint just taken must be readable");

    let rules_row = captured
        .iter()
        .find(|state| state.file_path == RULES_FILE)
        .unwrap_or_else(|| {
            panic!(
                "the checkpoint must carry a row for the rules file the apply creates, \
                 otherwise a rollback has no way to remove it. Captured: {captured:?}"
            )
        });
    assert_eq!(
        rules_row.file_permissions, 0,
        "a file that was absent at capture must be stored with a zero mode, which is what \
         the restore reads as 'remove this'. Captured: {captured:?}"
    );
}

// =============================================================================
// What augenrules writes outside the rules directory
// =============================================================================

/// The compiled rule set `augenrules` produces, and which auditd loads at boot.
const COMPILED_RULES: &str = "/etc/audit/audit.rules";

/// The copy `augenrules` saves of whatever the compiled file held before it ran.
const COMPILED_RULES_PREV: &str = "/etc/audit/audit.rules.prev";

/// `augenrules --load` saves the previous compiled rule set beside the new one,
/// so an apply that reloads leaves a file behind that the host never had.
///
/// Both this path and the compiled file itself sit in /etc/audit rather than in
/// /etc/audit/rules.d, so the recursive capture of the rules directory does not
/// reach either: the only way a row exists for them is for the apply to declare
/// them. Measured on five distributions, `.prev` was created by the apply and
/// still there after a rollback that reported success on four of them; openSUSE
/// simply produces no `.prev`, which is the absent-at-capture case this test
/// describes and the one the removal half of the mechanism handles.
///
/// The assertion is on the stored row, because the row is what a later rollback
/// reads. It does not prove the removal itself: that belongs to the restore
/// side, which is exercised in `hardener-state`.
#[tokio::test]
async fn audit_apply_checkpoints_the_previous_compiled_rules_augenrules_saves() {
    // A host on which augenrules has never run, so it has no .prev to keep.
    let executor = Arc::new(audit_apply_executor().with_directory(RULES_DIR));
    let mut ctx =
        Context::with_executor_and_checkpoint(executor.clone(), test_checkpoint_manager().await);

    let result = AuditHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("audit apply should not error");

    let checkpoint_id = result
        .apply_checkpoint_id
        .clone()
        .expect("the apply must take a checkpoint on a host with auditd");
    let (_, captured) = ctx
        .checkpoint_manager()
        .expect("the context carries a checkpoint manager")
        .get_checkpoint(&hardener_state::CheckpointId::new(checkpoint_id))
        .await
        .expect("the checkpoint just taken must be readable");

    let prev_row = captured
        .iter()
        .find(|state| state.file_path == COMPILED_RULES_PREV)
        .unwrap_or_else(|| {
            panic!(
                "the checkpoint must carry a row for the copy augenrules saves, otherwise a \
                 rollback has no way to remove a file the apply brought into being. \
                 Captured: {captured:?}"
            )
        });
    assert_eq!(
        prev_row.file_permissions, 0,
        "a file that was absent at capture must be stored with a zero mode, which is what \
         the restore reads as 'remove this'. Captured: {captured:?}"
    );
}

/// The compiled rule set is rewritten by the apply and has to be restorable,
/// which asks more of the checkpoint than a removal does: the row must carry the
/// bytes the file held before the run.
///
/// `augenrules --load` compiles everything in /etc/audit/rules.d into
/// /etc/audit/audit.rules, so the file grew from five or six lines to thirty on
/// every distribution measured and read exactly the same after a rollback that
/// reported success. Removing it is not the fix, because auditd loads it at
/// boot and every host measured had one before the apply: the row has to hold
/// the pre-apply content so the restore can write it back.
///
/// The assertion is on the stored content rather than on a mode, because a row
/// recorded present with no content restores nothing, and that is the failure
/// this half of the mechanism has to rule out.
#[tokio::test]
async fn audit_apply_checkpoints_the_content_of_the_compiled_rules_it_replaces() {
    const PRE_APPLY_COMPILED: &str = "## This file is automatically generated\n-D\n-b 8192\n";

    // The ordinary host: auditd shipped a compiled rule set, and the apply is
    // about to have augenrules overwrite it.
    let executor = Arc::new(
        audit_apply_executor()
            .with_directory(RULES_DIR)
            .with_file(COMPILED_RULES, PRE_APPLY_COMPILED),
    );
    let mut ctx =
        Context::with_executor_and_checkpoint(executor.clone(), test_checkpoint_manager().await);

    let result = AuditHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("audit apply should not error");

    let checkpoint_id = result
        .apply_checkpoint_id
        .clone()
        .expect("the apply must take a checkpoint on a host with auditd");
    let (_, captured) = ctx
        .checkpoint_manager()
        .expect("the context carries a checkpoint manager")
        .get_checkpoint(&hardener_state::CheckpointId::new(checkpoint_id))
        .await
        .expect("the checkpoint just taken must be readable");

    let compiled_row = captured
        .iter()
        .find(|state| state.file_path == COMPILED_RULES)
        .unwrap_or_else(|| {
            panic!(
                "the checkpoint must carry a row for the compiled rule set augenrules \
                 rewrites, otherwise a rollback leaves the hardening loaded at the next \
                 boot. Captured: {captured:?}"
            )
        });
    assert_eq!(
        compiled_row.file_content.as_deref(),
        Some(PRE_APPLY_COMPILED.as_bytes()),
        "a file that existed at capture must be stored with its content, because that is \
         what the restore writes back; a row with no content restores nothing. \
         Captured: {captured:?}"
    );
}

/// A host with no audit package is not a host that refused.
///
/// `read_current_audit_rules` returned `PermissionDenied` from the `Err(_)` arm
/// of `execute_command`, and `LocalExecutor` turns ENOENT into exactly that
/// `Err`, so a machine that has never had auditd installed was told that
/// listing its audit rules requires root. No privilege installs a package.
///
/// The three fixtures differ only in what `auditctl` does, and they must reach
/// three different answers.
#[tokio::test]
async fn an_absent_auditctl_is_not_reported_as_a_refusal() {
    let entry_for = async |executor: MockExecutor| {
        let ctx = Context::with_executor(Arc::new(executor));
        let result = AuditHardeningPlugin::new()
            .scan(&ctx, &PluginConfig::default())
            .await
            .expect("an unreadable rule set is reported through ScanResult, never as Err");
        result
            .scan_unchecked
            .iter()
            .find(|check| check.unchecked_title.starts_with("Audit rule:"))
            .cloned()
    };

    // auditd is up, but auditctl is not there. `auditctl -l` is deliberately
    // left unregistered, so the mock fails the spawn exactly as a real host
    // does for ENOENT, which is the path that used to be called a refusal.
    let absent = MockExecutor::new()
        .with_command_exists("auditd", true)
        .with_command_exists("auditctl", false)
        .with_command(
            "systemctl",
            &["is-enabled", "auditd"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "auditd"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        );
    let entry = entry_for(absent)
        .await
        .expect("the rules must still be reported unchecked");
    assert_eq!(
        entry.unchecked_blocker,
        UncheckedBlocker::Environment,
        "a package that is not installed will not install itself for root"
    );
    assert!(
        entry.unchecked_reason.contains("auditctl could not be run"),
        "the reason must name what actually happened, got: {}",
        entry.unchecked_reason
    );

    // auditctl is there and refuses: the case the old code was right about,
    // which must keep working or this fix would have traded one silence for
    // another.
    let refused = entry_for(auditctl_permission_denied_executor())
        .await
        .expect("a refusal must still be reported unchecked");
    assert_eq!(
        refused.unchecked_blocker,
        UncheckedBlocker::Privilege,
        "an unprivileged session that auditctl refused still has root to try"
    );
    assert!(
        refused.unchecked_reason.contains("requires root"),
        "got: {}",
        refused.unchecked_reason
    );
}

/// A subsystem-level exception for one of auditd's three states.
fn audit_exception_config(key: &str) -> PluginConfig {
    let mut config = PluginConfig::default();
    config.exceptions.insert(
        key.to_string(),
        PolicyException {
            value: "absent".to_string(),
            allowed: true,
            reason: "auditing is collected off-host by the agent, JIRA-7731".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );
    config
}

/// Auditd's three states take three keys rather than one, because accepting a
/// host where auditd is not installed is a different decision from accepting
/// one where it is installed and merely stopped.
#[tokio::test]
async fn scan_honours_an_exception_for_a_host_without_auditd_installed() {
    let ctx = Context::with_executor(Arc::new(no_auditd_executor()));
    let plugin = AuditHardeningPlugin::new();

    let plain = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();
    let plain_finding = plain
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "audit_not_installed")
        .expect("a host without auditd raises the finding at all");
    assert!(
        !plain_finding.is_policy_excepted(),
        "with nothing declared the finding must stay a live violation"
    );

    let excepted = plugin
        .scan(&ctx, &audit_exception_config("auditd-present"))
        .await
        .unwrap();
    assert!(
        excepted
            .scan_findings
            .iter()
            .find(|f| f.finding_id == "audit_not_installed")
            .expect("an approved deviation is still reported, annotated rather than dropped")
            .is_policy_excepted(),
        "the declared exception must reach the finding, or report fails the control"
    );
}

#[tokio::test]
async fn scan_honours_separate_exceptions_for_auditd_at_boot_and_running() {
    let ctx = Context::with_executor(Arc::new(auditd_disabled_executor()));
    let plugin = AuditHardeningPlugin::new();

    let plain = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();
    for id in ["audit_not_enabled", "auditd_not_running"] {
        let finding = plain
            .scan_findings
            .iter()
            .find(|f| f.finding_id == id)
            .unwrap_or_else(|| panic!("{id} is raised at all on this host"));
        assert!(
            !finding.is_policy_excepted(),
            "{id} must stay a live violation when nothing excuses it"
        );
    }

    // Declaring one must not silence the other: they are separate decisions.
    let at_boot_only = plugin
        .scan(&ctx, &audit_exception_config("auditd-at-boot"))
        .await
        .unwrap();
    let excepted = |id: &str| {
        at_boot_only
            .scan_findings
            .iter()
            .find(|f| f.finding_id == id)
            .map(|f| f.is_policy_excepted())
    };
    assert_eq!(
        excepted("audit_not_enabled"),
        Some(true),
        "the boot key must reach the boot finding"
    );
    assert_eq!(
        excepted("auditd_not_running"),
        Some(false),
        "approving a unit that does not start at boot does not approve one that is stopped"
    );
}

/// Every finding this plugin reports must name the key that silences it, and
/// an audit finding names a failure (`audit_not_installed`) while its exception
/// is keyed on the requirement (`auditd-present`), so neither can be derived
/// from the other.
///
/// The loop is the point: asserting one finding would leave every other
/// directive in this plugin free to advertise a key that does nothing. The
/// emptiness check is the control, because a fixture reporting nothing would
/// satisfy a loop that never runs.
#[tokio::test]
async fn every_audit_finding_names_the_exception_key_that_silences_it() {
    let scan = async |config: &PluginConfig| {
        AuditHardeningPlugin::new()
            .scan(
                &Context::with_executor(Arc::new(no_auditd_executor())),
                config,
            )
            .await
            .expect("audit scan should not error")
    };

    let result = scan(&PluginConfig::default()).await;
    assert!(
        !result.scan_findings.is_empty(),
        "the fixture must report something, or the loop below measures nothing",
    );

    let mut config = PluginConfig::default();
    let mut sampled = Vec::new();
    for finding in &result.scan_findings {
        let key = finding
            .finding_exception_key
            .clone()
            .unwrap_or_else(|| panic!("{} advertises no exception key", finding.finding_id));
        assert_ne!(
            key, finding.finding_id,
            "the key is not the id; an id is derived from the key and loses information",
        );
        sampled.push(key.clone());
        config.exceptions.insert(
            key,
            PolicyException {
                value: finding.finding_current_value.clone(),
                allowed: true,
                reason: "measured deviation".to_string(),
                approved_by: None,
                approved_date: None,
                ticket: None,
                expires: None,
            },
        );
    }

    assert!(
        sampled.iter().any(|key| key == "auditd-present"),
        "the missing-auditd finding is keyed on auditd-present",
    );

    for finding in &scan(&config).await.scan_findings {
        assert!(
            finding.is_policy_excepted(),
            "{} was not annotated by an exception written under the key it named",
            finding.finding_id,
        );
    }
}
