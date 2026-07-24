//! Audit plugin tests using MockExecutor.
//!
//! These tests verify plugin behavior without touching real auditd.

use hardener_common::types::{PluginId, Severity};
use hardener_core::{
    CommandOutput, Context, MockExecutor, PluginConfig, PolicyException, SystemExecutor,
    plugin::HardeningPlugin,
};
use hardener_plugins::AuditHardeningPlugin;
use std::sync::Arc;

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
        .with_command("mkdir", &["-p", "/etc/audit/rules.d"], ok.clone())
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
        .with_command("mkdir", &["-p", "/etc/audit/rules.d"], ok.clone())
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
        .with_command("mkdir", &["-p", "/etc/audit/rules.d"], ok.clone())
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
        .with_command("mkdir", &["-p", "/etc/audit/rules.d"], ok)
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
        .with_command("mkdir", &["-p", "/etc/audit/rules.d"], ok.clone())
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
        .with_command("mkdir", &["-p", "/etc/audit/rules.d"], ok.clone())
        .with_command("augenrules", &["--load"], ok)
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
