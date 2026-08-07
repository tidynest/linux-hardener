//! Services plugin tests using MockExecutor.
//!
//! These tests verify plugin behavior without touching real systemd services.

mod common;

use common::test_checkpoint_manager;
use hardener_common::types::{PluginId, Severity};
use hardener_core::{
    CommandOutput, Context, MockExecutor, PluginConfig, PolicyException, SystemExecutor,
    plugin::HardeningPlugin,
};
use hardener_plugins::ServicesHardeningPlugin;
use std::sync::Arc;

/// Unit patterns the scan path's batched spawns pass, in directive order.
const ASSESSED_UNITS: &[&str] = &[
    "bluetooth.service",
    "cups.service",
    "avahi-daemon.service",
    "ModemManager.service",
    "xinetd.service",
];

/// Stub for the scan path's batched `systemctl list-unit-files` spawn.
fn with_unit_files(executor: MockExecutor, stdout: &str) -> MockExecutor {
    let mut args = vec!["list-unit-files", "--type=service", "--no-legend"];
    args.extend(ASSESSED_UNITS);
    executor.with_command(
        "systemctl",
        &args,
        CommandOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: 0,
        },
    )
}

/// Stub for the scan path's batched `systemctl list-units` spawn.
fn with_units(executor: MockExecutor, stdout: &str) -> MockExecutor {
    let mut args = vec![
        "list-units",
        "--type=service",
        "--all",
        "--no-legend",
        "--plain",
    ];
    args.extend(ASSESSED_UNITS);
    executor.with_command(
        "systemctl",
        &args,
        CommandOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: 0,
        },
    )
}

/// Creates a mock executor where all unnecessary services are disabled.
fn clean_system_executor() -> MockExecutor {
    let executor = MockExecutor::new().with_command_exists("systemctl", true);
    // Services exist but are disabled and not loaded: no findings expected.
    let executor = with_unit_files(
        executor,
        "bluetooth.service disabled disabled\ncups.service disabled disabled\n",
    );
    with_units(executor, "")
}

/// Creates a mock executor with insecure services running.
///
/// Stubs BOTH probing styles: the batched listings the scan path consumes and
/// the per-service commands validate/apply still issue. Scenario: bluetooth
/// enabled+active, cups enabled only, avahi absent, ModemManager disabled.
fn insecure_services_executor() -> MockExecutor {
    let executor = MockExecutor::new().with_command_exists("systemctl", true);
    let executor = with_unit_files(
        executor,
        "bluetooth.service enabled enabled\n\
         cups.service enabled enabled\n\
         ModemManager.service disabled disabled\n",
    );
    with_units(
        executor,
        "bluetooth.service loaded active running Bluetooth service\n\
         cups.service loaded inactive dead CUPS Scheduler\n",
    )
    // Bluetooth - exists, enabled, and active
    .with_command(
        "systemctl",
        &["list-unit-files", "bluetooth.service"],
        CommandOutput {
            stdout: "bluetooth.service enabled enabled\n".to_string(),
            stderr: String::new(),
            exit_code: 0,
        },
    )
    .with_command(
        "systemctl",
        &["is-enabled", "bluetooth"],
        CommandOutput {
            stdout: "enabled\n".to_string(),
            stderr: String::new(),
            exit_code: 0,
        },
    )
    .with_command(
        "systemctl",
        &["is-active", "bluetooth"],
        CommandOutput {
            stdout: "active\n".to_string(),
            stderr: String::new(),
            exit_code: 0,
        },
    )
    // CUPS - exists and enabled but not active
    .with_command(
        "systemctl",
        &["list-unit-files", "cups.service"],
        CommandOutput {
            stdout: "cups.service enabled enabled\n".to_string(),
            stderr: String::new(),
            exit_code: 0,
        },
    )
    .with_command(
        "systemctl",
        &["is-enabled", "cups"],
        CommandOutput {
            stdout: "enabled\n".to_string(),
            stderr: String::new(),
            exit_code: 0,
        },
    )
    .with_command(
        "systemctl",
        &["is-active", "cups"],
        CommandOutput {
            stdout: "inactive\n".to_string(),
            stderr: String::new(),
            exit_code: 3, // Not active
        },
    )
    // Avahi - does not exist on this system
    .with_command(
        "systemctl",
        &["list-unit-files", "avahi-daemon.service"],
        CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        },
    )
    // ModemManager - exists but disabled
    .with_command(
        "systemctl",
        &["list-unit-files", "ModemManager.service"],
        CommandOutput {
            stdout: "ModemManager.service disabled disabled\n".to_string(),
            stderr: String::new(),
            exit_code: 0,
        },
    )
    .with_command(
        "systemctl",
        &["is-enabled", "ModemManager"],
        CommandOutput {
            stdout: "disabled\n".to_string(),
            stderr: String::new(),
            exit_code: 1,
        },
    )
    .with_command(
        "systemctl",
        &["is-active", "ModemManager"],
        CommandOutput {
            stdout: "inactive\n".to_string(),
            stderr: String::new(),
            exit_code: 3,
        },
    )
}

/// Creates a mock executor without systemctl (non-systemd system).
fn no_systemd_executor() -> MockExecutor {
    MockExecutor::new().with_command_exists("systemctl", false)
}

#[tokio::test]
async fn test_services_scan_clean_system_no_findings() {
    let executor = clean_system_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = ServicesHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    assert!(result.scan_success, "clean system scan should succeed");
    assert_eq!(result.scan_plugin_id, PluginId::new("service-minimisation"));
    assert!(
        result.scan_findings.is_empty(),
        "Clean system should have no findings, but got: {:?}",
        result
            .scan_findings
            .iter()
            .map(|f| &f.finding_title)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_services_scan_finds_enabled_services() {
    let executor = insecure_services_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = ServicesHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    assert!(result.scan_success, "insecure services scan should succeed");

    // Should find bluetooth (enabled and active) and cups (enabled)
    let finding_ids: Vec<_> = result
        .scan_findings
        .iter()
        .map(|f| f.finding_id.as_str())
        .collect();

    assert!(
        finding_ids.contains(&"service_bluetooth"),
        "Should find bluetooth service"
    );
    assert!(
        finding_ids.contains(&"service_cups"),
        "Should find cups service"
    );

    // Should NOT find avahi (doesn't exist) or ModemManager (disabled)
    assert!(
        !finding_ids.contains(&"service_avahi_daemon"),
        "Should not flag non-existent avahi"
    );
    assert!(
        !finding_ids.contains(&"service_ModemManager"),
        "Should not flag disabled ModemManager"
    );
}

#[tokio::test]
async fn test_services_scan_finding_structure() {
    let executor = insecure_services_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = ServicesHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    // Find bluetooth finding
    let bt_finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "service_bluetooth")
        .expect("Should have bluetooth finding");

    assert_eq!(bt_finding.finding_current_value, "enabled and active");
    assert_eq!(bt_finding.finding_recommended_value, "disabled and masked");
    assert_eq!(bt_finding.finding_severity, Severity::High);
    assert!(
        bt_finding.finding_title.contains("bluetooth"),
        "finding title should mention bluetooth, got: {}",
        bt_finding.finding_title
    );
    assert!(
        !bt_finding.finding_remediation_steps.is_empty(),
        "bluetooth finding should have remediation steps"
    );

    // Check remediation steps
    let steps: Vec<_> = bt_finding
        .finding_remediation_steps
        .iter()
        .map(|s| s.as_str())
        .collect();
    assert!(
        steps.iter().any(|s| s.contains("systemctl stop")),
        "remediation should include systemctl stop"
    );
    assert!(
        steps.iter().any(|s| s.contains("systemctl disable")),
        "remediation should include systemctl disable"
    );
    assert!(
        steps.iter().any(|s| s.contains("systemctl mask")),
        "remediation should include systemctl mask"
    );
}

#[tokio::test]
async fn test_services_scan_cups_enabled_only() {
    let executor = insecure_services_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = ServicesHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    // Find CUPS finding - enabled but not active
    let cups_finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "service_cups")
        .expect("Should have cups finding");

    // CUPS is enabled but not active
    assert_eq!(cups_finding.finding_current_value, "enabled");
    assert_eq!(cups_finding.finding_severity, Severity::Medium);
}

#[tokio::test]
async fn test_services_validate_with_systemctl() {
    let executor = insecure_services_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = ServicesHardeningPlugin::new();
    let config = hardener_core::PluginConfig::default();

    let result = plugin.validate(&ctx, &config).await.unwrap();

    assert!(
        result.validation_report_is_valid,
        "validation with systemctl should be valid"
    );
    assert!(
        result.validation_report_issues.is_empty(),
        "validation with systemctl should have no issues, found: {:?}",
        result.validation_report_issues
    );

    // Should list estimated changes for enabled services
    assert!(
        !result.validation_report_estimated_changes.is_empty(),
        "enabled services should produce estimated changes"
    );

    let changes_str = result.validation_report_estimated_changes.join(" ");
    assert!(
        changes_str.contains("bluetooth"),
        "estimated changes should mention bluetooth, got: {changes_str}"
    );
    assert!(
        changes_str.contains("cups"),
        "estimated changes should mention cups, got: {changes_str}"
    );
}

#[tokio::test]
async fn test_services_validate_no_systemctl() {
    let executor = no_systemd_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = ServicesHardeningPlugin::new();
    let config = hardener_core::PluginConfig::default();

    let result = plugin.validate(&ctx, &config).await.unwrap();

    // Should have critical issue about missing systemctl
    assert!(
        !result.validation_report_is_valid,
        "validation without systemctl should be invalid"
    );
    assert!(
        !result.validation_report_issues.is_empty(),
        "validation without systemctl should have issues"
    );

    let issue = &result.validation_report_issues[0];
    assert_eq!(issue.validation_issue_severity, Severity::Critical);
    assert!(
        issue.validation_issue_message.contains("systemctl"),
        "issue should mention systemctl, got: {}",
        issue.validation_issue_message
    );
    assert!(
        issue.validation_issue_message.contains("systemd"),
        "issue should mention systemd, got: {}",
        issue.validation_issue_message
    );
}

#[tokio::test]
async fn test_services_scan_logs_commands() {
    let executor = insecure_services_executor();
    let ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = ServicesHardeningPlugin::new();

    let _ = plugin.scan(&ctx, &PluginConfig::default()).await;

    let log = executor.log();

    // Should have executed systemctl commands
    assert!(
        log.commands_executed
            .iter()
            .any(|(cmd, _)| cmd == "systemctl"),
        "Should execute systemctl commands"
    );

    // Should check list-unit-files for each service
    assert!(
        log.commands_executed
            .iter()
            .any(|(_, args)| args.contains(&"list-unit-files".to_string())),
        "Should check list-unit-files"
    );
}

#[tokio::test]
async fn test_services_scan_spawns_exactly_two_systemctl_commands() {
    let executor = insecure_services_executor();
    let ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = ServicesHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();
    assert!(!result.scan_findings.is_empty(), "scenario has findings");

    // The whole scan must cost two spawns: one unit-file listing and one
    // unit listing, never a per-service probe triple.
    let log = executor.log();
    let args: Vec<&str> = log
        .commands_executed
        .iter()
        .map(|(_, a)| a[0].as_str())
        .collect();
    assert_eq!(
        args,
        vec!["list-unit-files", "list-units"],
        "scan must batch systemctl probing into exactly two spawns, got: {:?}",
        log.commands_executed
    );
}

#[tokio::test]
async fn test_services_scan_duration_recorded() {
    let executor = clean_system_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = ServicesHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    assert!(
        result.scan_duration_us > 0,
        "Scan duration should be recorded"
    );
}

#[tokio::test]
async fn test_services_metadata() {
    let plugin = ServicesHardeningPlugin::new();
    let metadata = plugin.metadata();

    assert_eq!(metadata.plugin_id, PluginId::new("service-minimisation"));
    assert_eq!(metadata.plugin_name, "Service Minimisation");
    assert!(
        metadata.plugin_description.contains("systemd"),
        "plugin description should mention systemd, got: {}",
        metadata.plugin_description
    );
}

#[tokio::test]
async fn test_services_scan_with_remote_executor() {
    // Simulate scanning services on a remote system
    let executor = MockExecutor::new()
        .remote()
        .with_description("ssh://admin@server.example.com")
        .with_command_exists("systemctl", true);
    let executor = with_unit_files(executor, "bluetooth.service enabled enabled\n");
    let executor = with_units(
        executor,
        "bluetooth.service loaded active running Bluetooth service\n",
    );

    assert!(
        executor.is_remote(),
        "remote executor should report as remote"
    );

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = ServicesHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    assert!(result.scan_success, "remote services scan should succeed");
    // Should find bluetooth on remote system
    assert!(
        result
            .scan_findings
            .iter()
            .any(|f| f.finding_id == "service_bluetooth"),
        "should find bluetooth on remote, got: {:?}",
        result
            .scan_findings
            .iter()
            .map(|f| &f.finding_id)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_services_compliance_mappings() {
    // Create executor with cups and avahi enabled to test compliance mappings
    let executor = MockExecutor::new().with_command_exists("systemctl", true);
    let executor = with_unit_files(
        executor,
        "cups.service enabled enabled\navahi-daemon.service enabled enabled\n",
    );
    let executor = with_units(
        executor,
        "cups.service loaded active running CUPS Scheduler\n\
         avahi-daemon.service loaded active running Avahi mDNS/DNS-SD Stack\n",
    );

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = ServicesHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    // CUPS should have CIS 2.2.4 mapping
    let cups_finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "service_cups")
        .expect("Should have cups finding");
    assert!(
        !cups_finding.finding_compliance.is_empty(),
        "cups finding should have compliance mappings"
    );
    assert_eq!(
        cups_finding.finding_compliance[0].compliance_control_id,
        "2.2.4"
    );

    // Avahi should have CIS 2.2.3 mapping
    let avahi_finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "service_avahi_daemon")
        .expect("Should have avahi finding");
    assert!(
        !avahi_finding.finding_compliance.is_empty(),
        "avahi finding should have compliance mappings"
    );
    assert_eq!(
        avahi_finding.finding_compliance[0].compliance_control_id,
        "2.2.3"
    );
}

#[tokio::test]
async fn test_services_apply_skips_exceptions() {
    let ok = CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    };
    // Bluetooth exists + enabled + active, but NO stop/disable/mask commands
    // registered: if the plugin tries to call them the mock will error.
    // CUPS has full commands so the rest of apply succeeds.
    let executor = MockExecutor::new()
        .with_command_exists("systemctl", true)
        // Bluetooth: exists, enabled, active
        .with_command(
            "systemctl",
            &["list-unit-files", "bluetooth.service"],
            CommandOutput {
                stdout: "bluetooth.service enabled enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        // CUPS: exists, enabled, not active: full apply path
        .with_command(
            "systemctl",
            &["list-unit-files", "cups.service"],
            CommandOutput {
                stdout: "cups.service enabled enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-enabled", "cups"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "cups"],
            CommandOutput {
                stdout: "inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 3,
            },
        )
        .with_command("systemctl", &["disable", "cups"], ok.clone())
        .with_command("systemctl", &["mask", "cups"], ok)
        // Avahi + ModemManager: don't exist
        .with_command(
            "systemctl",
            &["list-unit-files", "avahi-daemon.service"],
            CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["list-unit-files", "ModemManager.service"],
            CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        );

    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = ServicesHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "bluetooth".to_string(),
        PolicyException {
            value: "enabled".to_string(),
            allowed: true,
            reason: "Desktop workstation needs Bluetooth".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let result = plugin.apply(&mut ctx, &config).await.unwrap();

    assert!(
        result.apply_success,
        "apply should succeed, errors: {:?}",
        result
            .apply_changes
            .iter()
            .filter(|c| !c.change_success)
            .collect::<Vec<_>>()
    );

    // Should have a "skipped" change for bluetooth
    let skipped = result.apply_changes.iter().find(|c| {
        c.change_description.contains("skipped") && c.change_description.contains("bluetooth")
    });
    assert!(
        skipped.is_some(),
        "should have a skipped change for bluetooth"
    );
    assert!(
        skipped
            .expect("checked above")
            .change_description
            .contains("Desktop workstation"),
    );

    // Verify no systemctl stop/disable/mask for bluetooth
    let log = executor.log();
    assert!(
        !log.commands_executed
            .iter()
            .any(|(cmd, args)| cmd == "systemctl"
                && args.iter().any(|a| a == "bluetooth")
                && args
                    .iter()
                    .any(|a| a == "stop" || a == "disable" || a == "mask")),
        "should not execute stop/disable/mask for excepted bluetooth"
    );
}

#[tokio::test]
async fn scan_annotates_valid_exception() {
    // Bluetooth is enabled and active, plus a valid exception for it: the
    // finding is still reported but annotated. Services has no directive
    // override, so there is no target value to assert here.
    let executor = insecure_services_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = ServicesHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "bluetooth".to_string(),
        PolicyException {
            value: "enabled".to_string(),
            allowed: true,
            reason: "Desktop workstation needs Bluetooth".to_string(),
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
        .find(|f| f.finding_id == "service_bluetooth")
        .expect("unnecessary service should still produce a finding");
    assert!(
        f.is_policy_excepted(),
        "finding should be annotated with the valid exception"
    );
}

#[tokio::test]
async fn test_services_validate_skips_exceptions() {
    let executor = insecure_services_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = ServicesHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "bluetooth".to_string(),
        PolicyException {
            value: "enabled".to_string(),
            allowed: true,
            reason: "Desktop workstation needs Bluetooth".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let report = plugin.validate(&ctx, &config).await.unwrap();

    // bluetooth should NOT appear in estimated_changes
    assert!(
        !report
            .validation_report_estimated_changes
            .iter()
            .any(|c| c.contains("bluetooth")),
        "excepted service should not appear in estimated changes"
    );

    // CUPS should still appear (not excepted)
    assert!(
        report
            .validation_report_estimated_changes
            .iter()
            .any(|c| c.contains("cups")),
        "non-excepted services should still appear"
    );
}

/// The preview line for an excepted service may not present the exception's
/// `value` as something read from the host.
///
/// A service exception is keyed on the service name and `value` is advisory
/// only, so nothing checks it. Echoing it into the slot documented as the
/// value the host keeps prints an operator's own text as a reading.
#[tokio::test]
async fn an_advisory_exception_value_is_not_reported_as_the_service_state() {
    let executor = insecure_services_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = ServicesHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "bluetooth".to_string(),
        PolicyException {
            value: "runtime-only".to_string(),
            allowed: true,
            reason: "desktop workstation needs the radio".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let report = plugin.validate(&ctx, &config).await.unwrap();
    let line = report
        .validation_report_exceptions
        .iter()
        .find(|l| l.contains("bluetooth"))
        .expect("an excepted service must still be previewed");

    // Positive control first: a line that stopped being emitted at all would
    // satisfy the absence assertion below.
    assert!(
        line.contains("desktop workstation needs the radio"),
        "the preview line must carry the documented reason: {line}"
    );
    assert!(
        !line.contains("runtime-only"),
        "the advisory value was never compared against the host, so the preview \
         may not present it as the service's state: {line}"
    );
}

/// `list-unit-files` stub that fails the way a broken systemd does: a non-zero
/// exit that also writes to stderr.
fn with_unit_files_failing(executor: MockExecutor) -> MockExecutor {
    let mut args = vec!["list-unit-files", "--type=service", "--no-legend"];
    args.extend(ASSESSED_UNITS);
    executor.with_command(
        "systemctl",
        &args,
        CommandOutput {
            stdout: String::new(),
            stderr: "Failed to connect to bus: No such file or directory".to_string(),
            exit_code: 1,
        },
    )
}

/// `list-unit-files` stub for the ordinary case where none of the named units
/// are installed: systemd exits 1 with an empty stderr.
fn with_unit_files_no_matches(executor: MockExecutor) -> MockExecutor {
    let mut args = vec!["list-unit-files", "--type=service", "--no-legend"];
    args.extend(ASSESSED_UNITS);
    executor.with_command(
        "systemctl",
        &args,
        CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 1,
        },
    )
}

#[tokio::test]
async fn scan_reports_unchecked_when_the_service_listing_fails() {
    // A failed listing used to produce zero findings, which is byte-identical
    // to a host with nothing wrong. The scan must say it could not look.
    let executor = with_units(
        with_unit_files_failing(MockExecutor::new().with_command_exists("systemctl", true)),
        "",
    );
    let ctx = Context::with_executor(Arc::new(executor) as Arc<dyn SystemExecutor>);
    let plugin = ServicesHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    assert!(
        !result.scan_success,
        "a listing failure must not be reported as a successful scan"
    );
    assert!(
        result.scan_error.is_some(),
        "the failure reason must reach the result"
    );
    assert!(
        result.scan_findings.is_empty(),
        "nothing was observed, so nothing may be asserted as a finding"
    );
    assert!(
        !result.scan_unchecked.is_empty(),
        "every managed service must be reported as unchecked, not silently dropped"
    );
}

#[tokio::test]
async fn scan_treats_no_installed_units_as_a_clean_host_not_a_failure() {
    // systemd exits 1 when none of the named units exist. That is the ordinary
    // answer on a minimal host and must not be mistaken for a broken probe,
    // which is why the check looks at stderr rather than the exit code alone.
    let executor = with_units(
        with_unit_files_no_matches(MockExecutor::new().with_command_exists("systemctl", true)),
        "",
    );
    let ctx = Context::with_executor(Arc::new(executor) as Arc<dyn SystemExecutor>);
    let plugin = ServicesHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    assert!(
        result.scan_success,
        "a host with none of these services installed is a successful scan"
    );
    assert!(result.scan_findings.is_empty());
    assert!(
        result.scan_unchecked.is_empty(),
        "nothing was unverifiable: the listing answered, it just listed nothing"
    );
}

/// Where `systemctl mask` records itself, and the only unit directory this
/// plugin's changes reach.
const ADMIN_UNIT_DIR: &str = "/etc/systemd/system";

/// A host on which bluetooth is the one unit installed, and on which nothing
/// has yet written a `/etc/systemd/system/bluetooth.service`.
///
/// `ADMIN_UNIT_DIR` is registered as a directory so the capture recurses into
/// it exactly as it would on a real host; it is deliberately left empty, which
/// is the state the defect lives in. The four other assessed units answer with
/// an empty listing, so they are absent.
fn one_installed_service_executor() -> MockExecutor {
    // Serves double duty: the empty successful reply a mutation command gives,
    // and the empty listing `list-unit-files` gives for a unit that is not
    // installed, which is what the existence probe reads as absent.
    let ok = CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    };

    let mut executor = MockExecutor::new()
        .with_command_exists("systemctl", true)
        .with_directory(ADMIN_UNIT_DIR)
        .with_command(
            "systemctl",
            &["list-unit-files", "bluetooth.service"],
            CommandOutput {
                stdout: "bluetooth.service enabled enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-enabled", "bluetooth"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "bluetooth"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command("systemctl", &["stop", "bluetooth"], ok.clone())
        .with_command("systemctl", &["disable", "bluetooth"], ok.clone())
        .with_command("systemctl", &["mask", "bluetooth"], ok.clone());

    for unit in ASSESSED_UNITS.iter().filter(|u| **u != "bluetooth.service") {
        executor = executor.with_command("systemctl", &["list-unit-files", unit], ok.clone());
    }
    executor
}

/// `systemctl mask` creates `/etc/systemd/system/<unit>.service` as a symlink
/// to /dev/null, and nothing but this checkpoint can undo it.
///
/// The capture recurses into the declared directory and emits a row per child
/// that is there at capture time; the mask link is by definition not there yet,
/// so no row carried it and the rollback, which walks only rows the checkpoint
/// holds, had nothing to remove. The plugin must therefore declare the path
/// itself, the way the kernel and ssh plugins declare the files their applies
/// create: an absent declared path is stored with a zero mode, which the
/// rollback reads as "remove this".
///
/// The assertion is on the stored row rather than on the commands logged,
/// because the row is the thing the rollback later reads, and because the mock
/// answers a command from its registry without ever consulting the virtual
/// filesystem, so no command's exit status could prove anything about a path.
#[tokio::test]
async fn services_apply_checkpoints_the_mask_link_of_an_installed_unit() {
    let executor = one_installed_service_executor();
    let mut ctx =
        Context::with_executor_and_checkpoint(Arc::new(executor), test_checkpoint_manager().await);

    let result = ServicesHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("services apply should not error");

    let checkpoint_id = result
        .apply_checkpoint_id
        .clone()
        .expect("the apply must take a checkpoint when a manager is present");
    let (_, captured) = ctx
        .checkpoint_manager()
        .expect("the context carries a checkpoint manager")
        .get_checkpoint(&hardener_state::CheckpointId::new(checkpoint_id))
        .await
        .expect("the checkpoint just taken must be readable");

    let mask_link = format!("{ADMIN_UNIT_DIR}/bluetooth.service");
    let mask_row = captured
        .iter()
        .find(|state| state.file_path == mask_link)
        .unwrap_or_else(|| {
            panic!(
                "the checkpoint must carry a row for {mask_link}; without one the mask this \
                 apply just created can never be undone. Captured: {captured:?}"
            )
        });

    assert_eq!(
        mask_row.file_permissions, 0,
        "the path was absent when the checkpoint was taken, and only a zero mode tells the \
         rollback to remove what the mask put there. Captured: {captured:?}"
    );

    // Narrowing, at the level where it matters: a unit this host has never had
    // installed must contribute no row at all, because a declared path found
    // absent is deleted on rollback unconditionally and /etc/systemd/system is
    // also where an administrator's own unit overrides live.
    assert!(
        !captured
            .iter()
            .any(|state| state.file_path == format!("{ADMIN_UNIT_DIR}/cups.service")),
        "an uninstalled unit must not have its override slot declared. Captured: {captured:?}"
    );
}

/// The identifier a finding carries is not the identifier an exception needs:
/// this plugin renders `service_bluetooth` from a key of `bluetooth`, and the
/// transform collapses `-` and `_` onto `_`, so it cannot be inverted. The
/// finding therefore has to carry the key, and the second half of this test is
/// the part that matters: the key it advertises must be the one that actually
/// silences it.
#[tokio::test]
async fn a_service_finding_names_the_exception_key_that_silences_it() {
    let ctx = Context::with_executor(Arc::new(insecure_services_executor()));
    let plugin = ServicesHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();
    let finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "service_bluetooth")
        .expect("the fixture leaves bluetooth enabled");

    assert_eq!(
        finding.finding_exception_key.as_deref(),
        Some("bluetooth"),
        "the finding must name the key an exception is written under, not its own id",
    );

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        finding
            .finding_exception_key
            .clone()
            .expect("the key is present"),
        PolicyException {
            value: finding.finding_current_value.clone(),
            allowed: true,
            reason: "desktop workstation needs Bluetooth".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let excepted = plugin.scan(&ctx, &config).await.unwrap();
    let annotated = excepted
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "service_bluetooth")
        .expect("an excepted finding is still reported, annotated");

    assert!(
        annotated.is_policy_excepted(),
        "an exception written under the advertised key must annotate the finding",
    );
}
