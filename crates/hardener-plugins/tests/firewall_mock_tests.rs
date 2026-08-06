//! Firewall plugin tests using MockExecutor.
//!
//! These tests verify plugin behaviour without touching real firewall configuration.
//! Includes tests for permission-denied scenarios (Bug D).

use hardener_common::types::{PluginId, Severity};
use hardener_core::{
    ChangeType, CommandOutput, Context, MockExecutor, PluginConfig, PolicyException,
    UncheckedBlocker, plugin::HardeningPlugin,
};
use hardener_plugins::FirewallHardeningPlugin;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

mod common;
use common::test_checkpoint_manager;
use std::sync::Arc;

/// Creates a mock executor where UFW is installed and active.
fn ufw_active_executor() -> MockExecutor {
    MockExecutor::new()
        .with_command_exists("ufw", true)
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("nft", false)
        .with_command(
            "ufw",
            &["status"],
            CommandOutput {
                stdout: "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
}

/// The Debian container's real state, measured 2026-07-30: the `ufw` systemd
/// unit is active while ufw itself is not enforcing anything, because Debian
/// ships `ENABLED=no` in `/etc/ufw/ufw.conf` and the unit is a oneshot that
/// happily reports active having loaded no rules. `ufw status` is the only one
/// of the two that answers the question the plugin is actually asking.
fn ufw_unit_active_but_not_enforcing_executor() -> MockExecutor {
    MockExecutor::new()
        .with_command_exists("ufw", true)
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("nft", false)
        .with_command(
            "systemctl",
            &["is-active", "ufw"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        // ufw's own answer, and the only one that reflects what the kernel
        // holds. It runs cleanly here and reports inactive, which is what
        // makes this fixture Debian's state rather than a blocked probe.
        .with_command(
            "ufw",
            &["status"],
            CommandOutput {
                stdout: "Status: inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
}

#[tokio::test]
async fn an_active_unit_is_not_proof_the_firewall_is_enforcing() {
    // The defect this pins was measured on the debian container: the plugin
    // took `systemctl is-active ufw` as proof, skipped `ufw enable`, and then
    // reported three applied rules while the kernel held an empty filter table
    // and a default-ACCEPT policy. The unit being active and the rules being in
    // force are different questions, and only ufw can answer the second.
    let executor = ufw_unit_active_but_not_enforcing_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    use hardener_plugins::firewall::FirewallBackend;
    let backend = hardener_plugins::firewall::ufw::UfwBackend::new();

    assert!(
        backend.is_enabled(&ctx).await.is_err(),
        "a host whose ufw unit is active but whose ufw reports inactive is NOT \
         enforcing, and reporting it as enabled makes apply skip the enable"
    );
}

/// Creates a mock executor where UFW is installed but disabled.
fn ufw_disabled_executor() -> MockExecutor {
    MockExecutor::new()
        .with_command_exists("ufw", true)
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("nft", false)
        .with_command(
            "ufw",
            &["status"],
            CommandOutput {
                stdout: "Status: inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
}

/// Creates a mock executor simulating permission denied when running `ufw status`.
/// This is Bug D: UFW requires root to check status.
fn ufw_permission_denied_executor() -> MockExecutor {
    MockExecutor::new()
        .with_command_exists("ufw", true)
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("nft", false)
        .with_command(
            "ufw",
            &["status"],
            CommandOutput {
                stdout: String::new(),
                stderr: "ERROR: You need to be root to run this script\n".to_string(),
                exit_code: 1,
            },
        )
        // Also provide systemctl check which doesn't require root
        .with_command(
            "systemctl",
            &["is-active", "ufw"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
}

/// Creates a mock executor where no firewall backend is installed.
fn no_firewall_executor() -> MockExecutor {
    MockExecutor::new()
        .with_command_exists("ufw", false)
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("nft", false)
}

#[tokio::test]
async fn test_firewall_scan_ufw_active_no_findings() {
    let executor = ufw_active_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = FirewallHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    assert!(result.scan_success, "active firewall scan should succeed");
    assert_eq!(result.scan_plugin_id, PluginId::new("firewall-hardening"));

    // UFW is active, should have no "disabled" findings
    let disabled_findings: Vec<_> = result
        .scan_findings
        .iter()
        .filter(|f| f.finding_title.to_lowercase().contains("disabled"))
        .collect();

    assert!(
        disabled_findings.is_empty(),
        "Active firewall should NOT have 'disabled' findings, but got: {:?}",
        disabled_findings
            .iter()
            .map(|f| &f.finding_title)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_firewall_scan_ufw_disabled_has_finding() {
    let executor = ufw_disabled_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = FirewallHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    assert!(result.scan_success, "disabled firewall scan should succeed");

    // UFW is disabled, should have a "disabled" finding
    let disabled_findings: Vec<_> = result
        .scan_findings
        .iter()
        .filter(|f| f.finding_title.to_lowercase().contains("disabled"))
        .collect();

    assert!(
        !disabled_findings.is_empty(),
        "Disabled firewall SHOULD have 'disabled' finding"
    );

    // Verify severity (High per current implementation)
    let finding = &disabled_findings[0];
    assert_eq!(
        finding.finding_severity,
        Severity::High,
        "Disabled firewall should be High severity"
    );
}

/// BUG D TEST: This test exposes the false positive bug.
///
/// When `ufw status` fails due to permission denied, the plugin should NOT
/// report "Firewall disabled" - it should either:
/// 1. Fall back to `systemctl is-active ufw` (doesn't need root)
/// 2. Report "Unable to determine firewall status (permission denied)"
/// 3. Return scan_success=false with appropriate error
///
/// Currently this test will FAIL because the plugin incorrectly reports
/// "Firewall disabled" when it can't check status due to permissions.
#[tokio::test]
async fn test_firewall_scan_permission_denied_should_not_report_disabled() {
    let executor = ufw_permission_denied_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = FirewallHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    // The plugin detected UFW exists (command_exists returns true)
    // But `ufw status` failed with permission denied

    // BUG D: Currently this incorrectly reports "Firewall disabled"
    // The correct behaviour would be one of:
    // A) No "disabled" finding (because we don't actually know if it's disabled)
    // B) scan_success = false with error explaining permission issue
    // C) Fall back to systemctl check

    let disabled_findings: Vec<_> = result
        .scan_findings
        .iter()
        .filter(|f| f.finding_title.to_lowercase().contains("disabled"))
        .collect();

    // This assertion documents the EXPECTED behaviour (not current buggy behaviour)
    assert!(
        disabled_findings.is_empty(),
        "BUG D: Permission denied should NOT result in 'Firewall disabled' finding. \
         The firewall might actually be active (and in this mock it IS active via systemctl). \
         Got findings: {:?}",
        disabled_findings
            .iter()
            .map(|f| &f.finding_title)
            .collect::<Vec<_>>()
    );

    // Alternative acceptable behaviours:
    // 1. scan_success = false with permission error
    // 2. Finding that says "Unable to verify firewall status" (not "disabled")
}

#[tokio::test]
async fn test_firewall_scan_no_backend_fails_gracefully() {
    let executor = no_firewall_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = FirewallHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    // No backend found - scan should indicate this
    assert!(
        !result.scan_success || result.scan_error.is_some(),
        "Scan with no firewall backend should fail or have error"
    );

    if let Some(error) = &result.scan_error {
        assert!(
            error.contains("firewall") || error.contains("backend"),
            "Error message should mention firewall or backend"
        );
    }
}

#[tokio::test]
async fn test_firewall_metadata() {
    let plugin = FirewallHardeningPlugin::new();
    let metadata = plugin.metadata();

    assert_eq!(metadata.plugin_id, PluginId::new("firewall-hardening"));
    assert_eq!(metadata.plugin_name, "Firewall Hardening");
}

#[tokio::test]
async fn test_firewall_scan_logs_commands() {
    let executor = ufw_active_executor();
    let ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = FirewallHardeningPlugin::new();

    let _ = plugin.scan(&ctx, &PluginConfig::default()).await;

    let log = executor.log();

    // Should have executed ufw command
    assert!(
        log.commands_executed.iter().any(|(cmd, _)| cmd == "ufw"),
        "Should execute ufw command"
    );
}

#[tokio::test]
async fn test_firewall_scan_duration_recorded() {
    let executor = ufw_active_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = FirewallHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    assert!(
        result.scan_duration_us > 0,
        "scan duration should be recorded"
    );
}

/// Helper: UFW active + all baseline rule commands registered.
/// Accepts an optional port override for the SSH rule (default "22").
///
/// Deliberately does NOT register a bare `ufw allow` response: that was the
/// old, wrong mapping for "established and related" (ufw is stateful by
/// default and needs no rule for it at all). If the plugin regresses and
/// tries to run it, the mock returns "command not registered" and the
/// apply fails loudly instead of silently applying nothing.
fn ufw_apply_executor(ssh_port: &str) -> MockExecutor {
    let ok = CommandOutput {
        stdout: "Rule added\n".to_string(),
        stderr: String::new(),
        exit_code: 0,
    };
    MockExecutor::new()
        .with_command_exists("ufw", true)
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("nft", false)
        // This host's default incoming policy is still allow, so the
        // baseline's default-deny rule has real work to do. Registering it
        // matters: without an answer the probe fails, and the rule would then
        // be applied for want of a reading rather than because the host needs
        // it, which is a test passing through the fallback path instead of the
        // one it means to exercise.
        .with_command(
            "ufw",
            &["status", "verbose"],
            CommandOutput {
                stdout: "Status: active\nDefault: allow (incoming), allow (outgoing), \
                         disabled (routed)\n"
                    .to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "ufw"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        // ufw's own answer, which is what is_enabled asks now. An active unit
        // is not proof the rules are loaded: Debian's unit reports active with
        // ENABLED=no and no ruleset at all.
        .with_command(
            "ufw",
            &["status"],
            CommandOutput {
                stdout: "Status: active
"
                .to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        // The boot half of the question, asked of every backend that is already
        // running. This host's unit is wanted at boot, so the apply has nothing
        // to repair and these tests stay about the rules. `systemctl enable ufw`
        // is deliberately left unregistered: a run that issued it anyway would
        // fail loudly here rather than pass unnoticed.
        .with_command(
            "systemctl",
            &["is-enabled", "ufw"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        // Baseline rule commands (UFW build_ufw_rule_args output)
        .with_command("ufw", &["allow", "from", "127.0.0.1/8"], ok.clone())
        .with_command(
            "ufw",
            &["allow", "to", "any", "port", ssh_port, "proto", "tcp"],
            ok.clone(),
        )
        .with_command("ufw", &["default", "deny", "incoming"], ok)
}

#[tokio::test]
async fn test_firewall_apply_respects_directives() {
    let executor = ufw_apply_executor("2222");
    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = FirewallHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config
        .directives
        .insert("ssh.port".to_string(), "2222".to_string());

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

    // Verify the mock received the overridden port in the ufw command
    let log = executor.log();
    let ssh_cmd = log
        .commands_executed
        .iter()
        .find(|(cmd, args)| cmd == "ufw" && args.iter().any(|a| a == "2222"));
    assert!(
        ssh_cmd.is_some(),
        "ufw should have been called with port 2222, got: {:?}",
        log.commands_executed
    );
}

/// A host with an active ufw, registering every baseline rule command EXCEPT
/// the SSH one, so a plugin that ignored the SSH exception would fail rather
/// than quietly succeed.
///
/// Shared by the apply test, the validate test and the test that they name the
/// same rule. That last one is why this is a single fixture rather than one per
/// half: two fixtures would prove that two similar hosts agree, not that one
/// host is described consistently by the preview and by the run.
fn ufw_exception_executor() -> MockExecutor {
    let ok = CommandOutput {
        stdout: "Rule added\n".to_string(),
        stderr: String::new(),
        exit_code: 0,
    };
    MockExecutor::new()
        .with_command_exists("ufw", true)
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("nft", false)
        .with_command(
            "systemctl",
            &["is-active", "ufw"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        // ufw's own answer, which is what is_enabled asks now. An active unit
        // is not proof the rules are loaded: Debian's unit reports active with
        // ENABLED=no and no ruleset at all.
        .with_command(
            "ufw",
            &["status"],
            CommandOutput {
                stdout: "Status: active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        // This host's default incoming policy is still allow, so the baseline's
        // default-deny rule has real work to do. Without an answer here the
        // probe fails and the rule is applied for want of a reading rather than
        // because the host needs it.
        .with_command(
            "ufw",
            &["status", "verbose"],
            CommandOutput {
                stdout: "Status: active\nDefault: allow (incoming), allow (outgoing), \
                         disabled (routed)\n"
                    .to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        // The boot half of the question, asked of every backend that is already
        // running. This host's unit is wanted at boot, so the apply has nothing
        // to repair and these tests stay about the excepted rule.
        .with_command(
            "systemctl",
            &["is-enabled", "ufw"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command("ufw", &["allow", "from", "127.0.0.1/8"], ok.clone())
        // No SSH rule registered: if the plugin tries to call it, the mock errors
        .with_command("ufw", &["default", "deny", "incoming"], ok)
}

/// The exception every test in this group installs, keyed on the `ssh` rule id.
fn ssh_exception_config() -> PluginConfig {
    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "ssh".to_string(),
        PolicyException {
            value: "skip".to_string(),
            allowed: true,
            reason: "SSH managed externally".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );
    config
}

/// The rule both halves must name, spelled the way the baseline spells it.
const EXCEPTED_RULE_DESCRIPTION: &str = "Allow SSH to prevent lockout";

/// The name a preview or change line carries, which is everything before the
/// first `": "`. Both sides render `"{rule_description}: <tail>"`.
///
/// Returns `None` rather than an empty string when the separator is absent, so
/// a format change on either side surfaces as a missing name instead of as two
/// silences that happen to compare equal.
fn rule_name_in(line: &str) -> Option<&str> {
    line.split_once(": ").map(|(name, _)| name)
}

#[tokio::test]
async fn apply_and_validate_name_an_excepted_rule_the_same_way() {
    // Both halves were pinned only against literals on their own side, so they
    // could drift apart with a fully green suite: apply's test asserted the
    // change contains "skipped" and the reason, pinning no identifier at all,
    // and could have been switched to the config's "ssh" id without a single
    // failure. This asserts the two against each other, from ONE host.
    let executor = ufw_exception_executor();
    let config = ssh_exception_config();

    let mut apply_ctx = Context::with_executor(Arc::new(executor.clone()));
    let applied = FirewallHardeningPlugin::new()
        .apply(&mut apply_ctx, &config)
        .await
        .unwrap();
    let validate_ctx = Context::with_executor(Arc::new(executor));
    let previewed = FirewallHardeningPlugin::new()
        .validate(&validate_ctx, &config)
        .await
        .unwrap();

    let apply_line = applied
        .apply_changes
        .iter()
        .map(|c| c.change_description.as_str())
        .find(|d| d.contains("skipped (exception:"))
        .expect("apply must record the excepted rule as a skipped change");
    let preview_line = previewed
        .validation_report_exceptions
        .iter()
        .find(|e| e.contains("SSH managed externally"))
        .expect("validate must report the excepted rule as a documented deviation");

    let apply_name = rule_name_in(apply_line).expect("apply's change must carry a rule name");
    let preview_name =
        rule_name_in(preview_line).expect("validate's preview must carry a rule name");

    assert_eq!(
        apply_name, preview_name,
        "the preview and the run must identify the same rule the same way, or an \
         operator reading the dry run cannot match it to what the apply reports.\n\
         apply:    {apply_line}\n  preview:  {preview_line}"
    );
    // Without this the assertion above passes on two names that are both wrong
    // in the same way, which a shared format change would produce. Anchoring to
    // the baseline's own spelling is what stops equal-and-empty counting as
    // agreement.
    assert_eq!(
        apply_name, EXCEPTED_RULE_DESCRIPTION,
        "both sides must name the rule by the baseline's description rather than \
         by the config's rule id, got: {apply_line}"
    );
}

#[tokio::test]
async fn test_firewall_apply_skips_exceptions() {
    let executor = ufw_exception_executor();

    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = FirewallHardeningPlugin::new();
    let config = ssh_exception_config();

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

    // Found by the exception wording rather than by the bare word "skipped",
    // which several unrelated no-ops now also carry.
    let skipped = result
        .apply_changes
        .iter()
        .find(|c| c.change_description.contains("skipped (exception:"));
    assert!(skipped.is_some(), "should have a skipped change for SSH");
    assert!(
        skipped
            .expect("checked above")
            .change_description
            .contains("SSH managed externally"),
    );

    // Verify no ufw command was issued for SSH port
    let log = executor.log();
    assert!(
        !log.commands_executed
            .iter()
            .any(|(cmd, args)| cmd == "ufw" && args.iter().any(|a| a == "22")),
        "should not execute ufw command for excepted SSH rule"
    );
}

#[tokio::test]
async fn test_firewall_validate_skips_exceptions() {
    let executor = ufw_active_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = FirewallHardeningPlugin::new();

    // Exception on the SSH rule: should reduce baseline count from 4 to 3
    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "ssh".to_string(),
        PolicyException {
            value: "skip".to_string(),
            allowed: true,
            reason: "SSH managed externally".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let report = plugin.validate(&ctx, &config).await.unwrap();

    // Should say "Apply 3 baseline firewall rules" (not 4)
    let rule_change = report
        .validation_report_estimated_changes
        .iter()
        .find(|c| c.contains("baseline firewall rules"));
    assert!(
        rule_change.is_some(),
        "should have estimated changes for rules"
    );
    assert!(
        rule_change.expect("checked above").contains("3"),
        "expected 3 rules after exception, got: {:?}",
        report.validation_report_estimated_changes
    );
}

#[tokio::test]
async fn validate_reports_a_rule_left_alone_by_a_policy_exception() {
    // The sibling above pins that an excepted rule leaves the count, and that
    // is the whole of what it pinned: the count shrank from 4 to 3 and nothing
    // anywhere said why. Apply names every skipped rule and its reason, so the
    // preview described less than the run it previews.
    let executor = ufw_active_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = FirewallHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "ssh".to_string(),
        PolicyException {
            value: "skip".to_string(),
            allowed: true,
            reason: "SSH managed externally".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let report = plugin.validate(&ctx, &config).await.unwrap();

    // "Allow SSH to prevent lockout" is the string apply prints when it skips
    // this rule. Pinning that rather than the "ssh" config key is what fails if
    // the preview ever drifts to naming the id, because the preview and the run
    // would then identify the same rule differently.
    assert!(
        report.validation_report_exceptions.iter().any(|e| {
            e.contains("Allow SSH to prevent lockout") && e.contains("SSH managed externally")
        }),
        "an excepted rule must be reported by the description apply prints, \
         naming its reason, got: {:?}",
        report.validation_report_exceptions
    );
    // The other three baseline rules are still work this run intends to do, so
    // a fix that reports every rule rather than every excepted one fails here.
    assert_eq!(
        report.validation_report_exceptions.len(),
        1,
        "only the excepted rule is a documented deviation, got: {:?}",
        report.validation_report_exceptions
    );
}

#[tokio::test]
async fn validate_reports_every_rule_when_the_whole_baseline_is_excepted() {
    // The sharp edge of the same defect. With every baseline rule excepted the
    // count reaches zero, so `push_rule_estimate` emits no line at all and the
    // preview became indistinguishable from a host whose firewall already
    // matches the baseline, while apply would report four skipped rules.
    let executor = ufw_active_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = FirewallHardeningPlugin::new();

    let mut config = PluginConfig::default();
    for id in ["loopback", "established", "ssh", "drop_default"] {
        config.exceptions.insert(
            id.to_string(),
            PolicyException {
                value: "skip".to_string(),
                allowed: true,
                reason: format!("{id} managed externally"),
                approved_by: None,
                approved_date: None,
                ticket: None,
                expires: None,
            },
        );
    }

    let report = plugin.validate(&ctx, &config).await.unwrap();

    assert!(
        !report
            .validation_report_estimated_changes
            .iter()
            .any(|c| c.contains("baseline firewall rules")),
        "no baseline rule is pending, so no rule estimate belongs in the \
         preview, got: {:?}",
        report.validation_report_estimated_changes
    );
    assert_eq!(
        report.validation_report_exceptions.len(),
        4,
        "every excepted rule must be reported, got: {:?}",
        report.validation_report_exceptions
    );
}

#[test]
fn test_zone_name_validation() {
    use hardener_plugins::firewall::firewalld::validate_zone_name;

    assert!(validate_zone_name("public").is_ok());
    assert!(validate_zone_name("trusted").is_ok());
    assert!(validate_zone_name("my-zone").is_ok());
    assert!(validate_zone_name("zone_1").is_ok());

    assert!(validate_zone_name("").is_err());
    assert!(validate_zone_name("--help").is_err());
    assert!(validate_zone_name("zone; rm -rf /").is_err());
    assert!(validate_zone_name(&"a".repeat(65)).is_err());
    assert!(validate_zone_name("zone\nnewline").is_err());
}

// --- Backend selection: prefer the ACTIVE backend, not merely the first
// installed one (reproduces the maintainer's Arch host: ufw installed but
// inactive, nftables installed and active). ---

/// Mock executor mirroring the maintainer's Arch host: ufw is installed but
/// inactive, nftables is installed and active. Selection must prefer the
/// active backend, not the first one found by mere presence.
fn ufw_inactive_nftables_active_executor() -> MockExecutor {
    MockExecutor::new()
        .with_command_exists("ufw", true)
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("nft", true)
        .with_command(
            "systemctl",
            &["is-active", "ufw"],
            CommandOutput {
                stdout: "inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 3,
            },
        )
        // What a genuinely inactive host answers. is_enabled asks ufw rather
        // than systemd now, so a fixture answering only systemctl would stand
        // for a host where `ufw status` cannot run at all, which is a third
        // state and not the one these tests are about.
        .with_command(
            "ufw",
            &["status"],
            CommandOutput {
                stdout: "Status: inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "nft",
            &["list", "ruleset"],
            CommandOutput {
                stdout: "table inet linux_hardener {\n\tchain input {\n\t\ttype filter hook input \
                          priority 0; policy drop;\n\t}\n}\n"
                    .to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
}

#[tokio::test]
async fn test_backend_selection_prefers_active_nftables_over_inactive_ufw() {
    let executor = ufw_inactive_nftables_active_executor();
    let ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = FirewallHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    assert!(result.scan_success, "scan should succeed");
    let disabled_findings: Vec<_> = result
        .scan_findings
        .iter()
        .filter(|f| f.finding_title.to_lowercase().contains("disabled"))
        .collect();
    assert!(
        disabled_findings.is_empty(),
        "the active nftables backend should be selected over the installed-but-inactive \
         ufw backend, but got findings: {:?}",
        disabled_findings
            .iter()
            .map(|f| &f.finding_id)
            .collect::<Vec<_>>()
    );

    // Confirm nftables, not just ufw, was actually probed for its ruleset.
    let log = executor.log();
    assert!(
        log.commands_executed
            .iter()
            .any(|(cmd, args)| cmd == "nft" && args == &["list".to_string(), "ruleset".to_string()]),
        "nftables should have been probed for an active ruleset, commands: {:?}",
        log.commands_executed
    );
}

/// Both ufw and nftables are installed and would report active if probed;
/// the existing priority order (firewalld > ufw > nftables) must still
/// decide the winner once an active backend is found, without probing the
/// lower-priority candidates.
fn ufw_active_nftables_also_present_executor() -> MockExecutor {
    MockExecutor::new()
        .with_command_exists("ufw", true)
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("nft", true)
        .with_command(
            "systemctl",
            &["is-active", "ufw"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        // ufw's own answer, which is what is_enabled asks now. An active unit
        // is not proof the rules are loaded: Debian's unit reports active with
        // ENABLED=no and no ruleset at all.
        .with_command(
            "ufw",
            &["status"],
            CommandOutput {
                stdout: "Status: active
"
                .to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "nft",
            &["list", "ruleset"],
            CommandOutput {
                stdout: "table inet linux_hardener {\n\tchain input {\n\t\ttype filter hook input \
                          priority 0; policy drop;\n\t}\n}\n"
                    .to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
}

#[tokio::test]
async fn test_backend_selection_keeps_priority_order_when_ufw_active() {
    let executor = ufw_active_nftables_also_present_executor();
    let ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = FirewallHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();
    assert!(result.scan_success, "scan should succeed");

    let log = executor.log();
    assert!(
        log.commands_executed
            .iter()
            .any(|(cmd, args)| cmd == "ufw" && args == &["status".to_string()]),
        "ufw should be probed first per the existing priority order"
    );
    assert!(
        log.commands_executed.iter().any(|(cmd, _)| cmd == "nft"),
        "nftables should be probed to classify all installed backends, \
         commands: {:?}",
        log.commands_executed
    );
}

/// Neither ufw nor nftables is active. Selection must fall back to the
/// existing installed-order behaviour (first detected in priority order),
/// which is ufw here since firewalld is absent.
fn ufw_inactive_nftables_inactive_executor() -> MockExecutor {
    MockExecutor::new()
        .with_command_exists("ufw", true)
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("nft", true)
        .with_command(
            "systemctl",
            &["is-active", "ufw"],
            CommandOutput {
                stdout: "inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 3,
            },
        )
        // What a genuinely inactive host answers. is_enabled asks ufw rather
        // than systemd now, so a fixture answering only systemctl would stand
        // for a host where `ufw status` cannot run at all, which is a third
        // state and not the one these tests are about.
        .with_command(
            "ufw",
            &["status"],
            CommandOutput {
                stdout: "Status: inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "nft",
            &["list", "ruleset"],
            CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
}

#[tokio::test]
async fn test_backend_selection_falls_back_to_first_installed_when_none_active() {
    let executor = ufw_inactive_nftables_inactive_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = FirewallHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();
    assert!(result.scan_success, "scan should succeed");

    let disabled = result
        .scan_findings
        .iter()
        .find(|f| f.finding_title.to_lowercase().contains("disabled"))
        .expect("should report a disabled finding when nothing is active");
    assert_eq!(
        disabled.finding_id, "ufw-disabled",
        "with nothing active, fallback should keep the existing installed-order priority \
         (ufw before nftables)"
    );
}

// --- nftables activity heuristic: a bare `table` is not sufficient evidence
// of an active packet filter. Docker, libvirt, and iptables-nft all create
// their own nftables tables (NAT/routing) even when the admin's intended
// firewall is ufw or firewalld; only a chain that hooks input counts as
// "enabled". ---

#[tokio::test]
async fn test_nftables_is_enabled_requires_input_hook_not_bare_table() {
    use hardener_plugins::firewall::FirewallBackend;
    use hardener_plugins::firewall::nftables::NftablesBackend;

    // Docker-style NAT table only: no chain hooks input.
    let executor = MockExecutor::new().with_command(
        "nft",
        &["list", "ruleset"],
        CommandOutput {
            stdout: "table ip docker0 {\n\tchain POSTROUTING {\n\t\ttype nat hook postrouting \
                      priority 100;\n\t}\n}\n"
                .to_string(),
            stderr: String::new(),
            exit_code: 0,
        },
    );
    let ctx = Context::with_executor(Arc::new(executor));
    let backend = NftablesBackend::new();

    assert!(
        backend.is_enabled(&ctx).await.is_err(),
        "a docker/libvirt-style NAT table with no input hook must not count as an active \
         firewall"
    );
}

#[tokio::test]
async fn test_nftables_is_enabled_true_with_input_hook_chain() {
    use hardener_plugins::firewall::FirewallBackend;
    use hardener_plugins::firewall::nftables::NftablesBackend;

    let executor = MockExecutor::new().with_command(
        "nft",
        &["list", "ruleset"],
        CommandOutput {
            stdout: "table inet linux_hardener {\n\tchain input {\n\t\ttype filter hook input \
                      priority 0; policy drop;\n\t}\n}\n"
                .to_string(),
            stderr: String::new(),
            exit_code: 0,
        },
    );
    let ctx = Context::with_executor(Arc::new(executor));
    let backend = NftablesBackend::new();

    assert!(
        backend.is_enabled(&ctx).await.is_ok(),
        "a ruleset with an input-hook chain must count as an active firewall"
    );
}

/// ufw is installed but inactive, and nftables owns only a docker-style NAT
/// table (no input-hook chain). This mirrors a host running Docker with the
/// admin's intended firewall (ufw) switched off: selection must not mistake
/// docker's table for an active firewall and must still report ufw disabled.
fn ufw_inactive_nftables_docker_table_only_executor() -> MockExecutor {
    MockExecutor::new()
        .with_command_exists("ufw", true)
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("nft", true)
        .with_command(
            "systemctl",
            &["is-active", "ufw"],
            CommandOutput {
                stdout: "inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 3,
            },
        )
        // What a genuinely inactive host answers. is_enabled asks ufw rather
        // than systemd now, so a fixture answering only systemctl would stand
        // for a host where `ufw status` cannot run at all, which is a third
        // state and not the one these tests are about.
        .with_command(
            "ufw",
            &["status"],
            CommandOutput {
                stdout: "Status: inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "nft",
            &["list", "ruleset"],
            CommandOutput {
                stdout: "table ip docker0 {\n\tchain POSTROUTING {\n\t\ttype nat hook \
                          postrouting priority 100;\n\t}\n}\n"
                    .to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
}

#[tokio::test]
async fn test_backend_selection_ignores_docker_style_nat_table_falls_back_to_ufw() {
    let executor = ufw_inactive_nftables_docker_table_only_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = FirewallHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();
    assert!(result.scan_success, "scan should succeed");

    let disabled = result
        .scan_findings
        .iter()
        .find(|f| f.finding_title.to_lowercase().contains("disabled"))
        .expect(
            "a docker-owned NAT table must not suppress the disabled finding; nftables \
             should not be considered active",
        );
    assert_eq!(
        disabled.finding_id, "ufw-disabled",
        "with only app-owned nftables tables present, fallback should keep the existing \
         installed-order priority (ufw before nftables)"
    );
}

// --- ufw rule mapping fixes: "established and related" is a stateful no-op
// for ufw, and the default-deny rule uses ufw's real syntax. ---

#[tokio::test]
async fn test_ufw_established_rule_is_skipped_not_executed() {
    let executor = ufw_apply_executor("22");
    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = FirewallHardeningPlugin::new();
    let config = PluginConfig::default();

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

    // Found by the rule it is about rather than by being the first Skipped
    // change in the list. It was the only one when this test was written, so
    // taking the first happened to work and pinned nothing: an apply now
    // records a no-op for an already-enabled backend and for a rule already in
    // force, any of which would satisfy a bare "some change was skipped".
    let skipped = result
        .apply_changes
        .iter()
        .find(|c| {
            c.change_type == ChangeType::Skipped
                && c.change_description
                    .starts_with("Allow established and related connections")
        })
        .expect("established/related rule should be recorded as a Skipped change for ufw");
    assert!(
        skipped.change_success,
        "a stateful no-op is not an apply failure"
    );
    assert!(
        skipped
            .change_description
            .to_lowercase()
            .contains("connection state"),
        "skipped change should explain ufw tracks connection state implicitly, got: {}",
        skipped.change_description
    );

    // The mock has no response registered for a bare `ufw allow` (the old,
    // wrong mapping for this rule). If the plugin regressed and still tried
    // to run it, apply_success would already be false above; double-check
    // no such command was issued at all.
    let log = executor.log();
    assert!(
        !log.commands_executed
            .iter()
            .any(|(cmd, args)| cmd == "ufw" && args == &["allow".to_string()]),
        "ufw should never receive a bare 'allow' for the established/related rule, commands: {:?}",
        log.commands_executed
    );
}

#[tokio::test]
async fn test_ufw_drop_default_rule_uses_default_deny_incoming() {
    let executor = ufw_apply_executor("22");
    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = FirewallHardeningPlugin::new();
    let config = PluginConfig::default();

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

    let log = executor.log();
    assert!(
        log.commands_executed.iter().any(|(cmd, args)| {
            cmd == "ufw"
                && args
                    == &[
                        "default".to_string(),
                        "deny".to_string(),
                        "incoming".to_string(),
                    ]
        }),
        "the default-deny-inbound rule should map to `ufw default deny incoming`, commands: {:?}",
        log.commands_executed
    );
}

// --- nftables apply, atomic-load design (issue #92): `apply_rules` diffs
// against the live chain first, purely to classify each rule as Skipped or
// FirewallRule, then writes the whole rendered ruleset to
// `/etc/nftables.conf` and loads it with a single `nft -f`. No per-rule
// `nft add rule` runs any more, so re-running apply cannot stack duplicate
// rules: the load replaces this plugin's own table outright every time. ---

/// A successful, empty-stdout nft command response.
fn nft_ok() -> CommandOutput {
    CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    }
}

/// Registers the `list chain` presence probe returning `chain_body`, plus the
/// single `nft -f` load of the plugin's own fragment that `apply_rules`
/// always issues after it, regardless of whether every rule the probe found
/// was already present (see `render_ruleset`'s doc comment: the table is
/// replaced outright, so loading the same scoped file again is idempotent and
/// the load is not gated on anything having changed). Also registers the
/// `systemctl show` probe both `checkpoint_paths` and `apply_rules` itself run
/// (naming the Arch/Debian boot file, `/etc/nftables.conf`), and a
/// program-level `mkdir` response covering both directories `apply_rules`
/// creates, since their exact arguments vary with the boot path a fixture
/// names.
fn nft_apply_base(chain_body: &str) -> MockExecutor {
    MockExecutor::new()
        .with_command(
            "nft",
            &["list", "chain", "inet", "linux_hardener", "input"],
            CommandOutput {
                stdout: chain_body.to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &[
                "show",
                "nftables.service",
                "-p",
                "ExecStart",
                "-p",
                "ConditionPathExists",
            ],
            CommandOutput {
                stdout: "ExecStart={ path=/usr/sbin/nft ; argv[]=/usr/sbin/nft -f /etc/nftables.conf }\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command_program("mkdir", nft_ok())
        .with_command(
            "nft",
            &["-f", "/etc/linux-hardener/nftables/50-linux-hardener.nft"],
            nft_ok(),
        )
        .with_command(
            "nft",
            &[
                "--check",
                "--file",
                "/run/linux-hardener-nftables-check.nft",
            ],
            nft_ok(),
        )
        .with_command(
            "rm",
            &["-f", "/run/linux-hardener-nftables-check.nft"],
            nft_ok(),
        )
}

/// An `nft list chain` body for the plugin's own input chain, with no rules.
const NFT_EMPTY_CHAIN: &str = "table inet linux_hardener {\n\tchain input {\n\t\ttype filter hook input priority 0; policy drop;\n\t}\n}\n";

/// True if the command log contains an `nft add rule ...` invocation.
fn logged_nft_add_rule(executor: &MockExecutor) -> bool {
    executor.log().commands_executed.iter().any(|(cmd, args)| {
        cmd == "nft"
            && args.first().map(String::as_str) == Some("add")
            && args.get(1).map(String::as_str) == Some("rule")
    })
}

/// The rendered ruleset `apply_rules` wrote to its own fragment,
/// `/etc/linux-hardener/nftables/50-linux-hardener.nft`, or a panic naming
/// what is missing: every test using this expects the write to have
/// happened. Not `/etc/nftables.conf` any more: that file, the boot path on
/// Arch and Debian, now gains only the include line, and the administrator's
/// own content in it must survive untouched (issue #98).
fn written_ruleset(executor: &MockExecutor) -> String {
    executor
        .files()
        .get(Path::new(
            "/etc/linux-hardener/nftables/50-linux-hardener.nft",
        ))
        .cloned()
        .expect("apply_rules must write the rendered ruleset to its own fragment")
}

/// A source `nft` cannot match on stops the apply at the host's edge: nothing
/// is written and nothing is loaded.
///
/// The unit tests pin that `render_ruleset` returns `Err`; only this pins that
/// `apply_rules` acts on it. Turning the `?` at that call site into
/// `unwrap_or_default()` left every unit test green while writing an EMPTY
/// ruleset to the boot path and loading it, which replaces the file
/// `nftables.service` reads and leaves no baseline rule in force.
#[tokio::test]
async fn an_unmatchable_source_writes_and_loads_nothing() {
    use hardener_plugins::firewall::nftables::NftablesBackend;
    use hardener_plugins::firewall::{FirewallBackend, Rule};

    // Registered so both would SUCCEED if issued. The assertions are then what
    // refuse them, rather than the mock refusing an unregistered command.
    let executor = nft_apply_base(NFT_EMPTY_CHAIN);
    let ctx = Context::with_executor(Arc::new(executor.clone()));
    let backend = NftablesBackend::new();

    let mut rules = backend.get_default_rules();
    rules.push(Rule {
        rule_description: "Allow HTTPS from a source nft cannot read".to_string(),
        rule_protocol: "tcp".to_string(),
        rule_port: "443".to_string(),
        rule_source: "not-an-address".to_string(),
        rule_action: "accept".to_string(),
    });

    let refusal = backend.apply_rules(&ctx, &rules).await;

    assert!(
        refusal.is_err(),
        "an unmatchable source must fail the whole backend, got: {refusal:?}"
    );
    assert!(
        !executor
            .files()
            .contains_key(Path::new("/etc/nftables.conf")),
        "nothing may be written to the boot path when the ruleset was refused"
    );
    assert!(
        !executor
            .log()
            .commands_executed
            .iter()
            .any(|(command, args)| command == "nft"
                && args.first().map(String::as_str) == Some("-f")),
        "nft must not be asked to load a ruleset that was refused, got: {:?}",
        executor.log().commands_executed
    );
}

/// Was `test_nftables_apply_ensures_chain_then_adds_all_rules_when_empty`
/// before the atomic-load rewrite (issue #92) retired the per-rule `nft add
/// rule` path it pinned. Its intent survives unchanged - every baseline rule
/// must reach the host against an empty chain - only the evidence moves from
/// individual commands to the written file's contents.
#[tokio::test]
async fn test_nftables_apply_ensures_chain_then_adds_all_rules_when_empty() {
    use hardener_plugins::firewall::FirewallBackend;
    use hardener_plugins::firewall::nftables::NftablesBackend;

    let executor = nft_apply_base(NFT_EMPTY_CHAIN);
    let ctx = Context::with_executor(Arc::new(executor.clone()));
    let backend = NftablesBackend::new();

    let changes = backend
        .apply_rules(&ctx, &backend.get_default_rules())
        .await
        .unwrap();

    // Empty chain: all four baseline rules are absent, so all four are added
    // and nothing is skipped.
    assert_eq!(
        changes
            .iter()
            .filter(|c| c.change_type == ChangeType::FirewallRule && c.change_success)
            .count(),
        4,
        "every baseline rule should be added against an empty chain, got: {changes:?}"
    );
    assert!(
        changes.iter().all(|c| c.change_type != ChangeType::Skipped),
        "nothing should be skipped when the chain is empty"
    );

    // The classification above is a promise about intent; this is the proof
    // the rule actually reached the host. `build_nft_rule_args` is
    // crate-private, so these four statements are spelled out rather than
    // derived; they are pinned against the real builder by the unit tests in
    // `crates/hardener-plugins/src/firewall/tests.rs`
    // (`every_baseline_rule_renders_the_statement_the_argv_builder_produces`).
    // Matched as whole lines. `contains` over the blob could not fail for the
    // drop-all rule, whose entire statement is the bare string `drop`: the
    // chain header `type filter hook input priority 0; policy drop;` contains
    // it, so the assertion held whether or not the rule rendered at all. That
    // is the defect issue #96 was filed for, and it was still here.
    let ruleset = written_ruleset(&executor);
    let lines: Vec<&str> = ruleset.lines().map(str::trim).collect();
    for statement in [
        "iif lo accept",
        "ct state established,related accept",
        "tcp dport 22 accept",
        "drop",
    ] {
        assert!(
            lines.contains(&statement),
            "the baseline rule rendered as {statement:?} must reach the written \
             file as a statement of its own: ruleset\n{ruleset}"
        );
    }
}

/// Keeps the Skipped-classification half of the test this replaced; the
/// command-level assertion it also made (no `nft add rule` ran) no longer
/// applies now that no code path issues that command at all, per-rule or
/// otherwise. The load itself still runs unconditionally even though nothing
/// changed: loading the same scoped file again is idempotent, so this is not
/// gated on anything having changed, and that is deliberate rather than an
/// oversight.
#[tokio::test]
async fn test_nftables_apply_skips_all_rules_already_present() {
    use hardener_plugins::firewall::FirewallBackend;
    use hardener_plugins::firewall::nftables::NftablesBackend;

    // Canonical nft output: `iif "lo"` is quoted and established uses the
    // comma-joined state list; the presence check must tolerate both.
    let full_chain = "table inet linux_hardener {\n\tchain input {\n\t\t\
        type filter hook input priority 0; policy drop;\n\t\t\
        iif \"lo\" accept\n\t\tct state established,related accept\n\t\t\
        tcp dport 22 accept\n\t\tdrop\n\t}\n}\n";
    let executor = nft_apply_base(full_chain);
    let ctx = Context::with_executor(Arc::new(executor.clone()));
    let backend = NftablesBackend::new();

    let changes = backend
        .apply_rules(&ctx, &backend.get_default_rules())
        .await
        .unwrap();

    assert_eq!(
        changes
            .iter()
            .filter(|c| c.change_type == ChangeType::Skipped)
            .count(),
        4,
        "every already-present rule must be a Skipped change, got: {changes:?}"
    );
    assert!(
        changes.iter().all(|c| c.change_success),
        "an already-present rule is not an apply failure"
    );
}

/// Keeps the classification half of the test this replaced (a mixed chain
/// must split Skipped/FirewallRule correctly); drops the per-command
/// assertions, since which specific `nft add rule` ran or did not is no
/// longer a question this design has an answer to.
#[tokio::test]
async fn test_nftables_apply_adds_only_missing_rules() {
    use hardener_plugins::firewall::FirewallBackend;
    use hardener_plugins::firewall::nftables::NftablesBackend;

    // loopback + ssh already present; established + drop are missing.
    let partial_chain = "table inet linux_hardener {\n\tchain input {\n\t\t\
        type filter hook input priority 0; policy drop;\n\t\t\
        iif \"lo\" accept\n\t\ttcp dport 22 accept\n\t}\n}\n";
    let executor = nft_apply_base(partial_chain);
    let ctx = Context::with_executor(Arc::new(executor.clone()));
    let backend = NftablesBackend::new();

    let changes = backend
        .apply_rules(&ctx, &backend.get_default_rules())
        .await
        .unwrap();

    assert_eq!(
        changes
            .iter()
            .filter(|c| c.change_type == ChangeType::Skipped)
            .count(),
        2,
        "loopback and ssh are present -> 2 skipped, got: {changes:?}"
    );
    assert_eq!(
        changes
            .iter()
            .filter(|c| c.change_type == ChangeType::FirewallRule && c.change_success)
            .count(),
        2,
        "established and drop are missing -> 2 added, got: {changes:?}"
    );
}

// --- The atomic-load wiring for issue #92: `apply_rules` now writes the
// whole ruleset and loads it in a single `nft -f`, replacing the per-rule
// `nft add rule` loop the four tests above used to pin. Those four were
// rewritten against the new path rather than left red; the two tests below
// prove the properties the per-rule loop took with it when it went. ---

/// The atomic-load guarantee for issue #92, proven at the wiring layer: no
/// per-rule `nft add rule` may run alongside `apply_rules`' single `nft -f`
/// load, or a remote apply is back to two writes an interruption can land
/// between, which is the exact window the render-then-load design exists to
/// close.
#[tokio::test]
async fn apply_rules_never_issues_a_per_rule_add() {
    use hardener_plugins::firewall::FirewallBackend;
    use hardener_plugins::firewall::nftables::NftablesBackend;

    // A mix of present and absent rules, so a reintroduced per-rule path has
    // both something to add and something to skip; deliberately no `add
    // rule` command is registered, so any attempt logs before this mock
    // refuses it.
    let partial_chain = "table inet linux_hardener {\n\tchain input {\n\t\t\
        type filter hook input priority 0; policy drop;\n\t\t\
        iif \"lo\" accept\n\t\ttcp dport 22 accept\n\t}\n}\n";
    let executor = nft_apply_base(partial_chain);
    let ctx = Context::with_executor(Arc::new(executor.clone()));
    let backend = NftablesBackend::new();

    backend
        .apply_rules(&ctx, &backend.get_default_rules())
        .await
        .expect("the single `nft -f` load is registered and must succeed");

    assert!(
        !logged_nft_add_rule(&executor),
        "no per-rule `nft add rule` may run alongside the single-transaction load, \
         commands: {:?}",
        executor.log().commands_executed
    );
}

/// The diff-before-load classification, proven independently of whether any
/// `nft add rule` runs: a rule already in the chain must be reported Skipped
/// and a rule that is not must be reported FirewallRule, exactly as the old
/// per-rule path classified them, or `ApplyResult::applied_change_count()`
/// starts counting rules that changed nothing.
#[tokio::test]
async fn apply_rules_reports_skipped_only_for_rules_already_present() {
    use hardener_plugins::firewall::FirewallBackend;
    use hardener_plugins::firewall::nftables::NftablesBackend;

    // loopback + ssh already present; established + drop are missing.
    let partial_chain = "table inet linux_hardener {\n\tchain input {\n\t\t\
        type filter hook input priority 0; policy drop;\n\t\t\
        iif \"lo\" accept\n\t\ttcp dport 22 accept\n\t}\n}\n";
    let executor = nft_apply_base(partial_chain);
    let ctx = Context::with_executor(Arc::new(executor.clone()));
    let backend = NftablesBackend::new();

    let changes = backend
        .apply_rules(&ctx, &backend.get_default_rules())
        .await
        .expect("the single `nft -f` load is registered and must succeed");

    assert_eq!(
        changes
            .iter()
            .filter(|c| c.change_type == ChangeType::Skipped)
            .count(),
        2,
        "loopback and ssh are present -> 2 skipped, got: {changes:?}"
    );
    assert_eq!(
        changes
            .iter()
            .filter(|c| c.change_type == ChangeType::FirewallRule && c.change_success)
            .count(),
        2,
        "established and drop are missing -> 2 added, got: {changes:?}"
    );
}

/// Was the regression test for the ENOENT bug `ensure_managed_chain` fixed:
/// a foreign table already carrying a `hook input` chain made `is_enabled`
/// believe a filter was active, so `enable()` was skipped while this
/// plugin's own table still did not exist. That bug and its
/// fix are both gone now that the atomic load creates the table as part of
/// the same transaction regardless of what other tables already exist, so
/// this is repurposed as finding 1's regression test instead: the exact
/// fixture that used to prove a foreign table's presence did not break rule
/// application now proves a foreign table's presence is left alone by it.
/// A whole-ruleset flush would destroy the foreign table below, taking
/// whatever subsystem owns it (docker, libvirt, iptables-nft) down with it;
/// a future edit that reintroduced one must go red here.
#[tokio::test]
async fn test_nftables_plugin_apply_ensures_chain_when_foreign_hook_input_present() {
    let foreign_ruleset = "table ip foreign {\n\tchain input {\n\t\t\
        type filter hook input priority 0; policy accept;\n\t}\n}\n";
    let executor = MockExecutor::new()
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("ufw", false)
        .with_command_exists("nft", true)
        .with_command(
            "nft",
            &["list", "ruleset"],
            CommandOutput {
                stdout: foreign_ruleset.to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        // The boot half of the question, asked of every backend that is already
        // running. This host's unit is wanted at boot, so the apply has nothing
        // to repair and this test stays about the ruleset.
        .with_command(
            "systemctl",
            &["is-enabled", "nftables"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        // The pre-apply checkpoint probes for the boot file before it captures
        // anything, and `apply_rules` probes it again for the same reason;
        // naming it here matches the `-f` load of the plugin's own fragment
        // and the generic `mkdir` response registered below.
        .with_command(
            "systemctl",
            &[
                "show",
                "nftables.service",
                "-p",
                "ExecStart",
                "-p",
                "ConditionPathExists",
            ],
            CommandOutput {
                stdout: "ExecStart={ path=/usr/sbin/nft ; argv[]=/usr/sbin/nft -f /etc/nftables.conf }\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command_program("mkdir", nft_ok())
        // No `list chain` for the plugin's own input chain is registered: its
        // table does not exist yet on this host, exactly as before, and the
        // atomic load must create it as part of the same transaction that
        // leaves the foreign table alone.
        .with_command(
            "nft",
            &["-f", "/etc/linux-hardener/nftables/50-linux-hardener.nft"],
            nft_ok(),
        )
        .with_command(
            "nft",
            &[
                "--check",
                "--file",
                "/run/linux-hardener-nftables-check.nft",
            ],
            nft_ok(),
        )
        .with_command(
            "rm",
            &["-f", "/run/linux-hardener-nftables-check.nft"],
            nft_ok(),
        );
    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = FirewallHardeningPlugin::new();

    let result = plugin
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert!(
        result.apply_success,
        "apply must succeed despite the foreign hook-input chain, failed: {:?}",
        result
            .apply_changes
            .iter()
            .filter(|c| !c.change_success)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        result
            .apply_changes
            .iter()
            .filter(|c| c.change_type == ChangeType::FirewallRule && c.change_success)
            .count(),
        4,
        "all four baseline rules must be added, changes: {:?}",
        result.apply_changes
    );

    let ruleset = written_ruleset(&executor);
    assert!(
        !ruleset.contains("flush ruleset"),
        "a whole-ruleset flush would destroy the foreign table this fixture \
         proves exists: ruleset\n{ruleset}"
    );
    // Asserted against the rendered file, whose only input is the rule slice,
    // so `foreign` could never appear here whatever the code did: the string
    // exists solely in this fixture's `nft list ruleset` stdout. Issue #96
    // names this assertion, and the docstring that used to claim it "proves a
    // foreign table's presence is left alone by it", as unkillable. What the
    // load leaves alone is proved by the delete naming exactly one table, which
    // `the_rendered_file_replaces_only_its_own_table` pins; the honest thing to
    // assert here is that the fixture's own table survives the render, which is
    // the delete list again. Kept as a statement about the delete, not the blob.
    assert!(
        !ruleset.contains("delete table ip foreign"),
        "the load must not delete the foreign table this fixture proves exists: \
         ruleset\n{ruleset}"
    );
}

/// The load is refused and the file it was rendered into is already on disk.
///
/// The write precedes the load, so this is the one failure mode of the single
/// transaction that leaves durable state behind: the plugin's own fragment,
/// `/etc/linux-hardener/nftables/50-linux-hardener.nft`, holds a ruleset the
/// kernel has just rejected, and the boot file already carries the include
/// line reaching it. Nothing in the suite reached either error branch of
/// write-then-load before this, which issue #96 lists among its remaining
/// gaps.
///
/// The assertion is deliberately that the file IS there. That is the honest
/// description of the state, and pinning it is what stops a future reader
/// assuming the apply is atomic all the way to the disk. Recovering it is the
/// pre-apply checkpoint's job, which `the_apply_checkpoints_the_path_its_backend_writes`
/// pins separately.
#[tokio::test]
async fn a_refused_load_leaves_the_rendered_file_on_disk() {
    use hardener_plugins::firewall::FirewallBackend;
    use hardener_plugins::firewall::nftables::NftablesBackend;

    let executor = MockExecutor::new()
        .with_command(
            "nft",
            &["list", "chain", "inet", "linux_hardener", "input"],
            CommandOutput {
                stdout: NFT_EMPTY_CHAIN.to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &[
                "show",
                "nftables.service",
                "-p",
                "ExecStart",
                "-p",
                "ConditionPathExists",
            ],
            CommandOutput {
                stdout: "ExecStart={ path=/usr/sbin/nft ; argv[]=/usr/sbin/nft -f /etc/nftables.conf }\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command_program("mkdir", nft_ok())
        // The check PASSES here and the load fails, which is deliberate: it is
        // the residual case `nft --check` cannot cover, where the parse is fine
        // and the kernel refuses the ruleset anyway. That is what keeps this
        // test about the write/load ordering rather than about the check.
        .with_command(
            "nft",
            &[
                "--check",
                "--file",
                "/run/linux-hardener-nftables-check.nft",
            ],
            nft_ok(),
        )
        .with_command(
            "rm",
            &["-f", "/run/linux-hardener-nftables-check.nft"],
            nft_ok(),
        )
        .with_command(
            "nft",
            &["-f", "/etc/linux-hardener/nftables/50-linux-hardener.nft"],
            CommandOutput {
                stdout: String::new(),
                stderr: "/etc/linux-hardener/nftables/50-linux-hardener.nft:4:19-19: Error: \
                         File exists\n"
                    .to_string(),
                exit_code: 1,
            },
        );
    let ctx = Context::with_executor(Arc::new(executor.clone()));
    let backend = NftablesBackend::new();

    let failure = backend
        .apply_rules(&ctx, &backend.get_default_rules())
        .await
        .expect_err("a refused load must fail the whole backend");

    assert!(
        failure.to_string().contains("File exists"),
        "the operator must be told what nft said, got: {failure}"
    );
    assert!(
        executor.files().contains_key(Path::new(
            "/etc/linux-hardener/nftables/50-linux-hardener.nft"
        )),
        "the write precedes the load, so a refused load leaves the rendered \
         file behind: that is the state, and it is pinned rather than wished \
         away"
    );
}

// --- Issue #98: apply writes beside the administrator's ruleset rather than
// over it. `nftables_host()`, `written_files()` and `logged_commands()` are
// this file's own helpers, not brief-imagined production accessors: neither
// `nftables_host()` nor `written_files()` existed before this section, so
// they are built here in the shape `nft_apply_base()` and `written_ruleset()`
// already established above. ---

/// A base mock for `apply_rules`' commands whose path never varies with the
/// boot file a test names: the pre-write `nft --check`/`rm` scratch dance,
/// an empty existing chain, the load of the plugin's own fragment, and the
/// live-only load `execute_nft_from_string` issues when persistence is not
/// achieved. A program-level `mkdir` response covers both directories
/// `apply_rules` creates, since their exact arguments vary with the boot path.
/// Each test still registers its own `systemctl show` answer, because that is
/// exactly the boot file this section is about.
fn nftables_host() -> MockExecutor {
    MockExecutor::new()
        .with_command(
            "nft",
            &["list", "chain", "inet", "linux_hardener", "input"],
            CommandOutput {
                stdout: NFT_EMPTY_CHAIN.to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "nft",
            &[
                "--check",
                "--file",
                "/run/linux-hardener-nftables-check.nft",
            ],
            nft_ok(),
        )
        .with_command(
            "rm",
            &["-f", "/run/linux-hardener-nftables-check.nft"],
            nft_ok(),
        )
        .with_command_program("mkdir", nft_ok())
        .with_command(
            "nft",
            &["-f", "/etc/linux-hardener/nftables/50-linux-hardener.nft"],
            nft_ok(),
        )
        .with_command(
            "nft",
            &["-f", "/run/linux-hardener-nftables-check.nft"],
            nft_ok(),
        )
}

/// Every file the mock currently holds, minus the `/run` scratch path.
///
/// Real `nft -f` plus `rm` never leaves that tmpfs entry behind, but the
/// mock's virtual filesystem does not model `rm` actually removing anything
/// it holds; `refuse_a_ruleset_nft_will_not_parse` writes it on every apply,
/// whichever way the write-vs-no-persistence branch below goes. Filtering it
/// out here is what keeps this a fair stand-in for "what a real host would
/// still have on disk" rather than an artefact of the mock's own limits.
fn written_files(executor: &MockExecutor) -> HashMap<PathBuf, String> {
    let mut files = executor.files();
    files.remove(Path::new("/run/linux-hardener-nftables-check.nft"));
    files
}

/// Each executed command as one string, the program followed by its joined
/// arguments, so a test can match a command line the way an operator would
/// read it in a shell history rather than a `(String, Vec<String>)` tuple.
fn logged_commands(executor: &MockExecutor) -> Vec<String> {
    executor
        .log()
        .commands_executed
        .into_iter()
        .map(|(program, args)| format!("{program} {}", args.join(" ")))
        .collect()
}

/// Issue #98. /etc/nftables.conf is a file distributions ship with content: on
/// Arch it is where the administrator's own `inet filter` table is defined. A
/// whole-file write deletes that definition, so their table is live in the
/// kernel and gone at the next boot, and nothing warns at apply time.
#[tokio::test]
async fn an_apply_never_replaces_the_administrators_ruleset() {
    use hardener_plugins::firewall::FirewallBackend;
    use hardener_plugins::firewall::nftables::NftablesBackend;

    let administrators = "#!/usr/bin/nft -f\n\
                          destroy table inet filter\n\
                          table inet filter {\n  chain input {\n    tcp dport 443 accept\n  }\n}\n";
    let executor = Arc::new(
        nftables_host()
            .with_command(
                "systemctl",
                &[
                    "show",
                    "nftables.service",
                    "-p",
                    "ExecStart",
                    "-p",
                    "ConditionPathExists",
                ],
                CommandOutput {
                    stdout: "ExecStart={ path=/usr/bin/nft ; argv[]=/usr/bin/nft -f \
                             /etc/nftables.conf }\n"
                        .to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            )
            .with_file("/etc/nftables.conf", administrators),
    );
    let ctx = Context::with_executor(executor.clone());

    NftablesBackend::new()
        .apply_rules(&ctx, &hardener_plugins::firewall::get_baseline_rules())
        .await
        .expect("the apply must succeed on a host with a packaged ruleset");

    let written = written_files(&executor);
    let boot = written
        .get(Path::new("/etc/nftables.conf"))
        .expect("the boot file gains the include line, so it is written");

    assert!(
        boot.contains("table inet filter"),
        "the administrator's table must survive the apply, got:\n{boot}"
    );
    assert!(
        boot.contains("tcp dport 443 accept"),
        "their rules must survive too, got:\n{boot}"
    );
    assert!(
        boot.contains("include \"/etc/linux-hardener/nftables/*.nft\""),
        "the boot file must reach our fragment, got:\n{boot}"
    );
    assert!(
        !boot.contains("table inet linux_hardener"),
        "our table belongs in our own file, not in theirs, got:\n{boot}"
    );

    let ours = written
        .get(Path::new(
            "/etc/linux-hardener/nftables/50-linux-hardener.nft",
        ))
        .expect("the rendered ruleset must be written to our own file");
    assert!(
        ours.contains("table inet linux_hardener"),
        "our file holds our table, got:\n{ours}"
    );
}

/// A second apply must not stack include lines. The file is read first and the
/// line added only when absent.
#[tokio::test]
async fn appending_the_include_line_is_idempotent() {
    use hardener_plugins::firewall::FirewallBackend;
    use hardener_plugins::firewall::nftables::NftablesBackend;

    let already = "#!/usr/bin/nft -f\n\
                   table inet filter {}\n\
                   include \"/etc/linux-hardener/nftables/*.nft\"\n";
    let executor = Arc::new(
        nftables_host()
            .with_command(
                "systemctl",
                &[
                    "show",
                    "nftables.service",
                    "-p",
                    "ExecStart",
                    "-p",
                    "ConditionPathExists",
                ],
                CommandOutput {
                    stdout: "ExecStart={ path=/usr/bin/nft ; argv[]=/usr/bin/nft -f \
                             /etc/nftables.conf }\n"
                        .to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            )
            .with_file("/etc/nftables.conf", already),
    );
    let ctx = Context::with_executor(executor.clone());

    NftablesBackend::new()
        .apply_rules(&ctx, &hardener_plugins::firewall::get_baseline_rules())
        .await
        .expect("a second apply must succeed");

    let written = written_files(&executor);
    if let Some(boot) = written.get(Path::new("/etc/nftables.conf")) {
        assert_eq!(
            boot.matches("include \"/etc/linux-hardener/nftables/*.nft\"")
                .count(),
            1,
            "a repeat apply must not stack include lines, got:\n{boot}"
        );
    }
}

/// openSUSE's boot file does not exist on a stock host: /etc/nftables holds
/// only osf/, and the unit is ConditionPathExists-gated on a rules/main.nft
/// nobody has created. write_file cannot create a missing parent, so the
/// directory has to be made first.
#[tokio::test]
async fn a_boot_file_that_does_not_exist_is_created_with_its_parent() {
    use hardener_plugins::firewall::FirewallBackend;
    use hardener_plugins::firewall::nftables::NftablesBackend;

    let executor = Arc::new(
        nftables_host()
            .with_command(
                "systemctl",
                &[
                    "show",
                    "nftables.service",
                    "-p",
                    "ExecStart",
                    "-p",
                    "ConditionPathExists",
                ],
                CommandOutput {
                    stdout: "ExecStart={ path=/usr/sbin/nft ; argv[]=/usr/sbin/nft flush \
                             ruleset; include \"/etc/nftables/rules/main.nft\" }\n\
                             ConditionPathExists=/etc/nftables/rules/main.nft\n"
                        .to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            )
            .with_path_exists("/etc/nftables/rules/main.nft", false),
    );
    let ctx = Context::with_executor(executor.clone());

    NftablesBackend::new()
        .apply_rules(&ctx, &hardener_plugins::firewall::get_baseline_rules())
        .await
        .expect("an absent boot file is created, not an error");

    let commands = logged_commands(&executor);
    assert!(
        commands
            .iter()
            .any(|c| c.contains("mkdir") && c.contains("/etc/nftables/rules")),
        "the boot file's parent must be created before it is written, got {commands:?}"
    );
    let written = written_files(&executor);
    let boot = written
        .get(Path::new("/etc/nftables/rules/main.nft"))
        .expect("the boot file must be created");
    assert!(boot.contains("include \"/etc/linux-hardener/nftables/*.nft\""));
}

/// A probe that cannot answer never guesses a path. The host is filtered now,
/// and nothing is written anywhere, our own fragment included: a fragment with
/// no include to reach it goes live the moment somebody repairs the unit.
#[tokio::test]
async fn an_unreadable_probe_hardens_live_and_persists_nothing() {
    use hardener_plugins::firewall::FirewallBackend;
    use hardener_plugins::firewall::nftables::NftablesBackend;

    let executor = Arc::new(nftables_host().with_command(
        "systemctl",
        &[
            "show",
            "nftables.service",
            "-p",
            "ExecStart",
            "-p",
            "ConditionPathExists",
        ],
        CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        },
    ));
    let ctx = Context::with_executor(executor.clone());

    let changes = NftablesBackend::new()
        .apply_rules(&ctx, &hardener_plugins::firewall::get_baseline_rules())
        .await
        .expect("the host is still hardened, so this is not an error");

    assert!(
        written_files(&executor).is_empty(),
        "nothing may be written when the boot file is unknown, got {:?}",
        written_files(&executor).keys().collect::<Vec<_>>()
    );
    assert!(
        changes
            .iter()
            .any(|c| c.change_description.contains("not persist")),
        "the operator must be told persistence did not happen, got {changes:?}"
    );
    assert!(
        logged_commands(&executor)
            .iter()
            .any(|c| c.starts_with("nft -f ")),
        "the ruleset is still loaded, so the host is filtered now"
    );
}

/// A remote apply that would sever its own session is refused, and the backend
/// is never asked to install anything.
///
/// The pure guard is asserted in the unit tests; this pins that `apply` calls
/// it and acts on the answer. Without it the guard could be deleted from the
/// apply path outright with every unit test still green, which is how the
/// checkpoint wiring was found unpinned earlier.
///
/// The fixture excepts `ssh` ALONE, so the ruleset still admits loopback and
/// established connections. A guard that only asked "does anything survive?"
/// waves this through, and over SSH the drop policy then goes live with nothing
/// admitting the connection it arrived on.
#[tokio::test]
async fn a_remote_apply_that_would_sever_its_own_session_installs_nothing() {
    // Every command an apply could reach is registered as succeeding, so the
    // refusal is the assertion's doing rather than the mock's.
    let executor = nft_apply_base(NFT_EMPTY_CHAIN)
        .remote()
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("ufw", false)
        .with_command_exists("nft", true)
        .with_command(
            "nft",
            &["list", "ruleset"],
            CommandOutput {
                stdout: NFT_EMPTY_CHAIN.to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-enabled", "nftables"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        );
    let mut ctx = Context::with_executor(Arc::new(executor.clone()));

    let result = FirewallHardeningPlugin::new()
        .apply(&mut ctx, &ssh_exception_config())
        .await
        .expect("the apply must return a result rather than an error");

    assert!(
        !result.apply_success,
        "an apply that would sever its own session must not report success"
    );
    assert!(
        result
            .apply_changes
            .iter()
            .any(|change| !change.change_success
                && change.change_description.contains("sever the connection")),
        "the operator must be told why, got: {:?}",
        result.apply_changes
    );
    assert!(
        !executor
            .files()
            .contains_key(Path::new("/etc/nftables.conf")),
        "nothing may be written to the boot path when the ruleset was refused"
    );
    assert!(
        !executor
            .log()
            .commands_executed
            .iter()
            .any(|(command, args)| command == "nft"
                && args.first().map(String::as_str) == Some("-f")),
        "nft must not be asked to load a ruleset the guard refused, got: {:?}",
        executor.log().commands_executed
    );
}

/// A ruleset `nft` will not parse never reaches the boot path.
///
/// The render-time refusal reads a `source` and nothing else, which is an
/// enumeration of the fields somebody thought of: a `port` reached the file as
/// the operator's own string until #99 renotated it, and the same shape returns
/// with any field this plugin later renders. Asking `nft --check` ends the
/// class, because the parser that would refuse the file at load time is the one
/// that judges it first.
///
/// The assertion is about the boot path, not about the error. Before this, a
/// ruleset that rendered and failed at `nft` had already replaced
/// `/etc/nftables.conf`, on a unit the same apply enabled.
#[tokio::test]
async fn a_ruleset_nft_refuses_never_reaches_the_boot_path() {
    use hardener_plugins::firewall::FirewallBackend;
    use hardener_plugins::firewall::nftables::NftablesBackend;

    let executor = MockExecutor::new()
        .with_command(
            "nft",
            &["list", "chain", "inet", "linux_hardener", "input"],
            CommandOutput {
                stdout: NFT_EMPTY_CHAIN.to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "nft",
            &[
                "--check",
                "--file",
                "/run/linux-hardener-nftables-check.nft",
            ],
            CommandOutput {
                stdout: String::new(),
                stderr: "/run/linux-hardener-nftables-check.nft:4:19-19: Error: syntax \
                         error, unexpected +\n"
                    .to_string(),
                exit_code: 1,
            },
        )
        .with_command(
            "rm",
            &["-f", "/run/linux-hardener-nftables-check.nft"],
            nft_ok(),
        )
        // Registered so it WOULD succeed if it were issued. The assertions are
        // then what refuse the write and the load, rather than the mock
        // refusing an unregistered command.
        .with_command("nft", &["-f", "/etc/nftables.conf"], nft_ok());
    let ctx = Context::with_executor(Arc::new(executor.clone()));
    let backend = NftablesBackend::new();

    let refusal = backend
        .apply_rules(&ctx, &backend.get_default_rules())
        .await
        .expect_err("a ruleset nft will not parse must fail the whole backend");

    assert!(
        refusal.to_string().contains("unexpected +"),
        "nft's own words must reach the operator, got: {refusal}"
    );
    assert!(
        !executor
            .files()
            .contains_key(Path::new("/etc/nftables.conf")),
        "the boot path must be untouched when the check refused the ruleset"
    );
    assert!(
        !executor
            .log()
            .commands_executed
            .iter()
            .any(|(command, args)| command == "nft"
                && args.first().map(String::as_str) == Some("-f")),
        "nft must not be asked to load a ruleset its own check refused, got: {:?}",
        executor.log().commands_executed
    );
    assert!(
        executor
            .log()
            .commands_executed
            .iter()
            .any(|(command, args)| command == "rm"
                && args.contains(&"/run/linux-hardener-nftables-check.nft".to_string())),
        "the scratch file must be removed whichever way the check went, got: {:?}",
        executor.log().commands_executed
    );
}

/// `enable` marks the unit to start at boot and does nothing else.
///
/// This function was rewritten by this branch, from four `nft` calls that built
/// a `policy drop` chain with no rules in it, into a single `systemctl enable`.
/// That chain running before `apply_rules` installed the accepts is the whole
/// of issue #92. No test reached the function at all, before or after: every
/// nftables fixture makes `is_enabled` succeed, so the apply takes the
/// already-enabled arm and never calls it. Issue #96 lists that gap too.
#[tokio::test]
async fn enabling_nftables_only_marks_the_unit_to_start_at_boot() {
    use hardener_plugins::firewall::FirewallBackend;
    use hardener_plugins::firewall::nftables::NftablesBackend;

    let executor = MockExecutor::new().with_command(
        "systemctl",
        &["enable", "nftables"],
        CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        },
    );
    let ctx = Context::with_executor(Arc::new(executor.clone()));

    NftablesBackend::new()
        .enable(&ctx)
        .await
        .expect("enabling the unit must succeed");

    let commands: Vec<String> = executor
        .log()
        .commands_executed
        .into_iter()
        .map(|(program, args)| format!("{program} {}", args.join(" ")))
        .collect();

    assert_eq!(
        commands,
        vec!["systemctl enable nftables".to_string()],
        "enable must issue exactly one command. A chain built here is live \
         before `apply_rules` has installed a single accept, which is issue \
         #92, and a `start` or an `enable --now` would load a ruleset that may \
         not have been written yet"
    );
}

/// A unit that refuses to be enabled is reported, not swallowed.
#[tokio::test]
async fn a_refused_enable_is_surfaced_with_systemd_own_words() {
    use hardener_plugins::firewall::FirewallBackend;
    use hardener_plugins::firewall::nftables::NftablesBackend;

    let executor = MockExecutor::new().with_command(
        "systemctl",
        &["enable", "nftables"],
        CommandOutput {
            stdout: String::new(),
            stderr: "Failed to enable unit: Unit file nftables.service does not exist.\n"
                .to_string(),
            exit_code: 1,
        },
    );
    let ctx = Context::with_executor(Arc::new(executor));

    let failure = NftablesBackend::new()
        .enable(&ctx)
        .await
        .expect_err("a refused enable must be an error");

    assert!(
        failure.to_string().contains("does not exist"),
        "systemd's own words must reach the operator, got: {failure}"
    );
}

/// The apply hands the SELECTED backend's own paths to the pre-apply
/// checkpoint, and the checkpoint captures them.
///
/// `checkpoint_paths` has three unit assertions about what each backend
/// declares, and until this nothing asserted that `apply` passes them to
/// anything. Emptying the list at the call site left the whole suite green
/// while the checkpoint captured nothing, which silently removes the only
/// stated remedy for the whole-file overwrite of `/etc/nftables.conf`
/// recorded as issue #98.
#[tokio::test]
async fn the_apply_checkpoints_the_path_its_backend_writes() {
    let executor = MockExecutor::new()
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("ufw", false)
        .with_command_exists("nft", true)
        .with_command(
            "nft",
            &["list", "ruleset"],
            CommandOutput {
                stdout: NFT_EMPTY_CHAIN.to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "nft",
            &["list", "chain", "inet", "linux_hardener", "input"],
            CommandOutput {
                stdout: NFT_EMPTY_CHAIN.to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-enabled", "nftables"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        // The probe checkpoint_paths runs before create_checkpoint_for_apply,
        // and apply_rules runs the same probe again before it writes; naming
        // it here matches both, so the assertions below still see
        // /etc/nftables.conf declared.
        .with_command(
            "systemctl",
            &[
                "show",
                "nftables.service",
                "-p",
                "ExecStart",
                "-p",
                "ConditionPathExists",
            ],
            CommandOutput {
                stdout: "ExecStart={ path=/usr/sbin/nft ; argv[]=/usr/sbin/nft -f /etc/nftables.conf }\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command_program("mkdir", nft_ok())
        .with_command(
            "nft",
            &["-f", "/etc/linux-hardener/nftables/50-linux-hardener.nft"],
            nft_ok(),
        )
        .with_command(
            "nft",
            &[
                "--check",
                "--file",
                "/run/linux-hardener-nftables-check.nft",
            ],
            nft_ok(),
        )
        .with_command(
            "rm",
            &["-f", "/run/linux-hardener-nftables-check.nft"],
            nft_ok(),
        );
    let mut ctx =
        Context::with_executor_and_checkpoint(Arc::new(executor), test_checkpoint_manager().await);

    let result = FirewallHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("the apply must not error");

    let checkpoint_id = result
        .apply_checkpoint_id
        .clone()
        .expect("an apply that reaches a backend must take a checkpoint");
    let (_, captured) = ctx
        .checkpoint_manager()
        .expect("the context carries a checkpoint manager")
        .get_checkpoint(&hardener_state::CheckpointId::new(checkpoint_id))
        .await
        .expect("the checkpoint just taken must be readable");

    let paths: Vec<String> = captured.iter().map(|file| file.file_path.clone()).collect();

    assert!(
        paths.iter().any(|path| path == "/etc/nftables.conf"),
        "the apply appends its include line to this file, so it must be \
         checkpointed too; a rollback restores it to exactly what the \
         administrator had, got {paths:?}"
    );
    assert!(
        !paths
            .iter()
            .any(|path| path.starts_with("/etc/ufw") || path.starts_with("/etc/firewalld")),
        "and it must carry no path another backend owns, because a row \
         recorded absent is an instruction to delete, got {paths:?}"
    );
}

/// fedora's container after one apply, measured 2026-07-30 from
/// `test-results/fedora.log`: 22/tcp is already in the zone's permanent port
/// list and the zone target is already DROP, because the run before it put
/// them there. `firewall-cmd` exits 0 for both commands anyway, printing
/// ALREADY_ENABLED for the port, so the exit status cannot tell an addition
/// from a no-op.
fn firewalld_already_hardened_executor() -> MockExecutor {
    let ok = CommandOutput {
        stdout: "success\n".to_string(),
        stderr: String::new(),
        exit_code: 0,
    };
    MockExecutor::new()
        .with_command_exists("firewall-cmd", true)
        .with_command(
            "firewall-cmd",
            &["--get-default-zone"],
            CommandOutput {
                stdout: "public\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        // The permanent state the apply is about to write into. Both readings
        // already hold the target values.
        .with_command(
            "firewall-cmd",
            &["--permanent", "--zone", "public", "--list-ports"],
            CommandOutput {
                stdout: "22/tcp\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "firewall-cmd",
            &["--permanent", "--zone", "public", "--get-target"],
            CommandOutput {
                stdout: "DROP\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        // Both write commands succeed on an already-hardened zone, which is
        // exactly why their exit status is not evidence of a change.
        .with_command(
            "firewall-cmd",
            &["--permanent", "--zone", "public", "--add-port", "22/tcp"],
            CommandOutput {
                stdout: "ALREADY_ENABLED: 22:tcp\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "firewall-cmd",
            &["--permanent", "--zone", "public", "--set-target=DROP"],
            ok.clone(),
        )
        .with_command("firewall-cmd", &["--reload"], ok)
}

#[tokio::test]
async fn firewalld_records_a_no_op_for_a_port_and_a_target_already_in_force() {
    use hardener_plugins::firewall::{FirewallBackend, firewalld::FirewalldBackend};

    let ctx = Context::with_executor(Arc::new(firewalld_already_hardened_executor()));
    let changes = FirewalldBackend::new()
        .apply_rules(&ctx, &hardener_plugins::firewall::get_baseline_rules())
        .await
        .expect("apply_rules must not fail on an already-hardened zone");

    let claimed_port = changes
        .iter()
        .any(|c| c.change_description.starts_with("Added port") && !c.is_skipped());
    assert!(
        !claimed_port,
        "22/tcp was already in the zone's permanent port list, so nothing added it: {:?}",
        changes
    );

    let claimed_target = changes
        .iter()
        .any(|c| c.change_description.starts_with("Set zone") && !c.is_skipped());
    assert!(
        !claimed_target,
        "the zone target was already DROP, so nothing set it: {:?}",
        changes
    );

    let applied = changes.iter().filter(|c| !c.is_skipped()).count();
    assert_eq!(
        applied, 0,
        "an already-hardened firewalld zone needs no changes at all, and a count \
         above zero is what the renderer prints as 'N change(s) applied': {:?}",
        changes
    );

    // The three assertions above all pass if the rules vanish entirely, because
    // each of them asserts the absence of a wrong claim. Proved by mutation
    // during review: making the drop-rule predicate `false` dropped that rule
    // silently and the test stayed green. A no-op has to be reported, not just
    // not-misreported.
    let no_ops: Vec<&str> = changes
        .iter()
        .filter(|c| c.is_skipped())
        .map(|c| c.change_description.as_str())
        .collect();
    assert!(
        no_ops
            .iter()
            .any(|d| d.contains("Port 22/tcp is already allowed")),
        "the port already in force must be named as a no-op: {:?}",
        changes
    );
    assert!(
        no_ops
            .iter()
            .any(|d| d.contains("default target is already DROP")),
        "the zone target already in force must be named as a no-op: {:?}",
        changes
    );
}

/// The debian container on a second apply, measured 2026-07-30 from
/// `test-results/debian.log`: every baseline rule is already in force because
/// the run before it put them there. ufw reports that itself, printing
/// "Skipping adding existing rule" and exiting 0, and the default incoming
/// policy is already deny, which `ufw status verbose` states in its Default
/// line. The tool reported "3 change(s) applied" all the same.
fn ufw_already_hardened_executor() -> MockExecutor {
    let already_there = CommandOutput {
        stdout: "Skipping adding existing rule\nSkipping adding existing rule (v6)\n".to_string(),
        stderr: String::new(),
        exit_code: 0,
    };
    MockExecutor::new()
        .with_command_exists("ufw", true)
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("nft", false)
        .with_command(
            "ufw",
            &["status", "verbose"],
            CommandOutput {
                stdout: "Status: active\nLogging: on (low)\nDefault: deny (incoming), \
                         allow (outgoing), disabled (routed)\nNew profiles: skip\n\n\
                         To                         Action      From\n\
                         --                         ------      ----\n\
                         22/tcp                     ALLOW IN    Anywhere\n"
                    .to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "ufw",
            &["allow", "from", "127.0.0.1/8"],
            already_there.clone(),
        )
        .with_command(
            "ufw",
            &["allow", "to", "any", "port", "22", "proto", "tcp"],
            already_there,
        )
        // Registered so a backend that still runs it produces a clean applied
        // change rather than a spawn error: the defect is that it is reported,
        // not that it fails. ufw prints this whether or not the policy moved.
        .with_command(
            "ufw",
            &["default", "deny", "incoming"],
            CommandOutput {
                stdout: "Default incoming policy changed to 'deny'\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
}

#[tokio::test]
async fn ufw_records_a_no_op_for_rules_and_a_policy_already_in_force() {
    use hardener_plugins::firewall::{FirewallBackend, ufw::UfwBackend};

    let ctx = Context::with_executor(Arc::new(ufw_already_hardened_executor()));
    let changes = UfwBackend::new()
        .apply_rules(&ctx, &hardener_plugins::firewall::get_baseline_rules())
        .await
        .expect("apply_rules must not fail on an already-hardened host");

    let claimed_rule = changes
        .iter()
        .any(|c| c.change_description.starts_with("Added firewall rule") && !c.is_skipped());
    assert!(
        !claimed_rule,
        "ufw reported every baseline rule as already present, so nothing was added: {:?}",
        changes
    );

    let claimed_policy = changes
        .iter()
        .any(|c| c.change_description.contains("Drop all other inbound") && !c.is_skipped());
    assert!(
        !claimed_policy,
        "the default incoming policy was already deny, so nothing set it: {:?}",
        changes
    );

    let applied = changes.iter().filter(|c| !c.is_skipped()).count();
    assert_eq!(
        applied, 0,
        "an already-hardened ufw host needs no changes at all, and a count above \
         zero is what the renderer prints as 'N change(s) applied': {:?}",
        changes
    );

    // As in the firewalld sibling: everything above passes if a rule disappears
    // rather than being reported as already in force, so the no-ops are asserted
    // present rather than merely not-wrong.
    let no_ops: Vec<&str> = changes
        .iter()
        .filter(|c| c.is_skipped())
        .map(|c| c.change_description.as_str())
        .collect();
    assert!(
        no_ops
            .iter()
            .any(|d| d.contains("Firewall rule already present: Allow SSH to prevent lockout")),
        "a rule ufw reports as already present must be named as a no-op: {:?}",
        changes
    );
    assert!(
        no_ops.iter().any(|d| d.contains("already in force")),
        "the default incoming policy already in force must be named as a no-op: {:?}",
        changes
    );
}

/// debian's container before the first apply, measured 2026-07-30: ufw is
/// installed and reports inactive, so apply enables it. That enable is the
/// single most consequential thing the run does on such a host, taking it from
/// no firewall to a firewall.
fn ufw_needs_enabling_executor() -> MockExecutor {
    let ok = CommandOutput {
        stdout: "Rule added\n".to_string(),
        stderr: String::new(),
        exit_code: 0,
    };
    MockExecutor::new()
        .with_command_exists("ufw", true)
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("nft", false)
        .with_command(
            "ufw",
            &["status"],
            CommandOutput {
                stdout: "Status: inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "ufw",
            &["--force", "enable"],
            CommandOutput {
                stdout: "Firewall is active and enabled on system startup\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        // debian's packaging already wants the unit at boot, so systemd has
        // nothing to do and nothing to say. The enable is issued regardless,
        // because ufw itself never touches systemd on any distribution.
        .with_command(
            "systemctl",
            &["enable", "ufw"],
            CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "ufw",
            &["status", "verbose"],
            CommandOutput {
                stdout: "Status: active\nDefault: allow (incoming), allow (outgoing), \
                         disabled (routed)\n"
                    .to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command("ufw", &["allow", "from", "127.0.0.1/8"], ok.clone())
        .with_command(
            "ufw",
            &["allow", "to", "any", "port", "22", "proto", "tcp"],
            ok.clone(),
        )
        .with_command("ufw", &["default", "deny", "incoming"], ok)
}

#[tokio::test]
async fn enabling_the_firewall_is_recorded_as_a_change() {
    let executor = ufw_needs_enabling_executor();
    let mut ctx = Context::with_executor(Arc::new(executor.clone()));

    let result = FirewallHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .unwrap();

    // The enable did happen, so the question is only whether it was recorded.
    assert!(
        executor
            .log()
            .commands_executed
            .iter()
            .any(|(cmd, args)| cmd == "ufw"
                && args == &["--force".to_string(), "enable".to_string()]),
        "this fixture must reach the enable, or the assertion below proves nothing"
    );

    let recorded = result
        .apply_changes
        .iter()
        .find(|c| {
            c.change_description
                .to_lowercase()
                .contains("enabled the ufw firewall")
        })
        .expect(
            "turning the firewall on must appear in the record apply leaves behind, not \
             only in the log",
        );
    assert!(
        !recorded.is_skipped() && recorded.change_success,
        "enabling a firewall that was off is real work, not a no-op: {:?}",
        recorded
    );
    assert_eq!(
        recorded.change_type,
        ChangeType::Service,
        "starting and enabling a firewall's unit is a service state change, not a \
         firewall rule, and a renderer grouping by type reads this: {:?}",
        recorded
    );
}

#[tokio::test]
async fn a_firewall_that_was_already_enabled_is_recorded_as_a_no_op() {
    let mut ctx = Context::with_executor(Arc::new(ufw_apply_executor("22")));

    let result = FirewallHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .unwrap();

    let recorded = result
        .apply_changes
        .iter()
        .find(|c| c.change_description.contains("already enabled"))
        .expect("an already-enabled backend is a no-op worth naming, like the rules are");
    assert!(
        recorded.is_skipped() && recorded.change_success,
        "a backend that needed no enabling must not be counted as applied work: {:?}",
        recorded
    );
}

/// arch's container after the first apply, measured 2026-07-30: `ufw --force
/// enable` succeeded and printed its usual "enabled on system startup" line,
/// `/etc/ufw/ufw.conf` read `ENABLED=yes`, and yet after a reboot
/// `systemctl is-active ufw` read `inactive` and
/// `/etc/systemd/system/multi-user.target.wants/ufw.service` did not exist.
///
/// ufw's own code never touches systemd (`grep -rn systemctl` over ufw
/// 0.36.2-7's python sources returns nothing), so whether the unit is wanted at
/// boot is decided by the packaging alone: Debian's package enables it, Arch's
/// does not. The message ufw prints is about ufw's own `ENABLED=yes` flag, not
/// about the unit, so it cannot be read as boot persistence.
fn ufw_unit_not_enabled_at_boot_executor() -> MockExecutor {
    MockExecutor::new()
        .with_command(
            "ufw",
            &["--force", "enable"],
            CommandOutput {
                stdout: "Firewall is active and enabled on system startup\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["enable", "ufw"],
            CommandOutput {
                stdout: String::new(),
                stderr: "Created symlink \
                         /etc/systemd/system/multi-user.target.wants/ufw.service.\n"
                    .to_string(),
                exit_code: 0,
            },
        )
}

#[tokio::test]
async fn enabling_ufw_also_wants_its_unit_at_boot() {
    let executor = ufw_unit_not_enabled_at_boot_executor();
    let ctx = Context::with_executor(Arc::new(executor.clone()));
    use hardener_plugins::firewall::FirewallBackend;
    let backend = hardener_plugins::firewall::ufw::UfwBackend::new();

    backend
        .enable(&ctx)
        .await
        .expect("both steps succeed in this fixture");

    assert!(
        executor.log().commands_executed.iter().any(|(cmd, args)| {
            cmd == "systemctl" && args == &["enable".to_string(), "ufw".to_string()]
        }),
        "`ufw --force enable` loads rules into the running kernel and writes ufw's own \
         ENABLED=yes; it never asks systemd to want the unit at boot. A host whose \
         packaging did not enable the unit loses its firewall at the next reboot while \
         apply reports it enabled, which is what arch measured. Commands run: {:?}",
        executor.log().commands_executed
    );
}

#[tokio::test]
async fn a_unit_that_cannot_be_enabled_fails_the_enable() {
    let executor = MockExecutor::new()
        .with_command(
            "ufw",
            &["--force", "enable"],
            CommandOutput {
                stdout: "Firewall is active and enabled on system startup\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["enable", "ufw"],
            CommandOutput {
                stdout: String::new(),
                stderr: "Failed to enable unit: Unit file ufw.service does not exist.\n"
                    .to_string(),
                exit_code: 1,
            },
        );
    let ctx = Context::with_executor(Arc::new(executor));
    use hardener_plugins::firewall::FirewallBackend;
    let backend = hardener_plugins::firewall::ufw::UfwBackend::new();

    let error = backend.enable(&ctx).await.expect_err(
        "a firewall that vanishes at the next reboot has not been enabled, and \
         reporting success for it is the defect arch measured",
    );

    assert!(
        error
            .to_string()
            .contains("Unit file ufw.service does not exist"),
        "the operator has to be told why the unit could not be enabled, so systemd's \
         own words belong in the error: {error}"
    );
}

/// debian's container, measured 2026-07-30: its packaging already enabled the
/// `ufw` unit, so the symlink is present and `systemctl is-active ufw` reads
/// active, while `/etc/ufw/ufw.conf` ships `ENABLED=no` and the kernel holds no
/// rules. The unit and the firewall are separate switches, and this fixture is
/// the half arch's is not.
fn ufw_unit_already_enabled_executor() -> MockExecutor {
    MockExecutor::new()
        .with_command(
            "ufw",
            &["--force", "enable"],
            CommandOutput {
                stdout: "Firewall is active and enabled on system startup\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        // What systemd answers for a unit it already wants at boot: exit 0 and
        // nothing to say, indistinguishable from the run that created the link.
        .with_command(
            "systemctl",
            &["enable", "ufw"],
            CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
}

#[tokio::test]
async fn the_unit_and_the_firewall_are_enabled_independently() {
    let executor = ufw_unit_already_enabled_executor();
    let ctx = Context::with_executor(Arc::new(executor.clone()));
    use hardener_plugins::firewall::FirewallBackend;
    let backend = hardener_plugins::firewall::ufw::UfwBackend::new();

    backend
        .enable(&ctx)
        .await
        .expect("both steps succeed in this fixture");

    let log = executor.log();
    assert!(
        log.commands_executed
            .iter()
            .any(|(cmd, args)| cmd == "ufw"
                && args == &["--force".to_string(), "enable".to_string()]),
        "a unit already wanted at boot says nothing about whether ufw is enforcing: \
         debian ships that exact host with ENABLED=no and an empty filter table. \
         Commands run: {:?}",
        log.commands_executed
    );
    assert!(
        log.commands_executed.iter().any(|(cmd, args)| {
            cmd == "systemctl" && args == &["enable".to_string(), "ufw".to_string()]
        }),
        "and neither does ufw's own enable say anything about the unit, so both \
         switches are thrown every time. Commands run: {:?}",
        log.commands_executed
    );
}

/// The arch container as apply finds it on a re-run, measured 2026-07-30: ufw
/// is enforcing, so `is_enabled` succeeds and the whole of `enable` is skipped,
/// and the unit that was never wanted at boot stays that way however many times
/// the tool is run. `state` is what `systemctl is-enabled ufw` answers.
///
/// Drives the preview half as well as the run half, which is why it is one
/// fixture and not two: two would prove that two similar hosts agree, not that
/// one host is described the same way by the dry run and by the apply.
fn ufw_active_with_unit_state_apply_executor(state: &str, exit_code: i32) -> MockExecutor {
    ufw_apply_executor("22")
        .with_command(
            "systemctl",
            &["is-enabled", "ufw"],
            CommandOutput {
                stdout: format!("{state}\n"),
                stderr: String::new(),
                exit_code,
            },
        )
        .with_command(
            "systemctl",
            &["enable", "ufw"],
            CommandOutput {
                stdout: String::new(),
                stderr: "Created symlink /etc/systemd/system/multi-user.target.wants/\
                         ufw.service.\n"
                    .to_string(),
                exit_code: 0,
            },
        )
}

fn logged_systemctl_enable_ufw(executor: &MockExecutor) -> bool {
    executor
        .log()
        .commands_executed
        .iter()
        .any(|(cmd, args)| cmd == "systemctl" && args == &["enable".to_string(), "ufw".to_string()])
}

#[tokio::test]
async fn a_running_firewall_whose_unit_is_disabled_is_repaired_by_apply() {
    let executor = ufw_active_with_unit_state_apply_executor("disabled", 1);
    let mut ctx = Context::with_executor(Arc::new(executor.clone()));

    let result = FirewallHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert!(
        logged_systemctl_enable_ufw(&executor),
        "apply skips `enable` entirely on a host whose firewall is already running, so \
         nothing ever asked systemd to want the unit at boot and a re-run could not \
         repair it. Commands run: {:?}",
        executor.log().commands_executed
    );
    let recorded = result
        .apply_changes
        .iter()
        .find(|c| c.change_description.contains("at boot"))
        .expect(
            "asking systemd to start the firewall at boot is real work and belongs in \
                 the record apply leaves behind",
        );
    assert!(
        !recorded.is_skipped() && recorded.change_success,
        "a unit that was not wanted at boot and now is has been changed, not skipped: {recorded:?}"
    );
    assert_eq!(
        recorded.change_type,
        ChangeType::Service,
        "wanting a unit at boot is a service state change, not a firewall rule: {recorded:?}"
    );
    assert!(
        result.apply_success,
        "the repair succeeded in this fixture: {:?}",
        result
            .apply_changes
            .iter()
            .filter(|c| !c.change_success)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn a_unit_already_wanted_at_boot_is_recorded_as_a_no_op() {
    let executor = ufw_active_with_unit_state_apply_executor("enabled", 0);
    let mut ctx = Context::with_executor(Arc::new(executor.clone()));

    let result = FirewallHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert!(
        !logged_systemctl_enable_ufw(&executor),
        "the unit is already enabled, so there is nothing to enable. Commands run: {:?}",
        executor.log().commands_executed
    );
    let recorded = result
        .apply_changes
        .iter()
        .find(|c| c.change_description.contains("at boot"))
        .expect("a setting already at its target is a no-op worth naming, as the rules are");
    assert!(
        recorded.is_skipped() && recorded.change_success,
        "a unit that needed no enabling must not be counted as applied work: {recorded:?}"
    );
}

/// The one word a boot line's two halves are allowed to differ in is its verb:
/// apply writes "Enabled ..." of work it has done and a preview writes
/// "Enable ..." of work it intends, the same tense split the enable pair beside
/// them already uses. Everything after that first space must match exactly.
///
/// Returns None rather than an empty string when there is no second word, so a
/// reworded line surfaces as a missing subject instead of as two silences that
/// happen to compare equal.
fn boot_subject_in(line: &str) -> Option<&str> {
    line.split_once(' ')
        .map(|(_verb, subject)| subject)
        .filter(|subject| !subject.is_empty())
}

/// What both halves must say about the unit, spelled as the baseline spells it.
const BOOT_SUBJECT: &str = "the ufw unit to start the firewall at boot";

/// The boot line in a list of descriptions, which is the only one of them that
/// mentions boot at all.
fn boot_line_in<'a>(mut lines: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    lines.find(|line| line.contains("at boot"))
}

#[tokio::test]
async fn the_preview_and_the_run_agree_that_a_unit_is_not_wanted_at_boot() {
    // apply pushes a boot change for every host whose firewall was already
    // running, and validate's verified-active arm never asked the boot question
    // at all, so the dry run previewed nothing for a line the run would write.
    // The preview omitting a change the run will make is the worse direction of
    // the two, because the preview is what the operator approves. fedora, rhel
    // and openSUSE all took that arm in the container runs of 2026-07-30, each
    // carrying a boot line no dry run would have shown.
    let executor = ufw_active_with_unit_state_apply_executor("disabled", 1);

    let mut apply_ctx = Context::with_executor(Arc::new(executor.clone()));
    let applied = FirewallHardeningPlugin::new()
        .apply(&mut apply_ctx, &PluginConfig::default())
        .await
        .unwrap();
    let validate_ctx = Context::with_executor(Arc::new(executor));
    let previewed = FirewallHardeningPlugin::new()
        .validate(&validate_ctx, &PluginConfig::default())
        .await
        .unwrap();

    let apply_line = boot_line_in(
        applied
            .apply_changes
            .iter()
            .map(|c| c.change_description.as_str()),
    )
    .expect("apply must record the boot enable it performs");
    let preview_line = boot_line_in(
        previewed
            .validation_report_estimated_changes
            .iter()
            .map(String::as_str),
    )
    .expect(
        "the preview must name the boot change the run makes, or an operator \
         approves a dry run that is one line short of the apply",
    );

    let apply_subject = boot_subject_in(apply_line).expect("apply's change must carry a subject");
    let preview_subject =
        boot_subject_in(preview_line).expect("the preview's line must carry a subject");

    assert_eq!(
        apply_subject, preview_subject,
        "the preview and the run must describe the same boot change the same way, \
         or an operator reading the dry run cannot match it to what the apply \
         reports.\n  apply:    {apply_line}\n  preview:  {preview_line}"
    );
    // Without this the assertion above passes on two subjects that are both
    // wrong in the same way, which a shared rewording would produce. Anchoring
    // to the baseline's own spelling is what stops equal-and-empty counting as
    // agreement.
    assert_eq!(
        apply_subject, BOOT_SUBJECT,
        "both halves must name the unit and say what enabling it buys, got: \
         {apply_line}"
    );

    // Order, because an operator compares the two lists by reading them down.
    // apply pushes its boot change before it walks the baseline, so the preview
    // that stands for it belongs before the rule estimate too.
    let apply_boot_index = applied
        .apply_changes
        .iter()
        .position(|c| c.change_description.contains("at boot"))
        .expect("found above");
    let apply_first_rule_index = applied
        .apply_changes
        .iter()
        .position(|c| c.change_type == ChangeType::FirewallRule)
        .expect("this host's baseline rules are all pending, so apply writes them");
    assert!(
        apply_boot_index < apply_first_rule_index,
        "the fixture the order is read from: apply enables the unit before it \
         applies any rule, got {:?}",
        applied
            .apply_changes
            .iter()
            .map(|c| c.change_description.as_str())
            .collect::<Vec<_>>()
    );
    let preview_boot_index = previewed
        .validation_report_estimated_changes
        .iter()
        .position(|c| c.contains("at boot"))
        .expect("found above");
    let preview_rule_index = previewed
        .validation_report_estimated_changes
        .iter()
        .position(|c| c.contains("baseline firewall rules"))
        .expect("the baseline rules are pending on this host, so the preview says so");
    assert!(
        preview_boot_index < preview_rule_index,
        "and the preview must list them in the order the run emits them, got: {:?}",
        previewed.validation_report_estimated_changes
    );
}

#[tokio::test]
async fn a_unit_already_wanted_at_boot_is_previewed_as_nothing_pending() {
    // The other side of the same host state. apply records a skipped no-op
    // here, and a preview line standing for a no-op would be counted: the
    // pending list's length is what a renderer prints as the change count.
    let executor = ufw_active_with_unit_state_apply_executor("enabled", 0);

    let mut apply_ctx = Context::with_executor(Arc::new(executor.clone()));
    let applied = FirewallHardeningPlugin::new()
        .apply(&mut apply_ctx, &PluginConfig::default())
        .await
        .unwrap();
    let validate_ctx = Context::with_executor(Arc::new(executor));
    let previewed = FirewallHardeningPlugin::new()
        .validate(&validate_ctx, &PluginConfig::default())
        .await
        .unwrap();

    // The run half is asserted to have spoken first, so the preview's silence
    // below is measured against a host that genuinely has a boot answer rather
    // than against one where neither half said anything.
    let recorded = applied
        .apply_changes
        .iter()
        .find(|c| c.change_description.contains("at boot"))
        .expect("apply names the no-op, which is what makes this host boot-relevant");
    assert!(
        recorded.is_skipped() && recorded.change_success,
        "a unit that needed no enabling is a no-op, not applied work: {recorded:?}"
    );

    // And the preview is asserted to have reached the arm under test, so its
    // silence is a considered nothing rather than a validate that produced
    // nothing at all.
    assert!(
        previewed
            .validation_report_estimated_changes
            .iter()
            .any(|c| c.contains("baseline firewall rules")),
        "this host's baseline rules are pending, so a preview that says nothing \
         about them never reached the verified-active arm: {:?}",
        previewed.validation_report_estimated_changes
    );
    assert!(
        previewed.validation_report_issues.is_empty(),
        "systemd answered the boot question on this host, so there is no \
         limitation to report: {:?}",
        previewed.validation_report_issues
    );

    assert!(
        boot_line_in(
            previewed
                .validation_report_estimated_changes
                .iter()
                .map(String::as_str)
        )
        .is_none(),
        "a unit already wanted at boot has no pending change, and a preview line \
         standing for a no-op inflates the count a renderer prints and the \
         `would_change` the fleet path sums: {:?}",
        previewed.validation_report_estimated_changes
    );
}

#[tokio::test]
async fn an_unreadable_boot_state_is_an_issue_rather_than_a_queued_change() {
    // `static` is the state that traps a probe reading exit codes: it exits 0
    // like `enabled` does, and it has no [Install] section, so the unit can be
    // neither enabled nor disabled while something else may still pull it in.
    // Neither "will start at boot" nor "will not" is true of this host, and the
    // preview has to say so rather than queue a write for it.
    let executor = ufw_active_with_unit_state_apply_executor("static", 0);
    let ctx = Context::with_executor(Arc::new(executor));
    let previewed = FirewallHardeningPlugin::new()
        .validate(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    let issue = previewed
        .validation_report_issues
        .iter()
        .find(|i| i.validation_issue_message.contains("boot"))
        .unwrap_or_else(|| {
            panic!(
                "an unanswered question is reported as unanswered, never passed \
                 over in silence: {:?}",
                previewed.validation_report_issues
            )
        });
    assert_eq!(
        issue.validation_issue_severity,
        Severity::Medium,
        "a limit on what this run could read is not a fault of the host, and \
         failing the dry run over it would fail it on every host in that \
         state: {issue:?}"
    );
    assert!(
        boot_line_in(
            previewed
                .validation_report_estimated_changes
                .iter()
                .map(String::as_str)
        )
        .is_none(),
        "the pending list is documented as genuinely pending changes, and its \
         length is what a renderer prints as the change count and what the fleet \
         path sums into `would_change`, so a line saying nothing is known must \
         not be counted as one queued write: {:?}",
        previewed.validation_report_estimated_changes
    );
}

/// The defect issue #37 was opened for, measured rather than argued.
///
/// This plugin used to assert that a privileged re-run would reach the ruleset
/// check, without ever asking whether it was already privileged. On an
/// unprivileged host that advice is right. On a privileged one it is a remedy
/// the operator has already applied, and whatever stopped the probe will stop
/// it again: `systemd-nspawn` grants `CAP_NET_ADMIN` only to a container with
/// its own network namespace, so a uid-0 container was told to try again as
/// root.
///
/// The two fixtures differ in one registered command, `id -u`, which is the
/// whole point: the observation the claim rests on is now made rather than
/// assumed.
#[tokio::test]
async fn a_root_session_blocked_from_the_ruleset_is_not_told_to_try_root() {
    let blocker_for = async |uid: &str| {
        let executor = ufw_permission_denied_executor().with_command(
            "id",
            &["-u"],
            CommandOutput {
                stdout: format!("{uid}\n"),
                stderr: String::new(),
                exit_code: 0,
            },
        );
        let ctx = Context::with_executor(Arc::new(executor));
        let result = FirewallHardeningPlugin::new()
            .scan(&ctx, &PluginConfig::default())
            .await
            .expect("the scan reports a blocked probe through ScanResult, never as Err");
        result
            .scan_unchecked
            .iter()
            .find(|check| check.unchecked_title == "Active firewall ruleset")
            .map(|check| check.unchecked_blocker)
            .unwrap_or_else(|| panic!("the blocked ruleset must be reported unchecked"))
    };

    assert_eq!(
        blocker_for("1000").await,
        UncheckedBlocker::Privilege,
        "an unprivileged session has a privileged re-run left to try"
    );
    assert_eq!(
        blocker_for("0").await,
        UncheckedBlocker::Environment,
        "a session already at uid 0 has nothing left to try, so offering sudo \
         sends the operator after a remedy they have already applied"
    );
}

/// A ufw that is installed and broken is not a ufw that refused.
///
/// `is_enabled` used to return the literal string "Unable to determine UFW
/// status (permission denied)" for every failure of `ufw status`, discarding
/// whatever ufw had actually said. The caller classifies on that message, so a
/// backend failure with nothing to do with privilege reported that the operator
/// should try again as root, and on a host already running as root that advice
/// was doubly useless.
///
/// The two fixtures differ only in ufw's stderr. One is the refusal ufw prints,
/// the other is a real failure of its iptables backend, and they must not reach
/// the same conclusion.
#[tokio::test]
async fn a_broken_ufw_is_not_reported_as_a_refusal() {
    let unchecked_titles_for = async |stderr: &str| {
        let executor = MockExecutor::new()
            .with_command_exists("ufw", true)
            .with_command_exists("firewall-cmd", false)
            .with_command_exists("nft", false)
            .with_command(
                "ufw",
                &["status"],
                CommandOutput {
                    stdout: String::new(),
                    stderr: stderr.to_string(),
                    exit_code: 1,
                },
            )
            .with_command(
                "id",
                &["-u"],
                CommandOutput {
                    stdout: "1000\n".to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            );
        let ctx = Context::with_executor(Arc::new(executor));
        let result = FirewallHardeningPlugin::new()
            .scan(&ctx, &PluginConfig::default())
            .await
            .expect("a failing backend probe is reported through ScanResult, never as Err");
        result
            .scan_unchecked
            .iter()
            .any(|check| check.unchecked_title == "Active firewall ruleset")
    };

    assert!(
        unchecked_titles_for("ERROR: You need to be root to run this script").await,
        "ufw's own refusal must still be recognised, or removing the fabricated \
         string would have silenced the case it was covering for"
    );
    assert!(
        !unchecked_titles_for("ERROR: problem running iptables-restore").await,
        "a broken iptables backend is not a privilege problem and must not be \
         classified as one"
    );
}

/// A host whose ufw is installed but switched off, and whose `--force enable`
/// refuses. `ufw status` reporting anything but "Status: active" is what makes
/// `is_enabled` return `Err`, which is how apply learns the firewall is down.
fn ufw_enable_refused_executor() -> MockExecutor {
    MockExecutor::new()
        .with_command_exists("ufw", true)
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("nft", false)
        .with_command(
            "ufw",
            &["status"],
            CommandOutput {
                stdout: "Status: inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "ufw",
            &["--force", "enable"],
            CommandOutput {
                stdout: String::new(),
                stderr: "ERROR: problem running ufw-init\n".to_string(),
                exit_code: 1,
            },
        )
}

#[tokio::test]
async fn an_enable_failure_is_reported_as_a_result_rather_than_a_bare_error() {
    let executor = ufw_enable_refused_executor();
    let mut ctx = Context::with_executor(Arc::new(executor.clone()));

    let result = FirewallHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect(
            "a firewall that refuses to start is a failed apply, not an absent one: \
             every other plugin records the failure and returns its result document",
        );

    assert!(
        !result.apply_success,
        "an apply that could not start the firewall has not succeeded"
    );
    assert!(
        result.apply_error.is_some(),
        "the result must carry why it failed, or the operator is left with a \
         change list and no cause"
    );

    let failed: Vec<_> = result
        .apply_changes
        .iter()
        .filter(|c| !c.change_success)
        .collect();
    assert_eq!(
        failed.len(),
        1,
        "exactly one change failed, the enable itself; got {:?}",
        result.apply_changes
    );
    assert_eq!(
        failed[0].change_type,
        ChangeType::Service,
        "starting a firewall is a service change, the same variant the \
         successful path records"
    );
    assert!(
        failed[0]
            .change_error
            .as_deref()
            .is_some_and(|e| e.contains("ufw-init")),
        "the backend's own words must survive into the change, not be replaced \
         by a summary: got {:?}",
        failed[0].change_error
    );

    // The rules were never attempted, and the result must not suggest they
    // were. This is the assertion that separates "recorded the failure" from
    // "recorded the failure and then invented outcomes for work that never
    // ran".
    let issued_a_rule = executor
        .log()
        .commands_executed
        .iter()
        .any(|(program, args)| program == "ufw" && args.first().is_some_and(|a| a == "allow"));
    assert!(
        !issued_a_rule,
        "no rule may be applied to a firewall that could not be started: {:?}",
        executor.log().commands_executed
    );
}

/// nftables installed and already filtering, so `is_enabled` succeeds and the
/// enable is skipped entirely. `nft add table` is then left unregistered, which
/// is what `ensure_managed_chain` runs first, so the failure arrives through
/// `apply_rules`: the second place this plugin used to abandon a half-built
/// result, and the costlier one, because by then the list is not empty.
///
/// The ruleset must contain "hook input" or `is_enabled` reports the firewall
/// down and the run takes the enable path instead, which is the other test.
fn nft_chain_refused_executor() -> MockExecutor {
    MockExecutor::new()
        .with_command_exists("nft", true)
        .with_command_exists("ufw", false)
        .with_command_exists("firewall-cmd", false)
        .with_command(
            "nft",
            &["list", "ruleset"],
            CommandOutput {
                stdout: "table inet linux_hardener {\n  chain input {\n    type filter hook input \
                         priority 0; policy drop;\n  }\n}\n"
                    .to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-enabled", "nftables"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        // The pre-apply checkpoint's probe, which must succeed here or the
        // apply never reaches the rule failure this test is pinning.
        .with_command(
            "systemctl",
            &[
                "show",
                "nftables.service",
                "-p",
                "ExecStart",
                "-p",
                "ConditionPathExists",
            ],
            CommandOutput {
                stdout: "ExecStart={ path=/usr/sbin/nft ; argv[]=/usr/sbin/nft -f /etc/nftables.conf }\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
}

#[tokio::test]
async fn a_rule_failure_keeps_the_changes_already_recorded() {
    let executor = nft_chain_refused_executor();
    let mut ctx = Context::with_executor(Arc::new(executor.clone()));

    let result = FirewallHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("a backend that cannot write its chain is a failed apply, not an absent one");

    assert!(!result.apply_success, "nothing was applied");
    assert!(
        result.apply_error.is_some(),
        "the cause must reach the result"
    );
    assert!(
        result
            .apply_changes
            .iter()
            .any(|c| c.change_success && c.change_type == ChangeType::Skipped),
        "the changes decided BEFORE the failure must survive it: the firewall \
         was already running, which this apply recorded, and abandoning the \
         result threw that away along with everything else. Got {:?}",
        result.apply_changes
    );
    assert!(
        result.apply_changes.iter().any(|c| !c.change_success),
        "and the failure itself must be in the list, not only in apply_error"
    );
}

/// An exception naming a whole-firewall state rather than a baseline rule.
///
/// `rule_id` maps a rule description to `loopback`, `established`, `ssh` or
/// `drop_default`, and none of those describes a host with no firewall at all:
/// a rule never applied is a different statement from a firewall never
/// enabled. The key therefore names the subsystem state, the way `[mac]`
/// already keys `selinux-enforcing`.
fn whole_firewall_exception_config(key: &str) -> PluginConfig {
    let mut config = PluginConfig::default();
    config.exceptions.insert(
        key.to_string(),
        PolicyException {
            value: "disabled".to_string(),
            allowed: true,
            reason: "perimeter firewall covers this host, tracked in JIRA-8812".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );
    config
}

/// The finding an operator has approved must still be reported, carrying the
/// exception, because `ReportGenerator` fails a control on any finding whose
/// `finding_policy_exception` is `None`. Scan is the only site that can attach
/// it, so a scan that ignores the config makes the deviation unexcusable
/// however the operator writes it down.
#[tokio::test]
async fn scan_honours_an_exception_for_a_host_with_no_firewall_enabled() {
    let ctx = Context::with_executor(Arc::new(ufw_disabled_executor()));
    let plugin = FirewallHardeningPlugin::new();

    // Positive control. The assertion below is an absence claim about
    // `is_none`, and a finding that quietly stopped being emitted would
    // satisfy it perfectly, so pin the finding first and pin that it is a
    // live violation when nothing excuses it.
    let plain = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();
    let plain_finding = plain
        .scan_findings
        .iter()
        .find(|f| f.finding_title == "Firewall disabled")
        .expect("a disabled firewall raises the finding at all");
    assert!(
        plain_finding.finding_policy_exception.is_none(),
        "with nothing declared the finding must stay a live violation"
    );

    let excepted = plugin
        .scan(&ctx, &whole_firewall_exception_config("firewall-enabled"))
        .await
        .unwrap();
    let finding = excepted
        .scan_findings
        .iter()
        .find(|f| f.finding_title == "Firewall disabled")
        .expect("an approved deviation is still reported, annotated rather than dropped");

    let exception = finding
        .finding_policy_exception
        .as_ref()
        .expect("the declared exception must reach the finding, or report fails the control");
    assert!(
        exception.exception_reason.contains("JIRA-8812"),
        "the operator's own reason travels with the finding, got {:?}",
        exception.exception_reason
    );
}

/// The second of the plugin's two findings, keyed separately because accepting
/// a host with no firewall is a different decision from accepting one whose
/// firewall is enforcing now and gone after a reboot.
///
/// A scan fixture, not the apply one above it: the boot question is asked only
/// of a backend the scan has verified as enforcing, so this host answers `ufw
/// status` as active and `systemctl is-enabled` as `disabled`.
fn ufw_active_but_not_wanted_at_boot_executor() -> MockExecutor {
    ufw_active_executor().with_command(
        "systemctl",
        &["is-enabled", "ufw"],
        CommandOutput {
            stdout: "disabled\n".to_string(),
            stderr: String::new(),
            exit_code: 1,
        },
    )
}

#[tokio::test]
async fn scan_honours_an_exception_for_a_firewall_that_does_not_start_at_boot() {
    let ctx = Context::with_executor(Arc::new(ufw_active_but_not_wanted_at_boot_executor()));
    let plugin = FirewallHardeningPlugin::new();

    let plain = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();
    let plain_finding = plain
        .scan_findings
        .iter()
        .find(|f| f.finding_title == "Firewall does not start at boot")
        .expect("a unit not wanted at boot raises the finding at all");
    assert!(
        plain_finding.finding_policy_exception.is_none(),
        "with nothing declared the finding must stay a live violation"
    );

    let excepted = plugin
        .scan(&ctx, &whole_firewall_exception_config("firewall-at-boot"))
        .await
        .unwrap();
    let finding = excepted
        .scan_findings
        .iter()
        .find(|f| f.finding_title == "Firewall does not start at boot")
        .expect("an approved deviation is still reported, annotated rather than dropped");

    assert!(
        finding.finding_policy_exception.is_some(),
        "the boot-persistence finding takes its own key, so an exception for the \
         disabled state must not silence it and its own key must reach it"
    );
}

/// The checkpoint has to capture the file this host boots from, which is not a
/// constant: Fedora and RHEL load /etc/sysconfig/nftables.conf and never read
/// /etc/nftables.conf at all. A checkpoint naming the wrong file restores the
/// wrong file, and declares nothing for the one the apply actually appended to.
///
/// Reaches the backend directly, the way the `apply_rules` tests above do:
/// `nftables_host()` and `backend_for_tests` do not exist in this file, and a
/// production accessor is not worth adding purely to save this test a
/// constructor call.
#[tokio::test]
async fn the_checkpoint_declares_the_file_this_host_boots_from() {
    use hardener_plugins::firewall::FirewallBackend;
    use hardener_plugins::firewall::nftables::NftablesBackend;

    let executor = Arc::new(
        MockExecutor::new()
            .with_command(
                "systemctl",
                &[
                    "show",
                    "nftables.service",
                    "-p",
                    "ExecStart",
                    "-p",
                    "ConditionPathExists",
                ],
                CommandOutput {
                    stdout: "ExecStart={ path=/sbin/nft ; argv[]=/sbin/nft -f /etc/sysconfig/nftables.conf }\n".to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            )
            .with_file("/etc/sysconfig/nftables.conf", "# Fedora ships this\n"),
    );
    let ctx = Context::with_executor(executor.clone());

    let declared = NftablesBackend::new()
        .checkpoint_paths(&ctx)
        .await
        .expect("the probe succeeded, so the paths are knowable");

    assert!(
        declared.iter().any(|p| p == "/etc/sysconfig/nftables.conf"),
        "the probed boot file must be declared, got {declared:?}"
    );
    assert!(
        declared
            .iter()
            .any(|p| p == "/etc/linux-hardener/nftables/50-linux-hardener.nft"),
        "the file the apply creates must be declared so a rollback can remove it, got {declared:?}"
    );
    assert!(
        !declared.iter().any(|p| p == "/etc/nftables.conf"),
        "a path this host never loads must not be declared, got {declared:?}"
    );
}

/// `systemctl show` for a unit that does not exist prints an empty line and
/// still exits 0, which is the real shape of an unreadable probe rather than
/// a contrived error. The apply must go on so the host is filtered live, so
/// `checkpoint_paths` has to answer `Ok`, and with exactly the one path that
/// is never in doubt: this plugin's own fragment. Neither a boot path (there
/// is none to name) nor an `Err` (which would abort the apply before the
/// firewall is even enabled) may appear here.
#[tokio::test]
async fn an_unreadable_probe_checkpoints_only_the_fragment() {
    use hardener_plugins::firewall::FirewallBackend;
    use hardener_plugins::firewall::nftables::NftablesBackend;

    let executor = Arc::new(MockExecutor::new().with_command(
        "systemctl",
        &[
            "show",
            "nftables.service",
            "-p",
            "ExecStart",
            "-p",
            "ConditionPathExists",
        ],
        CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        },
    ));
    let ctx = Context::with_executor(executor);

    let declared = NftablesBackend::new()
        .checkpoint_paths(&ctx)
        .await
        .expect("an unreadable probe must not abort the apply, so this must be Ok");

    assert_eq!(
        declared,
        vec!["/etc/linux-hardener/nftables/50-linux-hardener.nft".to_string()],
        "with no boot path knowable, exactly the fragment must be declared and \
         nothing else, got {declared:?}"
    );
}

/// Every finding this plugin reports must name the key that silences it, and
/// a firewall finding is named after the detected backend (`ufw-disabled`)
/// while its exception is keyed on the backend-independent
/// `firewall-enabled`, which is why an id built from a backend cannot serve.
///
/// The loop is the point: asserting one finding would leave every other
/// directive in this plugin free to advertise a key that does nothing. The
/// emptiness check is the control, because a fixture reporting nothing would
/// satisfy a loop that never runs.
#[tokio::test]
async fn every_firewall_finding_names_the_exception_key_that_silences_it() {
    let scan = async |config: &PluginConfig| {
        FirewallHardeningPlugin::new()
            .scan(
                &Context::with_executor(Arc::new(ufw_disabled_executor())),
                config,
            )
            .await
            .expect("firewall scan should not error")
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
        sampled.iter().any(|key| key == "firewall-enabled"),
        "the disabled-firewall finding is keyed on firewall-enabled",
    );

    for finding in &scan(&config).await.scan_findings {
        assert!(
            finding.finding_policy_exception.is_some(),
            "{} was not annotated by an exception written under the key it named",
            finding.finding_id,
        );
    }
}
