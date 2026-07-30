//! Firewall plugin tests using MockExecutor.
//!
//! These tests verify plugin behaviour without touching real firewall configuration.
//! Includes tests for permission-denied scenarios (Bug D).

use hardener_common::types::{PluginId, Severity};
use hardener_core::{
    ChangeType, CommandOutput, Context, MockExecutor, PluginConfig, PolicyException,
    plugin::HardeningPlugin,
};
use hardener_plugins::FirewallHardeningPlugin;
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
                stdout: "table inet filter {\n\tchain input {\n\t\ttype filter hook input \
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
                stdout: "table inet filter {\n\tchain input {\n\t\ttype filter hook input \
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
            stdout: "table inet filter {\n\tchain input {\n\t\ttype filter hook input \
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

// --- nftables apply idempotency: `nft add rule` always appends a fresh
// handle, so re-running apply must not stack duplicate baseline rules. The
// managed table + input chain are ensured unconditionally (idempotent `add`)
// so a rule add can never fail with ENOENT, and each rule is only added when a
// presence check against the live chain shows it absent. ---

/// A successful, empty-stdout nft command response.
fn nft_ok() -> CommandOutput {
    CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    }
}

/// Registers the idempotent table+chain "ensure" commands the nftables apply
/// path issues before any rule, plus the `list chain` presence probe returning
/// `chain_body`. Callers additionally register the `add rule` commands they
/// expect to run; a rule already present in `chain_body` must NOT be re-added.
fn nft_apply_base(chain_body: &str) -> MockExecutor {
    MockExecutor::new()
        .with_command("nft", &["add", "table", "inet", "filter"], nft_ok())
        .with_command(
            "nft",
            &[
                "add", "chain", "inet", "filter", "input", "{", "type", "filter", "hook", "input",
                "priority", "0", ";", "policy", "drop", ";", "}",
            ],
            nft_ok(),
        )
        .with_command(
            "nft",
            &["list", "chain", "inet", "filter", "input"],
            CommandOutput {
                stdout: chain_body.to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
}

/// An `nft list chain inet filter input` body with no rules (freshly ensured).
const NFT_EMPTY_CHAIN: &str = "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority 0; policy drop;\n\t}\n}\n";

/// True if the command log contains an `nft add rule ...` invocation.
fn logged_nft_add_rule(executor: &MockExecutor) -> bool {
    executor.log().commands_executed.iter().any(|(cmd, args)| {
        cmd == "nft"
            && args.first().map(String::as_str) == Some("add")
            && args.get(1).map(String::as_str) == Some("rule")
    })
}

/// True if the command log contains the table + input-chain "ensure" pair.
fn logged_nft_ensure(executor: &MockExecutor) -> bool {
    let log = executor.log();
    let ensured_table = log
        .commands_executed
        .iter()
        .any(|(cmd, args)| cmd == "nft" && *args == ["add", "table", "inet", "filter"]);
    let ensured_chain = log.commands_executed.iter().any(|(cmd, args)| {
        cmd == "nft"
            && args.first().map(String::as_str) == Some("add")
            && args.get(1).map(String::as_str) == Some("chain")
    });
    ensured_table && ensured_chain
}

#[tokio::test]
async fn test_nftables_apply_ensures_chain_then_adds_all_rules_when_empty() {
    use hardener_plugins::firewall::FirewallBackend;
    use hardener_plugins::firewall::nftables::NftablesBackend;

    let executor = nft_apply_base(NFT_EMPTY_CHAIN)
        .with_command(
            "nft",
            &[
                "add", "rule", "inet", "filter", "input", "iif", "lo", "accept",
            ],
            nft_ok(),
        )
        .with_command(
            "nft",
            &[
                "add",
                "rule",
                "inet",
                "filter",
                "input",
                "ct",
                "state",
                "established,related",
                "accept",
            ],
            nft_ok(),
        )
        .with_command(
            "nft",
            &[
                "add", "rule", "inet", "filter", "input", "tcp", "dport", "22", "accept",
            ],
            nft_ok(),
        )
        .with_command(
            "nft",
            &["add", "rule", "inet", "filter", "input", "drop"],
            nft_ok(),
        );
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

    // The table + input chain were ensured before any rule was added.
    assert!(
        logged_nft_ensure(&executor),
        "the managed table and input chain must be ensured, commands: {:?}",
        executor.log().commands_executed
    );
}

#[tokio::test]
async fn test_nftables_apply_skips_all_rules_already_present() {
    use hardener_plugins::firewall::FirewallBackend;
    use hardener_plugins::firewall::nftables::NftablesBackend;

    // Canonical nft output: `iif "lo"` is quoted and established uses the
    // comma-joined state list; the presence check must tolerate both. NO
    // `add rule` command is registered, so any attempt to add would fail
    // loudly - proving nothing was re-added.
    let full_chain = "table inet filter {\n\tchain input {\n\t\t\
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
    assert!(
        !logged_nft_add_rule(&executor),
        "no `nft add rule` may run when every rule is present, commands: {:?}",
        executor.log().commands_executed
    );
}

#[tokio::test]
async fn test_nftables_apply_adds_only_missing_rules() {
    use hardener_plugins::firewall::FirewallBackend;
    use hardener_plugins::firewall::nftables::NftablesBackend;

    // loopback + ssh already present; established + drop are missing.
    let partial_chain = "table inet filter {\n\tchain input {\n\t\t\
        type filter hook input priority 0; policy drop;\n\t\t\
        iif \"lo\" accept\n\t\ttcp dport 22 accept\n\t}\n}\n";
    let executor = nft_apply_base(partial_chain)
        .with_command(
            "nft",
            &[
                "add",
                "rule",
                "inet",
                "filter",
                "input",
                "ct",
                "state",
                "established,related",
                "accept",
            ],
            nft_ok(),
        )
        .with_command(
            "nft",
            &["add", "rule", "inet", "filter", "input", "drop"],
            nft_ok(),
        );
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

    // The present loopback rule must not be re-added; the missing drop must be.
    let log = executor.log();
    assert!(
        !log.commands_executed.iter().any(|(cmd, args)| cmd == "nft"
            && *args
                == [
                    "add", "rule", "inet", "filter", "input", "iif", "lo", "accept"
                ]),
        "an already-present rule must not be re-added, commands: {:?}",
        log.commands_executed
    );
    assert!(
        log.commands_executed.iter().any(|(cmd, args)| cmd == "nft"
            && *args == ["add", "rule", "inet", "filter", "input", "drop"]),
        "the missing drop rule must be added, commands: {:?}",
        log.commands_executed
    );
}

#[tokio::test]
async fn test_nftables_plugin_apply_ensures_chain_when_foreign_hook_input_present() {
    // A foreign table carries a `hook input` chain (e.g. docker, or another
    // address family), so is_enabled's ruleset grep believes a filter is
    // already active and the plugin skips enable(). The inet filter chain the
    // baseline rules target does NOT exist, so before the fix every `add rule`
    // failed with ENOENT. apply_rules must now ensure the chain itself.
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
        .with_command("nft", &["add", "table", "inet", "filter"], nft_ok())
        .with_command(
            "nft",
            &[
                "add", "chain", "inet", "filter", "input", "{", "type", "filter", "hook", "input",
                "priority", "0", ";", "policy", "drop", ";", "}",
            ],
            nft_ok(),
        )
        .with_command(
            "nft",
            &["list", "chain", "inet", "filter", "input"],
            CommandOutput {
                stdout: NFT_EMPTY_CHAIN.to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "nft",
            &[
                "add", "rule", "inet", "filter", "input", "iif", "lo", "accept",
            ],
            nft_ok(),
        )
        .with_command(
            "nft",
            &[
                "add",
                "rule",
                "inet",
                "filter",
                "input",
                "ct",
                "state",
                "established,related",
                "accept",
            ],
            nft_ok(),
        )
        .with_command(
            "nft",
            &[
                "add", "rule", "inet", "filter", "input", "tcp", "dport", "22", "accept",
            ],
            nft_ok(),
        )
        .with_command(
            "nft",
            &["add", "rule", "inet", "filter", "input", "drop"],
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
        "apply must succeed once the chain is ensured, failed: {:?}",
        result
            .apply_changes
            .iter()
            .filter(|c| !c.change_success)
            .collect::<Vec<_>>()
    );
    assert!(
        logged_nft_ensure(&executor),
        "the inet filter table + input chain must be ensured despite the foreign hook-input \
         chain, commands: {:?}",
        executor.log().commands_executed
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
