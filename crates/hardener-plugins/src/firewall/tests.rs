#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`firewall`].
//!
//! Split out of `firewall.rs`. This file sits in the `firewall/` directory
//! beside it, so `super` still resolves to `crate::firewall` and every
//! import carried across unchanged, private items included.

use super::*;
use hardener_core::{CommandOutput, MockExecutor};
use std::path::Path;
use std::sync::Arc;

/// Reproduces the maintainer's hardened-Arch scenario: nftables and ufw
/// are both installed, the unprivileged `nft list ruleset` probe fails
/// with permission denied, but the nftables systemd unit is active while
/// ufw's is not. Selection must prefer nftables via the root-free unit
/// hint, and the ruleset check must be reported unchecked rather than
/// as a false "Firewall disabled" finding.
#[tokio::test]
async fn scan_prefers_systemd_active_backend_and_reports_unchecked_when_probe_needs_root() {
    let mock = MockExecutor::new()
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("ufw", true)
        .with_command_exists("nft", true)
        .with_command(
            "nft",
            &["list", "ruleset"],
            CommandOutput {
                stdout: String::new(),
                stderr: "nft: Permission denied".to_string(),
                exit_code: 1,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "nftables"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "ufw"],
            CommandOutput {
                stdout: "inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 3,
            },
        )
        // ufw's own probe, which is_enabled asks instead of systemd now.
        // A fixture answering only systemctl stands for a host where
        // `ufw status` cannot run at all, which classifies Unknown rather
        // than Inactive and is not the state these tests are about.
        .with_command(
            "ufw",
            &["status"],
            CommandOutput {
                stdout: "Status: inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        );
    let ctx = Context::with_executor(std::sync::Arc::new(mock));
    let result = FirewallHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert!(result.scan_findings.is_empty(), "no false disabled finding");
    assert_eq!(result.scan_unchecked.len(), 1);
    assert_eq!(
        result.scan_unchecked[0].unchecked_check_id,
        "nftables-disabled"
    );
}

/// Reproduces the maintainer-host acceptance gap: ufw and nftables are
/// both installed, nftables' ruleset is loaded in-kernel but its unit is
/// inactive (loaded outside the unit) and the probe is permission
/// blocked, so nftables' true state is unknowable. ufw's own probe runs
/// cleanly and reports disabled. Reporting the red finding here would be
/// a false positive: nftables might well be the active firewall.
#[tokio::test]
async fn scan_reports_unchecked_when_blocked_backend_might_be_active() {
    // ufw + nftables installed; nft probe permission-blocked; BOTH units
    // inactive (ruleset loaded outside the unit). ufw's probe runs and says
    // disabled - but nftables' state is unknowable, so no red finding.
    let mock = MockExecutor::new()
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("ufw", true)
        .with_command_exists("nft", true)
        .with_command(
            "nft",
            &["list", "ruleset"],
            CommandOutput {
                stdout: String::new(),
                stderr: "Operation not permitted (you must be root)".to_string(),
                exit_code: 1,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "nftables"],
            CommandOutput {
                stdout: "inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 3,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "ufw"],
            CommandOutput {
                stdout: "inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 3,
            },
        )
        // ufw's own probe, which is_enabled asks instead of systemd now.
        // A fixture answering only systemctl stands for a host where
        // `ufw status` cannot run at all, which classifies Unknown rather
        // than Inactive and is not the state these tests are about.
        .with_command(
            "ufw",
            &["status"],
            CommandOutput {
                stdout: "Status: inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        );
    let ctx = Context::with_executor(std::sync::Arc::new(mock));
    let result = FirewallHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert!(
        result.scan_findings.is_empty(),
        "no red finding while nftables is unknowable"
    );
    assert_eq!(result.scan_unchecked.len(), 1);
    assert_eq!(
        result.scan_unchecked[0].unchecked_check_id,
        "nftables-disabled"
    );
}

/// Negative control for the above: nftables' probe genuinely succeeds
/// (not permission-blocked) and finds no active input-hook chain, and
/// ufw is genuinely inactive. Every installed backend's probe ran and
/// reported inactive, so the red finding is warranted here.
#[tokio::test]
async fn scan_reports_disabled_when_every_backend_probe_confirms_inactive() {
    let mock = MockExecutor::new()
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("ufw", true)
        .with_command_exists("nft", true)
        .with_command(
            "nft",
            &["list", "ruleset"],
            CommandOutput {
                stdout: "table inet filter {\n}\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "ufw"],
            CommandOutput {
                stdout: "inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 3,
            },
        )
        // ufw's own probe, which is_enabled asks instead of systemd now.
        // A fixture answering only systemctl stands for a host where
        // `ufw status` cannot run at all, which classifies Unknown rather
        // than Inactive and is not the state these tests are about.
        .with_command(
            "ufw",
            &["status"],
            CommandOutput {
                stdout: "Status: inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        );
    let ctx = Context::with_executor(std::sync::Arc::new(mock));
    let result = FirewallHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert!(
        result.scan_unchecked.is_empty(),
        "every backend probe ran; nothing is unverifiable"
    );
    assert_eq!(result.scan_findings.len(), 1);
    assert_eq!(result.scan_findings[0].finding_id, "ufw-disabled");
}

/// A verified-active winner settles the host-level question: nftables'
/// probe confirms an input-hook chain (Verified), while ufw's state is
/// unknowable (its systemctl hint errors and its status fallback is
/// permission-blocked, classifying Unknown). The scan must stay silent -
/// no finding AND no unchecked entry - because one confirmed active
/// firewall makes the sibling's unknowability irrelevant.
#[tokio::test]
async fn scan_stays_silent_when_winner_is_verified_despite_unknown_sibling() {
    let mock = MockExecutor::new()
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("ufw", true)
        .with_command_exists("nft", true)
        .with_command(
            "nft",
            &["list", "ruleset"],
            CommandOutput {
                stdout: "table inet filter {\n  chain input {\n    \
                         type filter hook input priority 0;\n  }\n}\n"
                    .to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        // `systemctl is-active ufw` deliberately unregistered: the mock
        // errors, so ufw's is_enabled falls through to its `ufw status`
        // fallback and the unit hint reads inactive.
        .with_command(
            "ufw",
            &["status"],
            CommandOutput {
                stdout: String::new(),
                stderr: "ERROR: You need to be root to run this script".to_string(),
                exit_code: 1,
            },
        )
        // The winner's boot question, which is asked of every verified
        // winner and is not what this test is about. Answered `enabled`
        // so the host described here is one whose firewall does survive a
        // reboot, leaving the silence this asserts about the ruleset.
        .with_command(
            "systemctl",
            &["is-enabled", "nftables"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        );
    let ctx = Context::with_executor(std::sync::Arc::new(mock));
    let result = FirewallHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert!(
        result.scan_findings.is_empty(),
        "a verified-active firewall must not raise a finding"
    );
    assert!(
        result.scan_unchecked.is_empty(),
        "a verified-active winner answers the check; no unchecked entry"
    );
}

/// The unchecked entry must name the WINNER when the winner classifies
/// UnitActiveUnverified, not whichever unverifiable backend happens to
/// come first in installed order. Here ufw (earlier in installed order)
/// classifies Unknown, while nftables classifies UnitActiveUnverified
/// and is therefore the winner the apply path would drive - so the
/// entry must read "nftables-disabled", not "ufw-disabled".
#[tokio::test]
async fn scan_unchecked_names_the_winner_not_the_first_unknown_sibling() {
    let mock = MockExecutor::new()
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("ufw", true)
        .with_command_exists("nft", true)
        .with_command(
            "nft",
            &["list", "ruleset"],
            CommandOutput {
                stdout: String::new(),
                stderr: "nft: Permission denied".to_string(),
                exit_code: 1,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "nftables"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        // `systemctl is-active ufw` deliberately unregistered: the mock
        // errors, so ufw's is_enabled falls through to its `ufw status`
        // fallback and the unit hint reads inactive, classifying Unknown.
        .with_command(
            "ufw",
            &["status"],
            CommandOutput {
                stdout: String::new(),
                stderr: "ERROR: You need to be root to run this script".to_string(),
                exit_code: 1,
            },
        );
    let ctx = Context::with_executor(std::sync::Arc::new(mock));
    let result = FirewallHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert!(
        result.scan_findings.is_empty(),
        "nothing is confirmed inactive; no red finding"
    );
    assert_eq!(result.scan_unchecked.len(), 1);
    assert_eq!(
        result.scan_unchecked[0].unchecked_check_id, "nftables-disabled",
        "the unchecked entry must name the winner, not the first unknown sibling"
    );
}

/// Part A honesty gate for the dry-run preview, the same class of fix
/// the scan gained in 62e8c14. On the maintainer's hardened host
/// nftables' ruleset is live but its probe needs root and its oneshot
/// unit reads inactive (classifies Unknown), while ufw is installed and
/// genuinely inactive. Selection falls back to ufw (installed order), but
/// validate must NOT claim "Enable ufw": the firewall's true state is
/// unverifiable, so it reports the honest limitation instead of a false
/// pending change, and never names ufw.
#[tokio::test]
async fn validate_reports_unverifiable_instead_of_false_enable_when_probe_needs_root() {
    let mock = MockExecutor::new()
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("ufw", true)
        .with_command_exists("nft", true)
        .with_command(
            "nft",
            &["list", "ruleset"],
            CommandOutput {
                stdout: String::new(),
                stderr: "nft: Permission denied".to_string(),
                exit_code: 1,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "nftables"],
            CommandOutput {
                stdout: "inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 3,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "ufw"],
            CommandOutput {
                stdout: "inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 3,
            },
        )
        // ufw's own probe, which is_enabled asks instead of systemd now.
        // A fixture answering only systemctl stands for a host where
        // `ufw status` cannot run at all, which classifies Unknown rather
        // than Inactive and is not the state these tests are about.
        .with_command(
            "ufw",
            &["status"],
            CommandOutput {
                stdout: "Status: inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        );
    let ctx = Context::with_executor(std::sync::Arc::new(mock));
    let report = FirewallHardeningPlugin::new()
        .validate(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    let changes = &report.validation_report_estimated_changes;
    assert!(
        changes.is_empty(),
        "a state this run could not read queues no writes, got {changes:?}"
    );
    let reported: Vec<&str> = report
        .validation_report_issues
        .iter()
        .map(|i| i.validation_issue_message.as_str())
        .collect();
    assert!(
        reported.iter().any(|m| m.contains("could not be verified")),
        "must report the honest unverifiable line, got {reported:?}"
    );
    assert!(
        !reported.iter().any(|m| m.contains("Enable")),
        "must NOT claim a false enable for an unverifiable ruleset, got {reported:?}"
    );
    assert!(
        !reported.iter().any(|m| m.to_lowercase().contains("ufw")),
        "must NOT name ufw when nftables is the live-but-unverifiable winner, got {reported:?}"
    );
    assert!(
        !report.has_blocking_issue(),
        "a privileged apply re-classifies and succeeds, so this must not fail the dry run"
    );
}

/// When the winning backend is active by its systemd unit but its ruleset
/// probe needs root (UnitActiveUnverified), validate reports the honest
/// limitation rather than guessing at an enable or a rule count.
#[tokio::test]
async fn validate_reports_unverifiable_when_winner_unit_active_but_probe_blocked() {
    let mock = MockExecutor::new()
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("ufw", true)
        .with_command_exists("nft", true)
        .with_command(
            "nft",
            &["list", "ruleset"],
            CommandOutput {
                stdout: String::new(),
                stderr: "nft: Permission denied".to_string(),
                exit_code: 1,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "nftables"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "ufw"],
            CommandOutput {
                stdout: "inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 3,
            },
        )
        // ufw's own probe, which is_enabled asks instead of systemd now.
        // A fixture answering only systemctl stands for a host where
        // `ufw status` cannot run at all, which classifies Unknown rather
        // than Inactive and is not the state these tests are about.
        .with_command(
            "ufw",
            &["status"],
            CommandOutput {
                stdout: "Status: inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        );
    let ctx = Context::with_executor(std::sync::Arc::new(mock));
    let report = FirewallHardeningPlugin::new()
        .validate(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    let changes = &report.validation_report_estimated_changes;
    assert!(
        changes.is_empty(),
        "a state this run could not read queues no writes, got {changes:?}"
    );
    let reported: Vec<&str> = report
        .validation_report_issues
        .iter()
        .map(|i| i.validation_issue_message.as_str())
        .collect();
    assert!(
        reported.iter().any(|m| m.contains("could not be verified")),
        "unit-active-but-unverifiable winner must report the honest line, got {reported:?}"
    );
    assert!(
        !reported.iter().any(|m| m.contains("Enable")),
        "must NOT claim an enable for a unit-active winner, got {reported:?}"
    );
}

/// Negative control: every installed backend's probe ran and reported
/// inactive (nftables' ruleset has no input hook, ufw's unit is
/// inactive), so the firewall is genuinely disabled. "Enable X" is then a
/// real pending change and must be kept, naming the selected backend,
/// alongside the baseline rule estimate.
#[tokio::test]
async fn validate_keeps_enable_when_every_backend_probe_confirms_inactive() {
    let mock = MockExecutor::new()
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("ufw", true)
        .with_command_exists("nft", true)
        .with_command(
            "nft",
            &["list", "ruleset"],
            CommandOutput {
                stdout: "table inet filter {\n}\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "ufw"],
            CommandOutput {
                stdout: "inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 3,
            },
        )
        // ufw's own probe, which is_enabled asks instead of systemd now.
        // A fixture answering only systemctl stands for a host where
        // `ufw status` cannot run at all, which classifies Unknown rather
        // than Inactive and is not the state these tests are about.
        .with_command(
            "ufw",
            &["status"],
            CommandOutput {
                stdout: "Status: inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        );
    let ctx = Context::with_executor(std::sync::Arc::new(mock));
    let report = FirewallHardeningPlugin::new()
        .validate(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    let changes = &report.validation_report_estimated_changes;
    assert!(
        changes.iter().any(|c| c == "Enable ufw firewall"),
        "a genuinely disabled firewall keeps the enable line, got {changes:?}"
    );
    assert!(
        changes
            .iter()
            .any(|c| c.contains("baseline firewall rules")),
        "the baseline rule estimate is still reported, got {changes:?}"
    );
    assert!(
        !changes.iter().any(|c| c.contains("could not be verified")),
        "a positively inactive firewall is not unverifiable, got {changes:?}"
    );
}

/// Verified-active winner (nftables input-hook chain present): validate
/// reports the rule-level pending changes exactly as before and emits
/// neither an enable line nor the unverifiable notice.
#[tokio::test]
async fn validate_reports_rule_changes_when_backend_verified_active() {
    let mock = MockExecutor::new()
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("ufw", false)
        .with_command_exists("nft", true)
        .with_command(
            "nft",
            &["list", "ruleset"],
            CommandOutput {
                stdout: "table inet filter {\n  chain input {\n    \
                         type filter hook input priority 0;\n  }\n}\n"
                    .to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        );
    let ctx = Context::with_executor(std::sync::Arc::new(mock));
    let report = FirewallHardeningPlugin::new()
        .validate(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert_eq!(
        report.validation_report_estimated_changes,
        vec!["Apply 4 baseline firewall rules".to_string()],
        "a verified-active firewall reports only the rule estimate"
    );
}

/// A host whose only installed backend is ufw, genuinely enforcing, with
/// `systemctl is-enabled ufw` answering `state` and exiting `exit_code`.
///
/// Both are registered because systemd's word and its exit status disagree
/// by design: `enabled-runtime` and `static` exit 0 while neither starts the
/// unit at the next boot, and `disabled` exits non-zero while `systemctl
/// enable` fixes it. A fixture that set only one of the two would let a
/// probe reading the wrong one pass.
fn ufw_active_with_unit_state(state: &str, exit_code: i32) -> MockExecutor {
    MockExecutor::new()
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("ufw", true)
        .with_command_exists("nft", false)
        .with_command(
            "ufw",
            &["status"],
            CommandOutput {
                stdout: "Status: active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-enabled", "ufw"],
            CommandOutput {
                stdout: format!("{state}\n"),
                stderr: String::new(),
                exit_code,
            },
        )
}

async fn scan_with(mock: MockExecutor) -> ScanResult {
    let ctx = Context::with_executor(std::sync::Arc::new(mock));
    FirewallHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .expect("the scan itself must not fail on an installed backend")
}

/// The arch container's state, measured 2026-07-30: `ufw status` reads
/// `Status: active` and `/etc/ufw/ufw.conf` reads `ENABLED=yes`, while
/// `/etc/systemd/system/multi-user.target.wants/ufw.service` does not exist
/// and `systemctl is-enabled ufw` reads `disabled`. The host has a firewall
/// now and will have none after a reboot, and every re-run of apply skips
/// `enable` because `is_enabled` says the firewall is up.
///
/// The finding must not be the `{backend}-disabled` one: the firewall IS
/// running, and calling it disabled would be a false statement about the
/// host in front of the operator.
#[tokio::test]
async fn a_running_firewall_whose_unit_is_disabled_is_reported_as_lost_at_reboot() {
    let result = scan_with(ufw_active_with_unit_state("disabled", 1)).await;

    let ids: Vec<&str> = result
        .scan_findings
        .iter()
        .map(|f| f.finding_id.as_str())
        .collect();
    assert!(
        ids.contains(&"ufw-not-enabled-at-boot"),
        "a firewall enforcing now whose unit is not wanted at boot loses the host \
         its firewall at the next reboot, and nothing reported it: {ids:?}"
    );
    assert!(
        !ids.contains(&"ufw-disabled"),
        "the firewall is running, so calling it disabled is false: {ids:?}"
    );
    assert!(
        result.scan_unchecked.is_empty(),
        "systemd answered the question, so nothing is unverified: {:?}",
        result.scan_unchecked
    );
    let finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "ufw-not-enabled-at-boot")
        .expect("asserted present above");
    assert_eq!(finding.finding_severity, Severity::High);
    assert!(
        finding.finding_description.contains("reboot"),
        "the description has to say plainly that the firewall does not survive a \
         reboot: {}",
        finding.finding_description
    );
    assert!(
        !finding.finding_compliance.is_empty(),
        "a finding with no mappings can never be rendered by a framework report"
    );
}

/// `enabled-runtime` is the trap the probe exists to avoid. It exits 0 and
/// its word starts with "enabled", yet it is a `/run/systemd/system` symlink
/// that the next boot discards: exactly the failure being fixed. Reading it
/// as enabled would reintroduce the defect through the probe itself.
#[tokio::test]
async fn a_runtime_only_enablement_is_lost_at_reboot_and_is_reported() {
    let result = scan_with(ufw_active_with_unit_state("enabled-runtime", 0)).await;

    let finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "ufw-not-enabled-at-boot")
        .unwrap_or_else(|| {
            panic!(
                "enabled-runtime is enablement for this boot only; treating it as \
                 enabled is the defect: {:?}",
                result.scan_findings
            )
        });
    assert!(
        finding.finding_description.contains("enabled-runtime"),
        "the operator is told which of the several ways of not starting at boot \
         this host is in: {}",
        finding.finding_description
    );
}

/// A masked unit is worse than one merely not enabled: systemd refuses to
/// start it at all, so `systemctl enable` alone does not repair the host and
/// the wording has to say so.
#[tokio::test]
async fn a_masked_unit_is_reported_in_its_own_words() {
    let result = scan_with(ufw_active_with_unit_state("masked", 1)).await;

    let finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "ufw-not-enabled-at-boot")
        .unwrap_or_else(|| {
            panic!(
                "a masked unit will not start at boot either: {:?}",
                result.scan_findings
            )
        });
    assert!(
        finding.finding_description.contains("masked"),
        "masked is not the same state as disabled and must not be described as \
         it: {}",
        finding.finding_description
    );
    assert!(
        finding
            .finding_remediation_steps
            .iter()
            .any(|step| step.contains("unmask")),
        "enabling a masked unit fails until it is unmasked, so the steps must \
         say so: {:?}",
        finding.finding_remediation_steps
    );
}

/// `systemctl` absent, or erroring: the question was not answered, and an
/// unanswered question is not a pass. It becomes an unchecked entry, the
/// same machinery the root-blocked ruleset probe already uses.
#[tokio::test]
async fn an_unanswerable_boot_question_is_unchecked_rather_than_passed() {
    // `systemctl is-enabled ufw` deliberately unregistered, so the mock
    // errors exactly as a host without systemctl would.
    let mock = MockExecutor::new()
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("ufw", true)
        .with_command_exists("nft", false)
        .with_command(
            "ufw",
            &["status"],
            CommandOutput {
                stdout: "Status: active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        );
    let result = scan_with(mock).await;

    assert!(
        result.scan_findings.is_empty(),
        "a question that was not answered is not evidence of a fault: {:?}",
        result.scan_findings
    );
    let ids: Vec<&str> = result
        .scan_unchecked
        .iter()
        .map(|u| u.unchecked_check_id.as_str())
        .collect();
    assert!(
        ids.contains(&"ufw-not-enabled-at-boot"),
        "an unanswered question must be reported as unchecked, never passed \
         over in silence: {ids:?}"
    );
}

/// `static` has no `[Install]` section, so it cannot be enabled, but it may
/// still be pulled in by another unit. Exit code 0 makes it look like a pass
/// to anything judging by status alone. It is neither a pass nor a fault:
/// the honest answer is that this scan does not know.
#[tokio::test]
async fn a_unit_with_no_install_section_is_unchecked_rather_than_enabled() {
    let result = scan_with(ufw_active_with_unit_state("static", 0)).await;

    assert!(
        result.scan_findings.is_empty(),
        "a static unit may well be pulled in by another unit, so claiming a \
         fault would be a guess: {:?}",
        result.scan_findings
    );
    let ids: Vec<&str> = result
        .scan_unchecked
        .iter()
        .map(|u| u.unchecked_check_id.as_str())
        .collect();
    assert!(
        ids.contains(&"ufw-not-enabled-at-boot"),
        "static exits 0 but starts nothing at boot on its own, so it must not \
         read as enabled: {ids:?}"
    );
}

/// The positive control for all of the above. `enabled` is the one word
/// that means the unit is started at boot, and a host in that state must
/// hear nothing at all: no finding, no unchecked entry.
#[tokio::test]
async fn a_unit_enabled_at_boot_says_nothing() {
    let result = scan_with(ufw_active_with_unit_state("enabled", 0)).await;

    assert!(
        result.scan_findings.is_empty(),
        "a firewall that survives a reboot is not a fault: {:?}",
        result.scan_findings
    );
    assert!(
        result.scan_unchecked.is_empty(),
        "systemd answered the question, so nothing is unverified: {:?}",
        result.scan_unchecked
    );
}

#[test]
fn coverage_includes_firewall_installed_control() {
    let ids: Vec<String> = coverage()
        .into_iter()
        .filter(|m| m.compliance_framework == ComplianceFramework::CIS)
        .map(|m| m.compliance_control_id)
        .collect();
    assert!(ids.contains(&"3.4.1.1".to_string()), "must map CIS 3.4.1.1");
    assert!(
        ids.contains(&"3.4.1.2".to_string()),
        "must retain CIS 3.4.1.2"
    );
}

/// Confirms the firewall finding now carries multi-framework mappings:
/// CIS (existing) plus STIG and NIST sourced from SSG.
#[test]
fn firewall_maps_cis_stig_and_nist() {
    let mappings = get_firewall_compliance_mappings();

    let frameworks: Vec<ComplianceFramework> =
        mappings.iter().map(|m| m.compliance_framework).collect();

    assert!(
        frameworks.contains(&ComplianceFramework::CIS),
        "CIS mapping must be preserved"
    );
    assert!(
        frameworks.contains(&ComplianceFramework::STIG),
        "STIG mapping must be added"
    );
    assert!(
        frameworks.contains(&ComplianceFramework::NIST),
        "NIST mapping must be added"
    );
}

/// Confirms the firewall finding additionally carries the data-protection
/// frameworks (HIPAA transmission security, GDPR network protection, ISO
/// 27001) alongside the existing CIS/STIG/NIST/PCI-DSS mappings.
#[test]
fn firewall_maps_hipaa_gdpr_and_iso27001() {
    let mappings = get_firewall_compliance_mappings();

    let frameworks: Vec<ComplianceFramework> =
        mappings.iter().map(|m| m.compliance_framework).collect();

    assert!(
        frameworks.contains(&ComplianceFramework::HIPAA),
        "HIPAA mapping must be added"
    );
    assert!(
        frameworks.contains(&ComplianceFramework::GDPR),
        "GDPR mapping must be added"
    );
    assert!(
        frameworks.contains(&ComplianceFramework::ISO27001),
        "ISO 27001 mapping must be added"
    );

    // Networks-security control 8.20 must be present for a network boundary
    // control, and HIPAA maps to the transmission-security standard.
    assert!(
        mappings
            .iter()
            .any(|m| m.compliance_framework == ComplianceFramework::ISO27001
                && m.compliance_control_id == "8.20"),
        "ISO 27001 clause 8.20 (Networks security) must be present"
    );
    let hipaa = mappings
        .iter()
        .find(|m| m.compliance_framework == ComplianceFramework::HIPAA)
        .expect("HIPAA mapping present");
    assert_eq!(hipaa.compliance_control_id, "164.312(e)(1)");
}

/// Confirms the host firewall carries the SOC 2 boundary-protection
/// criterion CC6.6, filed under its Trust Services Criteria series.
#[test]
fn firewall_maps_soc2_boundary_criterion() {
    let soc2 = get_firewall_compliance_mappings()
        .into_iter()
        .find(|m| m.compliance_framework == ComplianceFramework::SOC2)
        .expect("firewall must carry a SOC 2 mapping");
    assert_eq!(soc2.compliance_control_id, "CC6.6");
    assert_eq!(
        soc2.compliance_section.as_deref(),
        Some("Logical and Physical Access Controls")
    );
}

/// Confirms the 800-171r3 crosswalk for the host firewall: SC-7 → 3.13.1
/// and CM-7 → 3.4.6, each filed under its official family.
#[test]
fn firewall_maps_nist_800_171_requirements() {
    let mappings: Vec<_> = get_firewall_compliance_mappings()
        .into_iter()
        .filter(|m| m.compliance_framework == ComplianceFramework::NIST800171)
        .map(|m| (m.compliance_control_id, m.compliance_section))
        .collect();
    for (id, family) in [
        ("3.13.1", "System and Communications Protection"),
        ("3.4.6", "Configuration Management"),
    ] {
        assert!(
            mappings.contains(&(id.to_string(), Some(family.to_string()))),
            "firewall must carry 800-171 {id} under {family}"
        );
    }
}

/// Confirms the FedRAMP derivation for the host firewall: SC-7 and CM-7
/// are both GSA rev5 Moderate baseline members, mirrored verbatim from
/// the existing 800-53 entries under their official families.
#[test]
fn firewall_maps_fedramp_moderate_controls() {
    let mappings: Vec<_> = get_firewall_compliance_mappings()
        .into_iter()
        .filter(|m| m.compliance_framework == ComplianceFramework::FedRAMP)
        .map(|m| (m.compliance_control_id, m.compliance_section))
        .collect();
    for (id, family) in [
        ("SC-7", "System and Communications Protection"),
        ("CM-7", "Configuration Management"),
    ] {
        assert!(
            mappings.contains(&(id.to_string(), Some(family.to_string()))),
            "firewall must carry FedRAMP {id} under {family}"
        );
    }
}

/// A directive override may tighten a rule and never weaken it, which is what
/// every other plugin taking one already guarantees and what the configuration
/// reference promises for all of them.
///
/// The catch-all is the case that matters. `drop_default` exists so that
/// anything the three allow rules did not admit is refused, and an override
/// turning it into `accept` is the whole baseline undone by one line of
/// configuration, applied by the tool whose job is to prevent exactly that.
#[test]
fn an_override_cannot_turn_the_catch_all_drop_into_accept() {
    let mut config = PluginConfig::default();
    config
        .directives
        .insert("drop_default.action".to_string(), "accept".to_string());

    let mut rule = get_baseline_rules()
        .into_iter()
        .find(|r| rule_id(r) == "drop_default")
        .expect("the baseline carries a catch-all rule");
    apply_rule_directives(&mut rule, "drop_default", &config);

    assert_eq!(
        rule.rule_action, "drop",
        "a blocking rule must not be weakened to accept by an override"
    );
}

/// The other direction still works, or the clamp would be a ban rather than a
/// clamp. Tightening an allow rule into a drop is a legitimate thing to ask for.
#[test]
fn an_override_may_tighten_an_accepting_rule() {
    let mut config = PluginConfig::default();
    config
        .directives
        .insert("ssh.action".to_string(), "drop".to_string());

    let mut rule = get_baseline_rules()
        .into_iter()
        .find(|r| rule_id(r) == "ssh")
        .expect("the baseline carries an ssh rule");
    apply_rule_directives(&mut rule, "ssh", &config);

    assert_eq!(
        rule.rule_action, "drop",
        "tightening must still be honoured"
    );
}

/// `drop` and `reject` are both blocking, so swapping one for the other is
/// neither a loosening nor a tightening and is the operator's business.
#[test]
fn an_override_may_swap_one_blocking_action_for_the_other() {
    let mut config = PluginConfig::default();
    config
        .directives
        .insert("drop_default.action".to_string(), "reject".to_string());

    let mut rule = get_baseline_rules()
        .into_iter()
        .find(|r| rule_id(r) == "drop_default")
        .expect("the baseline carries a catch-all rule");
    apply_rule_directives(&mut rule, "drop_default", &config);

    assert_eq!(rule.rule_action, "reject");
}

/// The three fields that are not clamped, pinned as a positive control. Without
/// them a clamp that refused every override would pass the assertions above,
/// and changing the SSH port is the configuration reference's own worked
/// example of a legitimate override.
#[test]
fn port_source_and_protocol_overrides_are_still_applied() {
    let mut config = PluginConfig::default();
    config
        .directives
        .insert("ssh.port".to_string(), "2222".to_string());
    config
        .directives
        .insert("ssh.source".to_string(), "10.0.0.0/8".to_string());
    config
        .directives
        .insert("ssh.protocol".to_string(), "udp".to_string());

    let mut rule = get_baseline_rules()
        .into_iter()
        .find(|r| rule_id(r) == "ssh")
        .expect("the baseline carries an ssh rule");
    apply_rule_directives(&mut rule, "ssh", &config);

    assert_eq!(rule.rule_port, "2222");
    assert_eq!(rule.rule_source, "10.0.0.0/8");
    assert_eq!(rule.rule_protocol, "udp");
}

/// An action the configuration layer would have rejected never reaches a rule.
/// It cannot arrive through a validated config, so this pins the fail-closed
/// posture rather than a reachable path: an unrecognised action is not a
/// tightening and must not be written to a backend.
#[test]
fn an_unrecognised_action_is_refused_rather_than_written() {
    let mut config = PluginConfig::default();
    config
        .directives
        .insert("ssh.action".to_string(), "allow".to_string());

    let mut rule = get_baseline_rules()
        .into_iter()
        .find(|r| rule_id(r) == "ssh")
        .expect("the baseline carries an ssh rule");
    apply_rule_directives(&mut rule, "ssh", &config);

    assert_eq!(rule.rule_action, "accept", "the baseline must stand");
}

/// Names only firewall's own paths, so a failure here cannot come from
/// another plugin's entry in a shared list.
#[test]
fn firewall_reloads_for_its_own_paths_and_no_others() {
    let plugin = FirewallHardeningPlugin::new();
    assert!(plugin.reloads_for_path(Path::new("/etc/nftables.conf")));
    assert!(plugin.reloads_for_path(Path::new("/etc/firewalld/zones/public.xml")));
    assert!(plugin.reloads_for_path(Path::new("/etc/ufw/ufw.conf")));
    assert!(!plugin.reloads_for_path(Path::new("/etc/sysctl.conf")));
}

/// Ties the predicate to the literals `apply` actually checkpoints, so the
/// two cannot drift apart unnoticed.
#[test]
fn every_path_firewall_checkpoints_is_one_it_reloads_for() {
    let plugin = FirewallHardeningPlugin::new();
    for path in ["/etc/nftables.conf", "/etc/firewalld", "/etc/ufw"] {
        assert!(
            plugin.reloads_for_path(Path::new(path)),
            "firewall checkpoints {path} but would not reload for it"
        );
    }
}

/// The commands a fixture logged, as `("program", ["arg", ...])` pairs
/// flattened into one string per command, so an assertion can ask whether a
/// rollback reload issued something it must never issue.
fn logged_commands(executor: &MockExecutor) -> Vec<String> {
    executor
        .log()
        .commands_executed
        .into_iter()
        .map(|(program, args)| format!("{program} {}", args.join(" ")))
        .collect()
}

/// Asserts the shape every backend's rollback reload shares: the reload
/// command was issued, and nothing that would change whether the firewall
/// runs now or at the next boot was.
///
/// A rollback restores files and re-reads them. Starting a unit, enabling it
/// at boot, or installing a chain is hardening, and hardening during an undo
/// is the defect these tests exist to keep out.
fn assert_reload_only(commands: &[String], expected_reload: &str) {
    assert!(
        commands.iter().any(|c| c == expected_reload),
        "the rollback must issue `{expected_reload}`, got: {commands:?}"
    );
    assert!(
        !commands.iter().any(|c| c.starts_with("systemctl enable")),
        "a rollback must not enable a unit at boot, got: {commands:?}"
    );
    assert!(
        !commands.iter().any(|c| c.starts_with("systemctl start")),
        "a rollback must not start a service, got: {commands:?}"
    );
}

/// firewalld re-reads `/etc/firewalld/**` on `firewall-cmd --reload` and on
/// nothing else. `systemctl start firewalld` is a no-op on a host where
/// firewalld already runs, which is every host a rollback of a firewalld
/// configuration reaches, so the restored zone files were never read back.
#[tokio::test]
async fn a_firewalld_rollback_reloads_rather_than_enables() {
    let executor = Arc::new(
        MockExecutor::new()
            .with_command_exists("firewall-cmd", true)
            .with_command_exists("ufw", false)
            .with_command_exists("nft", false)
            .with_command(
                "firewall-cmd",
                &["--state"],
                CommandOutput {
                    stdout: "running\n".to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            )
            .with_command(
                "firewall-cmd",
                &["--reload"],
                CommandOutput {
                    stdout: "success\n".to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            ),
    );
    let ctx = Context::with_executor(executor.clone());

    let reloaded = FirewallHardeningPlugin::new()
        .reload_after_rollback(&ctx)
        .await
        .expect("a firewalld reload that succeeded is not an error");

    assert!(reloaded.is_some(), "the reload must be reported");
    assert_reload_only(&logged_commands(&executor), "firewall-cmd --reload");
}

/// nftables re-reads its persistent ruleset with `nft -f /etc/nftables.conf`.
/// The old path built an `inet filter` table with an input chain whose policy
/// is `drop`, which leaves the applied posture live and hardens a host that
/// had no firewall before the apply the operator is undoing.
#[tokio::test]
async fn an_nftables_rollback_reloads_rather_than_installing_a_drop_policy() {
    let executor = Arc::new(
        MockExecutor::new()
            .with_command_exists("firewall-cmd", false)
            .with_command_exists("ufw", false)
            .with_command_exists("nft", true)
            .with_command(
                "nft",
                &["list", "ruleset"],
                CommandOutput {
                    stdout: "table inet filter { chain input { type filter hook input }}"
                        .to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            )
            .with_command(
                "nft",
                &["-f", "/etc/nftables.conf"],
                CommandOutput {
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            ),
    );
    let ctx = Context::with_executor(executor.clone());

    let reloaded = FirewallHardeningPlugin::new()
        .reload_after_rollback(&ctx)
        .await
        .expect("an nftables reload that succeeded is not an error");

    assert!(reloaded.is_some(), "the reload must be reported");
    let commands = logged_commands(&executor);
    assert_reload_only(&commands, "nft -f /etc/nftables.conf");
    assert!(
        !commands
            .iter()
            .any(|c| c.contains("policy") && c.contains("drop")),
        "a rollback must not install a drop-policy chain, got: {commands:?}"
    );
}

/// ufw re-reads `/etc/ufw/**` on `ufw reload`, which leaves an inactive ufw
/// inactive. `ufw --force enable` would turn the firewall on and write
/// `ENABLED=yes` into the very file the rollback has just restored.
#[tokio::test]
async fn a_ufw_rollback_reloads_rather_than_forcing_it_on() {
    let executor = Arc::new(
        MockExecutor::new()
            .with_command_exists("firewall-cmd", false)
            .with_command_exists("ufw", true)
            .with_command_exists("nft", false)
            .with_command(
                "ufw",
                &["status"],
                CommandOutput {
                    stdout: "Status: active\n".to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            )
            .with_command(
                "ufw",
                &["reload"],
                CommandOutput {
                    stdout: "Firewall reloaded\n".to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            ),
    );
    let ctx = Context::with_executor(executor.clone());

    let reloaded = FirewallHardeningPlugin::new()
        .reload_after_rollback(&ctx)
        .await
        .expect("a ufw reload that succeeded is not an error");

    assert!(reloaded.is_some(), "the reload must be reported");
    let commands = logged_commands(&executor);
    assert_reload_only(&commands, "ufw reload");
    assert!(
        !commands.iter().any(|c| c.contains("--force enable")),
        "a rollback must not force ufw on, got: {commands:?}"
    );
}

/// A reload the backend refused must reach the caller as an error rather than
/// as a green row: the files came back but the running firewall is still the
/// one the apply installed, and that is the difference the operator acts on.
#[tokio::test]
async fn a_refused_firewall_reload_is_reported_as_an_error() {
    let executor = Arc::new(
        MockExecutor::new()
            .with_command_exists("firewall-cmd", true)
            .with_command_exists("ufw", false)
            .with_command_exists("nft", false)
            .with_command(
                "firewall-cmd",
                &["--state"],
                CommandOutput {
                    stdout: "running\n".to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            )
            .with_command(
                "firewall-cmd",
                &["--reload"],
                CommandOutput {
                    stdout: String::new(),
                    stderr: "Authorization failed".to_string(),
                    exit_code: 1,
                },
            ),
    );
    let ctx = Context::with_executor(executor);

    let error = FirewallHardeningPlugin::new()
        .reload_after_rollback(&ctx)
        .await
        .expect_err("a refused reload must not be reported as a success");

    assert!(
        error.to_string().contains("Authorization failed"),
        "the error must carry the backend's own stderr, got: {error}"
    );
}
