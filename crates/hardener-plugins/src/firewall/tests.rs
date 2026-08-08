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
use hardener_state::manager::DEFAULT_ROLLBACK_PREFIXES;
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

/// Applies one directive to one baseline rule and hands the rule back, which is
/// what every clamp assertion below needs and nothing else.
fn rule_after_directive(id: &str, field: &str, value: &str) -> Rule {
    let mut config = PluginConfig::default();
    config
        .directives
        .insert(format!("{id}.{field}"), value.to_string());
    let mut rule = get_baseline_rules()
        .into_iter()
        .find(|r| rule_id(r) == id)
        .expect("the baseline carries the rule this test names");
    apply_rule_directives(&mut rule, id, &config);
    rule
}

/// An accepting rule admits what it matches, so it weakens as it matches more.
/// Loopback is the only accepting baseline rule with a source narrower than
/// everything, which makes it the only one this can be asked of: the SSH rule
/// the issue's own worked example names is already `any`, so `0.0.0.0/0` there
/// changes nothing and would have passed a clamp that did not exist.
#[test]
fn a_source_that_widens_an_accepting_rule_is_refused() {
    let rule = rule_after_directive("loopback", "source", "0.0.0.0/0");
    assert_eq!(rule.rule_source, "127.0.0.1/8");

    // The same value written the other way up, because a check that refused the
    // literal `0.0.0.0/0` and nothing else would pass the assertion above while
    // admitting every other spelling of the whole address space.
    let rule = rule_after_directive("loopback", "source", "8.8.8.8/0");
    assert_eq!(rule.rule_source, "127.0.0.1/8");
}

/// The direction the issue does not name, and the sharpest of the four. A
/// blocking rule refuses what it matches, so narrowing the catch-all drop to
/// one subnet stops everything outside that subnet from being dropped at all.
#[test]
fn a_source_that_narrows_a_blocking_rule_is_refused() {
    let rule = rule_after_directive("drop_default", "source", "10.0.0.0/8");
    assert_eq!(rule.rule_source, "any");
}

/// Narrowing the catch-all by protocol or by port has the same effect, and the
/// port case carries a second one: `sets_default_target` in the firewalld
/// backend is gated on this rule still holding `any`, so an override here also
/// silently stopped the zone's default target being set to DROP.
#[test]
fn a_protocol_or_port_that_narrows_a_blocking_rule_is_refused() {
    let rule = rule_after_directive("drop_default", "protocol", "tcp");
    assert_eq!(rule.rule_protocol, "all");

    let rule = rule_after_directive("drop_default", "port", "22");
    assert_eq!(rule.rule_port, "any");
}

/// `port` does not merely move. `1-65535` passes the configuration layer's
/// range check, and on the accepting SSH rule it is accept-all-TCP.
#[test]
fn a_port_range_that_widens_an_accepting_rule_is_refused() {
    let rule = rule_after_directive("ssh", "port", "1-65535");
    assert_eq!(rule.rule_port, "22");

    // A range that widens without covering everything, so the refusal is not
    // resting on the full span being recognised as a special case.
    let rule = rule_after_directive("ssh", "port", "80-90");
    assert_eq!(rule.rule_port, "22");
}

/// `any` is a protocol the configuration layer accepts, and on an accepting
/// rule it admits every protocol rather than the one the baseline named.
#[test]
fn a_protocol_that_widens_an_accepting_rule_is_refused() {
    let rule = rule_after_directive("ssh", "protocol", "any");
    assert_eq!(rule.rule_protocol, "tcp");
}

/// The stated ceiling, asserted rather than described. Two ranges of the same
/// size are ordered equal, so a source of the same width but a different
/// address is admitted. Closing this needs CIDR containment across both
/// families, which is the comparator #64 decided this plugin would not own.
///
/// This is also the control for every refusal above: a clamp that refused
/// everything would satisfy all of them and fail here.
#[test]
fn a_source_of_the_same_width_is_admitted_and_that_ceiling_is_deliberate() {
    let rule = rule_after_directive("loopback", "source", "10.0.0.0/8");
    assert_eq!(rule.rule_source, "10.0.0.0/8");
}

/// The prefix comparison itself, in both directions, which is the one thing
/// every assertion above leaves untested: they compare equal widths, or compare
/// against a value that is the whole space and never reaches the prefix
/// arithmetic at all. Fewer bits is a broader match, so the comparison runs the
/// opposite way round from the numbers, and a mutant that reversed it survived
/// the whole file until these two were written.
#[test]
fn a_bounded_source_is_measured_by_its_prefix_in_both_directions() {
    // Narrower than the baseline's /8, so an accepting rule admits it.
    let rule = rule_after_directive("loopback", "source", "127.0.0.1/16");
    assert_eq!(rule.rule_source, "127.0.0.1/16");

    // Broader than the baseline's /8 without being the whole space, so the
    // refusal cannot be resting on `Everything` being recognised.
    let rule = rule_after_directive("loopback", "source", "10.0.0.0/4");
    assert_eq!(rule.rule_source, "127.0.0.1/8");
}

/// A prefix of length zero is the whole of its family, and the whole of a
/// family is the whole of what the field can express. Without that an operator
/// spelling the catch-all's existing `any` as `0.0.0.0/0` would be refused for
/// narrowing a blocking rule, which is a refusal of a change that changes
/// nothing.
#[test]
fn a_zero_length_prefix_is_the_same_breadth_as_any() {
    let rule = rule_after_directive("drop_default", "source", "0.0.0.0/0");
    assert_eq!(rule.rule_source, "0.0.0.0/0");
}

/// Fail-closed where the two values cannot be compared at all. An IPv6 source
/// against an IPv4 baseline has no shared space to be measured in, and a
/// prefix this cannot read is not a narrowing it can vouch for.
#[test]
fn a_source_this_cannot_compare_is_refused_rather_than_guessed_at() {
    let rule = rule_after_directive("loopback", "source", "::1/128");
    assert_eq!(rule.rule_source, "127.0.0.1/8");

    let rule = rule_after_directive("loopback", "source", "10.0.0.0/33");
    assert_eq!(rule.rule_source, "127.0.0.1/8");
}

/// The order the two clamps run in is load-bearing. `action` is applied first,
/// so the field clamps are judged against the action the rule will actually
/// carry: tightening SSH into a drop rule makes a wider port a TIGHTENING, and
/// judging it against the accepting baseline would refuse a stricter ruleset.
#[test]
fn the_fields_are_judged_against_the_action_the_rule_ends_up_with() {
    let mut config = PluginConfig::default();
    config
        .directives
        .insert("ssh.action".to_string(), "drop".to_string());
    config
        .directives
        .insert("ssh.port".to_string(), "1-65535".to_string());

    let mut rule = get_baseline_rules()
        .into_iter()
        .find(|r| rule_id(r) == "ssh")
        .expect("the baseline carries an ssh rule");
    apply_rule_directives(&mut rule, "ssh", &config);

    assert_eq!(rule.rule_action, "drop");
    assert_eq!(rule.rule_port, "1-65535");
}

/// The three fields that are clamped only by direction, pinned as a positive
/// control. Without them a clamp that refused every override would pass the
/// assertions above, and changing the SSH port is the configuration
/// reference's own worked example of a legitimate override.
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

/// An apply that would leave the host admitting nothing is refused, and says
/// which of the two shapes it is.
///
/// The input chain is rendered with `policy drop` whatever it holds, so the
/// surviving rules are the whole of what the host still admits. An operator
/// reaches both bad shapes through the sanctioned route rather than by
/// accident: a policy exception, which is a documented deviation with an
/// approval date and a reason.
#[test]
fn a_ruleset_that_admits_nothing_is_refused() {
    let baseline = get_baseline_rules();
    let without = |excepted: &[&str]| -> Vec<Rule> {
        baseline
            .iter()
            .filter(|rule| !excepted.contains(&rule_id(rule).as_str()))
            .cloned()
            .collect()
    };

    // The control, and it must come first: the whole baseline is allowed from
    // anywhere. Without it a guard that refused everything would satisfy every
    // refusal assertion below.
    assert_eq!(ruleset_refusal(&baseline, true), None);
    assert_eq!(ruleset_refusal(&baseline, false), None);

    // Every rule excepted. Refused whether the session is remote or local: a
    // chain dropping even loopback is not a stricter firewall, it is an
    // unreachable host.
    for remote in [true, false] {
        let refusal = ruleset_refusal(&[], remote).expect("an empty ruleset must be refused");
        assert!(
            refusal.contains("admits nothing"),
            "the refusal must name the shape, got: {refusal}"
        );
    }

    // Only the drop-all rule survives. Not empty, and still admits nothing,
    // which is why the guard asks about accepting rules rather than about
    // count.
    let drop_only = without(&["loopback", "established", "ssh"]);
    assert_eq!(
        drop_only.len(),
        1,
        "the fixture must not be vacuously empty"
    );
    assert!(
        ruleset_refusal(&drop_only, false)
            .is_some_and(|refusal| refusal.contains("admits nothing")),
        "a ruleset of drops alone must be refused"
    );
}

/// Excepting the ssh rule alone is refused over SSH and allowed from a console.
///
/// The sharper half of #101, and the reason the guard cannot simply ask whether
/// anything survived: loopback and established are still accepting here, so a
/// ruleset that admits *something* still severs the session carrying the apply.
#[test]
fn excepting_the_ssh_rule_is_refused_only_when_it_would_sever_this_session() {
    let without_ssh: Vec<Rule> = get_baseline_rules()
        .into_iter()
        .filter(|rule| rule_id(rule) != "ssh")
        .collect();

    assert!(
        without_ssh.iter().any(|rule| rule.rule_action == "accept"),
        "the fixture must still admit something, or this measures the other \
         refusal instead of this one"
    );

    let refusal = ruleset_refusal(&without_ssh, true)
        .expect("a remote apply with no ssh accept must be refused");
    assert!(
        refusal.contains("sever the connection"),
        "the refusal must name the harm, got: {refusal}"
    );

    assert_eq!(
        ruleset_refusal(&without_ssh, false),
        None,
        "from a console the same ruleset is a coherent thing to ask for, and \
         refusing it would override a decision this tool asked the operator to \
         record"
    );

    // The ssh rule SURVIVING is not the same as the ssh rule admitting
    // anything, and this route needs no exception at all. `ssh.action = "drop"`
    // is a tightening, so `action_override_is_allowed` permits it, and the rule
    // stays in the ruleset under its own id while accepting nothing. A guard
    // that asked only whether an ssh rule was present waved this through, which
    // a surviving mutant proved before this case existed.
    let mut config = PluginConfig::default();
    config
        .directives
        .insert("ssh.action".to_string(), "drop".to_string());
    let dropping_ssh: Vec<Rule> = get_baseline_rules()
        .into_iter()
        .map(|mut rule| {
            let id = rule_id(&rule);
            apply_rule_directives(&mut rule, &id, &config);
            rule
        })
        .collect();

    assert!(
        dropping_ssh
            .iter()
            .any(|rule| rule_id(rule) == "ssh" && rule.rule_action == "drop"),
        "the fixture must reach a surviving ssh rule that drops, or it is \
         measuring the excepted case again"
    );
    assert!(
        ruleset_refusal(&dropping_ssh, true)
            .is_some_and(|refusal| refusal.contains("sever the connection")),
        "an ssh rule that survives and drops admits nothing, so a remote apply \
         must be refused exactly as if it had been excepted"
    );
}

/// A port reaches the backend as the number this tool validated, not as the
/// operator spelled it.
///
/// Every layer here reads a port with `str::parse::<u16>()`, which takes a
/// leading zero as decimal. `nft` takes it as OCTAL. Measured under nft 1.1.6:
/// `tcp dport 022 accept` loads as `tcp dport 18 accept`, and `0100` as `64`.
/// So `ssh.port = "022"` validated as 22, was clamped as one port wide against
/// a baseline of one port wide, rendered as the operator's own string, and
/// installed an accept for port 18 while 22 fell through to `policy drop`. On a
/// remote apply that severs SSH and reports success with four green changes,
/// which is issue #92's outcome arriving by a different door.
///
/// Re-rendering through the parsed `u16` makes the tool's reading and nft's
/// reading the same by construction, rather than by agreeing about notation.
#[test]
fn a_port_directive_is_applied_as_the_number_it_was_validated_as() {
    // Each of these is what `str::parse::<u16>()` accepts and `nft` reads
    // differently or refuses outright. `+22` is the second: Rust takes the
    // leading sign, nft answers "syntax error, unexpected +".
    //
    // Asserted against the transformation rather than through a directive,
    // because the breadth clamp sits between the two and would answer for it.
    // The range cases are the reason: widening the ssh rule from one port to
    // twenty-one is a weakening, so `080-0100` is refused before it can be
    // rewritten, and a test that went through a directive would report the
    // baseline value and look like a normalisation failure. The clamp reads
    // the range with the same `u16` parse, so the two cannot disagree about
    // which ports were named.
    for (spelled, canonical) in [
        ("022", "22"),
        ("0100", "100"),
        ("+22", "22"),
        ("00022", "22"),
        ("2222", "2222"),
        ("080-0100", "80-100"),
        ("80-443", "80-443"),
    ] {
        assert_eq!(
            canonical_field_value("port", spelled),
            canonical,
            "a port spelled {spelled:?} must reach the backend as {canonical:?}, \
             or the tool and nft disagree about which port was asked for"
        );
    }

    // Total, and never a guess: a value that will not parse is restated, not
    // replaced. Nothing that survives `validate_firewall_value` reaches this,
    // so it pins the fail-safe rather than a reachable path.
    assert_eq!(
        canonical_field_value("port", "any"),
        "any",
        "a value this cannot read must pass through unchanged"
    );

    // The other two fields are carried untouched. A source rewritten here would
    // silently change which addresses a rule matches.
    //
    // The fixture is deliberately a value the PORT branch would rewrite, which
    // is what makes the field check observable at all. `010.0.0.1` was the
    // first choice and proved nothing: it does not parse as a `u16`, so it
    // falls through the port branch unchanged and the assertion held whether
    // the field was checked or not. A mutation dropping the field check
    // survived it.
    for field in ["source", "protocol"] {
        assert_eq!(
            canonical_field_value(field, "022"),
            "022",
            "only `port` is renotated; {field} must reach the backend as \
             written, whatever the port branch would have made of it"
        );
    }
}

/// The clamp and the renotation must read a port the same way, or one of them
/// is measuring a value the other will not produce.
#[test]
fn the_breadth_clamp_reads_a_port_the_way_it_will_be_rendered() {
    let mut config = PluginConfig::default();
    // 1024-2048 is 1025 ports against the ssh rule's one, so this is refused
    // for its width. Spelled with leading zeros it must be refused for exactly
    // the same reason: if the clamp read `01024` as anything else, an override
    // could be admitted on a width nobody asked for.
    config
        .directives
        .insert("ssh.port".to_string(), "01024-02048".to_string());

    let mut rule = get_baseline_rules()
        .into_iter()
        .find(|r| rule_id(r) == "ssh")
        .expect("the baseline carries an ssh rule");
    apply_rule_directives(&mut rule, "ssh", &config);

    assert_eq!(
        rule.rule_port, "22",
        "a range that widens the rule must be refused however it is spelled"
    );
}

/// The same value, followed all the way to the statement nft is handed.
///
/// The assertion above is about the rule; this one is about the file, because
/// the defect was only ever visible at the point the two readings met.
#[test]
fn a_port_spelled_with_a_leading_zero_renders_as_the_decimal_port() {
    let mut config = PluginConfig::default();
    config
        .directives
        .insert("ssh.port".to_string(), "022".to_string());

    let mut rule = get_baseline_rules()
        .into_iter()
        .find(|r| rule_id(r) == "ssh")
        .expect("the baseline carries an ssh rule");
    apply_rule_directives(&mut rule, "ssh", &config);

    let statement = nftables::NftablesBackend::new().build_nft_rule_args(&rule)[5..].join(" ");

    assert_eq!(
        statement, "tcp dport 22 accept",
        "the rendered statement must name the port the operator asked for; \
         `tcp dport 022 accept` is read by nft as port 18"
    );
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

/// The dispatcher only calls a plugin's reload when one of these matches, and
/// this method cannot probe: it is synchronous and has no Context. So it names
/// every boot path the shipped units use. Missing one means a rollback on that
/// distribution silently reloads nothing.
#[test]
fn the_rollback_dispatcher_reaches_every_nftables_boot_path() {
    let plugin = FirewallHardeningPlugin::new();
    for path in [
        "/etc/nftables.conf",
        "/etc/sysconfig/nftables.conf",
        "/etc/nftables/rules/main.nft",
        "/etc/linux-hardener/nftables/50-linux-hardener.nft",
        "/etc/ufw",
        "/etc/firewalld",
    ] {
        assert!(
            plugin.reloads_for_path(Path::new(path)),
            "{path} must trigger a firewall reload after a rollback"
        );
    }
    assert!(
        !plugin.reloads_for_path(Path::new("/etc/ssh/sshd_config")),
        "an unrelated path must not"
    );
}

/// A bare successful command, for a mock registration whose only relevant
/// fact is that the command was allowed to run.
fn nft_ok() -> CommandOutput {
    CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
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
            // Present on this fixture's host, unlike the Fedora/RHEL case
            // covered by `an_nftables_rollback_does_not_fail_when_the_restored_file_is_absent`,
            // so the reload's existence guard does not skip the `nft -f` call
            // this test exists to assert.
            .with_path_exists("/etc/nftables.conf", true)
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
            // The reload now probes which file nftables.service actually
            // loads, rather than assuming NFTABLES_CONFIG_PATH, so a mock
            // that never answers `systemctl show` would make that probe
            // report "cannot tell" and skip the `nft -f` call this test
            // exists to assert.
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
                    stdout: "ExecStart={ path=/usr/bin/nft ; argv[]=/usr/bin/nft -f /etc/nftables.conf }\n"
                        .to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            )
            .with_command("nft", &["destroy", "table", "inet", "linux_hardener"], nft_ok())
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

/// Fedora and RHEL ship `/etc/sysconfig/nftables.conf`, not
/// `/etc/nftables.conf`. On a host where nftables wins backend detection and
/// `/etc/nftables.conf` was never present, the checkpoint correctly records
/// the path as absent and the restore DELETES the ruleset the apply rendered
/// there, leaving nothing to reload, but the reload used to run
/// `nft -f /etc/nftables.conf` regardless: `nft` exits 1 on a file that is
/// not there, `execute_nft` turns that into an error, and a rollback that did
/// everything possible on that host still exited 1 telling the operator a
/// service was left on the old configuration.
#[tokio::test]
async fn an_nftables_rollback_does_not_fail_when_the_restored_file_is_absent() {
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
            // The reload now probes for the boot path rather than assuming
            // NFTABLES_CONFIG_PATH, and an unregistered `systemctl show`
            // would make that probe report "cannot tell" instead of
            // exercising the confirmed-absence guard this test is for, so the
            // probe is answered exactly as it would be for the file this test
            // is about.
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
                    stdout: "ExecStart={ path=/usr/bin/nft ; argv[]=/usr/bin/nft -f /etc/nftables.conf }\n"
                        .to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            )
            .with_command("nft", &["destroy", "table", "inet", "linux_hardener"], nft_ok()),
        // Deliberately no `with_path_exists` for /etc/nftables.conf and no
        // `nft -f /etc/nftables.conf` registration: MockExecutor's default
        // `path_exists` answer for an unregistered path is `false`, which is
        // exactly what a Fedora or RHEL host that never had this file looks
        // like. If the fix ever asks `nft` to load it anyway, the command is
        // unregistered and the mock refuses it, failing this test.
    );
    let ctx = Context::with_executor(executor.clone());

    let reloaded = FirewallHardeningPlugin::new()
        .reload_after_rollback(&ctx)
        .await
        .expect("an absent /etc/nftables.conf must not fail the rollback");

    assert!(reloaded.is_some(), "the reload must still be reported");
    let commands = logged_commands(&executor);
    assert!(
        !commands.iter().any(|c| c.starts_with("nft -f")),
        "nft must not be asked to load a file that is not there, got: {commands:?}"
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

/// Builds one accepting rule carrying `port`, which is all three assertions
/// below need and nothing else.
fn rule_with_port(port: &str) -> Rule {
    Rule {
        rule_description: "Allow a range".to_string(),
        rule_protocol: "tcp".to_string(),
        rule_port: port.to_string(),
        rule_source: "any".to_string(),
        rule_action: "accept".to_string(),
    }
}

/// ufw spells a port range with a colon and refuses the dash outright, so the
/// canonical dash has to be translated at the point it reaches ufw and nowhere
/// earlier. Measured before this was written: `ufw --dry-run allow to any port
/// 80-443 proto tcp` answers `ERROR: Bad port '80-443'` and exits 1, while the
/// colon form gets past the parser to the root check.
///
/// The whole argument list is pinned rather than one element of it, so the
/// command measured against real ufw and the command this backend builds cannot
/// drift apart.
#[test]
fn a_port_range_reaches_ufw_in_ufws_own_syntax() {
    let args = ufw::UfwBackend::new().build_ufw_rule_args(&rule_with_port("80-443"));

    assert_eq!(
        args,
        vec!["allow", "to", "any", "port", "80:443", "proto", "tcp"],
        "ufw must be given its own range syntax, and the rest of the rule unchanged"
    );
}

/// The control that keeps the translation ufw-local. nftables takes the dash
/// natively, so a fix applied to the shared canonical form rather than to ufw
/// would break this backend while making the one above pass. firewalld is the
/// third case and needs the dash too, rendering `80-443/tcp` inside its own
/// `apply_rules`; it has no pure builder to assert against here, and the rule
/// it depends on is the one this test pins.
#[test]
fn a_port_range_reaches_nftables_in_the_canonical_syntax() {
    let args = nftables::NftablesBackend::new().build_nft_rule_args(&rule_with_port("80-443"));

    assert!(
        args.contains(&"80-443".to_string()),
        "nftables takes the canonical range unchanged, got: {args:?}"
    );
}

/// The second control, and the one that says the translation fires on a range
/// rather than on every port. A single port has no separator to rewrite, and a
/// translation that reached it would corrupt the one value every baseline rule
/// carries.
#[test]
fn a_single_port_is_untouched_by_either_backend() {
    let ufw_args = ufw::UfwBackend::new().build_ufw_rule_args(&rule_with_port("22"));
    let nft_args = nftables::NftablesBackend::new().build_nft_rule_args(&rule_with_port("22"));

    assert!(
        ufw_args.contains(&"22".to_string()),
        "ufw must carry a single port through unchanged, got: {ufw_args:?}"
    );
    assert!(
        nft_args.contains(&"22".to_string()),
        "nftables must carry a single port through unchanged, got: {nft_args:?}"
    );
}

/// The guard on the translation, and the reason it is a parse rather than a
/// blind character swap. A value that is not a dash-separated pair of port
/// numbers is passed to ufw unchanged, so it fails at ufw with ufw's own
/// message instead of being quietly rewritten into a different malformed
/// value here. `validate_firewall_value` refuses such a value on every path
/// that goes through a config, so this pins intent rather than a reachable
/// case.
#[test]
fn a_value_that_is_not_a_range_is_handed_to_ufw_unchanged() {
    let args = ufw::UfwBackend::new().build_ufw_rule_args(&rule_with_port("22-"));

    assert!(
        args.contains(&"22-".to_string()),
        "an unparseable range must reach ufw as written, got: {args:?}"
    );
}

/// The input chain's rules, one whole line per element, with the chain header
/// and the braces around it removed.
///
/// Every assertion about the rendered ruleset used to be a `contains` or a
/// `find` over the whole blob, which anchors a needle to nothing, and two
/// mutations proved the cost. Rendering each statement behind a `# ` marker
/// ships `policy drop;` with no effective rules, which is issue #92's own
/// outcome delivered in one transaction, and every needle still matched inside
/// the commented line in the same byte order. Slicing the argv from index 4
/// rather than 5 prefixes every statement with the chain name, which `nft`
/// refuses outright, and a needle built from `args[5..]` is then a suffix of
/// the rendered line and invisible to `contains`.
///
/// Comparing whole lines for equality kills both: a commented-out statement is
/// not its statement, and a prefixed one is not its statement either.
fn input_chain_rule_lines(rendered: &str) -> Vec<String> {
    let after_header = rendered
        .split("chain input {")
        .nth(1)
        .expect("an input chain must be rendered");

    // `split(..).next()` was the first form of this and could not fail:
    // `Split::next` returns `Some` even when the separator is absent, yielding
    // the whole remainder, so a ruleset with no forward chain silently handed
    // back the output chain's header and policy line as though they were rules
    // of the input chain. `split_once` is the form whose `None` means what the
    // message says.
    after_header
        .split_once("chain forward")
        .expect("the input chain must end before the forward chain")
        .0
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && *line != "}")
        .skip_while(|line| line.contains("hook input"))
        .map(str::to_string)
        .collect()
}

/// The ordering guarantee issue #92 is about, asserted inside the input chain
/// alone.
///
/// Searching the whole rendered file was vacuous: the `forward` chain's own
/// `policy drop` always follows the statements block, so any "the drop comes
/// last" assertion held regardless of rule order. The needles come from
/// `build_nft_rule_args` so the test cannot drift from what a rule renders as,
/// and each is matched against a whole line for the reasons
/// [`input_chain_rule_lines`] records.
#[test]
fn the_ssh_accept_precedes_the_drop_all_rule() {
    let backend = nftables::NftablesBackend::new();
    let rules = get_baseline_rules();
    let rendered = nftables::render_ruleset(&rules).expect("the baseline renders");
    let statements = input_chain_rule_lines(&rendered);

    let position = |needle: &str| {
        let rule = rules
            .iter()
            .find(|r| r.rule_description.contains(needle))
            .unwrap_or_else(|| panic!("no baseline rule describing {needle:?}"));
        let statement = backend.build_nft_rule_args(rule)[5..].join(" ");
        statements
            .iter()
            .position(|line| *line == statement)
            .unwrap_or_else(|| {
                panic!(
                    "no rule of the input chain is exactly {statement:?}, so the \
                     rule describing {needle:?} is not in force: the chain's rules \
                     were {statements:#?}"
                )
            })
    };

    assert!(
        position("Allow SSH") < position("Drop all other"),
        "the SSH accept must precede the drop-all rule, or a remote apply locks \
         the operator out: the input chain's rules were {statements:#?}"
    );
    assert!(
        position("established and related") < position("Drop all other"),
        "the established/related accept must precede the drop-all rule, or an \
         in-flight connection is severed: the input chain's rules were \
         {statements:#?}"
    );
    // Named separately rather than left to the other two. `drop` is a terminal
    // verdict, so any accept rendered after it is dead, and rotating the
    // loopback rule to the end left both assertions above holding while
    // loopback traffic was dropped.
    assert!(
        position("loopback") < position("Drop all other"),
        "the loopback accept must precede the drop-all rule, or the host cannot \
         talk to itself: the input chain's rules were {statements:#?}"
    );
}

/// The load must replace the plugin's own table outright rather than merge
/// into it, or a second apply stacks a duplicate of every baseline rule, and
/// the replacement must reach no table the plugin did not create.
///
/// Both rejected drafts are pinned by name, because both are destructive and
/// both looked reasonable when written. A whole-ruleset `flush ruleset` came
/// first and would take Docker's and libvirt's tables down with it. Scoping
/// the same statements to `inet filter` came second: that is the conventional
/// default name and not an owned one, so the delete destroyed administrators'
/// own rules on any host using it, measured in a network namespace against an
/// admin chain that survived the old incremental path and did not survive
/// this one.
#[test]
fn the_rendered_file_replaces_only_its_own_table() {
    let rendered = nftables::render_ruleset(&get_baseline_rules()).expect("the baseline renders");
    let table = nftables::NFTABLES_TABLE;

    // Every conventional name, not only `filter`. One literal was one literal
    // deep: renaming the constant to `nat` left this test green while the
    // ruleset issued `delete table inet nat` on every apply.
    for conventional in ["filter", "nat", "route", "mangle", "raw", "security"] {
        assert_ne!(
            table, conventional,
            "the owned table must not take a conventional name: those are the \
             names distributions and other subsystems give their own tables, so \
             replacing one replaces whatever its owner put there"
        );
    }
    assert!(
        rendered.starts_with(&format!("table inet {table}\ndelete table inet {table}\n")),
        "the file must create, then delete, then rebuild its own table, or a \
         second apply either fails against an absent table or merges into a \
         present one: rendered\n{rendered}"
    );

    // `destroy` is nftables' third destructive verb and was the hole here: a
    // rendered `destroy table inet filter` was measured live against an
    // administrator's table holding `tcp dport 443 accept`, the load reported
    // success, and the table was gone afterwards, with this test green.
    let destructive: Vec<&str> = rendered
        .lines()
        .map(str::trim)
        .filter(|line| {
            matches!(
                line.split_whitespace().next(),
                Some("delete") | Some("flush") | Some("destroy")
            )
        })
        .collect();
    assert_eq!(
        destructive,
        vec![format!("delete table inet {table}")],
        "the ruleset may destroy its own table and nothing else: a \
         `flush ruleset` takes down Docker's and libvirt's tables, and any \
         delete or destroy naming another table takes down whatever its owner \
         put there. Rendered\n{rendered}"
    );

    // Verb-agnostic, so a destructive statement spelled a way the list above
    // does not know still cannot name somebody else's table.
    let foreign: Vec<&str> = rendered
        .lines()
        .map(str::trim)
        .filter(|line| line.contains("table") && !line.contains(&format!("table inet {table}")))
        .collect();
    assert!(
        foreign.is_empty(),
        "no statement may name a table other than {table}, whatever it does to \
         it, got {foreign:#?} in\n{rendered}"
    );
}

/// The input chain keeps its drop policy. Inside one transaction it is never
/// live without the accepts, and dropping it would leave a host that fails a
/// mid-apply error open rather than closed.
///
/// Each declaration is matched as a whole line: a chain header behind a `# `
/// marker still contains every substring of itself, and a chain that declares
/// no type or hook is not a filter chain at all.
#[test]
fn the_input_chain_keeps_its_drop_policy() {
    let rendered = nftables::render_ruleset(&get_baseline_rules()).expect("the baseline renders");
    let declares = |declaration: &str| rendered.lines().any(|line| line.trim() == declaration);

    assert!(
        declares("type filter hook input priority 0; policy drop;"),
        "input must stay policy drop: rendered\n{rendered}"
    );
    assert!(
        declares("type filter hook forward priority 0; policy drop;"),
        "forward must stay policy drop, or the host silently routes traffic \
         between its interfaces: rendered\n{rendered}"
    );
    assert!(
        declares("type filter hook output priority 0; policy accept;"),
        "output must stay policy accept, or the host cannot reply at all: \
         rendered\n{rendered}"
    );
}

/// The renderer and the incremental path must not disagree about what a rule
/// means, so both take their statement from `build_nft_rule_args`.
///
/// Asserted in both directions. Every baseline rule must render as a whole
/// line, which refuses a statement that has gained a prefix or a comment
/// marker, and the chain must hold no line beyond them, which refuses one that
/// nothing in the baseline asked for.
#[test]
fn every_baseline_rule_renders_the_statement_the_argv_builder_produces() {
    let backend = nftables::NftablesBackend::new();
    let rules = get_baseline_rules();
    let rendered = nftables::render_ruleset(&rules).expect("the baseline renders");
    let statements = input_chain_rule_lines(&rendered);

    // Both sides of the comparison below come from `rules`, so an empty
    // baseline satisfies every one of them: the loop body never runs and
    // `0 == 0` holds. Refusing that first is what stops this test passing on a
    // ruleset with no rules in it at all.
    assert!(
        !rules.is_empty(),
        "the baseline must carry rules, or everything below is vacuous"
    );

    for rule in &rules {
        let statement = backend.build_nft_rule_args(rule)[5..].join(" ");
        assert!(
            statements.contains(&statement),
            "rule {:?} rendered as something other than the line {statement:?}: \
             the input chain's rules were {statements:#?}",
            rule.rule_description
        );
    }

    // Order included, not only membership and count. A rotation of the rendered
    // statements kept every membership assertion and the count holding while
    // moving an accept behind the terminal `drop`.
    let expected: Vec<String> = rules
        .iter()
        .map(|rule| backend.build_nft_rule_args(rule)[5..].join(" "))
        .collect();
    assert_eq!(
        statements, expected,
        "the input chain must hold one line per baseline rule, in the baseline's \
         own order and with nothing else among them"
    );
}

/// A rule whose only distinguishing feature is the source it matches on.
///
/// Deliberately not described as "loopback" or "established and related":
/// `build_nft_rule_args` branches on the description before it ever reads the
/// source, and a fixture that tripped one of those branches would render a
/// statement with no `saddr` in it at all and assert nothing.
fn rule_with_source(source: &str) -> Rule {
    Rule {
        rule_description: format!("Allow SSH from {source}"),
        rule_protocol: "tcp".to_string(),
        rule_port: "22".to_string(),
        rule_source: source.to_string(),
        rule_action: "accept".to_string(),
    }
}

/// `ip` and `ip6` are different match expressions and nft infers neither, so
/// the family has to come from the address.
///
/// An IPv6 source used to render `ip saddr ::1`, which nft refuses with
/// "Address family for hostname not supported". Under the per-rule path that
/// cost one rule; under one transaction it costs the whole load, so no baseline
/// rule lands at all, drop-all included.
#[test]
fn a_source_renders_the_match_of_its_own_address_family() {
    let backend = nftables::NftablesBackend::new();

    for (source, family) in [
        ("10.0.0.0/8", "ip"),
        ("127.0.0.1", "ip"),
        ("::1", "ip6"),
        ("2001:db8::/32", "ip6"),
        ("::ffff:10.0.0.1", "ip6"),
    ] {
        let args = backend.build_nft_rule_args(&rule_with_source(source));
        let statement = args[5..].join(" ");

        assert_eq!(
            statement,
            format!("{family} saddr {source} tcp dport 22 accept"),
            "a {source} source must be matched with {family}, or nft refuses \
             the statement and the whole transaction with it"
        );
    }
}

/// A source nft cannot match on is refused before anything is written.
///
/// This is the cheaper of two refusals, and it still matters with the other
/// one in place. `refuse_a_ruleset_nft_will_not_parse` asks a real
/// `nft --check` against a scratch file before `apply_rules` ever touches the
/// boot path, which is what actually stops a ruleset `nft` rejects from
/// reaching disk; this one is pure, costs no host access, and answers only
/// the fields `render_ruleset` itself knows about. Refusing here first means
/// a source this check alone can already tell is wrong never reaches the
/// scratch-file round trip at all.
#[test]
fn a_source_that_cannot_be_matched_on_refuses_the_whole_ruleset() {
    for source in [
        "not-an-address",
        "999.1.1.1",
        "10.0.0.0/33",
        "2001:db8::/129",
        "10.0.0.0/eight",
        "",
    ] {
        // Second of two, deliberately. Every fixture here was a one-rule slice
        // at first, so a check that stopped after the first source passed all
        // six: a ruleset whose first source is valid and whose second is not
        // still reached `nft`, and `nft` refuses it after the file is written.
        let rules = [rule_with_source("10.0.0.0/8"), rule_with_source(source)];
        let refusal = nftables::render_ruleset(&rules);

        assert!(
            refusal.is_err(),
            "a {source:?} source must refuse the ruleset rather than render a \
             statement nft will reject after the file is already written, got \
             {refusal:?}"
        );
    }

    assert!(
        nftables::render_ruleset(&[rule_with_source("10.0.0.0/8")]).is_ok(),
        "the control: a source that nft can match on must still render, or the \
         refusal above is measuring nothing"
    );
}

/// Each backend checkpoints what it writes, and never a path another backend
/// owns.
///
/// The apply site used to hold one combined list of all three backends' paths,
/// so every firewall apply recorded a checkpoint row for `/etc/nftables.conf`,
/// including on ufw and firewalld hosts where no apply can create it. A row
/// recorded absent is an instruction to delete, so a rollback on such a host
/// would have removed whatever had arrived at that path in the meantime, from
/// the `nftables` package or from the administrator, with nothing to show it
/// had ever been ours. Asking the selected backend is what stops the
/// declaration and the writing drifting apart.
#[tokio::test]
async fn a_backend_checkpoints_only_the_paths_it_writes() {
    let ruleset = nftables::NFTABLES_CONFIG_PATH;

    // checkpoint_paths now takes ctx and, for nftables, probes the host for
    // the file nftables.service actually loads. The mock answers with the
    // Arch/Debian form naming NFTABLES_CONFIG_PATH, so this fixture still
    // exercises the same "declares its own path, not a sibling's" question
    // the constant-list version asked; ufw and firewalld ignore ctx entirely.
    let ctx = Context::with_executor(Arc::new(MockExecutor::new().with_command(
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
            stdout: format!(
                "ExecStart={{ path=/usr/sbin/nft ; argv[]=/usr/sbin/nft -f {ruleset} }}\n"
            ),
            stderr: String::new(),
            exit_code: 0,
        },
    )));

    assert!(
        nftables::NftablesBackend::new()
            .checkpoint_paths(&ctx)
            .await
            .expect("a probe that succeeds must yield paths, not an error")
            .iter()
            .any(|path| path == ruleset),
        "the nftables backend renders its whole ruleset into {ruleset}, so a \
         pre-apply checkpoint has to capture it or the write is unrecoverable"
    );
    assert!(
        !ufw::UfwBackend::new()
            .checkpoint_paths(&ctx)
            .await
            .expect("ufw's declaration is a constant and never fails")
            .iter()
            .any(|path| path == ruleset),
        "a ufw apply can never create {ruleset}, so declaring it records a row \
         recorded absent that a later rollback would act on as a deletion"
    );
    assert!(
        !firewalld::FirewalldBackend::new()
            .checkpoint_paths(&ctx)
            .await
            .expect("firewalld's declaration is a constant and never fails")
            .iter()
            .any(|path| path == ruleset),
        "a firewalld apply can never create {ruleset}, so declaring it records \
         a row recorded absent that a later rollback would act on as a deletion"
    );
}

/// Ties `checkpoint_paths` to `DEFAULT_ROLLBACK_PREFIXES` directly, rather
/// than to a second, hand-copied list of the same paths that could silently
/// drift from it.
///
/// A live Debian container caught the gap this guards: nftables writes and
/// checkpoints its fragment under `/etc/linux-hardener/nftables`, a path no
/// prefix covered, so the rollback that had just captured it refused to
/// restore it. No mock ever exercises this, because MockExecutor's rollback
/// never runs `CheckpointManager`'s prefix check at all, so this asserts
/// against the exact same list that check reads from, for every boot path
/// `checkpoint_paths` can actually return: the three the shipped units load,
/// probed here with the real `ExecStart` strings the other test in this file
/// copied from the container images, plus the fragment itself.
#[tokio::test]
async fn every_path_checkpoint_paths_can_declare_is_within_the_rollback_allowlist() {
    let exec_starts = [
        (
            "Arch/Debian",
            "{ path=/usr/bin/nft ; argv[]=/usr/bin/nft -f /etc/nftables.conf ; ignore_errors=no ; status=0 }",
        ),
        (
            "Fedora/RHEL",
            "{ path=/sbin/nft ; argv[]=/sbin/nft -f /etc/sysconfig/nftables.conf ; ignore_errors=no }",
        ),
        (
            "openSUSE",
            "{ path=/usr/sbin/nft ; argv[]=/usr/sbin/nft flush ruleset; include \"/etc/nftables/rules/main.nft\" ; ignore_errors=no }",
        ),
    ];

    for (distro, exec_start) in exec_starts {
        let ctx = Context::with_executor(Arc::new(MockExecutor::new().with_command(
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
                stdout: format!("ExecStart={exec_start}\n"),
                stderr: String::new(),
                exit_code: 0,
            },
        )));

        let paths = nftables::NftablesBackend::new()
            .checkpoint_paths(&ctx)
            .await
            .expect("a probe fed a real ExecStart line must succeed");

        for path in &paths {
            assert!(
                DEFAULT_ROLLBACK_PREFIXES
                    .iter()
                    .any(|prefix| path.starts_with(prefix)),
                "{distro}: {path} is outside every DEFAULT_ROLLBACK_PREFIXES entry, \
                 so a rollback that had captured it would refuse to restore it, \
                 exactly as it did against a live Debian container"
            );
        }
    }
}

/// The four `-f` distributions and the one that is not.
///
/// These strings are what `systemctl show <unit> -p ExecStart` prints on the
/// five container images, copied rather than invented. Four of them agree,
/// which is exactly why reading only `-f` looked safe enough to ship.
#[test]
fn the_probe_reads_both_exec_start_forms() {
    let arch = "{ path=/usr/bin/nft ; argv[]=/usr/bin/nft -f /etc/nftables.conf ; ignore_errors=no ; status=0 }";
    let fedora =
        "{ path=/sbin/nft ; argv[]=/sbin/nft -f /etc/sysconfig/nftables.conf ; ignore_errors=no }";
    let opensuse = "{ path=/usr/sbin/nft ; argv[]=/usr/sbin/nft flush ruleset; include \"/etc/nftables/rules/main.nft\" ; ignore_errors=no }";

    assert_eq!(
        nftables::parse_boot_ruleset(arch, "").loads.as_deref(),
        Ok("/etc/nftables.conf"),
        "the Arch and Debian form names its file with -f"
    );
    assert_eq!(
        nftables::parse_boot_ruleset(fedora, "").loads.as_deref(),
        Ok("/etc/sysconfig/nftables.conf"),
        "Fedora and RHEL name a different file with the same -f form"
    );
    assert_eq!(
        nftables::parse_boot_ruleset(opensuse, "").loads.as_deref(),
        Ok("/etc/nftables/rules/main.nft"),
        "openSUSE carries no -f at all and names its file inside an inline include"
    );
}

/// A unit that does not exist prints an empty ExecStart and exits 0, so the
/// exit code cannot be the signal. Every unreadable answer has to name itself.
#[test]
fn the_probe_never_invents_a_path() {
    for (exec_start, why) in [
        ("", "an absent unit prints nothing and exits 0"),
        ("   ", "whitespace is the same nothing"),
        (
            "{ path=/usr/bin/nft ; ignore_errors=no }",
            "an ExecStart with no argv",
        ),
        (
            "{ path=/usr/bin/nft ; argv[]=/usr/bin/nft list ruleset ; ignore_errors=no }",
            "an argv naming neither -f nor an include",
        ),
        (
            "{ path=/usr/bin/nft ; argv[]=/usr/bin/nft -f ; ignore_errors=no }",
            "a -f with nothing after it",
        ),
    ] {
        let probed = nftables::parse_boot_ruleset(exec_start, "");
        assert!(
            probed.loads.is_err(),
            "{why} must not yield a path, got {:?}",
            probed.loads
        );
        assert!(
            !probed.loads.unwrap_err().is_empty(),
            "{why} must say why it could not tell"
        );
    }
}

/// openSUSE gates the unit on the very file it loads, so systemd already
/// treats that file's absence as "do not run" rather than as a failure. The
/// rollback guard in Task 4 turns on this flag, and without it that guard
/// repeats the mistake that got the first #97 fix withdrawn.
#[test]
fn a_condition_on_the_loaded_file_is_recognised() {
    let opensuse = "{ path=/usr/sbin/nft ; argv[]=/usr/sbin/nft flush ruleset; include \"/etc/nftables/rules/main.nft\" }";

    assert!(
        nftables::parse_boot_ruleset(opensuse, "/etc/nftables/rules/main.nft").condition_guards_it,
        "a condition naming the loaded file guards it"
    );
    assert!(
        !nftables::parse_boot_ruleset(opensuse, "/etc/nftables/rules/other.nft")
            .condition_guards_it,
        "a condition naming a different file guards nothing"
    );
    assert!(
        !nftables::parse_boot_ruleset(opensuse, "").condition_guards_it,
        "no condition guards nothing"
    );
}

/// The probe asks the target, not the controller. A distribution table read
/// from the controller's /etc/os-release would be wrong for every --ssh host.
#[tokio::test]
async fn the_probe_asks_the_target_through_the_executor() {
    let executor = Arc::new(
        MockExecutor::new().with_command(
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
                stdout:
                    "ExecStart={ path=/usr/bin/nft ; argv[]=/usr/bin/nft -f /etc/nftables.conf }\n"
                        .to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        ),
    );
    let ctx = Context::with_executor(executor.clone());

    let probed = nftables::boot_ruleset(&ctx).await;

    assert_eq!(probed.loads.as_deref(), Ok("/etc/nftables.conf"));
}

/// A systemctl that cannot be run is not a host with no boot file.
#[tokio::test]
async fn a_systemctl_that_fails_is_not_an_answer() {
    // The stdout here is deliberately a well-formed ExecStart line, not empty.
    // An empty stdout would still parse to an Err on its own (no ExecStart
    // found), which would let this test pass even if the exit-code gate that
    // is actually under test were deleted. Pairing a parseable stdout with a
    // failing exit code is what makes the gate itself the thing being
    // measured: the probe must distrust this stdout because the command that
    // produced it failed, not because the text was unreadable.
    let executor = Arc::new(
        MockExecutor::new().with_command(
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
                stdout:
                    "ExecStart={ path=/usr/bin/nft ; argv[]=/usr/bin/nft -f /etc/nftables.conf }\n"
                        .to_string(),
                stderr: "Failed to connect to bus".to_string(),
                exit_code: 1,
            },
        ),
    );
    let ctx = Context::with_executor(executor.clone());

    assert!(
        nftables::boot_ruleset(&ctx).await.loads.is_err(),
        "a failed systemctl must report that it could not tell"
    );
}

/// A rollback that leaves the applied table live reports an undo it did not
/// perform. The restored boot file never mentions our table, so loading it
/// cannot remove it.
#[tokio::test]
async fn a_rollback_removes_the_table_the_apply_installed() {
    let executor = Arc::new(
        MockExecutor::new()
            .with_command_exists("nft", true)
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
                    stdout: "ExecStart={ path=/usr/bin/nft ; argv[]=/usr/bin/nft -f /etc/nftables.conf }\n"
                        .to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            )
            .with_path_exists("/etc/nftables.conf", true)
            .with_command("nft", &["destroy", "table", "inet", "linux_hardener"], nft_ok())
            .with_command("nft", &["-f", "/etc/nftables.conf"], nft_ok()),
    );
    let ctx = Context::with_executor(executor.clone());

    nftables::NftablesBackend::new()
        .reload(&ctx)
        .await
        .expect("the reload must succeed");

    let commands = logged_commands(&executor);
    assert!(
        commands
            .iter()
            .any(|c| c == "nft destroy table inet linux_hardener"),
        "the applied table must be removed from the running kernel, got {commands:?}"
    );
}

/// A failed `destroy` is not by itself proof the table survived it: an nft
/// older than 1.0.6 refuses the subcommand outright, table or no table, and
/// that harmless case must not turn into a reported rollback failure. But
/// when `nft list table` confirms the table this destroy was meant to remove
/// is still there, the reload must fail rather than let a rollback report
/// success while `policy drop` is still live on the host.
#[tokio::test]
async fn a_rollback_fails_when_a_failed_destroy_leaves_the_table_present() {
    let executor = Arc::new(
        MockExecutor::new()
            .with_command_exists("nft", true)
            .with_command(
                "nft",
                &["destroy", "table", "inet", "linux_hardener"],
                CommandOutput {
                    stdout: String::new(),
                    stderr: "Error: unknown command destroy".to_string(),
                    exit_code: 1,
                },
            )
            .with_command(
                "nft",
                &["list", "table", "inet", "linux_hardener"],
                CommandOutput {
                    stdout: "table inet linux_hardener {\n\tchain input {\n\t\ttype filter \
                             hook input priority filter; policy drop;\n\t}\n}\n"
                        .to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            ),
    );
    let ctx = Context::with_executor(executor.clone());

    let error = nftables::NftablesBackend::new()
        .reload(&ctx)
        .await
        .expect_err(
            "a rollback must not report success while the table it tried to remove is \
             still there",
        );

    assert!(
        error.to_string().contains("linux_hardener"),
        "the error must name the table that survived the destroy, got: {error}"
    );
    let commands = logged_commands(&executor);
    assert!(
        commands
            .iter()
            .any(|c| c == "nft list table inet linux_hardener"),
        "a failed destroy must be confirmed against a real list, got: {commands:?}"
    );
    assert!(
        !commands
            .iter()
            .any(|c| c.starts_with("systemctl show") || c.starts_with("nft -f")),
        "the reload must fail before it ever probes the boot path, got: {commands:?}"
    );
}

/// Issue #97: an apply enables the unit and creates the file; a rollback
/// deletes the file and leaves the unit enabled, so Type=oneshot fails at the
/// next boot and the host comes up unfiltered.
#[tokio::test]
async fn a_rollback_disables_a_unit_left_with_nothing_to_load() {
    let executor = Arc::new(
        MockExecutor::new()
            .with_command_exists("nft", true)
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
                    stdout: "ExecStart={ path=/usr/bin/nft ; argv[]=/usr/bin/nft -f /etc/nftables.conf }\n"
                        .to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            )
            .with_path_exists("/etc/nftables.conf", false)
            .with_command("nft", &["destroy", "table", "inet", "linux_hardener"], nft_ok())
            .with_command("systemctl", &["disable", "nftables"], nft_ok()),
    );
    let ctx = Context::with_executor(executor.clone());

    nftables::NftablesBackend::new()
        .reload(&ctx)
        .await
        .expect("the reload must succeed");

    let commands = logged_commands(&executor);
    assert!(
        commands.iter().any(|c| c == "systemctl disable nftables"),
        "a unit whose file is gone must not be left to fail at boot, got {commands:?}"
    );
}

/// The mistake that got the first #97 fix withdrawn. On Fedora and RHEL the
/// unit loads /etc/sysconfig/nftables.conf, which a rollback of
/// /etc/nftables.conf never touched, so the firewall works and disabling it
/// would leave the host with none from the next reboot.
#[tokio::test]
async fn a_rollback_leaves_a_working_unit_alone() {
    let executor = Arc::new(
        MockExecutor::new()
            .with_command_exists("nft", true)
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
                    stdout: "ExecStart={ path=/sbin/nft ; argv[]=/sbin/nft -f /etc/sysconfig/nftables.conf }\n"
                        .to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            )
            .with_path_exists("/etc/sysconfig/nftables.conf", true)
            .with_command("nft", &["destroy", "table", "inet", "linux_hardener"], nft_ok())
            .with_command("nft", &["-f", "/etc/sysconfig/nftables.conf"], nft_ok()),
    );
    let ctx = Context::with_executor(executor.clone());

    nftables::NftablesBackend::new()
        .reload(&ctx)
        .await
        .expect("the reload must succeed");

    assert!(
        !logged_commands(&executor)
            .iter()
            .any(|c| c.contains("disable")),
        "a unit that loads a file which still exists must be left enabled"
    );
}

/// openSUSE gates the unit on the file it loads, so systemd already treats the
/// absence as "do not run" and there is no failing unit to prevent. Disabling
/// it would leave it off for an administrator who later creates main.nft.
#[tokio::test]
async fn a_rollback_leaves_a_condition_guarded_unit_alone() {
    let executor = Arc::new(
        MockExecutor::new()
            .with_command_exists("nft", true)
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
                    stdout: "ExecStart={ path=/usr/sbin/nft ; argv[]=/usr/sbin/nft flush ruleset; include \"/etc/nftables/rules/main.nft\" }\n\
                             ConditionPathExists=/etc/nftables/rules/main.nft\n"
                        .to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            )
            .with_path_exists("/etc/nftables/rules/main.nft", false)
            .with_command("nft", &["destroy", "table", "inet", "linux_hardener"], nft_ok()),
    );
    let ctx = Context::with_executor(executor.clone());

    nftables::NftablesBackend::new()
        .reload(&ctx)
        .await
        .expect("the reload must succeed");

    assert!(
        !logged_commands(&executor)
            .iter()
            .any(|c| c.contains("disable")),
        "systemd already handles a missing file here, so this must not be disabled"
    );
}

/// Finding 6 (final review): the rollback divergence probe used to treat
/// every `detect_backend` error alike, so an executor failure mid-detection
/// read exactly like "nothing installed" and produced silence rather than an
/// `Unverifiable` row. The split relies on `is_no_backend_error` telling the
/// two apart; these tests pin that predicate directly, since `MockExecutor`'s
/// own `command_exists` never errors and so cannot drive `classify_installed`
/// down its failure path.
#[test]
fn is_no_backend_error_matches_only_the_nothing_installed_case() {
    assert!(is_no_backend_error(&no_backend_error()));
}

#[test]
fn is_no_backend_error_rejects_any_other_plugin_error() {
    let other = hardener_common::error::HardeningError::Plugin("ufw is not responding".to_string());
    assert!(!is_no_backend_error(&other));
}

#[test]
fn is_no_backend_error_rejects_a_different_error_variant() {
    let executor_failure = hardener_common::error::HardeningError::Executor(
        "command_exists failed: sh not found".to_string(),
    );
    assert!(!is_no_backend_error(&executor_failure));
}
