#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`mac`].
//!
//! Split out of `mac.rs`. This file sits in the `mac/` directory
//! beside it, so `super` still resolves to `crate::mac` and every
//! import carried across unchanged, private items included.

use super::*;
use hardener_common::executor::{CommandOutput, MockExecutor};
use std::sync::Arc;

/// The arguments one command was called with, or `None` if it never ran.
fn call_args(executor: &MockExecutor, program: &str) -> Option<Vec<String>> {
    executor
        .log()
        .commands_executed
        .iter()
        .find(|(command, _)| command == program)
        .map(|(_, args)| args.clone())
}

/// A mock where `setenforce` exists and succeeds, so a test that expects it
/// not to run fails on the decision rather than on a missing command.
fn setenforce_available() -> MockExecutor {
    MockExecutor::new().with_command_program(
        "setenforce",
        CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        },
    )
}

#[tokio::test]
async fn the_restored_mode_is_read_from_the_target_not_the_controller() {
    // Every other file operation in rollback goes through the executor, so
    // against a remote host this one read the controller's own
    // /etc/selinux/config and restored the wrong mode on the target.
    let executor =
        Arc::new(setenforce_available().with_file("/etc/selinux/config", "SELINUX=permissive\n"));
    let ctx = Context::with_executor(executor.clone());

    MacHardeningPlugin::new().reload_mac_system(&ctx).await;

    assert_eq!(
        call_args(&executor, "setenforce").as_deref(),
        Some(["0".to_string()].as_slice()),
        "the target's config says permissive, so the target must be set permissive; \
         commands: {:?}",
        executor.log().commands_executed
    );
}

#[tokio::test]
async fn an_enforcing_config_on_the_target_restores_enforcing() {
    // The other direction, so the test above cannot pass by the mode being
    // hardcoded to the value it happens to expect.
    let executor =
        Arc::new(setenforce_available().with_file("/etc/selinux/config", "SELINUX=enforcing\n"));
    let ctx = Context::with_executor(executor.clone());

    MacHardeningPlugin::new().reload_mac_system(&ctx).await;

    assert_eq!(
        call_args(&executor, "setenforce").as_deref(),
        Some(["1".to_string()].as_slice()),
    );
}

#[tokio::test]
async fn a_config_that_cannot_be_read_is_not_guessed_at() {
    // The read used .ok().unwrap_or("1"), so a file that exists and cannot
    // be read produced the same answer as one that says enforcing. A
    // rollback exists to restore a recorded state, and enforcing a mode
    // nobody read is not restoring it.
    let executor = Arc::new(
        setenforce_available()
            .with_file("/etc/selinux/config", "SELINUX=permissive\n")
            .with_read_permission_denied("/etc/selinux/config"),
    );
    let ctx = Context::with_executor(executor.clone());

    MacHardeningPlugin::new().reload_mac_system(&ctx).await;

    assert!(
        call_args(&executor, "setenforce").is_none(),
        "a mode that could not be read must not be invented; commands: {:?}",
        executor.log().commands_executed
    );
}

#[tokio::test]
async fn a_host_with_no_selinux_config_reloads_apparmor() {
    // What an AppArmor host looks like. This used to work by accident:
    // setenforce was called with a guessed mode and the call failed because
    // the command is absent, which is what led to the AppArmor branch.
    let executor = Arc::new(MockExecutor::new().with_command_program(
        "systemctl",
        CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        },
    ));
    let ctx = Context::with_executor(executor.clone());

    MacHardeningPlugin::new().reload_mac_system(&ctx).await;

    assert!(
        call_args(&executor, "setenforce").is_none(),
        "no SELinux configuration means it is not an SELinux host; commands: {:?}",
        executor.log().commands_executed
    );
    assert_eq!(
        call_args(&executor, "systemctl").as_deref(),
        Some(["reload".to_string(), "apparmor".to_string()].as_slice()),
        "the AppArmor reload must still happen"
    );
}

#[test]
fn the_mode_parse_skips_comments_and_takes_the_first_directive() {
    // Pins the parse contract rather than the fix: SELinux itself takes the
    // first SELINUX= line, and a commented one sets nothing.
    assert_eq!(
        selinux_mode_argument("# SELINUX=disabled\nSELINUX=enforcing\nSELINUX=permissive\n"),
        Some("1")
    );
    assert_eq!(selinux_mode_argument("#SELINUX=enforcing\n"), None);
    assert_eq!(selinux_mode_argument("  SELINUX=permissive  \n"), Some("0"));
    // Not enforcing, and setenforce cannot disable SELinux at runtime.
    assert_eq!(selinux_mode_argument("SELINUX=disabled\n"), Some("0"));
    assert_eq!(selinux_mode_argument("SELINUXTYPE=targeted\n"), None);
}

#[tokio::test]
async fn setenforce_that_ran_and_failed_is_not_a_reload() {
    // execute_command returns Ok for a command that ran and failed, and the
    // SELinux branch tested only is_ok(). On a host carrying setenforce
    // without SELinux enabled, the rollback logged a policy reload that
    // never happened and never tried AppArmor. The AppArmor branch beside
    // it has always checked the exit code.
    let executor = Arc::new(
        MockExecutor::new()
            .with_file("/etc/selinux/config", "SELINUX=enforcing\n")
            .with_command_program(
                "setenforce",
                CommandOutput {
                    stdout: String::new(),
                    stderr: "setenforce: SELinux is disabled\n".to_string(),
                    exit_code: 1,
                },
            )
            .with_command_program(
                "systemctl",
                CommandOutput {
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            ),
    );
    let ctx = Context::with_executor(executor.clone());

    MacHardeningPlugin::new().reload_mac_system(&ctx).await;

    assert_eq!(
        call_args(&executor, "systemctl").as_deref(),
        Some(["reload".to_string(), "apparmor".to_string()].as_slice()),
        "a setenforce that exited non-zero reloaded nothing, so the other MAC \
         system is still worth trying; commands: {:?}",
        executor.log().commands_executed
    );
}

/// A host with neither SELinux nor AppArmor has nothing for a rollback to
/// reload. Claiming "MAC policy reloaded" there reports an action that never
/// happened, so the absent case must produce no row rather than a row nobody
/// can trust.
#[tokio::test]
async fn a_host_with_no_mac_system_reports_no_reload() {
    // No overrides: MockExecutor's default path_exists is false everywhere,
    // so detect_mac_system finds neither /sys/fs/selinux nor
    // /sys/kernel/security/apparmor and reports Absent.
    let executor = Arc::new(MockExecutor::new());
    let ctx = Context::with_executor(executor);

    let reloaded = MacHardeningPlugin::new()
        .reload_after_rollback(&ctx)
        .await
        .expect("an absent MAC system is not an error");

    assert_eq!(
        reloaded, None,
        "no MAC system was detected, so nothing was reloaded"
    );
}

/// A representative MAC check (`selinux-not-enforcing`) must now carry
/// multi-framework mappings: the existing CIS control plus NIST 800-53 and
/// STIG sourced from SSG `selinux_state`.
#[test]
fn selinux_enforcing_has_multi_framework_mappings() {
    let mappings = get_mac_compliance_mappings("selinux-not-enforcing");

    let has = |fw| mappings.iter().any(|m| m.compliance_framework == fw);
    assert!(
        has(ComplianceFramework::CIS),
        "CIS mapping must be retained"
    );
    assert!(
        has(ComplianceFramework::NIST),
        "NIST mapping must be present"
    );
    assert!(
        has(ComplianceFramework::STIG),
        "STIG mapping must be present"
    );

    // Verify the exact SSG-sourced STIG and NIST identifiers.
    let stig = mappings
        .iter()
        .find(|m| m.compliance_framework == ComplianceFramework::STIG)
        .unwrap();
    assert_eq!(stig.compliance_control_id, "OL08-00-010170");
    let nist = mappings
        .iter()
        .find(|m| m.compliance_framework == ComplianceFramework::NIST)
        .unwrap();
    assert_eq!(nist.compliance_control_id, "AC-3");
}

/// MAC enforcement findings must also carry HIPAA, GDPR and ISO/IEC
/// 27001:2022 mappings alongside the existing CIS/NIST/STIG set. ISO uses
/// both the Technological (8.3) and Organizational (5.15) access clauses.
#[test]
fn selinux_enforcing_has_privacy_and_iso_mappings() {
    let mappings = get_mac_compliance_mappings("selinux-not-enforcing");

    let has = |fw| mappings.iter().any(|m| m.compliance_framework == fw);
    assert!(has(ComplianceFramework::HIPAA), "HIPAA must be present");
    assert!(has(ComplianceFramework::GDPR), "GDPR must be present");
    assert!(
        has(ComplianceFramework::ISO27001),
        "ISO 27001 must be present"
    );

    // Both ISO access-control clauses (technological + organizational).
    let iso_ids: Vec<&str> = mappings
        .iter()
        .filter(|m| m.compliance_framework == ComplianceFramework::ISO27001)
        .map(|m| m.compliance_control_id.as_str())
        .collect();
    assert!(iso_ids.contains(&"8.3"), "ISO 8.3 must be present");
    assert!(iso_ids.contains(&"5.15"), "ISO 5.15 must be present");

    // HIPAA access-control safeguard for MAC enforcement. SSG cites
    // 164.312(a) (not the integrity standard) for SELinux state, so
    // 164.312(c)(1) is intentionally absent.
    assert!(
        mappings
            .iter()
            .any(|m| m.compliance_framework == ComplianceFramework::HIPAA
                && m.compliance_control_id == "164.312(a)(1)")
    );
    assert!(
        !mappings
            .iter()
            .any(|m| m.compliance_framework == ComplianceFramework::HIPAA
                && m.compliance_control_id == "164.312(c)(1)")
    );
}

/// Confirms every MAC finding type carries the SOC 2 unauthorised-software
/// criterion CC6.8, filed under its Trust Services Criteria series.
#[test]
fn mac_findings_map_soc2_unauthorised_software() {
    for finding_type in MAC_FINDING_TYPES {
        let soc2 = get_mac_compliance_mappings(finding_type)
            .into_iter()
            .find(|m| m.compliance_framework == ComplianceFramework::SOC2)
            .unwrap_or_else(|| panic!("{finding_type} must carry a SOC 2 mapping"));
        assert_eq!(soc2.compliance_control_id, "CC6.8");
        assert_eq!(
            soc2.compliance_section.as_deref(),
            Some("Logical and Physical Access Controls")
        );
    }
}

/// Confirms the 800-171r3 crosswalk: every MAC finding translates its
/// AC-3 entry to requirement 3.1.2 under the Access Control family.
#[test]
fn mac_findings_map_nist_800_171_access_enforcement() {
    for finding_type in MAC_FINDING_TYPES {
        let mapping = get_mac_compliance_mappings(finding_type)
            .into_iter()
            .find(|m| m.compliance_framework == ComplianceFramework::NIST800171)
            .unwrap_or_else(|| panic!("{finding_type} must carry an 800-171 mapping"));
        assert_eq!(mapping.compliance_control_id, "3.1.2");
        assert_eq!(
            mapping.compliance_section.as_deref(),
            Some("Access Control")
        );
    }
}

/// Confirms the FedRAMP derivation: AC-3 is a GSA rev5 Moderate baseline
/// member, so every MAC finding mirrors its existing 800-53 entry
/// verbatim under the Access Control family.
#[test]
fn mac_findings_map_fedramp_access_enforcement() {
    for finding_type in MAC_FINDING_TYPES {
        let mapping = get_mac_compliance_mappings(finding_type)
            .into_iter()
            .find(|m| m.compliance_framework == ComplianceFramework::FedRAMP)
            .unwrap_or_else(|| panic!("{finding_type} must carry a FedRAMP mapping"));
        assert_eq!(mapping.compliance_control_id, "AC-3");
        assert_eq!(
            mapping.compliance_section.as_deref(),
            Some("Access Control")
        );
    }
}

/// Names only mac's own paths, so a failure here cannot come from another
/// plugin's entry in a shared list.
#[test]
fn mac_reloads_for_its_own_paths_and_no_others() {
    let plugin = MacHardeningPlugin::new();
    assert!(plugin.reloads_for_path(Path::new("/etc/selinux/config")));
    assert!(plugin.reloads_for_path(Path::new("/etc/apparmor.d/usr.bin.foo")));
    assert!(!plugin.reloads_for_path(Path::new("/etc/nftables.conf")));
}

/// Ties the predicate to the literals `apply` actually checkpoints, so the
/// two cannot drift apart unnoticed. `/etc/apparmor` and `/etc/apparmor.d`
/// are checkpointed as two separate paths, and `Path::starts_with` compares
/// whole components, so the predicate has to name both.
#[test]
fn every_path_mac_checkpoints_is_one_it_reloads_for() {
    let plugin = MacHardeningPlugin::new();
    for path in [SELINUX_CONFIG_PATH, "/etc/apparmor", "/etc/apparmor.d"] {
        assert!(
            plugin.reloads_for_path(Path::new(path)),
            "mac checkpoints {path} but would not reload for it"
        );
    }
}
