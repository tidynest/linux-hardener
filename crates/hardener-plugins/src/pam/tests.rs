#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`pam`].
//!
//! Split out of `pam.rs`. This file sits in the `pam/` directory
//! beside it, so `super` still resolves to `crate::pam` and every
//! import carried across unchanged, private items included.

use super::*;

/// Every read failure used to render as "requires root", so an I/O error
/// or non-UTF-8 content told the operator to reach for sudo, which cannot
/// help. Only a genuine privilege failure earns that wording.
#[test]
fn only_a_privilege_failure_tells_the_operator_to_use_root() {
    let denied = unreadable_reason("/etc/security/pwquality.conf", true);
    assert!(
        denied.contains("requires root"),
        "a privilege failure is exactly the sudo case: {denied}"
    );

    let broken = unreadable_reason("/etc/security/pwquality.conf", false);
    assert!(
        !broken.contains("requires root"),
        "an I/O or encoding failure must not be blamed on privilege: {broken}"
    );
    assert!(
        broken.contains("/etc/security/pwquality.conf"),
        "the path must still be named: {broken}"
    );
}

/// The dry-run parenthetical carries the same distinction, so a preview
/// cannot claim a value is root-only when root would not reveal it.
#[test]
fn the_dry_run_caveat_matches_the_actual_cause() {
    assert_eq!(current_value_caveat(true), "current value requires root");
    assert!(!current_value_caveat(false).contains("root"));
}

/// The unchecked entry a scan emits inherits the same wording, and keeps
/// its compliance mappings either way so the control still reaches manual
/// review rather than passing.
#[test]
fn an_unchecked_pam_directive_reports_the_real_cause() {
    let directive = PAM_DIRECTIVES
        .iter()
        .find(|d| d.pam_directive_name == "minlen")
        .expect("minlen is a known PAM directive");

    // The privilege-versus-I/O wording moved out to the caller when a
    // second cause of an unchecked directive appeared: a stack file that
    // could not be read is one reason, and a distribution whose stack this
    // table does not name is another, and neither is phrased by this
    // function any more. `unreadable_reason` still owns that distinction
    // and `only_a_privilege_failure_tells_the_operator_to_use_root` still
    // pins it.
    let entry = unchecked_pam_directive(
        directive,
        unreadable_reason("/etc/security/pwquality.conf", true),
        true,
    );
    assert!(entry.unchecked_reason.contains("requires root"));
    assert!(
        entry.unchecked_needs_privilege,
        "a privilege failure must offer the remedy that reaches it"
    );
    assert_eq!(entry.unchecked_check_id, "pam-minlen");
    assert!(
        !entry.unchecked_compliance.is_empty(),
        "the mappings must survive so the control still reaches manual review"
    );

    let carried = unchecked_pam_directive(directive, "any reason at all".to_string(), false);
    assert_eq!(
        carried.unchecked_reason, "any reason at all",
        "the reason is the caller's, reported rather than reinterpreted"
    );
    assert!(
        !carried.unchecked_needs_privilege,
        "a cause privilege cannot reach must not offer sudo, which is what the \
         stack table's own unknown distribution case produces"
    );
}

/// Confirms a representative PAM finding (minimum password length) now
/// carries multi-framework mappings: CIS (existing) plus STIG, NIST and
/// PCI-DSS sourced from the SSG `accounts_password_pam_minlen` rule.
#[test]
fn pam_minlen_maps_cis_stig_nist_and_pcidss() {
    let frameworks: Vec<ComplianceFramework> = get_pam_compliance_mappings("minlen")
        .iter()
        .map(|m| m.compliance_framework)
        .collect();

    for expected in [
        ComplianceFramework::CIS,
        ComplianceFramework::STIG,
        ComplianceFramework::NIST,
        ComplianceFramework::PCIDSS,
    ] {
        assert!(
            frameworks.contains(&expected),
            "minlen must map framework {expected:?}"
        );
    }
}

/// Confirms the same representative PAM finding (minimum password length)
/// also carries the governance-framework mappings added alongside the
/// technical ones: ISO/IEC 27001:2022 8.5 (under the "Technological"
/// theme), HIPAA §164.308(a)(5)(ii)(D) and GDPR "TM-AUTH". Existing CIS /
/// STIG / NIST / PCI-DSS mappings are left intact (asserted above).
#[test]
fn pam_minlen_maps_iso_hipaa_and_gdpr() {
    let mappings = get_pam_compliance_mappings("minlen");
    let frameworks: Vec<ComplianceFramework> =
        mappings.iter().map(|m| m.compliance_framework).collect();

    for expected in [
        ComplianceFramework::ISO27001,
        ComplianceFramework::HIPAA,
        ComplianceFramework::GDPR,
    ] {
        assert!(
            frameworks.contains(&expected),
            "minlen must map framework {expected:?}"
        );
    }

    // The ISO 27001 control must be filed under the "Technological" theme,
    // not the PAM default "Access Control" section.
    let iso = mappings
        .iter()
        .find(|m| m.compliance_framework == ComplianceFramework::ISO27001)
        .expect("minlen must carry an ISO 27001 mapping");
    assert_eq!(iso.compliance_control_id, "8.5");
    assert_eq!(iso.compliance_section.as_deref(), Some("Technological"));
}

/// Confirms every PAM authentication check carries the SOC 2 logical-access
/// criterion CC6.1, filed under its Trust Services Criteria series.
#[test]
fn pam_minlen_maps_soc2_logical_access() {
    let soc2 = get_pam_compliance_mappings("minlen")
        .into_iter()
        .find(|m| m.compliance_framework == ComplianceFramework::SOC2)
        .expect("minlen must carry a SOC 2 mapping");
    assert_eq!(soc2.compliance_control_id, "CC6.1");
    assert_eq!(
        soc2.compliance_section.as_deref(),
        Some("Logical and Physical Access Controls")
    );
}

/// Confirms the 800-171r3 crosswalk: password-quality checks translate
/// IA-5(1) to 3.5.7, the faillock check translates AC-7 to 3.1.8, and the
/// pwhistory check (whose SSG rule carries no 800-53 reference) honestly
/// carries no 800-171 mapping.
#[test]
fn pam_checks_map_nist_800_171_requirements() {
    let nist171_for = |check: &str| {
        get_pam_compliance_mappings(check)
            .into_iter()
            .find(|m| m.compliance_framework == ComplianceFramework::NIST800171)
    };

    let minlen = nist171_for("minlen").expect("minlen must carry an 800-171 mapping");
    assert_eq!(minlen.compliance_control_id, "3.5.7");
    assert_eq!(
        minlen.compliance_section.as_deref(),
        Some("Identification and Authentication")
    );

    let lockout = nist171_for("lockout").expect("lockout must carry an 800-171 mapping");
    assert_eq!(lockout.compliance_control_id, "3.1.8");
    assert_eq!(
        lockout.compliance_section.as_deref(),
        Some("Access Control")
    );

    assert!(
        nist171_for("remember").is_none(),
        "pwhistory has no 800-53 source control and must not claim 800-171"
    );
}

/// Confirms the FedRAMP derivation: IA-5(1) and AC-7 are both GSA rev5
/// Moderate baseline members, so the quality and lockout checks mirror
/// their 800-53 ids verbatim; the pwhistory check (whose SSG rule
/// carries no 800-53 reference) honestly carries no FedRAMP mapping.
#[test]
fn pam_checks_map_fedramp_moderate_controls() {
    let fedramp_for = |check: &str| {
        get_pam_compliance_mappings(check)
            .into_iter()
            .find(|m| m.compliance_framework == ComplianceFramework::FedRAMP)
    };

    let minlen = fedramp_for("minlen").expect("minlen must carry a FedRAMP mapping");
    assert_eq!(minlen.compliance_control_id, "IA-5(1)(a)");
    assert_eq!(
        minlen.compliance_section.as_deref(),
        Some("Identification and Authentication")
    );

    let max_days =
        fedramp_for("PASS_MAX_DAYS").expect("PASS_MAX_DAYS must carry a FedRAMP mapping");
    assert_eq!(max_days.compliance_control_id, "IA-5(1)(d)");

    let lockout = fedramp_for("lockout").expect("lockout must carry a FedRAMP mapping");
    assert_eq!(lockout.compliance_control_id, "AC-7(a)");
    assert_eq!(
        lockout.compliance_section.as_deref(),
        Some("Access Control")
    );

    assert!(
        fedramp_for("remember").is_none(),
        "pwhistory has no 800-53 source control and must not claim FedRAMP"
    );
}

#[tokio::test]
async fn backup_reports_failure_when_cp_exits_non_zero() {
    use hardener_common::executor::{CommandOutput, MockExecutor};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    // The backup path embeds a unix timestamp, so register the cp across a
    // small clock window (the idiom used in pam_mock_tests.rs).
    let path = "/etc/security/faillock.conf";
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before the unix epoch")
        .as_secs();
    let mut executor = MockExecutor::new();
    for t in now..now + 3 {
        let backup = format!("{path}.backup-{t}");
        executor = executor.with_command(
            "cp",
            &["-p", "--no-dereference", path, &backup],
            CommandOutput {
                stdout: String::new(),
                stderr: "cp: cannot stat '/etc/security/faillock.conf': Permission denied\n"
                    .to_string(),
                exit_code: 1,
            },
        );
    }
    let ctx = Context::with_executor(Arc::new(executor));

    let result = create_config_backup(&ctx, path).await;

    let err = result.expect_err("a cp that exits non-zero must not report a backup");
    let message = err.to_string();
    assert!(
        message.contains(path),
        "the error must name the file it failed to back up, got: {message}"
    );
    assert!(
        message.contains("Permission denied"),
        "the error must carry cp's own stderr so an operator can act on it, got: {message}"
    );
}

/// A backup is only worth taking if it is a copy of the thing about to be
/// replaced, at the mode that thing carries.
///
/// `-p` keeps mode, ownership and timestamps, so an operator who copies the
/// backup back gets the file they had rather than one wearing whatever the
/// umask handed it, which on a `/etc/security/*.conf` is the difference
/// between a policy file and a world-readable one. `--no-dereference`
/// copies a symlink as a symlink, so a config that is a link elsewhere is
/// backed up as the object this plugin is about to overwrite rather than as
/// its target, which is a different file that nothing here is touching.
///
/// Asserted on the recorded argv rather than on the run succeeding, and
/// against a mock that answers any `cp` by program name. A test that leaned
/// on the exact-argument registration missing would fail with "command not
/// registered", which is a different failure wearing this one's clothes,
/// and it would stop failing the moment anyone added a program-level
/// fallback to the fixture.
#[tokio::test]
async fn the_backup_copy_keeps_the_mode_and_does_not_follow_a_symlink() {
    use hardener_common::executor::{CommandOutput, MockExecutor};
    use std::sync::Arc;

    let path = "/etc/security/faillock.conf";
    let executor = Arc::new(MockExecutor::new().with_command_program(
        "cp",
        CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        },
    ));
    let ctx = Context::with_executor(executor.clone());

    let backup = create_config_backup(&ctx, path)
        .await
        .expect("a mock that answers any cp must let the backup through");

    let log = executor.log();
    let (_, args) = log
        .commands_executed
        .iter()
        .find(|(program, _)| program == "cp")
        .expect("the backup must be taken with cp");
    for flag in ["-p", "--no-dereference"] {
        assert!(
            args.iter().any(|argument| argument == flag),
            "the backup cp must pass {flag}, got: {args:?}"
        );
    }
    // Checked separately from the flags because "the flag is present"
    // and "the flag is a flag" are different claims: an argument added
    // after the source would be read by cp as another file to copy.
    assert_eq!(
        &args[args.len() - 2..],
        &[path.to_string(), backup],
        "source and destination must stay the last two arguments, got: {args:?}"
    );
}

#[tokio::test]
async fn a_read_error_is_not_reported_as_empty_content() {
    use hardener_common::executor::MockExecutor;
    use std::sync::Arc;

    // A file that exists but cannot be read must never classify as content.
    // Empty content means "the directive is genuinely not set", which is a
    // different fact and drives a rewrite.
    let path = "/etc/security/faillock.conf";
    let executor = MockExecutor::new()
        .with_file(path, "deny = 3\n")
        .with_read_permission_denied(path);
    let ctx = Context::with_executor(Arc::new(executor));

    assert!(
        matches!(
            read_conf_classified(&ctx, path).await,
            ConfRead::Unreadable { .. }
        ),
        "an unreadable file must classify as Unreadable"
    );
}

#[tokio::test]
async fn an_absent_file_is_distinguishable_from_an_unreadable_one() {
    use hardener_common::executor::MockExecutor;
    use std::sync::Arc;

    // Nothing registered: the mock reports a confirmed absence.
    let ctx = Context::with_executor(Arc::new(MockExecutor::new()));

    assert!(
        matches!(
            read_conf_classified(&ctx, "/etc/security/faillock.conf").await,
            ConfRead::Absent
        ),
        "a file that is simply not there must classify as Absent, since creating it is correct"
    );
}

#[test]
fn threshold_directives_accept_stricter_and_flag_looser() {
    let deny = PamDirective {
        pam_directive_name: "deny",
        pam_secure_value: "5",
        pam_description: "t",
        pam_severity: Severity::High,
        pam_config_file: PamConfigFile::SecurityConf("/etc/security/faillock.conf"),
        pam_compare: Strictness::AtMost,
    };
    assert!(pam_violates(&deny, deny.pam_secure_value, Some("10"))); // too loose
    assert!(!pam_violates(&deny, deny.pam_secure_value, Some("3"))); // stricter, compliant
    assert!(!pam_violates(&deny, deny.pam_secure_value, Some("5")));
    assert!(pam_violates(&deny, deny.pam_secure_value, None)); // not configured

    // A clamped override target (not the raw baseline) is what scan()
    // actually compares against: a stricter override on an
    // already-compliant value must now violate.
    assert!(pam_violates(&deny, "2", Some("3"))); // baseline-compliant, override-violating

    let remember = PamDirective {
        pam_directive_name: "remember",
        pam_config_file: PamConfigFile::SecurityConf("/etc/security/pwhistory.conf"),
        pam_compare: Strictness::AtLeast,
        ..deny
    };
    assert!(pam_violates(
        &remember,
        remember.pam_secure_value,
        Some("2")
    )); // too few
    assert!(!pam_violates(
        &remember,
        remember.pam_secure_value,
        Some("10")
    )); // stricter, compliant
    assert!(!pam_violates(
        &remember,
        remember.pam_secure_value,
        Some("5")
    ));
    assert!(!pam_violates(&remember, "12", Some("15"))); // still compliant against a tighter override

    // This block used to build a synthetic `Exact` directive and assert
    // that 8 violates a baseline of 14 while 14 does not. Both assertions
    // were true of the code and the second was the defect: it pinned the
    // rule that any value other than the baseline is a violation, which is
    // what wrote 90 over a host's 30. The directives it stood for are real,
    // so they are asserted directly now, in the direction their units have.
    let minlen = PAM_DIRECTIVES
        .iter()
        .find(|d| d.pam_directive_name == "minlen")
        .expect("minlen is a known directive");
    assert!(!pam_violates(minlen, minlen.pam_secure_value, Some("14")));
    assert!(pam_violates(minlen, minlen.pam_secure_value, Some("8")));
    assert!(
        !pam_violates(minlen, minlen.pam_secure_value, Some("20")),
        "a longer minimum than the baseline is stricter, so it is compliant"
    );

    // maxrepeat counts downwards except at zero, which switches the check
    // off and is therefore never compliant however small a number it is.
    let maxrepeat = PAM_DIRECTIVES
        .iter()
        .find(|d| d.pam_directive_name == "maxrepeat")
        .expect("maxrepeat is a known directive");
    assert!(!pam_violates(
        maxrepeat,
        maxrepeat.pam_secure_value,
        Some("2")
    ));
    assert!(pam_violates(
        maxrepeat,
        maxrepeat.pam_secure_value,
        Some("4")
    ));
    assert!(
        pam_violates(maxrepeat, maxrepeat.pam_secure_value, Some("0")),
        "zero disables the check, so it is the loosest value and not the strictest"
    );
}
