#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`permissions`].
//!
//! Split out of `permissions.rs`. This file sits in the `permissions/` directory
//! beside it, so `super` still resolves to `crate::permissions` and every
//! import carried across unchanged, private items included.

use super::*;
use hardener_core::{CommandOutput, FileMetadata, MockExecutor};

/// A representative permissions check (`/etc/shadow`) must now carry
/// multi-framework mappings: the existing CIS control plus NIST 800-53
/// and PCI-DSS sourced from SSG `file_permissions_etc_shadow`. STIG is
/// intentionally absent because that SSG rule declares no `stigid@`.
#[test]
fn shadow_has_multi_framework_mappings() {
    let mappings = get_permissions_compliance_mappings("/etc/shadow");

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
        has(ComplianceFramework::PCIDSS),
        "PCI-DSS mapping must be present"
    );

    // Verify the exact SSG-sourced identifiers.
    let nist = mappings
        .iter()
        .find(|m| m.compliance_framework == ComplianceFramework::NIST)
        .unwrap();
    assert_eq!(nist.compliance_control_id, "AC-6(1)");
}

#[test]
fn max_mask_treats_stricter_as_compliant_and_never_loosens() {
    let shadow = PermissionDirective {
        permission_description: "t",
        permission_path: "/etc/shadow",
        permission_mode: 0o640, // used as the allowed mask
        _permission_owner: "root",
        _permission_group: "root",
        permission_severity: Severity::Critical,
        permission_max_mask: true,
    };
    // 0000 (RHEL) and 0640 (Debian) both compliant; 0644 (o-r) and 0660 (g-w) violate.
    assert!(!violates(&shadow, 0o000));
    assert!(!violates(&shadow, 0o640));
    assert!(!violates(&shadow, 0o600));
    assert!(violates(&shadow, 0o644));
    assert!(violates(&shadow, 0o660));
    // Apply strips disallowed bits only, never adds any.
    assert_eq!(target_mode(&shadow, 0o644), 0o640);
    assert_eq!(target_mode(&shadow, 0o600), 0o600);

    let passwd = PermissionDirective {
        permission_max_mask: false,
        permission_mode: 0o644,
        ..shadow
    };
    assert!(!violates(&passwd, 0o644));
    assert!(violates(&passwd, 0o646));
    assert_eq!(target_mode(&passwd, 0o646), 0o644);
}

/// The `validate` dry-run builds an effective directive (override applied to
/// `permission_mode`, `permission_max_mask` preserved) and routes it through
/// the same `violates`/`target_mode` helpers as scan/apply. This mirrors that
/// path: a mask directive must report NO pending change at a stricter mode
/// (0000 on RHEL) yet flag a looser one (0644).
#[test]
fn validate_effective_directive_honours_max_mask() {
    let shadow = PermissionDirective {
        permission_description: "t",
        permission_path: "/etc/shadow",
        permission_mode: 0o640,
        _permission_owner: "root",
        _permission_group: "root",
        permission_severity: Severity::Critical,
        permission_max_mask: true,
    };

    // Effective directive with a config override to 0o600 keeps mask semantics.
    let mut effective = shadow.clone();
    effective.permission_mode = 0o600;
    assert!(!violates(&effective, 0o000), "stricter mode is compliant");
    assert!(violates(&effective, 0o640), "0640 exceeds the 0600 mask");
    assert_eq!(target_mode(&effective, 0o640), 0o600);

    // No override: baseline 0640 mask; 0000 compliant, 0644 flagged.
    assert!(!violates(&shadow, 0o000));
    assert!(violates(&shadow, 0o644));
}

/// Sensitive-file permission checks must also carry HIPAA, GDPR and
/// ISO/IEC 27001:2022 mappings alongside the existing CIS/NIST/PCI-DSS set.
#[test]
fn shadow_has_privacy_and_iso_mappings() {
    let mappings = get_permissions_compliance_mappings("/etc/shadow");

    let has = |fw| mappings.iter().any(|m| m.compliance_framework == fw);
    assert!(has(ComplianceFramework::HIPAA), "HIPAA must be present");
    assert!(has(ComplianceFramework::GDPR), "GDPR must be present");
    assert!(
        has(ComplianceFramework::ISO27001),
        "ISO 27001 must be present"
    );

    // ISO control must be the access-restriction clause for sensitive files.
    let iso = mappings
        .iter()
        .find(|m| m.compliance_framework == ComplianceFramework::ISO27001)
        .unwrap();
    assert_eq!(iso.compliance_control_id, "8.3");

    // HIPAA is the access-control safeguard. The integrity standard
    // 164.312(c)(1) is intentionally absent: SSG carries no HIPAA reference
    // for these file-permission rules, so the access-control citation stands
    // alone (aligned with the SSG preference for 164.312(a)).
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

/// Confirms every assessed critical path carries the SOC 2 logical-access
/// criterion CC6.1, filed under its Trust Services Criteria series.
#[test]
fn critical_paths_map_soc2_logical_access() {
    for path in [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/gshadow",
        "/etc/ssh",
    ] {
        let soc2 = get_permissions_compliance_mappings(path)
            .into_iter()
            .find(|m| m.compliance_framework == ComplianceFramework::SOC2)
            .unwrap_or_else(|| panic!("{path} must carry a SOC 2 mapping"));
        assert_eq!(soc2.compliance_control_id, "CC6.1");
        assert_eq!(
            soc2.compliance_section.as_deref(),
            Some("Logical and Physical Access Controls")
        );
    }
}

/// Confirms the 800-171r3 crosswalk: the account files translate AC-6(1)
/// to 3.1.5 and the sshd config directory translates AC-17 to 3.1.12,
/// both under the Access Control family.
#[test]
fn critical_paths_map_nist_800_171_requirements() {
    let nist171_for = |path: &str| {
        get_permissions_compliance_mappings(path)
            .into_iter()
            .find(|m| m.compliance_framework == ComplianceFramework::NIST800171)
            .unwrap_or_else(|| panic!("{path} must carry an 800-171 mapping"))
    };

    for path in ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"] {
        let mapping = nist171_for(path);
        assert_eq!(mapping.compliance_control_id, "3.1.5", "{path}");
        assert_eq!(
            mapping.compliance_section.as_deref(),
            Some("Access Control")
        );
    }

    let sshd = nist171_for("/etc/ssh");
    assert_eq!(sshd.compliance_control_id, "3.1.12");
    assert_eq!(sshd.compliance_section.as_deref(), Some("Access Control"));
}

/// Confirms the FedRAMP derivation: AC-6(1) and AC-17 are both GSA rev5
/// Moderate baseline members, so the account files and the sshd config
/// directory mirror their existing 800-53 ids verbatim under the Access
/// Control family.
#[test]
fn critical_paths_map_fedramp_moderate_controls() {
    let fedramp_for = |path: &str| {
        get_permissions_compliance_mappings(path)
            .into_iter()
            .find(|m| m.compliance_framework == ComplianceFramework::FedRAMP)
            .unwrap_or_else(|| panic!("{path} must carry a FedRAMP mapping"))
    };

    for path in ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"] {
        let mapping = fedramp_for(path);
        assert_eq!(mapping.compliance_control_id, "AC-6(1)", "{path}");
        assert_eq!(
            mapping.compliance_section.as_deref(),
            Some("Access Control")
        );
    }

    let sshd = fedramp_for("/etc/ssh");
    assert_eq!(sshd.compliance_control_id, "AC-17(a)");
    assert_eq!(sshd.compliance_section.as_deref(), Some("Access Control"));
}

/// Proves `apply` and `validate` agree on every critical path whose mode
/// could not be verified even though the path is known to exist: an
/// exact-mode directive is hardened to its baseline regardless (so
/// `validate` must predict that change), a max-mask directive is skipped
/// (so `validate` must predict no change, but must still surface the
/// gap). `apply_path_permissions` and `validate_path_permissions` are the
/// only two call sites that decide this, and both are exercised directly
/// here with `current_mode` supplied as `None`.
///
/// This divergence is no longer reachable only by calling the decision
/// functions directly. [`MockExecutor`] gained `with_metadata_error` and
/// `with_path_exists`, which let its `path_exists` and `file_metadata`
/// disagree the way `SshExecutor` genuinely can (`test -e` succeeding
/// while `stat` fails for an unrelated reason), and
/// `permissions_mock_tests.rs` now reproduces exactly that divergence
/// through the plugin's public `apply`:
/// `apply_hardens_an_exact_directive_with_an_unverifiable_mode` and
/// `apply_records_a_skip_for_an_unverifiable_max_mask_directive`. Those
/// tests cover `apply` only; `validate` is not exercised through the mock
/// this way, so calling the two decision functions directly below is
/// still what gives both methods the same coverage, and does so for
/// every `CRITICAL_PERMISSIONS` directive in one table-driven pass
/// rather than one `MockExecutor` fixture per path.
///
/// The public loops that supply those inputs are not, in fact,
/// verbatim-shared wiring: apply's loop performs the exception check
/// and the directive-override construction inline before calling
/// `apply_path_permissions`, which takes no `config` and so cannot
/// check exceptions itself; validate's loop also builds the directive
/// override inline, but delegates the exception check into
/// `validate_path_permissions`. What this test actually proves does not
/// depend on that wiring matching: `apply_path_permissions` and
/// `validate_path_permissions` agree on the unverified-mode outcome
/// once `current_mode` is already `None`, a state neither loop's
/// exception check can be reached from (an unverified mode never
/// matches an exception in either path), so exercising the two
/// functions directly with `None` covers every real path into this
/// state.
#[tokio::test]
async fn validate_predicts_what_apply_does_for_an_unverified_mode() {
    for directive in CRITICAL_PERMISSIONS {
        // `path_exists` must read true; the current mode is supplied
        // directly as `None` below rather than through the mock, so the
        // metadata's `mode` here only needs to be a plausible post-chmod
        // state for apply's own verification re-read to confirm success.
        let mut executor = MockExecutor::new().remote().with_file_metadata(
            directive.permission_path,
            "",
            FileMetadata {
                exists: true,
                is_file: false,
                is_dir: false,
                mode: directive.permission_mode,
                size: 0,
                uid: 0,
                gid: 0,
            },
        );
        if !directive.permission_max_mask {
            executor = executor.with_command(
                "chmod",
                &[
                    &format!("{:04o}", directive.permission_mode),
                    directive.permission_path,
                ],
                CommandOutput {
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            );
        }
        let ctx = Context::with_executor(std::sync::Arc::new(executor));

        let applied = apply_path_permissions(&ctx, directive, None)
            .await
            .unwrap_or_else(|| {
                panic!(
                    "{} must always record a change (a chmod or a skip)",
                    directive.permission_path
                )
            });
        let (estimate, issue) = validate_path_permissions(&ctx, directive, None).await;

        if directive.permission_max_mask {
            assert!(
                applied.is_skipped(),
                "{} (max-mask): apply must skip rather than guess a target, got: {:?}",
                directive.permission_path,
                applied
            );
            assert!(
                estimate.is_none(),
                "{} (max-mask): validate must not predict a change apply will not make, got: {:?}",
                directive.permission_path,
                estimate
            );
            assert!(
                issue.is_some(),
                "{} (max-mask): validate must still flag the unreadable mode",
                directive.permission_path
            );
        } else {
            assert!(
                !applied.is_skipped() && applied.change_success,
                "{} (exact): apply must actually chmod to the baseline, got: {:?}",
                directive.permission_path,
                applied
            );
            let estimate = estimate.unwrap_or_else(|| {
                panic!(
                    "{} (exact): validate must predict the change apply makes",
                    directive.permission_path
                )
            });
            let target = format!("{:04o}", directive.permission_mode);
            assert!(
                estimate.contains(directive.permission_path) && estimate.contains(&target),
                "{} (exact): prediction must name the path and its baseline {target}, got: {estimate}",
                directive.permission_path
            );
            assert!(
                issue.is_none(),
                "{} (exact): validate must not also raise an issue duplicating the estimate",
                directive.permission_path
            );
        }
    }
}

#[test]
fn every_critical_path_is_protected_from_rollback_deletion() {
    // The two lists live in different crates: this plugin decides what is
    // critical, and hardener-state decides what a rollback may delete. A
    // path added here but not there would be deletable by a rollback
    // reading a checkpoint that wrongly records it as absent. This check
    // is one-directional only: UNDELETABLE_ROLLBACK_PATHS may legitimately
    // protect paths this plugin does not harden, so the reverse is not
    // asserted here.
    for directive in CRITICAL_PERMISSIONS {
        assert!(
            hardener_common::types::UNDELETABLE_ROLLBACK_PATHS.contains(&directive.permission_path),
            "{} is hardened by this plugin but rollback may still delete it",
            directive.permission_path
        );
    }
}

/// An operator's override may tighten a target and never relax it. This plugin
/// was the last one applying an override exactly as given.
///
/// The rule is a subset test rather than an ordering, because a mode is a
/// bitmask: 0640 and 0604 are neither stricter nor looser than one another,
/// they are different. An override earns its place by setting no bit the
/// baseline does not already set.
#[test]
fn a_directive_override_may_only_clear_bits() {
    let boot = CRITICAL_PERMISSIONS
        .iter()
        .find(|d| d.permission_path == "/boot")
        .expect("/boot is a shipped directive");
    assert_eq!(boot.permission_mode, 0o700, "baseline this test rests on");

    let mut loosening = PluginConfig::default();
    loosening
        .directives
        .insert("/boot".to_string(), "755".to_string());
    assert_eq!(
        effective_directive(boot, &loosening).permission_mode,
        0o700,
        "0755 adds group and world read and execute, so the baseline stands",
    );

    // The positive control. Without it this test would pass just as happily
    // against a clamp that refused every override, which is a different rule
    // and one the maintainer did not choose.
    let mut tightening = PluginConfig::default();
    tightening
        .directives
        .insert("/boot".to_string(), "500".to_string());
    assert_eq!(
        effective_directive(boot, &tightening).permission_mode,
        0o500,
        "0500 clears the write bit and adds nothing, so it is honoured",
    );
}

/// The sharper half, and the reason this is a security fix rather than a
/// tidying one. On the two mask directives `permission_mode` is the allowed-bits
/// mask, not a mode, so an override does not chmod anything wrong: it widens
/// what counts as compliant, and the scan then says nothing at all about a
/// world-readable shadow file. Silence is the worst outcome available here,
/// because it is indistinguishable from a clean host.
#[test]
fn an_override_cannot_widen_a_max_mask_into_silence() {
    let shadow = CRITICAL_PERMISSIONS
        .iter()
        .find(|d| d.permission_path == "/etc/shadow")
        .expect("/etc/shadow is a shipped directive");
    assert!(shadow.permission_max_mask, "the mask branch is the subject");
    assert!(
        violates(shadow, 0o644),
        "control: a world-readable shadow violates the shipped mask",
    );

    let mut widening = PluginConfig::default();
    widening
        .directives
        .insert("/etc/shadow".to_string(), "644".to_string());
    assert!(
        violates(&effective_directive(shadow, &widening), 0o644),
        "the override must not turn a world-readable shadow into a clean scan",
    );

    // 0600 sets no bit outside 0640, so narrowing the mask is still allowed and
    // a group-readable shadow becomes a violation under it.
    let mut narrowing = PluginConfig::default();
    narrowing
        .directives
        .insert("/etc/shadow".to_string(), "600".to_string());
    assert!(
        violates(&effective_directive(shadow, &narrowing), 0o640),
        "a narrowed mask must still be honoured, or the clamp refuses everything",
    );
}
