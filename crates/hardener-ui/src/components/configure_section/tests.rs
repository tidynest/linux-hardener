#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`configure_section`](super).
//!
//! Split out of `components/configure_section.rs`. This file sits in the
//! `components/configure_section/` directory beside it, which the 2018 path
//! rules allow with no `mod.rs` and no `#[path]`, so `super` still resolves
//! to `crate::components::configure_section` and every import carried across
//! unchanged, private items included.

use super::*;

#[test]
fn total_estimated_changes_excludes_compliant_groups() {
    // The task brief's hand example: 2 plugins, one with 3 estimated
    // changes, one verified_compliant (changes emptied). Honest N is 3,
    // never `decisions.len()` (which would read 2).
    let decisions = vec![
        PreviewDecision {
            plugin_id: "ssh-hardening".to_string(),
            verified_compliant: false,
            estimated_changes: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            issues: vec![],
            exceptions: vec![],
        },
        PreviewDecision {
            plugin_id: "permissions-hardening".to_string(),
            verified_compliant: true,
            estimated_changes: vec![],
            issues: vec![],
            exceptions: vec![],
        },
    ];
    assert_eq!(total_estimated_changes(&decisions), 3);
}

#[test]
fn total_estimated_changes_is_zero_when_everything_compliant() {
    let decisions = vec![PreviewDecision {
        plugin_id: "kernel-hardening".to_string(),
        verified_compliant: true,
        estimated_changes: vec![],
        issues: vec![],
        exceptions: vec![],
    }];
    assert_eq!(total_estimated_changes(&decisions), 0);
}

#[test]
fn plugin_display_name_maps_the_full_backend_id_via_prefix() {
    // Backend echoes the FULL registry id, not the short id this file
    // sends it - see plugin_display_name's own doc comment.
    assert_eq!(plugin_display_name("kernel-hardening"), "Kernel Hardening");
    assert_eq!(plugin_display_name("ssh-hardening"), "SSH Hardening");
    assert_eq!(
        plugin_display_name("service-minimisation"),
        "Service Minimisation"
    );
    assert_eq!(plugin_display_name("mac-hardening"), "MAC System");
    assert_eq!(plugin_display_name("unknown-plugin"), "Unknown area");
}

#[test]
fn lockout_class_flags_only_ssh_and_firewall() {
    assert_eq!(lockout_class("ssh-hardening"), Some("login"));
    assert_eq!(lockout_class("firewall-hardening"), Some("network"));
    assert_eq!(lockout_class("kernel-hardening"), None);
    assert_eq!(lockout_class("pam-hardening"), None);
}

// --- Task 2a.7: partial-row detail-text helpers ---

use crate::types::{Change, ChangeType, PluginId};

fn a_result(changes: Vec<Change>) -> ApplyResult {
    ApplyResult {
        apply_plugin_id: PluginId::new("pam-hardening"),
        apply_success: true,
        apply_changes: changes,
        apply_checkpoint_id: None,
        apply_error: None,
    }
}

fn ok_change() -> Change {
    Change {
        change_description: "ok".to_string(),
        change_type: ChangeType::ConfigFile,
        change_success: true,
        change_error: None,
    }
}

#[test]
fn failure_detail_prefers_the_real_error_over_the_description() {
    let result = a_result(vec![Change {
        change_description: "Set PermitRootLogin no".to_string(),
        change_type: ChangeType::ConfigFile,
        change_success: false,
        change_error: Some("sshd -t: syntax error".to_string()),
    }]);
    assert_eq!(failure_detail(&result), "sshd -t: syntax error");
}

#[test]
fn failure_detail_falls_back_to_description_when_error_is_empty() {
    let result = a_result(vec![Change {
        change_description: "Set PermitRootLogin no".to_string(),
        change_type: ChangeType::ConfigFile,
        change_success: false,
        change_error: Some(String::new()),
    }]);
    assert_eq!(failure_detail(&result), "Set PermitRootLogin no");
}

#[test]
fn failure_detail_skips_a_manual_action_to_find_the_genuine_failure() {
    let result = a_result(vec![
        Change {
            change_description: "edit the PAM stack manually".to_string(),
            change_type: ChangeType::ConfigFile,
            change_success: false,
            change_error: Some("inline pam.d override present".to_string()),
        },
        Change {
            change_description: "d".to_string(),
            change_type: ChangeType::ConfigFile,
            change_success: false,
            change_error: Some("permission denied".to_string()),
        },
    ]);
    assert_eq!(failure_detail(&result), "permission denied");
}

#[test]
fn manual_step_detail_reads_the_manual_changes_description() {
    let result = a_result(vec![Change {
        change_description: "edit the PAM stack manually to set X to Y".to_string(),
        change_type: ChangeType::ConfigFile,
        change_success: false,
        change_error: Some("inline pam.d override present".to_string()),
    }]);
    assert_eq!(
        manual_step_detail(&result),
        "edit the PAM stack manually to set X to Y"
    );
}

#[test]
fn skipped_status_text_reports_the_skip_reason() {
    let result = a_result(vec![Change {
        change_description: "Already minimised".to_string(),
        change_type: ChangeType::Skipped,
        change_success: true,
        change_error: None,
    }]);
    assert_eq!(skipped_status_text(&result), "Skipped: Already minimised");
}

#[test]
fn skipped_status_text_falls_back_when_no_reason_is_given() {
    assert_eq!(skipped_status_text(&a_result(vec![])), "Skipped");
}

#[test]
fn failure_detail_and_manual_step_detail_are_empty_without_a_match() {
    let result = a_result(vec![ok_change()]);
    assert_eq!(failure_detail(&result), "");
    assert_eq!(manual_step_detail(&result), "");
}
