#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a
// test module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`divergence`].

use super::*;
use hardener_common::executor::{CommandOutput, MockExecutor};
use std::sync::Arc;

/// `auditctl -l` succeeding is the measured-clean shape: the kernel's loaded
/// rule set was read, so the limitation is comparison, not access. The rule
/// count (3, not 0 and not some other number) is planted so this assertion
/// cannot pass by coincidence with either error arm's fixed wording, both of
/// which never mention a count at all.
#[tokio::test]
async fn a_readable_rule_set_names_the_count_and_defers_the_comparison() {
    let ctx = Context::with_executor(Arc::new(
        MockExecutor::new().with_command(
            "auditctl",
            &["-l"],
            CommandOutput {
                stdout: "-w /etc/passwd -p wa -k identity\n\
                     -w /etc/group -p wa -k identity\n\
                     -w /etc/shadow -p wa -k identity\n"
                    .to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        ),
    ));

    let rows = audit_divergences(&ctx).await;

    assert_eq!(rows.len(), 1, "one row, not silence");
    assert_eq!(rows[0].divergence_plugin_id, "audit-hardening");
    assert_eq!(rows[0].divergence_subject, "audit-rules");
    assert_eq!(
        rows[0].divergence_state,
        DivergenceState::Unverifiable,
        "reading the kernel's rule set is not the same as comparing it against the restored \
         file, so this can never be Diverged"
    );
    assert!(
        rows[0].divergence_detail.contains("3 loaded audit rule"),
        "the count read back must survive into the sentence: {}",
        rows[0].divergence_detail
    );
    assert!(
        rows[0].divergence_detail.contains("not implemented"),
        "the limitation named must be the missing comparison, not an access failure: {}",
        rows[0].divergence_detail
    );
    assert!(
        rows[0].divergence_detail.contains("#18"),
        "the sentence points at the issue that can answer it: {}",
        rows[0].divergence_detail
    );
}

/// `auditctl -l` refusing for lack of privilege is a different limitation
/// from the binary being unrunnable, and needs different words: "privilege"
/// is planted here and must be absent from the ProbeFailed arm's sentence
/// below, or the two would read as the same row with the labels swapped.
#[tokio::test]
async fn a_privilege_refusal_names_privilege_not_a_missing_binary() {
    let ctx = Context::with_executor(Arc::new(MockExecutor::new().with_command(
        "auditctl",
        &["-l"],
        CommandOutput {
            stdout: String::new(),
            stderr: "You must be root to run this program.".to_string(),
            exit_code: 4,
        },
    )));

    let rows = audit_divergences(&ctx).await;

    assert_eq!(rows.len(), 1, "one row, not silence");
    assert_eq!(rows[0].divergence_subject, "audit-rules");
    assert_eq!(rows[0].divergence_state, DivergenceState::Unverifiable);
    assert!(
        rows[0].divergence_detail.contains("privilege"),
        "a refusal must be named as a privilege problem: {}",
        rows[0].divergence_detail
    );
    assert!(
        !rows[0].divergence_detail.contains("could not be run"),
        "a refusal is not the same failure as an unrunnable binary: {}",
        rows[0].divergence_detail
    );
    assert!(
        rows[0].divergence_detail.contains("#18"),
        "the sentence points at the issue that can answer it: {}",
        rows[0].divergence_detail
    );
}

/// `auditctl` being unrunnable (the common case measured on every container:
/// no audit package, so the binary itself is absent) carries its own cause
/// string from `read_current_audit_rules`'s `Err` conversion into the
/// sentence, distinct from a mere privilege refusal.
#[tokio::test]
async fn an_unrunnable_probe_carries_its_own_cause_into_the_detail() {
    // No `auditctl` registration at all: `execute_command` fails outright
    // with "Mock: command not registered: ...", distinct from succeeding
    // with a non-zero exit the way the privilege-refusal test above does.
    let ctx = Context::with_executor(Arc::new(MockExecutor::new()));

    let rows = audit_divergences(&ctx).await;

    assert_eq!(rows.len(), 1, "one row, not silence");
    assert_eq!(rows[0].divergence_subject, "audit-rules");
    assert_eq!(rows[0].divergence_state, DivergenceState::Unverifiable);
    assert!(
        rows[0]
            .divergence_detail
            .contains("Mock: command not registered"),
        "the probe's own cause must survive into the sentence, not be dropped: {}",
        rows[0].divergence_detail
    );
    assert!(
        !rows[0].divergence_detail.contains("privilege"),
        "an unrunnable binary is not the same failure as a privilege refusal: {}",
        rows[0].divergence_detail
    );
    assert!(
        rows[0].divergence_detail.contains("#18"),
        "the sentence points at the issue that can answer it: {}",
        rows[0].divergence_detail
    );
}

/// `auditctl -l` running and exiting non-zero for a reason that is neither a
/// recognised permission refusal (no "Permission denied", "must be root" and
/// so on in stderr) nor an unspawnable binary. Scan and apply fold this back
/// to `Rules(Vec::new())`; this probe must not, because "auditctl read 0
/// loaded audit rule(s) from the kernel" is a positive claim about the
/// kernel that a failed, unrecognised command never earned.
#[tokio::test]
async fn an_unrecognised_failure_does_not_claim_zero_loaded_rules() {
    let ctx = Context::with_executor(Arc::new(MockExecutor::new().with_command(
        "auditctl",
        &["-l"],
        CommandOutput {
            stdout: String::new(),
            stderr: "auditctl: Error - netlink socket bind failed".to_string(),
            exit_code: 1,
        },
    )));

    let rows = audit_divergences(&ctx).await;

    assert_eq!(rows.len(), 1, "one row, not silence");
    assert_eq!(rows[0].divergence_subject, "audit-rules");
    assert_eq!(rows[0].divergence_state, DivergenceState::Unverifiable);
    assert!(
        !rows[0].divergence_detail.contains("0 loaded audit rule"),
        "a failed, unrecognised command must never be read as a clean 0-rule kernel: {}",
        rows[0].divergence_detail
    );
    assert!(
        !rows[0].divergence_detail.contains("privilege"),
        "an unrecognised failure is not the same failure as a privilege refusal: {}",
        rows[0].divergence_detail
    );
    assert!(
        rows[0]
            .divergence_detail
            .contains("netlink socket bind failed"),
        "the probe's own cause must survive into the sentence, not be dropped: {}",
        rows[0].divergence_detail
    );
    assert!(
        rows[0].divergence_detail.contains("#18"),
        "the sentence points at the issue that can answer it: {}",
        rows[0].divergence_detail
    );
}
