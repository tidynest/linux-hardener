#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`divergence`].

use super::*;
use hardener_common::executor::MockExecutor;
use std::sync::Arc;

/// A host with no readable LSM produces exactly one row, and it is
/// Unverifiable rather than empty. An empty vector here would mean "looked,
/// everything came back", which is a claim this probe cannot make on a host
/// whose kernel exposes no MAC at all (#18).
#[tokio::test]
async fn an_unreadable_lsm_is_one_unverifiable_row() {
    let ctx = Context::with_executor(Arc::new(MockExecutor::new()));

    let rows = mac_divergences(&MacHardeningPlugin::new(), &ctx).await;

    assert_eq!(rows.len(), 1, "one row, not silence");
    assert_eq!(rows[0].divergence_plugin_id, "mac-hardening");
    assert_eq!(
        rows[0].divergence_state,
        DivergenceState::Unverifiable,
        "the probe could not read a policy back, which is not a claim that anything is wrong"
    );
    assert!(
        rows[0].divergence_detail.contains("#18"),
        "the sentence points at the issue that can answer it: {}",
        rows[0].divergence_detail
    );
}

/// A host that detects SELinux gets a row naming SELinux, not the generic
/// `mac` subject the two arms below share.
#[tokio::test]
async fn a_detected_selinux_system_names_selinux_as_the_subject() {
    let ctx = Context::with_executor(Arc::new(
        MockExecutor::new().with_path_exists("/sys/fs/selinux", true),
    ));

    let rows = mac_divergences(&MacHardeningPlugin::new(), &ctx).await;

    assert_eq!(rows.len(), 1, "one row, not silence");
    assert_eq!(
        rows[0].divergence_subject, "selinux",
        "the SELinux arm must name its own subject, not AppArmor's or the generic one"
    );
    assert_eq!(
        rows[0].divergence_state,
        DivergenceState::Unverifiable,
        "detecting a MAC system is not the same as reading back what it enforces"
    );
}

/// The AppArmor arm names `apparmor`, distinct from the SELinux arm above and
/// from the generic `mac` subject the `Absent` and `Indeterminate` arms share.
#[tokio::test]
async fn a_detected_apparmor_system_names_apparmor_as_the_subject() {
    let ctx = Context::with_executor(Arc::new(
        MockExecutor::new().with_path_exists("/sys/kernel/security/apparmor", true),
    ));

    let rows = mac_divergences(&MacHardeningPlugin::new(), &ctx).await;

    assert_eq!(rows.len(), 1, "one row, not silence");
    assert_eq!(
        rows[0].divergence_subject, "apparmor",
        "the AppArmor arm must name its own subject, not SELinux's or the generic one"
    );
    assert_eq!(
        rows[0].divergence_state,
        DivergenceState::Unverifiable,
        "detecting a MAC system is not the same as reading back what it enforces"
    );
}

/// `Indeterminate` shares its subject, `mac`, with `Absent`, so subject alone
/// cannot prove the row came from this arm. What can: the detection's own
/// reason string, which this arm is the only one that interpolates into the
/// sentence. A distinctive reason is used deliberately, so the assertion
/// cannot pass by coincidence with either neighbour's fixed wording.
#[tokio::test]
async fn an_indeterminate_probe_carries_its_own_reason_into_the_detail() {
    let ctx = Context::with_executor(Arc::new(
        MockExecutor::new().with_path_exists_error("/sys/fs/selinux"),
    ));

    let rows = mac_divergences(&MacHardeningPlugin::new(), &ctx).await;

    assert_eq!(rows.len(), 1, "one row, not silence");
    assert_eq!(
        rows[0].divergence_subject, "mac",
        "Indeterminate shares its subject with Absent"
    );
    assert_eq!(
        rows[0].divergence_state,
        DivergenceState::Unverifiable,
        "a probe that failed to run is not evidence of anything, in either direction"
    );
    assert!(
        rows[0]
            .divergence_detail
            .contains("Mock: path_exists unavailable: /sys/fs/selinux"),
        "the detection's own reason must survive into the sentence, not be dropped: {}",
        rows[0].divergence_detail
    );
}
