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

/// A host with neither SELinux nor AppArmor detected reports nothing:
/// genuinely nothing installed leaves no restored configuration and no
/// enforced policy for either to disagree with, the same reasoning
/// `firewall/divergence.rs` applies to a host with no firewall backend.
/// An empty vector here is the correct answer, not a dodge; `MockExecutor`
/// with neither LSM path registered is exactly `MacDetection::Absent`.
#[tokio::test]
async fn a_host_with_no_mac_system_reports_nothing() {
    let ctx = Context::with_executor(Arc::new(MockExecutor::new()));

    let rows = mac_divergences(&MacHardeningPlugin::new(), &ctx).await;

    assert!(
        rows.is_empty(),
        "no MAC system installed is not a divergence: {rows:?}"
    );
}

/// A host that detects SELinux gets a row naming SELinux, not the generic
/// `mac` subject the `Indeterminate` arm below uses.
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
/// from the generic `mac` subject the `Indeterminate` arm below uses.
/// `Absent` no longer shares that subject: it reports nothing at all.
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

/// `Indeterminate` uses the generic `mac` subject, since it names no specific
/// LSM. The detection's own reason string is what proves the row came from
/// this arm rather than some other one: it is the only arm that interpolates
/// its detection reason into the sentence, so a distinctive reason is used
/// deliberately, and the assertion cannot pass by coincidence with any
/// neighbour's fixed wording.
#[tokio::test]
async fn an_indeterminate_probe_carries_its_own_reason_into_the_detail() {
    let ctx = Context::with_executor(Arc::new(
        MockExecutor::new().with_path_exists_error("/sys/fs/selinux"),
    ));

    let rows = mac_divergences(&MacHardeningPlugin::new(), &ctx).await;

    assert_eq!(rows.len(), 1, "one row, not silence");
    assert_eq!(
        rows[0].divergence_subject, "mac",
        "Indeterminate uses the generic mac subject"
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

/// The ceiling row, not a failure. It appears on every rollback on every host
/// this project can build, because loading an LSM policy is host-global and no
/// container can be given MAC enforcement. Expected and Unverifiable at once:
/// the row still prints "could not check", it just stops crowding a genuine
/// finding.
#[tokio::test]
async fn the_ceiling_row_is_expected_and_names_the_issue() {
    let ctx = Context::with_executor(Arc::new(
        MockExecutor::new().with_path_exists("/sys/fs/selinux", true),
    ));

    let rows = mac_divergences(&MacHardeningPlugin::new(), &ctx).await;

    assert_eq!(rows.len(), 1, "one row");
    assert_eq!(rows[0].divergence_state, DivergenceState::Unverifiable);
    let reason = rows[0]
        .divergence_expected
        .as_ref()
        .expect("a stated ceiling, not a probe that failed");
    assert!(
        reason.contains("#18"),
        "the demotion is only safe while it names the issue that ends it: {reason}"
    );
}
