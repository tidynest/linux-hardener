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
