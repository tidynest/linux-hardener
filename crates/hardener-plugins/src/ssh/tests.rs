#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`ssh`].
//!
//! Split out of `ssh.rs`. This file sits in the `ssh/` directory beside it,
//! so `super` still resolves to `crate::ssh` and every import carried across
//! unchanged, private items included.

use super::*;

/// Ties the predicate to the constants `apply` actually checkpoints, so the
/// two cannot drift apart unnoticed. Asserted against the constants
/// themselves, not their literal values: `tests/ssh_mock_tests.rs` compiles
/// as a separate crate and cannot see `SSHD_ADMIN_CONFIG_PATH` or
/// `dropin::DROPIN_PATH` (both are private), so a copy of this test living
/// there had to assert on string literals instead - which stayed green
/// through a change to either constant's value, catching nothing. This file
/// sits inside `crate::ssh`, where both names are visible, so a rename or a
/// value change fails here instead of passing silently.
#[test]
fn every_path_ssh_checkpoints_is_one_it_reloads_for() {
    let plugin = SshHardeningPlugin::new();
    for path in [SSHD_ADMIN_CONFIG_PATH, dropin::DROPIN_PATH] {
        assert!(
            plugin.reloads_for_path(Path::new(path)),
            "ssh checkpoints {path} but would not reload for it"
        );
    }
}
