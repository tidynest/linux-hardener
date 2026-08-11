#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`plugin`](super).
//!
//! Split out of `plugin.rs`. This file sits in the `plugin/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`, so
//! `super` still resolves to `crate::plugin` and every import carried across
//! unchanged, private items included.

use super::*;

#[test]
fn test_change_type_display() {
    assert_eq!(ChangeType::ConfigFile.to_string(), "Config File");
    assert_eq!(ChangeType::FirewallRule.to_string(), "Firewall Rule");
    assert_eq!(ChangeType::KernelParameter.to_string(), "Kernel Parameter");
    assert_eq!(ChangeType::Skipped.to_string(), "Skipped");
}

/// The two rollback hooks default to doing nothing, and a plugin that says
/// nothing inherits that.
///
/// Both are provided trait methods, so only an implementor that overrides
/// neither can pin them, and `MockPlugin` is exactly that. The directions
/// matter separately. `reloads_for_path` returning `true` by default would make
/// every plugin claim every restored path, so a rollback would reload
/// subsystems that were never touched, and the permissions plugin, whose paths
/// come from operator directives and cannot be enumerated, relies on the
/// `false` answer. `reload_after_rollback` returning `Some` by default would
/// put a row in the rollback output for work no plugin did, and an empty
/// `Some(String::new())` would print a blank line claiming an action.
#[tokio::test]
async fn a_plugin_that_overrides_neither_rollback_hook_does_nothing() {
    let plugin = crate::testing::MockPlugin::new("mock-hardening");

    assert!(
        !plugin.reloads_for_path(Path::new("/etc/ssh/sshd_config")),
        "a plugin that never said it owns a path must not claim it, or a \
         rollback reloads subsystems it did not touch"
    );

    let context = Context::new();
    assert_eq!(
        plugin
            .reload_after_rollback(&context)
            .await
            .expect("the default hook does not fail"),
        None,
        "nothing reloaded means no row in the rollback output, and `Some` of \
         anything, empty string included, claims an action that never happened"
    );
}
