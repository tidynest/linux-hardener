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
