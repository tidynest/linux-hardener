#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`ssh_config`](super).
//!
//! Split out of `ssh_config.rs`. This file sits in the `ssh_config/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`,
//! so `super` still resolves to `crate::ssh_config` and every import carried
//! across unchanged, private items included.

use super::*;

#[test]
fn test_parse_user_at_host() {
    let config = SshConnectionConfig::from_cli("root@server.com", 22, None, 30, false);
    assert_eq!(config.user, Some("root".to_string()));
    assert_eq!(config.host, "server.com");
    assert_eq!(config.port, 22);
    assert!(config.strict_host_key_checking);
}

#[test]
fn test_parse_host_only() {
    let config = SshConnectionConfig::from_cli("server.com", 2222, None, 60, true);
    assert_eq!(config.user, None);
    assert_eq!(config.host, "server.com");
    assert_eq!(config.port, 2222);
    assert!(!config.strict_host_key_checking);
}

#[test]
fn test_display_with_user() {
    let config = SshConnectionConfig::from_cli("admin@host", 22, None, 30, false);
    assert_eq!(config.display(), "admin@host:22");
}

#[test]
fn test_display_without_user() {
    let config = SshConnectionConfig::from_cli("host", 22, None, 30, false);
    assert_eq!(config.display(), "host:22");
}
