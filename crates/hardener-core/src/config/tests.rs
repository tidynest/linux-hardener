#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`config`](super).
//!
//! Split out of `config.rs`. This file sits in the `config/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`, so
//! `super` still resolves to `crate::config` and every import carried across
//! unchanged, private items included.

use super::*;

#[test]
fn policy_exception_maps_to_finding_exception() {
    let ex = PolicyException {
        value: "yes".into(),
        allowed: true,
        reason: "legacy jump host".into(),
        approved_by: Some("Security Team".into()),
        approved_date: Some("2026-01-15".into()),
        ticket: Some("SEC-1234".into()),
        expires: None,
    };
    let fe = ex.to_finding_exception();
    assert_eq!(fe.exception_allowed_value, "yes");
    assert_eq!(fe.exception_reason, "legacy jump host");
    assert_eq!(fe.exception_ticket.as_deref(), Some("SEC-1234"));
    assert!(!fe.exception_is_expired); // no expiry -> not expired
}

/// Builds a valid exception allowing `value` for testing.
fn exception(value: &str, expires: Option<&str>) -> PolicyException {
    PolicyException {
        value: value.into(),
        allowed: true,
        reason: "documented deviation".into(),
        approved_by: None,
        approved_date: None,
        ticket: None,
        expires: expires.map(str::to_string),
    }
}

fn plugin_with(key: &str, exception: PolicyException) -> PluginConfig {
    let mut plugin = PluginConfig::default();
    plugin.exceptions.insert(key.to_string(), exception);
    plugin
}

#[test]
fn matching_exception_honours_only_the_documented_value() {
    let plugin = plugin_with("PermitRootLogin", exception("yes", None));

    // The exception describes the real deviation: honoured.
    assert!(
        plugin
            .matching_exception("PermitRootLogin", "yes")
            .is_some()
    );
    // The system deviates differently from what was approved: ignored.
    assert!(
        plugin
            .matching_exception("PermitRootLogin", "prohibit-password")
            .is_none()
    );
    // Unknown key: nothing to honour.
    assert!(plugin.matching_exception("X11Forwarding", "yes").is_none());
}

#[test]
fn matching_exception_rejects_an_expired_exception() {
    let plugin = plugin_with("PermitRootLogin", exception("yes", Some("2020-01-01")));

    assert!(
        plugin
            .matching_exception("PermitRootLogin", "yes")
            .is_none()
    );
}

#[test]
fn matching_mode_exception_normalises_octal_spelling() {
    let plugin = plugin_with("/etc/passwd", exception("644", None));

    // Written without the leading zero, but the same mode.
    assert!(
        plugin
            .matching_mode_exception("/etc/passwd", 0o644)
            .is_some()
    );
    // A different mode is not the approved deviation.
    assert!(
        plugin
            .matching_mode_exception("/etc/passwd", 0o600)
            .is_none()
    );

    // The four-digit spelling of the same mode also matches.
    let padded = plugin_with("/etc/passwd", exception("0644", None));
    assert!(
        padded
            .matching_mode_exception("/etc/passwd", 0o644)
            .is_some()
    );
    // A non-octal value can never describe a mode.
    let bogus = plugin_with("/etc/passwd", exception("rw-r--r--", None));
    assert!(
        bogus
            .matching_mode_exception("/etc/passwd", 0o644)
            .is_none()
    );
}
