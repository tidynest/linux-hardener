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

/// The section a plugin's exceptions live under and the field
/// [`HardenerConfig::get_plugin_config`] returns are two separate eight-arm
/// matches that could drift apart in silence. Writing an exception under the
/// named section and reading it back through the other match is the only
/// thing that proves they did not.
#[test]
fn every_plugin_reads_exceptions_from_the_section_it_names() {
    const PLUGIN_IDS: &[&str] = &[
        "ssh-hardening",
        "kernel-hardening",
        "firewall-hardening",
        "pam-hardening",
        "audit-hardening",
        "mac-hardening",
        "permissions-hardening",
        "service-minimisation",
    ];

    for plugin_id in PLUGIN_IDS {
        let section = HardenerConfig::config_section(plugin_id)
            .unwrap_or_else(|| panic!("{plugin_id} names no config section"));
        let document = format!(
            "[{section}.exceptions.\"a.key\"]\n\
             value = \"live\"\n\
             allowed = true\n\
             reason = \"test\"\n"
        );
        let config: HardenerConfig = toml::from_str(&document).unwrap_or_else(|e| {
            panic!("{plugin_id} names section {section}, which did not parse: {e}")
        });

        assert!(
            config
                .get_plugin_config(plugin_id)
                .has_valid_exception("a.key")
                .is_some(),
            "{plugin_id} names section {section}, but get_plugin_config does not read that section",
        );
    }
}

/// The control for the test above. Without it a `config_section` returning one
/// wrong section for every plugin would still pass, because the exception
/// would be written and read back in the same wrong place.
#[test]
fn an_exception_in_another_plugins_section_is_not_read() {
    let config: HardenerConfig = toml::from_str(
        "[ssh.exceptions.\"a.key\"]\nvalue = \"live\"\nallowed = true\nreason = \"test\"\n",
    )
    .expect("the fixture parses");

    assert!(
        config
            .get_plugin_config("ssh-hardening")
            .has_valid_exception("a.key")
            .is_some(),
        "the fixture must be a real exception, or this control measures nothing",
    );
    assert!(
        config
            .get_plugin_config("kernel-hardening")
            .has_valid_exception("a.key")
            .is_none(),
        "an exception written under [ssh] must not be visible to the kernel plugin",
    );
}
