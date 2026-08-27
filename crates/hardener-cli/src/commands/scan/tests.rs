#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`scan`](super).
//!
//! Split out of `commands/scan.rs`. This file sits in the `scan/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`,
//! so `super` still resolves to `crate::commands::scan` and every import carried
//! across unchanged, private items included.

use super::*;

const ALL_IDS: &[&str] = &[
    "ssh-hardening",
    "kernel-hardening",
    "firewall-hardening",
    "pam-hardening",
    "audit-hardening",
    "mac-hardening",
    "permissions-hardening",
    "service-minimisation",
];

/// Whether any real plugin id answers to this `--plugin` entry.
fn names_a_plugin(entry: &str) -> bool {
    ALL_IDS
        .iter()
        .any(|id| hardener_types::plugin_id_named_by(id, entry))
}

#[test]
fn plugin_filter_entries_resolve_against_the_real_id_set() {
    for entry in [
        "kernel-hardening",
        "kernel",
        "service",
        "ssh",
        "permissions",
    ] {
        assert!(names_a_plugin(entry), "{entry} should name a plugin");
    }
    // "services" is the plural an operator reaches for; it matches nothing,
    // which is exactly why an unmatched entry must be refused rather than
    // dropped. The empty string is the degenerate case of the same rule.
    for entry in ["nonexistent", "services", ""] {
        assert!(!names_a_plugin(entry), "{entry} names no plugin");
    }
}

#[test]
fn disabled_plugin_excluded_from_selection() {
    // A plugin named in global.disabled_plugins must never appear in the
    // set scan() is about to run, regardless of the --plugin filter.
    let plugins = hardener_plugins::create_plugin_registry().list().unwrap();
    let mut config = HardenerConfig::default();
    config.global.disabled_plugins = vec!["mac-hardening".to_string()];

    let (selected, skipped) = select_enabled_plugins(&plugins, &config, &[]);

    assert!(
        selected
            .iter()
            .all(|metadata| metadata.plugin_id.as_str() != "mac-hardening"),
        "disabled plugin must be excluded from the selected set"
    );
    assert_eq!(
        selected.len(),
        plugins.len() - 1,
        "exactly the disabled plugin should be excluded"
    );
    // The exclusion is reported, not silent.
    assert_eq!(plugin_id_list(&skipped), "mac-hardening");
}

#[test]
fn filter_naming_only_config_disabled_plugins_selects_nothing() {
    // `hardener scan --plugin ssh` on a host whose config disables ssh:
    // the selection is empty and every skipped plugin is named, so the
    // caller can fail loudly instead of exiting clean with no output.
    let plugins = hardener_plugins::create_plugin_registry().list().unwrap();
    let mut config = HardenerConfig::default();
    config.global.disabled_plugins = vec!["ssh-hardening".to_string()];

    let (selected, skipped) = select_enabled_plugins(&plugins, &config, &["ssh".to_string()]);

    assert!(selected.is_empty());
    assert_eq!(plugin_id_list(&skipped), "ssh-hardening");
}

#[test]
fn enabled_plugins_list_narrows_the_selection_too() {
    // global.enabled_plugins is the other way to disable a plugin: anything
    // absent from a non-empty list is skipped by config.
    let plugins = hardener_plugins::create_plugin_registry().list().unwrap();
    let mut config = HardenerConfig::default();
    config.global.enabled_plugins = vec!["kernel-hardening".to_string()];

    let (selected, skipped) = select_enabled_plugins(&plugins, &config, &[]);

    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].plugin_id.as_str(), "kernel-hardening");
    assert_eq!(skipped.len(), plugins.len() - 1);
}

#[test]
fn scan_json_entry_carries_unchecked_key() {
    // The renderer contract Task 10's desktop parser depends on.
    let value = serde_json::json!({
        "plugin_id": "pam-hardening",
        "plugin_name": "PAM Hardening",
        "findings": [],
        "unchecked": [{
            "unchecked_check_id": "pam-minlen",
            "unchecked_title": "PAM setting: minlen",
            "unchecked_category": "Authentication",
            "unchecked_reason": "reading /etc/security/pwquality.conf requires root",
            "unchecked_compliance": []
        }],
    });
    let unchecked: Vec<hardener_core::plugin::UncheckedCheck> =
        serde_json::from_value(value["unchecked"].clone()).unwrap();
    assert_eq!(unchecked[0].unchecked_check_id, "pam-minlen");
}
