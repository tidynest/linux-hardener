#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`layer_drift`].
//!
//! Split out of `layer_drift.rs`. This file sits in the `layer_drift/` directory
//! beside it, so `super` still resolves to `crate::layer_drift` and every
//! import carried across unchanged, private items included.

use super::*;

/// A vendor file of the shape openSUSE ships, trimmed to the keys the
/// assertions need.
const VENDOR: &str = "\
UMASK           022
ENCRYPT_METHOD  yescrypt
PASS_MAX_DAYS   99999
PASS_MIN_DAYS   0
PASS_WARN_AGE   7
";

fn login_defs_conf() -> &'static LayeredConf {
    LAYERED_CONFS
        .iter()
        .find(|c| c.admin_path == "/etc/login.defs")
        .expect("login.defs is in the table")
}

#[test]
fn a_key_the_admin_file_omits_is_masked() {
    assert_eq!(
        masked_keys("PASS_MAX_DAYS 90\n", VENDOR),
        vec![
            "ENCRYPT_METHOD".to_string(),
            "PASS_MIN_DAYS".to_string(),
            "PASS_WARN_AGE".to_string(),
            "UMASK".to_string(),
        ],
        "the difference is vendor minus admin, sorted, and PASS_MAX_DAYS is \
         overridden rather than lost"
    );
}

#[test]
fn a_commented_key_is_not_a_key_on_either_side() {
    // Sharper than it looks. A commented key in /etc does not set anything,
    // so the vendor's value is still masked and must still be named; a
    // commented key in the vendor file was never in force, so naming it
    // would invent drift. Blank and whitespace-only lines are neither.
    assert_eq!(
        masked_keys(
            "# ENCRYPT_METHOD sha512\n\n   \n",
            "ENCRYPT_METHOD yescrypt\n"
        ),
        vec!["ENCRYPT_METHOD".to_string()],
        "a commented admin key sets nothing, so the vendor value is masked"
    );
    assert!(
        masked_keys("", "  # UMASK 022\n\n").is_empty(),
        "a commented vendor key is not in force and cannot be masked"
    );
}

#[test]
fn a_key_the_vendor_repeats_is_named_once() {
    assert_eq!(
        masked_keys("", "UMASK 022\nUMASK 027\n"),
        vec!["UMASK".to_string()]
    );
}

#[test]
fn an_admin_file_keeping_every_vendor_key_masks_nothing() {
    // Opposite direction: true of an implementation that reports nothing at
    // all, so it is not evidence. It pins that a full copy stays quiet.
    assert!(masked_keys(VENDOR, VENDOR).is_empty());
}

/// The `security/*.conf` files use `name = value` where `login.defs` uses
/// `NAME VALUE`. One set difference has to serve both, or generalising the
/// check to those three files would compare nothing.
#[test]
fn the_key_is_the_first_token_in_either_syntax() {
    assert_eq!(
        masked_keys(
            "minlen = 14\n",
            "minlen = 8\ndifok = 5\nENCRYPT_METHOD  yescrypt\n"
        ),
        vec!["ENCRYPT_METHOD".to_string(), "difok".to_string()],
        "minlen is set at both layers in the = syntax, so it is overridden, \
         not masked"
    );
}

/// Every entry must be a real `/etc` path, or `vendor_path_for` returns
/// `None` for it and the check silently covers one file fewer.
#[test]
fn every_table_entry_has_a_vendor_counterpart() {
    for conf in LAYERED_CONFS {
        assert!(
            hardener_common::vendor_config::vendor_path_for(conf.admin_path).is_some(),
            "{} has no /usr/etc counterpart, so it would never be checked",
            conf.admin_path
        );
    }
}

/// Two files sharing an id would report as one finding and the operator
/// could not tell which file drifted.
#[test]
fn every_table_entry_has_its_own_finding_id() {
    let ids: BTreeSet<&str> = LAYERED_CONFS.iter().map(|c| c.finding_id).collect();
    assert_eq!(
        ids.len(),
        LAYERED_CONFS.len(),
        "finding ids must be unique across the table"
    );
}

#[test]
fn the_finding_names_the_file_that_masks_and_the_file_masked() {
    let finding = masked_keys_finding(
        login_defs_conf(),
        "/usr/etc/login.defs",
        &["ENCRYPT_METHOD".to_string()],
    );
    assert_eq!(finding.finding_id, "pam-login-defs-masked-keys");
    assert!(finding.finding_description.contains("/etc/login.defs"));
    assert!(finding.finding_description.contains("/usr/etc/login.defs"));
    assert!(finding.finding_description.contains("ENCRYPT_METHOD"));
}
