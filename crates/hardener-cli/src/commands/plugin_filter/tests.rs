#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`plugin_filter`](super).
//!
//! Split out of `commands/plugin_filter.rs`. This file sits in the `plugin_filter/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`,
//! so `super` still resolves to `crate::commands::plugin_filter` and every import carried
//! across unchanged, private items included.

use super::*;
use hardener_common::types::{FindingCategory, PluginId};

fn meta(id: &str) -> PluginMetadata {
    PluginMetadata {
        plugin_category: FindingCategory::Kernel,
        plugin_description: String::new(),
        plugin_id: PluginId::new(id),
        plugin_name: id.to_string(),
        plugin_version: "0".to_string(),
    }
}

fn registry() -> Vec<PluginMetadata> {
    vec![
        meta("ssh-hardening"),
        meta("kernel-hardening"),
        meta("service-minimisation"),
    ]
}

#[test]
fn short_name_matches_the_segment_before_the_first_hyphen() {
    assert!(matches("service", "service-minimisation"));
    assert!(matches("ssh", "ssh-hardening"));
}

#[test]
fn full_id_matches_itself() {
    assert!(matches("service-minimisation", "service-minimisation"));
}

#[test]
fn a_longer_prefix_is_not_a_segment_and_must_not_match() {
    // The plural reads naturally and is the mistake an operator makes;
    // it names no plugin and must be refused rather than silently dropped.
    // Note that this one is refused with or without the trailing hyphen, so
    // it does not measure the hyphen; the two tests below do.
    assert!(!matches("services", "service-minimisation"));
}

#[test]
fn a_partial_segment_is_not_a_segment_and_must_not_match() {
    // This is what the trailing hyphen buys. A leading substring of the first
    // segment is not the segment, and without the hyphen every one of these
    // would match, so a typo would select a plugin the operator did not name.
    assert!(!matches("serv", "service-minimisation"));
    assert!(!matches("s", "ssh-hardening"));
    assert!(!matches("kernel-hard", "kernel-hardening"));
}

#[test]
fn an_empty_entry_names_nothing_and_selects_nothing() {
    // The sharp end of the same rule: `starts_with("")` is true of every id,
    // so without the hyphen an empty entry would match all three and `expand`
    // would hand back whichever the registry happened to list first. A filter
    // that names nothing must fail, never resolve to something.
    //
    // `scan::tests` already asserts that an empty entry names no plugin. What
    // is new here is the consequence one level up, that `expand` refuses it
    // rather than quietly resolving it, which is the behaviour an operator
    // actually meets.
    assert!(!matches("", "service-minimisation"));
    let err = expand(&registry(), &[String::new()])
        .expect_err("an empty entry must be refused, not resolved to a plugin");
    assert!(
        err.to_string().contains("Unknown plugin"),
        "refused as unknown rather than silently dropped: {err}"
    );
}

#[test]
fn expand_rejects_an_entry_that_names_no_plugin() {
    let err = expand(&registry(), &["services".to_string()])
        .expect_err("an unmatched entry must be an error, not an empty selection");
    let message = err.to_string();
    assert!(
        message.contains("services"),
        "names the bad entry: {message}"
    );
    assert!(
        message.contains("service-minimisation"),
        "lists the valid ids: {message}"
    );
}

#[test]
fn expand_rejects_a_bad_entry_even_when_another_entry_is_good() {
    // The dangerous shape: a filter that shrinks instead of failing, so
    // the operator believes both plugins ran.
    expand(&registry(), &["ssh".to_string(), "services".to_string()])
        .expect_err("one bad entry must fail the whole selection");
}

#[test]
fn expand_preserves_the_order_the_operator_wrote() {
    let ids = expand(&registry(), &["service".to_string(), "ssh".to_string()])
        .expect("both entries are valid");
    assert_eq!(
        ids.iter().map(|i| i.as_str()).collect::<Vec<_>>(),
        vec!["service-minimisation", "ssh-hardening"]
    );
}

#[test]
fn an_empty_filter_expands_to_nothing_without_error() {
    assert!(expand(&registry(), &[]).expect("empty is valid").is_empty());
}
