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

// Which entries name which plugin is `plugin_id_named_by`'s rule and is tested
// beside it in `hardener-types`, over every prefix of an id rather than over a
// handful of literals. What is left here is this module's own half: what
// `validate` and `expand` do once the rule has answered.

#[test]
fn an_empty_entry_names_nothing_and_selects_nothing() {
    // The sharp end of the rule, one level up. An entry that names no plugin
    // must fail rather than resolve to something, and the empty string is the
    // case where "resolve to something" would have meant whichever plugin the
    // registry happened to list first.
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
