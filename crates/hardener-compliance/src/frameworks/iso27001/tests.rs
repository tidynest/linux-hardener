#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`iso27001`](super).
//!
//! Split out of `frameworks/iso27001.rs`. This file sits in the
//! `frameworks/iso27001/` directory beside it, which the 2018 path rules
//! allow with no `mod.rs` and no `#[path]`, so `super` still resolves to
//! `crate::frameworks::iso27001` and every import carried across unchanged,
//! private items included.

use super::*;
use std::collections::HashSet;

#[test]
fn returns_all_93_annex_a_controls() {
    assert_eq!(get_controls().len(), 93);
}

#[test]
fn covers_all_four_themes() {
    let themes: HashSet<String> = get_controls()
        .into_iter()
        .filter_map(|c| c.compliance_section)
        .collect();
    for theme in ["Organizational", "People", "Physical", "Technological"] {
        assert!(themes.contains(theme), "missing theme: {theme}");
    }
}

#[test]
fn theme_counts_match_iso_structure() {
    let controls = get_controls();
    let count = |theme: &str| {
        controls
            .iter()
            .filter(|c| c.compliance_section.as_deref() == Some(theme))
            .count()
    };
    assert_eq!(count("Organizational"), 37);
    assert_eq!(count("People"), 8);
    assert_eq!(count("Physical"), 14);
    assert_eq!(count("Technological"), 34);
}

#[test]
fn all_mappings_use_iso27001_framework() {
    assert!(
        get_controls()
            .iter()
            .all(|c| c.compliance_framework == ComplianceFramework::ISO27001)
    );
}
