#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`report_wizard`](super).
//!
//! Split out of `commands/report_wizard.rs`. This file sits in the `report_wizard/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`,
//! so `super` still resolves to `crate::commands::report_wizard` and every import carried
//! across unchanged, private items included.

use super::*;
use std::collections::HashSet;

/// The custom picker must offer every supported framework. This guards the
/// regression where ISO 27001 was defined everywhere except this table.
#[test]
fn frameworks_table_is_complete_and_unique() {
    let listed: HashSet<ComplianceFramework> = FRAMEWORKS.iter().map(|f| f.framework).collect();
    assert_eq!(
        listed.len(),
        FRAMEWORKS.len(),
        "duplicate framework in the picker table"
    );
    assert_eq!(listed.len(), 10, "picker must list all 10 frameworks");
    assert!(
        listed.contains(&ComplianceFramework::ISO27001),
        "ISO 27001 missing from the picker table"
    );
}

/// Regression guard: colouring the score string before formatting it
/// with `{:.1}` truncated "75.0" down to "7" (precision on a Display
/// applies as a max-width truncation, not decimal rounding).
#[test]
fn format_score_renders_full_number() {
    assert_eq!(format_score(75.0), "75.0");
    assert_eq!(format_score(68.18181818), "68.2");
    assert_eq!(format_score(16.666), "16.7");
    assert_eq!(format_score(0.0), "0.0");
    assert_eq!(format_score(100.0), "100.0");
}

/// Regression guard: `~/` with no further input used to save a literal
/// file named `~.txt` in the current directory instead of expanding to
/// the home directory.
#[test]
fn resolve_output_path_expands_home_dir() {
    let home = dirs::home_dir().expect("test host must have a home directory");
    let resolved = resolve_output_path("~/");
    assert_eq!(resolved, home.join("compliance-report"));
}

#[test]
fn resolve_output_path_expands_tilde_in_nested_file_path() {
    let home = dirs::home_dir().expect("test host must have a home directory");
    let resolved = resolve_output_path("~/reports/out");
    assert_eq!(resolved, home.join("reports/out"));
}

#[test]
fn resolve_output_path_joins_default_name_for_existing_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let input = dir.path().to_str().expect("utf8 tempdir path");
    let resolved = resolve_output_path(input);
    assert_eq!(resolved, dir.path().join("compliance-report"));
}

#[test]
fn resolve_output_path_leaves_plain_file_path_unchanged() {
    let resolved = resolve_output_path("/tmp/some/report.json");
    assert_eq!(resolved, PathBuf::from("/tmp/some/report.json"));
}
