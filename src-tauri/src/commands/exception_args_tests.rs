#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. Present so the file
// says what it is on its own terms, matching its siblings in this directory.

//! Tests for `exception_add_args`: an optional field the operator left blank
//! must become no flag at all, not a flag paired with an empty string.

use super::*;

/// Every optional field absent means no flag, not an empty flag. `--ticket ""`
/// would write an empty ticket into the operator's config.
#[test]
fn absent_optional_fields_add_no_flags() {
    let args = exception_add_args(
        "service-minimisation",
        "bluetooth",
        "laptop needs it",
        None,
        None,
        None,
    );

    assert_eq!(
        args,
        vec![
            "--format",
            "json",
            "exception",
            "add",
            "service-minimisation",
            "bluetooth",
            "--reason",
            "laptop needs it",
        ]
    );
}

/// A supplied field becomes exactly one flag and one value.
#[test]
fn supplied_optional_fields_become_flags() {
    let args = exception_add_args(
        "ssh",
        "PermitRootLogin",
        "bastion",
        Some("eric"),
        Some("OPS-12"),
        Some("2027-01-01"),
    );

    assert!(args.windows(2).any(|w| w == ["--approved-by", "eric"]));
    assert!(args.windows(2).any(|w| w == ["--ticket", "OPS-12"]));
    assert!(args.windows(2).any(|w| w == ["--expires", "2027-01-01"]));
}
