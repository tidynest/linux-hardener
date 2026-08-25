#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`text`](super).

use super::*;

/// The budget covers the whole returned string, ellipsis included.
///
/// This is the assertion the two former copies disagreed about. The PDF
/// renderer's took `max_chars` characters and then appended three more, so a
/// 70-character budget produced 73 and the cell it was shaping had no say.
#[test]
fn the_result_never_exceeds_the_budget() {
    let long = "a".repeat(100);

    // Named first and unconditionally: 70 is the PDF title column's budget,
    // and the copy this replaced returned 73 for exactly this input.
    assert_eq!(truncate_string(&long, 70).chars().count(), 70);

    for max in 0..40usize {
        let out = truncate_string(&long, max);
        assert!(
            out.chars().count() <= max,
            "budget {max} produced {} chars: {out:?}",
            out.chars().count()
        );
    }
}

#[test]
fn text_within_the_budget_is_returned_whole() {
    assert_eq!(truncate_string("short", 10), "short");
    // Exactly at the budget is not a cut: nothing is gained by an ellipsis
    // that replaces characters it has room for.
    assert_eq!(truncate_string("exactly-10", 10), "exactly-10");
}

#[test]
fn a_cut_is_marked_and_the_marker_costs_three_characters() {
    assert_eq!(truncate_string("abcdefghij", 9), "abcdef...");
    assert_eq!(truncate_string("abcdefghij", 4), "a...");
}

/// Below four characters an ellipsis would be the whole budget or more, so
/// the text is cut bare instead of overflowing the column it is filling.
#[test]
fn a_budget_too_small_for_a_marker_cuts_without_one() {
    assert_eq!(truncate_string("abcdefghij", 3), "abc");
    assert_eq!(truncate_string("abcdefghij", 1), "a");
    assert_eq!(truncate_string("abcdefghij", 0), "");
}

/// The budget is characters, not bytes, so a multi-byte string is neither
/// split mid-character nor charged for its encoding.
#[test]
fn the_budget_counts_characters_rather_than_bytes() {
    // Ten characters, thirty bytes.
    let text = "日本語日本語日本語語";
    assert_eq!(text.chars().count(), 10);
    assert_eq!(text.len(), 30);

    assert_eq!(truncate_string(text, 10), text, "ten fits a budget of ten");
    assert_eq!(truncate_string(text, 6), "日本語...");
}

/// A cut landing in the middle of a gap does not leave the space behind.
///
/// The former PDF copy produced `this is a ...` for a ten-character budget,
/// which is both over budget and visibly wrong in a table.
#[test]
fn a_cut_landing_on_a_space_does_not_keep_it() {
    assert_eq!(truncate_string("this is a longer string", 10), "this is...");
    assert!(
        truncate_string("this is a longer string", 10)
            .chars()
            .count()
            <= 10
    );
}
