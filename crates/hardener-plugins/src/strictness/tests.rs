#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`strictness`].
//!
//! Split out of `strictness.rs`. This file sits in the `strictness/` directory
//! beside it, so `super` still resolves to `crate::strictness` and every
//! import carried across unchanged, private items included.

use super::Strictness;

/// `rp_filter`: off, then loose mode, then strict mode. The integer says
/// nothing about that order.
const RP_FILTER: Strictness = Strictness::Ranked(&[&["0"], &["2"], &["1"]]);
/// `PermitRootLogin`, weakest first. `without-password` is sshd's legacy
/// spelling of `prohibit-password` and therefore shares its rank;
/// `forced-commands-only` allows strictly less than either.
const PERMIT_ROOT_LOGIN: Strictness = Strictness::Ranked(&[
    &["yes"],
    &["prohibit-password", "without-password"],
    &["forced-commands-only"],
    &["no"],
]);

#[test]
fn a_ranked_value_is_ordered_by_the_table_and_not_by_its_number() {
    // rp_filter 2 is loose mode: weaker than strict mode 1, despite being
    // the larger integer. Both numeric directions get this wrong, which is
    // the entire reason the variant exists.
    assert!(RP_FILTER.violated_by("1", Some("2")));
    assert!(RP_FILTER.violated_by("1", Some("0")));
    assert!(!RP_FILTER.violated_by("1", Some("1")));
    assert!(!Strictness::AtLeast.violated_by("1", Some("2")));

    // And a clamp keeps strict mode rather than taking the bigger number.
    assert_eq!(RP_FILTER.clamp_target("1", Some("2")), "1");
    assert_eq!(RP_FILTER.clamp_target("2", Some("1")), "1");
}

#[test]
fn a_ranked_word_is_matched_the_way_sshd_matches_it() {
    // sshd compares directive values with strcasecmp, so a host spelling
    // it `No` is already at the target and must not be rewritten.
    assert!(!PERMIT_ROOT_LOGIN.violated_by("no", Some("No")));
    assert!(PERMIT_ROOT_LOGIN.violated_by("no", Some("prohibit-password")));
    assert!(!PERMIT_ROOT_LOGIN.violated_by("prohibit-password", Some("no")));

    // The table's spelling is what gets written, not the host's casing.
    assert_eq!(PERMIT_ROOT_LOGIN.clamp_target("yes", Some("NO")), "no");
}

#[test]
fn a_legacy_spelling_ranks_with_the_name_that_replaced_it() {
    // `without-password` and `prohibit-password` are one setting under two
    // names. Ranking them as neighbours rather than as equals would make a
    // host using the legacy spelling look weaker than the target and earn
    // it a rewrite that changes nothing sshd can observe.
    assert!(!PERMIT_ROOT_LOGIN.violated_by("prohibit-password", Some("without-password")));
    assert!(!PERMIT_ROOT_LOGIN.violated_by("without-password", Some("prohibit-password")));
    assert!(PERMIT_ROOT_LOGIN.violated_by("forced-commands-only", Some("without-password")));
}

#[test]
fn a_direction_judges_by_direction_rather_than_by_equality() {
    // AtMost: a smaller number is stricter, so it is compliant, and this
    // is the whole of the defect the shared module exists to prevent.
    assert!(Strictness::AtMost.violated_by("3", Some("5")));
    assert!(!Strictness::AtMost.violated_by("3", Some("2")));
    assert!(!Strictness::AtMost.violated_by("3", Some("3")));

    // AtLeast: the other way round.
    assert!(Strictness::AtLeast.violated_by("14", Some("8")));
    assert!(!Strictness::AtLeast.violated_by("14", Some("20")));

    // Unset is a violation under every direction: nothing is enforcing it.
    assert!(Strictness::AtMost.violated_by("3", None));
    assert!(Strictness::AtLeast.violated_by("14", None));
    assert!(Strictness::NonZeroAtMost.violated_by("3", None));
}

#[test]
fn zero_is_the_loosest_value_a_non_zero_at_most_setting_has() {
    // Smaller is stricter right up until the value that switches the
    // setting off, which a plain AtMost would have scored best of all.
    assert!(!Strictness::NonZeroAtMost.violated_by("3", Some("2")));
    assert!(Strictness::NonZeroAtMost.violated_by("3", Some("0")));
    assert_eq!(Strictness::NonZeroAtMost.clamp_target("3", Some("0")), "3");
    assert_eq!(Strictness::NonZeroAtMost.clamp_target("3", Some("2")), "2");
}

#[test]
fn a_clamp_keeps_the_stricter_of_the_two_in_each_direction() {
    assert_eq!(Strictness::AtMost.clamp_target("5", Some("3")), "3");
    assert_eq!(Strictness::AtMost.clamp_target("5", Some("9")), "5");
    assert_eq!(Strictness::AtLeast.clamp_target("14", Some("20")), "20");
    assert_eq!(Strictness::AtLeast.clamp_target("14", Some("8")), "14");
}

#[test]
fn a_value_the_comparison_cannot_place_is_never_compliant_and_never_wins() {
    // An unrecognised value is not evidence of anything, so it violates.
    assert!(Strictness::AtMost.violated_by("3", Some("banana")));
    assert!(PERMIT_ROOT_LOGIN.violated_by("no", Some("maybe")));

    // And as a candidate it loses, so a typo in an override cannot relax
    // the target the plugin would otherwise have used.
    assert_eq!(Strictness::AtMost.clamp_target("3", Some("banana")), "3");
    assert_eq!(Strictness::AtMost.clamp_target("3", None), "3");
    assert_eq!(PERMIT_ROOT_LOGIN.clamp_target("no", Some("maybe")), "no");
}

#[test]
fn a_clamp_returns_the_spelling_this_tool_writes() {
    // Two spellings of one number place identically, and the file gets the
    // canonical one either way.
    assert_eq!(Strictness::AtMost.clamp_target("5", Some("03")), "3");
    assert_eq!(Strictness::AtMost.clamp_target("5", Some("05")), "5");
    assert_eq!(Strictness::AtLeast.clamp_target("14", Some("+20")), "20");
}

#[test]
fn an_extreme_value_does_not_overflow_the_shared_scale() {
    // AtMost negates to put smaller first, and negating i64::MIN overflows.
    // A configuration file is free to contain it.
    let min = i64::MIN.to_string();
    assert!(!Strictness::AtMost.violated_by("3", Some(&min)));
    assert_eq!(Strictness::AtMost.clamp_target("3", Some(&min)), min);
}
