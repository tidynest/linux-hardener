#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms, following `fleet_tests.rs`.

//! Tests for [`scan_history_rows`](super::scan_history_rows), the row count
//! `get_scan_history` asks the database for.
//!
//! The command took its `i32` argument to SQL's `LIMIT` untouched, while its
//! sibling `get_host_history` had clamped since it was written. Two commands
//! answering "how many history rows" and only one of them with a ceiling.

use super::*;

/// The default is the desktop's own, not the database's.
#[test]
fn no_limit_asks_for_twenty() {
    assert_eq!(scan_history_rows(None), Ok(20));
}

/// A caller under the ceiling gets exactly what it asked for. Without this the
/// clamp could be a constant and every other test here would still pass.
#[test]
fn a_modest_request_is_passed_through() {
    assert_eq!(scan_history_rows(Some(1)), Ok(1));
    assert_eq!(scan_history_rows(Some(20)), Ok(20));
}

/// The ceiling binds, and it is the one `get_host_history` uses.
#[test]
fn a_large_request_is_capped_at_the_shared_ceiling() {
    assert_eq!(
        scan_history_rows(Some(5_000)),
        Ok(HISTORY_ROW_CEILING as i32)
    );
    assert_eq!(
        scan_history_rows(Some(i32::MAX)),
        Ok(HISTORY_ROW_CEILING as i32)
    );
}

/// A negative is refused, and refused rather than clamped.
///
/// This is the case the command had no answer for. `LIMIT -1` is unbounded in
/// SQLite, so the argument that looks like the smallest possible request is the
/// one that asks for every row in the database. Clamping it to 1 or to the
/// default would turn an obviously wrong argument into a plausible answer, and
/// the caller would never learn it sent one.
#[test]
fn a_negative_limit_is_refused_and_never_reaches_sql() {
    let refused = scan_history_rows(Some(-1));

    assert!(refused.is_err(), "LIMIT -1 is every row in the table");
    assert!(
        refused.unwrap_err().contains("-1"),
        "the refusal names what it was given, so the caller can see its own bug"
    );
    assert!(scan_history_rows(Some(i32::MIN)).is_err());
}

/// Zero is left alone: it asks for no rows and gets none, which is what it
/// says. Pinned so the negative refusal above is not read as a refusal of
/// everything unhelpful.
#[test]
fn zero_asks_for_nothing_and_is_allowed_to() {
    assert_eq!(scan_history_rows(Some(0)), Ok(0));
}
