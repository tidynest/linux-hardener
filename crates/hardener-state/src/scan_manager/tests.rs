#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`scan_manager`](super).
//!
//! These sit beside `scan_manager.rs` because `current_timestamp` is private
//! and an integration test cannot reach it. `tests/scan_manager_tests.rs`
//! keeps the public surface.

use super::*;

/// The scan clock is the real clock.
///
/// `current_timestamp` stamps both `started_at` and `completed_at` on every
/// scan session, and those are what the history, the trend report and the
/// regression check order rows by. Replaced with a constant the whole history
/// collapses onto one instant, every scan looks simultaneous, and nothing
/// ordering-dependent can be believed. No test asked what it returned, only
/// that a row was written.
///
/// The assertion is against a second, independent reading of the system clock
/// rather than against a hard-coded epoch, since only an independent reference
/// can fail a constant. The window is wide enough that a slow machine between
/// the two readings does not matter and narrow enough that no fixed value
/// survives it.
#[test]
fn the_scan_timestamp_is_read_from_the_clock() {
    let before = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the system clock is after the epoch")
        .as_secs() as i64;

    let stamped = current_timestamp();

    let after = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the system clock is after the epoch")
        .as_secs() as i64;

    assert!(
        (before..=after).contains(&stamped),
        "the stamp must fall between two readings of the clock taken either \
         side of it, got {stamped} outside {before}..={after}"
    );
}
