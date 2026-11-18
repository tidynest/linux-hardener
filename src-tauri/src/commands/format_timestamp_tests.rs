#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms, following `fleet_tests.rs`.

//! Tests for [`format_timestamp`](super::format_timestamp), the Unix-seconds
//! formatter behind the scan history and checkpoint times.

use super::*;

#[test]
fn unix_seconds_are_rendered_as_utc() {
    assert_eq!(format_timestamp(1767225600), "2026-01-01 00:00:00 UTC");
}

/// The last second of year 9999 is past what the time library can hold, so the
/// text names the number it could not read instead of showing a wrong date.
#[test]
fn a_timestamp_the_library_cannot_hold_names_the_number() {
    assert_eq!(
        format_timestamp(253402300799),
        "Invalid timestamp: 253402300799"
    );
}
