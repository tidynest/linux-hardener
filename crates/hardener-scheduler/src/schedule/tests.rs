#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Pins when schedule expressions fire.
//!
//! The instants in `FIRINGS` were recorded from the stack the daemon used
//! before the cron library was replaced: `tokio-cron-scheduler` 0.15.1 on
//! `croner` 3. They are Unix seconds, so a later library has to agree with
//! them without any edit to the table.

use super::{LONGEST_WAIT_STEP, Schedule, wait_step};
use hardener_common::error::{HardeningError, Result};
use hardener_types::time::{self, Timestamp};
use std::time::Duration;

/// 2026-01-01T00:00:00Z, the instant every expression is asked from.
const START: i64 = 1_767_225_600;

/// Each expression with the five instants it fires at after `START`.
const FIRINGS: &[(&str, [i64; 5])] = &[
    // The default: 02:00 UTC daily.
    (
        "0 0 2 * * *",
        [1767232800, 1767319200, 1767405600, 1767492000, 1767578400],
    ),
    // A step: every quarter of an hour.
    (
        "0 */15 * * * *",
        [1767226500, 1767227400, 1767228300, 1767229200, 1767230100],
    ),
    // A range: hourly from 09:00 to 17:00, here only the first five hours.
    (
        "0 0 9-17 * * *",
        [1767258000, 1767261600, 1767265200, 1767268800, 1767272400],
    ),
    // A list: 06:00 and 18:00.
    (
        "0 0 6,18 * * *",
        [1767247200, 1767290400, 1767333600, 1767376800, 1767420000],
    ),
    // A day-of-week name: Mondays at 03:30.
    (
        "0 30 3 * * Mon",
        [1767583800, 1768188600, 1768793400, 1769398200, 1770003000],
    ),
    // Day of month and day of week together: only a Friday the 13th.
    (
        "0 0 4 13 * Fri",
        [1770955200, 1773374400, 1794542400, 1818129600, 1855022400],
    ),
];

/// The instant `seconds` after the Unix epoch.
fn at(seconds: i64) -> Timestamp {
    time::from_unix_seconds(seconds).expect("a representable instant")
}

/// The next five instants after `after`, in Unix seconds.
fn next_five(expression: &str, after: i64) -> Result<[i64; 5]> {
    let schedule = Schedule::parse(expression)?;
    let mut start = at(after);
    let mut instants = [0; 5];
    for instant in &mut instants {
        let next = schedule.next_after(start).expect("the expression recurs");
        *instant = time::unix_seconds(next);
        start = next;
    }
    Ok(instants)
}

#[test]
fn the_schedule_fires_when_it_did_under_tokio_cron_scheduler() {
    let computed: Vec<_> = FIRINGS
        .iter()
        .map(|(expression, _)| (*expression, next_five(expression, START).unwrap()))
        .collect();
    let recorded = FIRINGS.to_vec();
    assert_eq!(computed, recorded);
}

#[test]
fn a_five_field_expression_is_refused() {
    assert!(next_five("0 2 * * *", START).is_err());
}

#[test]
fn nonsense_is_refused() {
    assert!(next_five("not a schedule", START).is_err());
}

#[test]
fn a_refusal_carries_the_text_the_daemon_wrote_before() {
    let Err(HardeningError::Config(text)) = Schedule::parse("0 2 * * *") else {
        panic!("a five-field expression must be a configuration error");
    };
    assert!(text.starts_with("Invalid cron expression: "), "{text}");
}

#[test]
fn the_start_instant_is_never_a_firing_and_a_fraction_counts_as_its_second() {
    let schedule = Schedule::parse("0 */15 * * * *").unwrap();
    let firing = 1767226500;
    let before = time::from_unix_parts(firing - 1, 500_000_000).unwrap();
    let on = at(firing);
    let after = time::from_unix_parts(firing, 500_000_000).unwrap();
    let results = [before, on, after].map(|start| schedule.next_after(start).unwrap());
    assert_eq!(results, [at(firing), at(firing + 900), at(firing + 900)]);
    for result in results {
        assert_eq!(result.subsec_nanosecond(), 0);
    }
}

#[test]
fn a_wait_step_never_exceeds_thirty_seconds_and_ends_when_due() {
    let now = at(START);
    assert_eq!(LONGEST_WAIT_STEP, Duration::from_secs(30));
    assert_eq!(
        wait_step(now, at(START + 10)),
        Some(Duration::from_secs(10))
    );
    assert_eq!(
        wait_step(now, at(START + 300)),
        Some(Duration::from_secs(30))
    );
    assert_eq!(wait_step(now, now), None);
    assert_eq!(wait_step(at(START + 1), now), None);
}

#[test]
fn an_expression_that_never_occurs_has_no_next_instant() {
    if let Ok(schedule) = Schedule::parse("0 0 0 30 2 *") {
        assert_eq!(schedule.next_after(at(START)), None);
    }
}
