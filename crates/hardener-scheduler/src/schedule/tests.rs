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

/// Each expression with the five instants it fires at after `START`, as
/// `croner` 3.0.1 gave them.
///
/// Recorded on 2026-11-20 by a scratch crate outside the repository, which
/// built croner 3.0.1's parser the way `tokio-cron-scheduler` 0.15.1 did,
/// seconds required and day of month and day of week combined. The in-tree
/// recording test that filled `FIRINGS`, last present at commit `cd90b01a`,
/// did not record these. Only rows on which croner 4 agrees are here.
///
/// The same run saw croner 3 refuse `0 /10 * * * *` and `0 0 3 LW * *`, and
/// croner 4 accepts both. It saw croner 3 parse `0 0 3 * * 7L` and never fire
/// it, where croner 4 fires on the last Sunday of each month. None of these
/// is in the table.
const CRONER_3_SCRATCH_FIRINGS: &[(&str, [i64; 5])] = &[
    // A step written with a single start: every 20 minutes from minute 0.
    (
        "0 0/20 * * * *",
        [1767226800, 1767228000, 1767229200, 1767230400, 1767231600],
    ),
    // A single start that is not zero: every 20 minutes from minute 5.
    (
        "0 5/20 * * * *",
        [1767225900, 1767227100, 1767228300, 1767229500, 1767230700],
    ),
    // A single start in the hours: every six hours from midnight.
    (
        "0 0 0/6 * * *",
        [1767247200, 1767268800, 1767290400, 1767312000, 1767333600],
    ),
    // The last day of the month.
    (
        "0 0 3 L * *",
        [1769828400, 1772247600, 1774926000, 1777518000, 1780196400],
    ),
    // The weekday nearest the 15th.
    (
        "0 0 3 15W * *",
        [1768446000, 1771210800, 1773630000, 1776222000, 1778814000],
    ),
    // The second Friday of the month.
    (
        "0 0 3 * * 5#2",
        [1767927600, 1770951600, 1773370800, 1775790000, 1778209200],
    ),
    // The last Friday of the month.
    (
        "0 0 3 * * 5L",
        [1769742000, 1772161200, 1774580400, 1776999600, 1780023600],
    ),
    // An alias, midnight daily.
    (
        "@daily",
        [1767312000, 1767398400, 1767484800, 1767571200, 1767657600],
    ),
    // A seventh field, the year.
    (
        "0 0 2 * * * 2027",
        [1798768800, 1798855200, 1798941600, 1799028000, 1799114400],
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

/// Checks that every expression in `recorded` fires at its five instants.
fn assert_fires_as_recorded(recorded: &[(&str, [i64; 5])]) {
    let computed: Vec<_> = recorded
        .iter()
        .map(|(expression, _)| (*expression, next_five(expression, START).unwrap()))
        .collect();
    assert_eq!(computed, recorded.to_vec());
}

#[test]
fn the_schedule_fires_when_it_did_under_tokio_cron_scheduler() {
    assert_fires_as_recorded(FIRINGS);
}

#[test]
fn the_schedule_fires_when_croner_3_did_in_the_scratch_recording() {
    assert_fires_as_recorded(CRONER_3_SCRATCH_FIRINGS);
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
    let outcome = Schedule::parse("0 0 0 30 2 *").map(|schedule| schedule.next_after(at(START)));
    assert!(matches!(outcome, Err(_) | Ok(None)), "{outcome:?}");
}
