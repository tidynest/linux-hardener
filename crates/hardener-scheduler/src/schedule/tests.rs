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

use croner::parser::{CronParser, Seconds};
use tokio_cron_scheduler::job::job_data::JobStoredData;

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

/// The next five instants after `after`, in Unix seconds.
///
/// This is the one thing the next task replaces. It parses the way
/// `tokio-cron-scheduler` does and takes its start instant from that crate's
/// own conversion, so the time library never needs naming here.
fn next_five(expression: &str, after: i64) -> Result<[i64; 5], croner::errors::CronError> {
    let schedule = CronParser::builder()
        .seconds(Seconds::Required)
        .dom_and_dow(true)
        .build()
        .parse(expression)?;
    let mut start = JobStoredData {
        id: None,
        last_updated: None,
        last_tick: None,
        next_tick: after as u64,
        job_type: 0,
        count: 0,
        extra: Vec::new(),
        ran: false,
        stopped: false,
        job: None,
        time_offset_seconds: 0,
    }
    .next_tick_utc()
    .expect("a non-zero start instant converts");
    let mut instants = [0; 5];
    for instant in &mut instants {
        let next = schedule.find_next_occurrence(&start, false)?;
        *instant = next.timestamp();
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
