//! Schedule expressions: when a cron expression fires.
//!
//! What `croner` 4.0.3 does, read from its source in the registry:
//!
//! - `CronParser::builder().seconds(Seconds::Required)` makes the first of six
//!   fields the seconds, and `.dom_and_dow(true)` makes a day of month and a
//!   day of week both have to match (`parser.rs:55` and `parser.rs:81`).
//! - With the `jiff` feature, `Cron::find_next_occurrence(&Zoned, inclusive)`
//!   gives the next firing (`lib.rs:321`, the `Zoned` impl at
//!   `time/jiff_impl.rs:57`). With `inclusive` false the search starts one
//!   second after the start instant, so a firing exactly at the start is
//!   skipped (`lib.rs:271` and `lib.rs:409`).
//! - When nothing matches it returns `Err(CronError::TimeSearchLimitExceeded)`
//!   after 366 * 24 * 60 * 60 search passes (`lib.rs:295` and `lib.rs:407`).
//!   It returns `Err(CronError::InvalidTime)` where the date arithmetic leaves
//!   the supported range.
//!
//! `tokio-cron-scheduler` asked for the firing strictly after now, and
//! [`Schedule::next_after`] asks for the same.

use croner::Cron;
use croner::parser::{CronParser, Seconds};
use hardener_common::error::{HardeningError, Result};
use hardener_types::time::{self, Timestamp};
use std::time::Duration;

/// A six-field cron expression, seconds first, read as UTC.
#[derive(Debug)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the daemon loop task adds the first caller")
)]
pub struct Schedule(Cron);

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the daemon loop task adds the first caller")
)]
impl Schedule {
    /// Reads `expression`. A five-field expression is refused, as it was
    /// under `tokio-cron-scheduler`.
    pub fn parse(expression: &str) -> Result<Self> {
        CronParser::builder()
            .seconds(Seconds::Required)
            .dom_and_dow(true)
            .build()
            .parse(expression)
            .map(Self)
            .map_err(|error| HardeningError::Config(format!("Invalid cron expression: {error}")))
    }

    /// The first firing strictly after `instant`, compared in whole seconds
    /// as `tokio-cron-scheduler` did, so a fraction of a second belongs to the
    /// second before it. `None` when the expression never fires again.
    pub fn next_after(&self, instant: Timestamp) -> Option<Timestamp> {
        let whole_second = time::from_unix_seconds(time::unix_seconds(instant))?;
        let next = self
            .0
            .find_next_occurrence(&time::utc_zoned(whole_second), false)
            .ok()?;
        Some(next.timestamp())
    }
}

/// The longest the daemon sleeps before it looks at the clock again.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the daemon loop task adds the first caller")
)]
pub(crate) const LONGEST_WAIT_STEP: Duration = Duration::from_secs(30);

/// How long to sleep before `due`, or `None` when `due` has been reached.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the daemon loop task adds the first caller")
)]
pub(crate) fn wait_step(now: Timestamp, due: Timestamp) -> Option<Duration> {
    Duration::try_from(due.duration_since(now))
        .ok()
        .filter(|remaining| !remaining.is_zero())
        .map(|remaining| remaining.min(LONGEST_WAIT_STEP))
}

#[cfg(test)]
mod tests;
