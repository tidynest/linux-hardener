//! Schedule expressions: when a cron expression fires.
//!
//! What `croner` 4.0.3 does, read from its source in the registry:
//!
//! - `CronParser::builder().seconds(Seconds::Required)` makes the first of six
//!   fields the seconds, and `.dom_and_dow(true)` makes a day of month and a
//!   day of week both have to match (`parser.rs:55` and `parser.rs:81`).
//! - `.sloppy_ranges(true)` gates two step forms and nothing else, in every
//!   field (`component.rs:495-519`). A single start, `N/S`, then runs from N
//!   to the field's maximum, as croner 3 read it. An empty start, `/S`, then
//!   reads as `*/S`, which croner 3 refused. Without the switch croner 4
//!   refuses both.
//! - With the `jiff` feature, `Cron::find_next_occurrence(&Zoned, inclusive)`
//!   gives the next firing (`lib.rs:321`, the `Zoned` impl at
//!   `time/jiff_impl.rs:57`). With `inclusive` false the search starts one
//!   second after the start instant, so a firing exactly at the start is
//!   skipped (`lib.rs:271` and `lib.rs:409`).
//! - A search that finds no match returns
//!   `Err(CronError::TimeSearchLimitExceeded)` from one of two limits. One is
//!   366 * 24 * 60 * 60 search passes (`lib.rs:416` and `lib.rs:421`). The
//!   other is the cursor reaching the year 5000 (`lib.rs:754`), which is where
//!   a date that never occurs, such as 30 February, ends.
//! - Date and time arithmetic that leaves the supported range returns
//!   `Err(CronError::InvalidTime)`, or `Err(CronError::InvalidDate)` when a
//!   step to the next day, month or year fails (`lib.rs:794`).
//!
//! `tokio-cron-scheduler` asked for the firing strictly after now, and
//! [`Schedule::next_after`] asks for the same.

use croner::Cron;
use croner::parser::{CronParser, Seconds};
use hardener_common::error::{HardeningError, Result};
use hardener_types::time::{self, Timestamp};
use std::time::Duration;
use tracing::warn;

/// A six-field cron expression, seconds first, read as UTC.
#[derive(Debug)]
pub struct Schedule(Cron);

impl Schedule {
    /// Reads `expression`. A five-field expression is refused, as it was
    /// under `tokio-cron-scheduler`.
    pub fn parse(expression: &str) -> Result<Self> {
        CronParser::builder()
            .seconds(Seconds::Required)
            .dom_and_dow(true)
            .sloppy_ranges(true)
            .build()
            .parse(expression)
            .map(Self)
            .map_err(|error| HardeningError::Config(format!("Invalid cron expression: {error}")))
    }

    /// The first firing strictly after `instant`, compared in whole seconds
    /// as `tokio-cron-scheduler` did, so a fraction of a second belongs to the
    /// second before it. `None` when `croner` returns an error, which an
    /// expression that never fires again gives. A fault in `croner` gives one
    /// too and would look the same to the caller, so the error is logged at
    /// `warn`.
    pub fn next_after(&self, instant: Timestamp) -> Option<Timestamp> {
        let whole_second = time::from_unix_seconds(time::unix_seconds(instant))?;
        match self
            .0
            .find_next_occurrence(&time::utc_zoned(whole_second), false)
        {
            Ok(next) => Some(next.timestamp()),
            Err(error) => {
                warn!(
                    "The schedule '{}' gives no firing after {whole_second}: {error}",
                    self.0.as_str()
                );
                None
            }
        }
    }
}

/// The longest the daemon sleeps before it looks at the clock again.
pub(crate) const LONGEST_WAIT_STEP: Duration = Duration::from_secs(30);

/// How long to sleep before `due`, or `None` when `due` has been reached.
pub(crate) fn wait_step(now: Timestamp, due: Timestamp) -> Option<Duration> {
    Duration::try_from(due.duration_since(now))
        .ok()
        .filter(|remaining| !remaining.is_zero())
        .map(|remaining| remaining.min(LONGEST_WAIT_STEP))
}

#[cfg(test)]
mod tests;
