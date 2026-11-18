//! Timestamps, dates and their text forms for the whole workspace.
//!
//! This is the only module that names the time library. Every other crate goes
//! through the functions here, so the bytes the tool writes for a timestamp are
//! decided in one place and a change of library is a change to this file.

pub use jiff::{Timestamp, Zoned, civil::Date};

use jiff::{Span, fmt::strtime, tz::TimeZone};
use serde::{Serialize, Serializer};
use std::fmt;

/// The pattern for a timestamp shown in a report, such as `2026-01-01 00:00:00 UTC`.
pub const REPORT_STAMP: &str = "%Y-%m-%d %H:%M:%S UTC";
/// The pattern for a timestamp in a file name, such as `20260101_000000`.
pub const FILE_STAMP_UNDERSCORE: &str = "%Y%m%d_%H%M%S";
/// The pattern for a timestamp in a file name, such as `20260101-000000`.
pub const FILE_STAMP_HYPHEN: &str = "%Y%m%d-%H%M%S";
/// The pattern for a timestamp to the minute in a scan history list, such as
/// `2026-01-01 00:00`.
pub const MINUTE_STAMP: &str = "%Y-%m-%d %H:%M";

/// The instant `seconds` after the Unix epoch, as chrono's
/// `DateTime::from_timestamp(seconds, 0)` gave. `None` outside the library's
/// range, 2 January -9999 to 30 December 9999, which is narrower than chrono's
/// and which no stored record reaches.
pub fn from_unix_seconds(seconds: i64) -> Option<Timestamp> {
    Timestamp::from_second(seconds).ok()
}

/// Whole seconds since the Unix epoch, rounded down as chrono's `timestamp()`
/// did, so half a second before the epoch is `-1` and not `0`.
pub fn unix_seconds(instant: Timestamp) -> i64 {
    // The library truncates towards zero, so an instant before the epoch with
    // a fraction needs one more second taken off to match the floor.
    instant.as_second() - i64::from(instant.subsec_nanosecond() < 0)
}

/// The calendar day `instant` falls on in UTC, as chrono's `date_naive()` gave
/// for a `DateTime<Utc>`.
pub fn date_utc(instant: Timestamp) -> Date {
    TimeZone::UTC.to_datetime(instant).date()
}

/// `instant` in UTC written with a strftime `pattern`, giving the same text
/// chrono's `format` did for the named patterns in this module. The library
/// writes a specifier it does not know as literal text where chrono panicked,
/// so a new pattern needs a test of its literal text.
pub fn format_utc(instant: Timestamp, pattern: &str) -> String {
    instant.strftime(pattern).to_string()
}

/// A `YYYY-MM-DD` date, or `None` when it is not a real calendar day. Accepts
/// what chrono's `%Y-%m-%d` accepted for any date a person writes, including a
/// month or day without its leading zero.
pub fn parse_iso_date(value: &str) -> Option<Date> {
    strtime::parse("%Y-%m-%d", value).ok()?.to_date().ok()
}

/// `date` moved forward by `months`, keeping the day of the month or stopping
/// at the last day of a shorter month, as chrono's `checked_add_months` did.
/// `None` when the result falls outside the dates the library can represent.
pub fn add_months(date: Date, months: u32) -> Option<Date> {
    date.checked_add(Span::new().try_months(months).ok()?).ok()
}

/// An instant in the RFC 3339 form chrono's serde support wrote for
/// `DateTime<Utc>`: seconds, then a fraction of 3, 6 or 9 digits only when
/// one is needed, then `Z`.
struct Rfc3339(Timestamp);

impl fmt::Display for Rfc3339 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let civil = TimeZone::UTC.to_datetime(self.0);
        // chrono gave a year outside 0 to 9999 an explicit sign, as ISO 8601
        // asks, and the library's own `%Y` does not.
        let year = civil.year();
        if (0..=9999).contains(&year) {
            write!(formatter, "{year:04}")?;
        } else {
            write!(formatter, "{year:+05}")?;
        }
        write!(
            formatter,
            "-{:02}-{:02}T{:02}:{:02}:{:02}",
            civil.month(),
            civil.day(),
            civil.hour(),
            civil.minute(),
            civil.second()
        )?;
        // The civil fraction is never negative, unlike the timestamp's own,
        // so an instant before the epoch writes the same digits chrono did.
        match civil.subsec_nanosecond() {
            0 => {}
            nanoseconds if nanoseconds % 1_000_000 == 0 => {
                write!(formatter, ".{:03}", nanoseconds / 1_000_000)?
            }
            nanoseconds if nanoseconds % 1_000 == 0 => {
                write!(formatter, ".{:06}", nanoseconds / 1_000)?
            }
            nanoseconds => write!(formatter, ".{nanoseconds:09}")?,
        }
        formatter.write_str("Z")
    }
}

impl Serialize for Rfc3339 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Serde adaptor writing the bytes chrono wrote. Use as
/// `#[serde(with = "hardener_types::time::rfc3339")]`.
pub mod rfc3339 {
    use super::{Rfc3339, Timestamp};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Writes `instant` as chrono wrote a `DateTime<Utc>`.
    pub fn serialize<S: Serializer>(instant: &Timestamp, serializer: S) -> Result<S::Ok, S::Error> {
        Rfc3339(*instant).serialize(serializer)
    }

    /// Reads an RFC 3339 timestamp with any offset, as chrono read one into a
    /// `DateTime<Utc>`.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Timestamp, D::Error> {
        Timestamp::deserialize(deserializer)
    }

    /// The same adaptor for an `Option<Timestamp>`, writing `None` as null as
    /// chrono's `Option<DateTime<Utc>>` did. A field that may be missing needs
    /// `#[serde(default)]` beside it, because serde stops treating a missing
    /// `Option` as `None` once a field names its own adaptor.
    pub mod option {
        use super::{Rfc3339, Timestamp};
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        /// Writes `Some` as [`super::serialize`] does and `None` as null,
        /// through serde's own `Option` handling as chrono's derive did.
        pub fn serialize<S: Serializer>(
            instant: &Option<Timestamp>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            instant.map(Rfc3339).serialize(serializer)
        }

        /// Reads null as `None` and anything else as [`super::deserialize`] does.
        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<Timestamp>, D::Error> {
            Option::<Timestamp>::deserialize(deserializer)
        }
    }
}

/// The current instant, as chrono's `Utc::now()` gave.
#[cfg(feature = "clock")]
pub fn now() -> Timestamp {
    Timestamp::now()
}

/// The current instant as whole seconds since the Unix epoch, as chrono's
/// `Utc::now().timestamp()` gave, for the history rows that store one.
#[cfg(feature = "clock")]
pub fn now_unix_seconds() -> i64 {
    unix_seconds(now())
}

/// Today's date in UTC, as chrono's `Utc::now().date_naive()` gave.
#[cfg(feature = "clock")]
pub fn today_utc() -> Date {
    date_utc(now())
}

/// Today's date on this machine's clock, as chrono's
/// `Local::now().date_naive()` gave.
#[cfg(feature = "clock")]
pub fn today_local() -> Date {
    local_zone().to_datetime(now()).date()
}

/// `instant` on this machine's clock written with a strftime `pattern`, as
/// chrono's `with_timezone(&Local).format(pattern)` gave. The library writes
/// a specifier it does not know as literal text where chrono panicked, so a
/// new pattern needs a test of its literal text.
#[cfg(feature = "clock")]
pub fn format_local(instant: Timestamp, pattern: &str) -> String {
    local_zone()
        .to_datetime(instant)
        .strftime(pattern)
        .to_string()
}

/// The current instant in UTC with its zone attached, for code that needs the
/// calendar fields of now without a second clock read.
#[cfg(feature = "clock")]
pub fn now_utc_zoned() -> Zoned {
    now().to_zoned(TimeZone::UTC)
}

/// The machine's time zone, found the way chrono's `Local` found it: `TZ`
/// first, then `/etc/localtime`, and UTC when neither gives a zone.
#[cfg(feature = "clock")]
fn local_zone() -> TimeZone {
    // The library gives up when `TZ` is set but unreadable, where chrono went
    // on to the machine's own zone, so `/etc/localtime` is read here as well.
    TimeZone::try_system()
        .ok()
        .or_else(|| {
            let data = std::fs::read("/etc/localtime").ok()?;
            TimeZone::tzif("localtime", &data).ok()
        })
        .unwrap_or(TimeZone::UTC)
}

#[cfg(test)]
mod tests;
