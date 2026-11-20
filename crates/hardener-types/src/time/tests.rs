#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading.

//! Unit tests for [`time`](super).
//!
//! Every literal here is what chrono gave for the same input on 1.9.1, checked
//! side by side against chrono 0.4.42, so these tests hold the module to the
//! bytes the tool has always written and read.

use super::*;
use jiff::civil::date;
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::time::SystemTime;

/// What 1.9.1 wrote for each instant, the same table the audit log's pinned
/// test holds in `hardener-state`.
const PINNED: [(i64, u32, &str); 4] = [
    (1767225600, 0, "2026-01-01T00:00:00Z"),
    (1767225600, 500_000_000, "2026-01-01T00:00:00.500Z"),
    (1767225600, 123_456_000, "2026-01-01T00:00:00.123456Z"),
    (1767225600, 123_456_789, "2026-01-01T00:00:00.123456789Z"),
];

/// The instant `seconds` and `nanoseconds` after the epoch, in the pairs 1.9.1
/// stored, whose fraction always counts forward, also before the epoch.
fn instant(seconds: i64, nanoseconds: u32) -> Timestamp {
    from_unix_parts(seconds, nanoseconds).expect("a representable instant")
}

#[derive(Debug, Deserialize, Serialize)]
struct Stamped {
    #[serde(with = "rfc3339")]
    at: Timestamp,
}

fn written(at: Timestamp) -> String {
    serde_json::to_string(&Stamped { at }).unwrap()
}

fn read(text: &str) -> Result<Timestamp, serde_json::Error> {
    serde_json::from_str::<Stamped>(&format!(r#"{{"at":"{text}"}}"#)).map(|stamped| stamped.at)
}

/// Each `(seconds, nanoseconds, literal)` case as written beside the JSON it
/// must be, so one assertion shows every case that moved.
fn written_and_expected(cases: &[(i64, u32, &str)]) -> (Vec<String>, Vec<String>) {
    cases
        .iter()
        .map(|&(seconds, nanoseconds, literal)| {
            let expected = format!(r#"{{"at":"{literal}"}}"#);
            (written(instant(seconds, nanoseconds)), expected)
        })
        .unzip()
}

#[test]
fn rfc3339_writes_the_fraction_in_groups_of_three_digits() {
    let (actual, expected) = written_and_expected(&PINNED);
    assert_eq!(actual, expected);

    let (actual, expected) = written_and_expected(&[
        (1767225600, 1, "2026-01-01T00:00:00.000000001Z"),
        (1767225600, 10, "2026-01-01T00:00:00.000000010Z"),
        (1767225600, 1_000, "2026-01-01T00:00:00.000001Z"),
        (1767225600, 100_000_000, "2026-01-01T00:00:00.100Z"),
        (1767225600, 120_000_000, "2026-01-01T00:00:00.120Z"),
        (1767225600, 999_999_999, "2026-01-01T00:00:00.999999999Z"),
    ]);
    assert_eq!(actual, expected);
}

/// Padding and sign are where a hand-written writer and chrono could part, so
/// the years either side of the four-digit range are held here.
#[test]
fn rfc3339_writes_early_years_and_instants_before_the_epoch_as_1_9_1_did() {
    let (actual, expected) = written_and_expected(&[
        (-1, 0, "1969-12-31T23:59:59Z"),
        (-1, 500_000_000, "1969-12-31T23:59:59.500Z"),
        (-30610224000, 0, "1000-01-01T00:00:00Z"),
        (-62135596800, 0, "0001-01-01T00:00:00Z"),
        (-62167219200, 0, "0000-01-01T00:00:00Z"),
        (-62198755200, 0, "-0001-01-01T00:00:00Z"),
    ]);
    assert_eq!(actual, expected);
}

#[test]
fn rfc3339_reads_an_explicit_utc_offset_as_the_same_instant() {
    let zulu = read("2026-01-01T00:00:00Z").unwrap();
    assert_eq!(read("2026-01-01T00:00:00+00:00").unwrap(), zulu);
    assert_eq!(read("2026-01-01T00:00:00-00:00").unwrap(), zulu);
    assert_eq!(read("2026-01-01T02:00:00+02:00").unwrap(), zulu);
    assert_eq!(zulu, instant(1767225600, 0));
}

#[test]
fn rfc3339_reads_back_every_pinned_literal_as_the_instant_it_came_from() {
    let read_back: Vec<Timestamp> = PINNED.iter().map(|case| read(case.2).unwrap()).collect();
    let built: Vec<Timestamp> = PINNED.iter().map(|case| instant(case.0, case.1)).collect();
    assert_eq!(read_back, built);
}

/// chrono read all of these, so a record that holds one keeps reading.
#[test]
fn rfc3339_reads_the_spellings_1_9_1_read() {
    let zulu = instant(1767225600, 0);
    assert_eq!(read("2026-01-01t00:00:00z").unwrap(), zulu);
    assert_eq!(read("2026-01-01 00:00:00Z").unwrap(), zulu);
    assert_eq!(read("2026-01-01T00:00:00+0000").unwrap(), zulu);
    assert_eq!(
        read("2026-01-01T00:00:00+05:30").unwrap(),
        instant(1767205800, 0)
    );
    assert_eq!(
        read("2026-01-01T00:00:00.5Z").unwrap(),
        instant(1767225600, 500_000_000)
    );
    assert_eq!(
        read("1969-12-31T23:59:59.5Z").unwrap(),
        instant(-1, 500_000_000)
    );
}

#[test]
fn rfc3339_refuses_a_timestamp_without_an_offset() {
    assert!(read("2026-01-01T00:00:00").is_err());
    assert!(read("2026-01-01").is_err());
}

#[test]
fn unix_seconds_round_trip() {
    let instant = from_unix_seconds(1767225600).unwrap();
    assert_eq!(unix_seconds(instant), 1767225600);
    assert_eq!(written(instant), r#"{"at":"2026-01-01T00:00:00Z"}"#);
}

/// 1.9.1 rounded Unix seconds down, and the library on its own rounds
/// towards zero, which differs only before the epoch.
#[test]
fn unix_seconds_round_down_before_the_epoch() {
    assert_eq!(unix_seconds(instant(-1, 500_000_000)), -1);
    assert_eq!(unix_seconds(instant(-2, 999_999_999)), -2);
    assert_eq!(unix_seconds(instant(0, 1)), 0);
}

#[test]
fn unix_seconds_out_of_range_is_none() {
    assert_eq!(from_unix_seconds(i64::MAX), None);
    assert_eq!(from_unix_seconds(i64::MIN), None);
    // The library stops a day short of the end of 9999, where chrono went on
    // to year 262143. No record holds an instant that late.
    assert_eq!(from_unix_seconds(253402300799), None);
}

/// The pairs chrono's `DateTime::from_timestamp` took, each compared with its
/// count of nanoseconds from the epoch, so the expected side is a plain number.
#[test]
fn unix_parts_count_the_fraction_forward_as_chrono_did() {
    let nanoseconds_of = |seconds, nanoseconds| {
        from_unix_parts(seconds, nanoseconds).map(|instant| instant.as_nanosecond())
    };
    assert_eq!(nanoseconds_of(-1, 500_000_000), Some(-500_000_000));
    assert_eq!(nanoseconds_of(-2, 999_999_999), Some(-1_000_000_001));
    assert_eq!(nanoseconds_of(0, 0), Some(0));
    assert_eq!(nanoseconds_of(0, 1), Some(1));
    assert_eq!(
        nanoseconds_of(1767225600, 123_456_789),
        Some(1_767_225_600_123_456_789)
    );
    assert_eq!(
        from_unix_parts(1767225600, 0),
        from_unix_seconds(1767225600)
    );

    // A thousand million nanoseconds or more is refused. chrono made a leap
    // second of it when the second was 59 and the value below two thousand
    // million, and gave `None` otherwise, so only values below a thousand
    // million are compared with chrono.
    assert_eq!(from_unix_parts(1767225599, 1_000_000_000), None);
    assert_eq!(from_unix_parts(0, u32::MAX), None);
    assert_eq!(from_unix_parts(i64::MAX, 0), None);
    assert_eq!(from_unix_parts(i64::MIN, 0), None);
}

#[test]
fn date_utc_is_the_day_in_utc() {
    assert_eq!(
        date_utc(instant(1767225599, 999_999_999)),
        date(2025, 12, 31)
    );
    assert_eq!(date_utc(instant(1767225600, 0)), date(2026, 1, 1));
}

#[test]
fn an_iso_date_must_be_a_real_calendar_day() {
    assert_eq!(parse_iso_date("2026-02-28"), Some(date(2026, 2, 28)));
    assert_eq!(parse_iso_date("2024-02-29"), Some(date(2024, 2, 29)));
    // chrono's `%Y-%m-%d` took a month or day without its leading zero, and
    // whitespace before a number, so a hand-written expiry date still reads.
    assert_eq!(parse_iso_date("2026-2-28"), Some(date(2026, 2, 28)));
    assert_eq!(parse_iso_date(" 2026-02-28"), Some(date(2026, 2, 28)));

    for refused in [
        "2026-02-30",
        "2025-02-29",
        "2026-13-01",
        "2026-00-10",
        "2026-02-00",
        "",
        "28-02-2026",
        "20260228",
        "2026-02-28 ",
        "2026-02-28\n",
        "2026-02-28T00:00:00",
        "10000-01-01",
    ] {
        assert_eq!(parse_iso_date(refused), None, "{refused:?}");
    }
}

/// `hardener scope` writes `approved_date` as the text of a `Date`, which 1.9.1
/// wrote through chrono's `NaiveDate` as `YYYY-MM-DD`, and the config layer
/// reads it back through `parse_iso_date`.
#[test]
fn a_date_is_written_as_1_9_1_wrote_one() {
    assert_eq!(date(2026, 1, 1).to_string(), "2026-01-01");
    assert_eq!(date(2026, 3, 7).to_string(), "2026-03-07");
    assert_eq!(date(2026, 12, 31).to_string(), "2026-12-31");

    let today = today_utc();
    let text = today.to_string();
    assert_eq!(text.len(), 10, "{text}");
    assert_eq!(parse_iso_date(&text), Some(today));
}

#[test]
fn adding_months_stops_at_the_end_of_a_short_month() {
    assert_eq!(add_months(date(2026, 1, 31), 1), Some(date(2026, 2, 28)));
    assert_eq!(add_months(date(2024, 1, 31), 1), Some(date(2024, 2, 29)));
    assert_eq!(add_months(date(2026, 3, 31), 1), Some(date(2026, 4, 30)));
    assert_eq!(add_months(date(2026, 1, 31), 13), Some(date(2027, 2, 28)));
    assert_eq!(add_months(date(2024, 2, 29), 12), Some(date(2025, 2, 28)));
    assert_eq!(add_months(date(2026, 5, 15), 12), Some(date(2027, 5, 15)));
    assert_eq!(add_months(date(2026, 5, 15), 0), Some(date(2026, 5, 15)));
    assert_eq!(add_months(date(9999, 12, 31), 1), None);
}

#[test]
fn the_named_formats_match_their_pinned_text() {
    let new_year = instant(1767225600, 0);
    assert_eq!(
        format_utc(new_year, REPORT_STAMP),
        "2026-01-01 00:00:00 UTC"
    );
    assert_eq!(
        format_utc(new_year, FILE_STAMP_UNDERSCORE),
        "20260101_000000"
    );
    assert_eq!(format_utc(new_year, FILE_STAMP_HYPHEN), "20260101-000000");
    assert_eq!(format_utc(new_year, MINUTE_STAMP), "2026-01-01 00:00");

    // Every field distinct, so a swapped pair of specifiers shows.
    let distinct = from_unix_seconds(1772888645).unwrap();
    assert_eq!(
        format_utc(distinct, REPORT_STAMP),
        "2026-03-07 13:04:05 UTC"
    );
    assert_eq!(
        format_utc(distinct, FILE_STAMP_UNDERSCORE),
        "20260307_130405"
    );
    assert_eq!(format_utc(distinct, FILE_STAMP_HYPHEN), "20260307-130405");
    assert_eq!(format_utc(distinct, MINUTE_STAMP), "2026-03-07 13:04");
}

#[test]
fn utc_zoned_keeps_the_instant_and_names_utc() {
    let zoned = utc_zoned(instant(1767225600, 500_000_000));
    assert_eq!(zoned.timestamp(), instant(1767225600, 500_000_000));
    assert_eq!(zoned.offset(), jiff::tz::Offset::UTC);
    assert_eq!((zoned.year(), zoned.month(), zoned.day()), (2026, 1, 1));
}

#[test]
fn now_reads_the_system_clock() {
    let before = Timestamp::try_from(SystemTime::now()).unwrap();
    let read = now();
    let zoned = now_utc_zoned();
    let after = Timestamp::try_from(SystemTime::now()).unwrap();
    assert!(before <= read && read <= zoned.timestamp() && zoned.timestamp() <= after);
    assert_eq!(zoned.offset(), jiff::tz::Offset::UTC);
}

/// Read against the standard library's clock, so a helper that returned a
/// fixed number or milliseconds would fail here.
#[test]
fn now_unix_seconds_is_the_whole_seconds_of_now() {
    let since_epoch = || {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    };
    let before = i64::try_from(since_epoch()).unwrap();
    let read = now_unix_seconds();
    let after = i64::try_from(since_epoch()).unwrap();
    assert!(before <= read && read <= after, "{before} {read} {after}");
}

#[test]
fn today_utc_is_the_date_of_now() {
    let before = date_utc(now());
    let today = today_utc();
    let after = date_utc(now());
    assert!(before <= today && today <= after);
}

/// Set in a child run of this test binary, which then reports instead of
/// testing.
const LOCAL_CHILD: &str = "HARDENER_TYPES_LOCAL_CHILD";

/// What a child run of [`the_local_functions_follow_the_tz_variable`] reports
/// with `TZ` set to `zone`, or removed when `zone` is `None`: the PINNED
/// instant through `format_local`, and `today_local`.
fn local_under(zone: Option<&str>) -> (String, Date) {
    let mut child = Command::new(std::env::current_exe().unwrap());
    child
        .args([
            "time::tests::the_local_functions_follow_the_tz_variable",
            "--exact",
        ])
        .args(["--nocapture", "--test-threads=1"])
        .env(LOCAL_CHILD, "1");
    match zone {
        Some(zone) => child.env("TZ", zone),
        None => child.env_remove("TZ"),
    };
    let output = child.output().unwrap();
    assert!(
        output.status.success(),
        "child under TZ={zone:?} failed: {output:?}"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    // The harness writes the test's name on the same line before the child's
    // own output, so the report is found by its marker, not at a line start.
    let report = stdout
        .lines()
        .find_map(|line| line.split_once("zone report: "))
        .unwrap()
        .1;
    let (text, today) = report.split_once(' ').unwrap();
    (text.to_owned(), parse_iso_date(today).unwrap())
}

/// The machine's zone is read from the environment of the process, so each
/// case runs in a child with its own `TZ` and the test never depends on the
/// zone of the host it runs on.
#[test]
fn the_local_functions_follow_the_tz_variable() {
    if std::env::var_os(LOCAL_CHILD).is_some() {
        let text = format_local(instant(1767225600, 0), FILE_STAMP_HYPHEN);
        println!("zone report: {text} {}", today_local());
        return;
    }
    assert_eq!(local_under(Some("UTC0")).0, "20260101-000000");
    assert_eq!(local_under(Some("")).0, "20260101-000000");
    assert_eq!(local_under(Some("<+0530>-5:30")).0, "20260101-053000");
    assert_eq!(local_under(Some("<-03>3")).0, "20251231-210000");

    // Twenty-six hours apart, so the dates differ whatever the time of day.
    assert!(local_under(Some("<+14>-14")).1 > local_under(Some("<-12>12")).1);

    // chrono went on to the machine's own zone when `TZ` named nothing it
    // could read. On a host whose zone is UTC this cannot tell that from
    // falling back to UTC, and it still holds.
    assert_eq!(local_under(Some("Not/AZone")).0, local_under(None).0);
}

/// What [`zone_named_in`] makes of a file holding `contents`, as the PINNED
/// instant written in that zone. The file sits in the system's scratch
/// directory under this process's id, so parallel runs do not share it.
fn zone_file_holding(label: &str, contents: &str) -> Option<String> {
    let path = std::env::temp_dir().join(format!(
        "hardener-types-zone-{}-{label}",
        std::process::id()
    ));
    std::fs::write(&path, contents).unwrap();
    let zone = zone_named_in(&path);
    std::fs::remove_file(&path).unwrap();
    zone.map(|zone| {
        zone.to_datetime(instant(1767225600, 0))
            .strftime(FILE_STAMP_HYPHEN)
            .to_string()
    })
}

/// `Etc/GMT-5` is five hours ahead of UTC all year, so the result does not
/// depend on this machine's own zone, only on the system's zoneinfo.
#[test]
fn a_zone_name_file_is_read_as_chrono_read_etc_timezone() {
    assert_eq!(
        zone_file_holding("named", "Etc/GMT-5\n").as_deref(),
        Some("20260101-050000")
    );
    assert_eq!(
        zone_file_holding("bare", "UTC").as_deref(),
        Some("20260101-000000")
    );
    assert_eq!(zone_file_holding("nonsense", "not a zone\n"), None);
    assert_eq!(zone_file_holding("empty", ""), None);

    let missing = std::env::temp_dir().join(format!(
        "hardener-types-zone-{}-missing",
        std::process::id()
    ));
    assert!(!missing.exists());
    assert!(zone_named_in(&missing).is_none());
}
