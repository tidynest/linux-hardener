#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`history`](super).
//!
//! Split out of `commands/history.rs`. This file sits in the `history/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`,
//! so `super` still resolves to `crate::commands::history` and every import carried
//! across unchanged, private items included.

use super::*;

fn session(host: &str, started_at: i64, critical: i32, high: i32) -> ScanSession {
    ScanSession {
        id: format!("{host}-{started_at}"),
        started_at,
        completed_at: Some(started_at),
        status: "completed".into(),
        trigger_type: "batch".into(),
        host_identifier: host.into(),
        plugins_scanned: String::new(),
        total_findings: critical + high,
        critical_count: critical,
        high_count: high,
        medium_count: 0,
        low_count: 0,
        info_count: 0,
        error_message: None,
        json_file_path: None,
        hash: None,
    }
}

#[test]
fn find_regressions_flags_only_worse_latest() {
    // Newest-first, as list_sessions returns.
    let sessions = vec![
        session("web", 200, 2, 0),  // latest: 2 crit, worse than prior (1 crit)
        session("web", 100, 1, 0),  // prior
        session("db", 200, 0, 1),   // latest: better than prior
        session("db", 100, 0, 3),   // prior
        session("solo", 100, 5, 5), // single scan, nothing to compare
    ];

    let regs = find_regressions(&sessions);

    assert_eq!(regs.len(), 1, "only web regressed");
    assert_eq!(regs[0].host, "web");
    assert_eq!(regs[0].delta_critical, 1);
    assert_eq!(regs[0].previous_total, 1);
    assert_eq!(regs[0].current_total, 2);
}

/// The session table names the host each row belongs to, and its header lines
/// up with its rows.
///
/// Until #162 there was no host column at all. On a machine that scans a
/// fleet, `history list` rendered every host's sessions as one unlabelled
/// timeline: eighteen rows from an SSH test container sat above two from this
/// desktop, and the plain reading was that findings here had fallen from 5
/// critical to 0. Two different machines, and nothing in the output said so.
#[test]
fn the_session_table_names_the_host_and_stays_aligned() {
    let desktop = session("TidyNest", 1_786_604_777, 0, 1);
    let container = session("root@10.242.117.2:22", 1_786_553_226, 5, 11);

    let desktop_row = session_row(&desktop);
    let container_row = session_row(&container);

    assert!(
        desktop_row.contains("TidyNest"),
        "the row must name its host: {desktop_row:?}"
    );
    assert!(
        container_row.contains("root@10.242.117.2:22"),
        "a host identifier is not truncated, because two machines that render \
         identically are the defect this column exists to fix: {container_row:?}"
    );

    // Alignment: the header's Host column has to start where the rows' does,
    // or the column is decorative rather than readable.
    //
    // Sliced at the offset rather than searched for, because the fixture's
    // session id is "{host}-{started_at}" and a search finds the host inside
    // the id at position 0. That is what this assertion caught when it was
    // written the obvious way.
    let header_host = SESSION_TABLE_HEADER
        .find("Host")
        .expect("the header declares a Host column");
    assert!(
        desktop_row[header_host..].starts_with("TidyNest"),
        "the value must begin under its own heading, at column {header_host}: \
         {desktop_row:?}"
    );
    assert!(
        container_row[header_host..].starts_with("root@10.242.117.2:22"),
        "and so must a longer one: {container_row:?}"
    );

    // The counts still read across, and in the right order: a row that put
    // high where crit belongs would satisfy every assertion above.
    assert!(
        container_row.trim_end().ends_with("5   11    0    0"),
        "crit, high, med, low in that order: {container_row:?}"
    );
}

/// Timestamps say which zone they are in, and the column is wide enough to
/// hold one that does.
///
/// The binary had two `format_timestamp` implementations, both converting to
/// local time and both printing no zone, so the same instant read `09:06:17` in
/// the history table and `07:06:17 UTC` in the compliance report on a `CEST`
/// host, and only the report said which. An operator correlating the table
/// against `journalctl` saw a two hour gap with nothing to explain it (#164).
///
/// The width assertion is not decoration: `Started` is a fixed-width column,
/// and a label that overflows it pushes every column after it out of
/// alignment on every row.
#[test]
fn session_timestamps_name_their_zone_and_fit_their_column() {
    // 1786604777 is 2026-08-13 07:06:17 UTC, and 09:06:17 in CEST. The host
    // that found this defect is CEST, so a renderer that silently kept local
    // time would print the second and pass any assertion that only checked for
    // digits.
    let row = session_row(&session("TidyNest", 1_786_604_777, 0, 1));

    let started = SESSION_TABLE_HEADER
        .find("Started")
        .expect("the header declares a Started column");
    let rendered = &row[started..];

    assert!(
        rendered.starts_with("2026-08-13 07:06:17 UTC"),
        "the instant must render in UTC and say so: {rendered:?}"
    );

    // The Status column is what gets pushed if the label does not fit.
    let status = SESSION_TABLE_HEADER
        .find("Status")
        .expect("the header declares a Status column");
    assert!(
        row[status..].starts_with("completed"),
        "the zone label must fit inside the Started column, or every column \
         after it shifts: {row:?}"
    );
}
