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
