#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`audit`](super).
//!
//! These sit beside `audit.rs` rather than in `tests/audit_tests.rs` because
//! `recover_chain` and `QueryFilter::matches` are private, and an integration
//! test cannot reach either. `tests/audit_tests.rs` keeps the public surface.

use super::*;

/// A fixed instant, so the boundary cases below name an exact second rather
/// than racing the clock.
fn at(second: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(second, 0).expect("a representable instant")
}

fn entry_at(timestamp: DateTime<Utc>) -> AuditEntry {
    AuditEntry::new(
        ActionType::Apply,
        "root".to_string(),
        "/etc/ssh/sshd_config".to_string(),
        vec![7u8; 32],
        timestamp,
    )
}

/// A detail added to an entry is an audit record, so it has to survive.
///
/// The whole method body can be replaced with nothing and every other test
/// still passes, which means the audit log could silently drop the context an
/// operator reads it for.
#[test]
fn a_detail_added_to_an_entry_is_recorded() {
    let mut entry = entry_at(at(1_700_000_000));
    entry.add_detail("directive".to_string(), "PermitRootLogin".to_string());

    assert_eq!(
        entry.entry_details.get("directive").map(String::as_str),
        Some("PermitRootLogin"),
        "an added detail must be readable back, or the log records the action \
         without the thing the action was about"
    );
}

/// Both ends of the time filter are inclusive, which is what the fields say.
///
/// A test that only asks about an entry well inside the window cannot fail
/// under `<=` for `<` or `>=` for `>`: every such entry matches either way.
/// Only the two boundary seconds separate them, and the pair just outside is
/// the control that stops a filter matching everything from passing.
#[test]
fn the_time_filter_includes_both_of_its_own_boundaries() {
    let start = at(1_700_000_000);
    let end = at(1_700_003_600);
    let filter = QueryFilter::new().with_start_time(start).with_end_time(end);

    assert!(
        filter.matches(&entry_at(start)),
        "an entry at exactly the start second is within the window the filter \
         declares inclusive"
    );
    assert!(
        filter.matches(&entry_at(end)),
        "and so is one at exactly the end second"
    );

    assert!(
        !filter.matches(&entry_at(at(1_699_999_999))),
        "the control: one second before the start is outside"
    );
    assert!(
        !filter.matches(&entry_at(at(1_700_003_601))),
        "and one second after the end is outside"
    );
}

/// Recovery reads the log it was given rather than starting a fresh chain.
///
/// The hash chain is what makes the audit log tamper-evident, and recovery runs
/// every time the logger opens an existing file. A body handing back a genesis
/// chain would relink the next entry to nothing, so the chain would verify
/// against itself from that point on while the entries before it were no longer
/// covered: tampering with the log becomes undetectable by restarting the tool.
///
/// The exact recovered hash is asserted, not merely that it is not genesis. An
/// independent reference is what fails a constant, and the entry's own hash is
/// that reference.
#[tokio::test]
async fn recovery_continues_the_chain_the_log_already_holds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log_path = dir.path().join("audit.log");
    let path_str = log_path.to_str().expect("utf-8 path");

    let entry = entry_at(at(1_700_000_000));
    let serialised = serde_json::to_string(&entry).expect("an entry serialises");
    tokio::fs::write(&log_path, format!("{serialised}\n"))
        .await
        .expect("write the existing log");

    let recovered = AuditLogger::recover_chain(path_str).await;
    assert_eq!(
        recovered.current_hash(),
        entry.entry_hash.as_slice(),
        "recovery must continue from the last entry's hash, or the next entry \
         links to nothing and everything already written stops being covered"
    );

    let genesis =
        AuditLogger::recover_chain(dir.path().join("absent.log").to_str().expect("utf-8 path"))
            .await;
    assert_eq!(
        genesis.current_hash(),
        HashChain::new().current_hash(),
        "the control, and the documented fallback: no log means a fresh chain"
    );
}
