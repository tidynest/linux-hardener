#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Tests for `restorable_here` in [`commands`](super).
//!
//! Every checkpoint records the host it captured, and
//! `CheckpointManager::rollback` refuses to restore one host's state onto
//! another. The desktop's list merged both local databases and showed all of
//! them, so a remote host's pre-apply checkpoints appeared as this machine's
//! restore points, each with an armed Roll back button that could only fail.
//!
//! Not an edge case: `batch apply --execute` runs unprivileged and writes every
//! remote host's checkpoints into the local user database, which is the first
//! source the list reads. The database on the machine this was found on held 84
//! such rows and no local one.

use super::*;

/// A checkpoint carrying nothing but an id and the host it captured, which is
/// all this decision reads.
fn row(id: &str, host_key: &str) -> (Checkpoint, ()) {
    (
        Checkpoint {
            checkpoint_id: CheckpointId::new(id),
            checkpoint_name: format!("{id}-pre-apply"),
            checkpoint_timestamp: 0,
            checkpoint_username: "operator".to_string(),
            checkpoint_signature: Vec::new(),
            host_key: host_key.to_string(),
        },
        (),
    )
}

fn ids(entries: &[(Checkpoint, ())]) -> Vec<&str> {
    entries
        .iter()
        .map(|(cp, _)| cp.checkpoint_id.as_str())
        .collect()
}

/// The mixed case, and the direction matters: keeping the remote rows and
/// dropping the local ones would satisfy any assertion that only counted.
#[test]
fn only_the_rows_captured_on_this_host_are_kept() {
    let (kept, dropped) = restorable_here(
        vec![
            row("cp_1_aaaaaaaa", "ssh://root@10.0.0.5:22"),
            row("cp_2_bbbbbbbb", "local"),
            row("cp_3_cccccccc", "ssh://root@10.0.0.6:22"),
            row("cp_4_dddddddd", "local"),
        ],
        "local",
    );

    assert_eq!(ids(&kept), vec!["cp_2_bbbbbbbb", "cp_4_dddddddd"]);
    assert_eq!(dropped, 2, "the two remote rows are counted, not discarded");
}

/// What the machine this was found on actually holds. The count is what the
/// operator is told, so a list that shrank to nothing while reporting nothing
/// would be the original defect wearing a filter.
#[test]
fn a_list_of_only_other_hosts_keeps_nothing_and_counts_all_of_it() {
    let (kept, dropped) = restorable_here(
        vec![
            row("cp_1_aaaaaaaa", "ssh://root@10.242.117.2:22"),
            row("cp_2_bbbbbbbb", "ssh://root@10.242.117.2:22"),
            row("cp_3_cccccccc", "ssh://root@10.242.117.3:22"),
        ],
        "local",
    );

    assert!(kept.is_empty());
    assert_eq!(dropped, 3);
}

/// Nothing in, nothing out, and **no note**. A zero count is what stops the
/// note appearing at all, so a rule that reported one row missing from an empty
/// database would put a sentence on every fresh install's screen.
#[test]
fn an_empty_list_reports_nothing_missing() {
    let (kept, dropped) = restorable_here(Vec::<(Checkpoint, ())>::new(), "local");

    assert!(kept.is_empty());
    assert_eq!(dropped, 0);
}

/// Kept plus dropped is what came in, over every mixture, so no row is invented
/// and none vanishes uncounted.
///
/// This is the assertion the three above cannot make between them: each of them
/// names one arrangement, and the failure this guards is a row that falls out of
/// both halves. Written as a sweep over the local/remote patterns of a
/// four-element list, all sixteen of them.
#[test]
fn every_row_is_either_kept_or_counted() {
    let mut patterns_checked = 0;

    for pattern in 0u8..16 {
        let entries: Vec<_> = (0..4)
            .map(|position| {
                let host = if pattern & (1 << position) == 0 {
                    "local"
                } else {
                    "ssh://root@10.0.0.5:22"
                };
                row(&format!("cp_{position}_aaaaaaaa"), host)
            })
            .collect();

        let (kept, dropped) = restorable_here(entries, "local");

        assert_eq!(
            kept.len() + dropped,
            4,
            "pattern {pattern:04b} lost or gained a row"
        );
        assert_eq!(
            dropped,
            pattern.count_ones() as usize,
            "pattern {pattern:04b} counted the wrong number as belonging elsewhere"
        );
        patterns_checked += 1;
    }

    // Top level, and not merely a guard against the loop running zero times:
    // sixteen is every local/remote arrangement four rows can take, so a
    // smaller number means the sweep stopped covering the space it was written
    // to cover rather than that it found nothing to say.
    assert_eq!(
        patterns_checked, 16,
        "all sixteen arrangements of four rows must be swept"
    );
}

/// The key is compared, not assumed. A desktop pointed at a remote target would
/// keep that host's rows and drop the local ones, which is the same rule read
/// from the other end and the reason the key is a parameter.
#[test]
fn the_local_key_is_whatever_the_caller_says_it_is() {
    let entries = vec![
        row("cp_1_aaaaaaaa", "local"),
        row("cp_2_bbbbbbbb", "ssh://root@10.0.0.5:22"),
    ];

    let (kept, dropped) = restorable_here(entries, "ssh://root@10.0.0.5:22");

    assert_eq!(ids(&kept), vec!["cp_2_bbbbbbbb"]);
    assert_eq!(dropped, 1);
}
