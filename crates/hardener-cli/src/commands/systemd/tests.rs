#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading.

//! Unit tests for [`systemd`](super).
//!
//! The four verbs shell out to `systemctl` and touch unit directories, so what
//! is tested here is the decision each verb makes about what it reports, which
//! is the half that was wrong.

use super::*;

/// `uninstall` said "Systemd units removed" whatever happened.
///
/// Wrong in both directions: on a host with nothing installed it claimed a
/// removal that never happened, and where `disable --now` failed it did not say
/// the timer may still be running against units that are now gone.
#[test]
fn the_uninstall_summary_reports_what_happened() {
    assert_eq!(
        uninstall_summary(2, true),
        "Systemd units removed",
        "the ordinary success"
    );
    assert_eq!(
        uninstall_summary(2, false),
        "Systemd units removed, but disabling the timer failed",
        "files gone, timer possibly still running"
    );
}

/// The answer reached stdout only when `systemctl` had put it there.
///
/// The absent-unit case is the one that was wrong and the one that matters: it
/// is all stderr and no stdout, so a renderer that forwards stream to stream
/// prints nothing at all. Asserted alongside the ordinary case so a fix that
/// simply swapped the streams would fail too.
#[test]
fn the_status_answer_is_on_one_stream_whichever_stream_systemctl_used() {
    assert_eq!(
        status_report("", "Unit linux-hardener.timer could not be found.\n"),
        "Unit linux-hardener.timer could not be found.\n",
        "absent units are reported on stderr and are still the answer"
    );
    assert_eq!(
        status_report("● linux-hardener.timer - Scheduled scan\n", ""),
        "● linux-hardener.timer - Scheduled scan\n",
        "the ordinary case is unchanged"
    );
    assert_eq!(
        status_report("● linux-hardener.timer\n", "Unit ...service not found.\n"),
        "● linux-hardener.timer\nUnit ...service not found.\n",
        "one unit found and one absent: both halves, in the order systemctl gave"
    );
}

/// Nothing installed is not a removal.
///
/// Split from the test above because it is what the old wording got most wrong,
/// and because it has to hold whichever way the disable went: `disable --now`
/// fails for a unit that was never enabled, which is exactly the host that has
/// nothing to remove.
#[test]
fn removing_nothing_does_not_claim_a_removal() {
    let disabled = uninstall_summary(0, true);
    let not_disabled = uninstall_summary(0, false);

    assert_eq!(
        disabled,
        "No systemd units were installed here; nothing to remove"
    );
    assert_eq!(
        disabled, not_disabled,
        "with nothing removed, the disable outcome does not change the answer"
    );
}
