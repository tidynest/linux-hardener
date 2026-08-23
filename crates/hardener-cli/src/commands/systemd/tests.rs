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

/// A user timer and a system timer are different facts about a host.
///
/// One runs as the operator and only while they are logged in; the other runs
/// as root on a timer the host keeps. Two entries naming only the unit, which
/// is the same string in both cases, would be indistinguishable.
#[test]
fn a_unit_entry_says_which_systemd_instance_it_changed() {
    let system = unit_audit(None, timer_name(), "install", false, &[]);
    let user = unit_audit(None, timer_name(), "install", true, &[]);

    assert_eq!(system.target, user.target, "the unit name is the same");
    assert_eq!(system.details["scope"], "system");
    assert_eq!(user.details["scope"], "user");
}

/// The target names the unit, not the path it landed on.
///
/// An auditor asking whether the scheduled scan was changed wants both the
/// `--user` and the system install, and a path-shaped target would split them
/// into two vocabularies.
#[test]
fn a_unit_entry_targets_the_unit_rather_than_its_directory() {
    let audit = unit_audit(None, service_name(), "install", false, &[]);

    assert_eq!(audit.target, "unit:linux-hardener.service");
    assert!(
        !audit.target.contains('/'),
        "a directory in the target splits user and system installs apart: {}",
        audit.target
    );
}

/// Install and uninstall are the same target and must be told apart by the
/// entry itself, since the absence of a later entry proves nothing.
#[test]
fn install_and_uninstall_are_distinguishable_at_the_same_target() {
    let installed = unit_audit(None, timer_name(), "install", false, &[]);
    let removed = unit_audit(None, timer_name(), "uninstall", false, &[]);

    assert_eq!(installed.details["operation"], "install");
    assert_eq!(removed.details["operation"], "uninstall");
}

/// Caller detail reaches the entry alongside the two keys every unit entry
/// carries, rather than replacing them.
#[test]
fn caller_detail_is_added_to_the_entry_rather_than_replacing_it() {
    let audit = unit_audit(
        None,
        timer_name(),
        "install",
        false,
        &[("schedule", "daily".to_string())],
    );

    assert_eq!(audit.details["schedule"], "daily");
    assert_eq!(audit.details["operation"], "install");
    assert_eq!(audit.details["scope"], "system");
}

/// A system install and a user install write the same two unit names to
/// different directories, and the directory is the whole difference.
#[test]
fn the_unit_directory_follows_the_mode() {
    let system = unit_dir_for(false).expect("a system unit directory always resolves");

    assert_eq!(system, std::path::PathBuf::from("/etc/systemd/system"));
    assert!(
        unit_dir_for(true)
            .expect("a home directory resolves on this runner")
            .ends_with(".config/systemd/user"),
    );
}
