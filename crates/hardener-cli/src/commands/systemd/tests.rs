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

// --- The join between a descriptor and a write -------------------------------
//
// Everything above this line asserts a decision in isolation: what a summary
// says, which stream an answer came back on. `unit_audit` was in that same
// position, asserted nowhere and reaching a writer nowhere a test could see, so
// a descriptor naming the wrong unit, or one built correctly and then dropped
// on the way to `write_atomically`, passed every test in this file.
//
// These drive `write_units` and `remove_units`, which is the whole of what
// `install` and `uninstall` do to the filesystem. What they cannot reach is the
// `systemctl` half: a test that called `install` itself would reload the
// operator's own systemd and enable a real timer in their session, which is not
// a thing a unit test may do to the machine running it. The unit directory is
// an argument for the same reason it is testable at all, so nothing here moves
// `HOME` under the other tests in this binary.

/// A unit directory and an audit log a test may write, since the two an install
/// actually picks are `/etc/systemd/system` and root's log.
struct Scratch {
    _dir: tempfile::TempDir,
    units: PathBuf,
    log: PathBuf,
}

impl Scratch {
    fn new() -> Scratch {
        let dir = tempfile::tempdir().expect("tempdir");
        let units = dir.path().join("units");
        let log = dir.path().join("audit.log");
        Scratch {
            _dir: dir,
            units,
            log,
        }
    }

    async fn logger(&self) -> Option<AuditLogger> {
        hardener_core::config_write::logger_at(self.log.to_str().expect("utf-8 path")).await
    }

    /// The filed entries, keyed by the unit each names.
    ///
    /// Keyed rather than indexed because the order the two units are written in
    /// is not what any of this is about, and a test that asserted it would go
    /// red on a reordering that changed nothing an operator sees.
    async fn entries_by_target(&self) -> HashMap<String, hardener_state::AuditEntry> {
        AuditLogger::query(
            self.log.to_str().expect("utf-8 path"),
            hardener_state::audit::QueryFilter::new(),
        )
        .await
        .expect("query")
        .into_iter()
        .map(|entry| (entry.entry_target.clone(), entry))
        .collect()
    }
}

fn generator() -> SystemdGenerator {
    SystemdGenerator::new(PathBuf::from("/usr/bin/hardener"), "Mon *-*-* 03:00:00")
        .with_user_mode(true)
}

/// An install puts each unit's own contents at its own path, and files an entry
/// naming it.
///
/// Four separate ways this has to hold, and each has failed somewhere in this
/// project before. The files must exist, since a writer reporting success and
/// writing nothing is the mutation `write_atomically` exists to catch. Each
/// must hold its own contents, since one temporary path shared by both units
/// left the service's text in the timer for exactly as long as nobody wrote
/// them concurrently. There must be two entries rather than one for the
/// install, because a run that writes the service and then fails on the timer
/// has done half of something. And each entry must carry the calendar systemd
/// was actually given, not the string the operator typed, since `install`
/// translates a five-field cron expression on the way past.
#[tokio::test]
async fn an_install_writes_each_unit_and_files_an_entry_naming_it() {
    let scratch = Scratch::new();
    let logger = scratch.logger().await;
    let generator = generator();
    let calendar = [("schedule", "Mon *-*-* 03:00:00".to_string())];

    let (service_path, timer_path) =
        write_units(&scratch.units, &generator, logger.as_ref(), true, &calendar)
            .await
            .expect("both units are written");

    assert_eq!(
        std::fs::read_to_string(&service_path).expect("the service file exists"),
        generator.generate_service(),
        "the service path must hold the service, not whatever was written last"
    );
    assert_eq!(
        std::fs::read_to_string(&timer_path).expect("the timer file exists"),
        generator.generate_timer(),
        "the timer path must hold the timer"
    );

    let entries = scratch.entries_by_target().await;
    assert_eq!(entries.len(), 2, "one entry per unit, not one per install");
    for unit in [service_name(), timer_name()] {
        let entry = entries
            .get(&format!("unit:{unit}"))
            .unwrap_or_else(|| panic!("an entry naming {unit}, got {:?}", entries.keys()));
        assert_eq!(entry.entry_action_type, ActionType::ConfigChange);
        assert_eq!(
            entry.entry_result,
            hardener_state::audit::ActionResult::Success
        );
        assert_eq!(entry.entry_details["operation"], "install");
        assert_eq!(entry.entry_details["scope"], "user");
        assert_eq!(
            entry.entry_details["schedule"], "Mon *-*-* 03:00:00",
            "the entry carries the calendar the timer runs on"
        );
    }
}

/// An uninstall reports only the units that were there, and records both.
///
/// The two halves pull in opposite directions on purpose. `removed` must name
/// the one file that existed, because a verb that reported both would tell an
/// operator it had undone something it never did. The log must carry two
/// entries anyway, because "I tried to remove this and there was nothing there"
/// is the answer somebody is looking for when they find a timer still running.
///
/// A mutation that made either follow the other passes exactly one of these.
///
/// Run in system scope, where the install test runs in user scope, so the
/// `scope` detail is pinned to both of its values across the pair. Neither is
/// this test's subject, and asserting it twice from one side would leave
/// `scope_name -> "user"` alive.
#[tokio::test]
async fn an_uninstall_records_both_units_and_reports_only_what_was_there() {
    let scratch = Scratch::new();
    let logger = scratch.logger().await;
    std::fs::create_dir_all(&scratch.units).expect("the unit directory");
    let service_path = scratch.units.join(service_name());
    std::fs::write(&service_path, "[Service]\n").expect("seed only the service");

    let removed = remove_units(&scratch.units, logger.as_ref(), false, true)
        .await
        .expect("the removal runs against a directory missing one unit");

    assert_eq!(
        removed,
        vec![service_path.clone()],
        "only the unit that was there was removed"
    );
    assert!(
        !service_path.exists(),
        "the file it reported removing must be gone"
    );

    let entries = scratch.entries_by_target().await;
    assert_eq!(
        entries.len(),
        2,
        "the absent unit is recorded too: nothing else reports a scan that stopped running"
    );
    for unit in [service_name(), timer_name()] {
        let entry = entries
            .get(&format!("unit:{unit}"))
            .unwrap_or_else(|| panic!("an entry naming {unit}, got {:?}", entries.keys()));
        assert_eq!(entry.entry_details["operation"], "uninstall");
        assert_eq!(entry.entry_details["scope"], "system");
        assert_eq!(entry.entry_details["timer_disabled"], "true");
    }
}
