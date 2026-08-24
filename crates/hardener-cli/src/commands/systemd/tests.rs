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
///
/// Both answers are asserted whole. This used to check that the user answer
/// merely `ends_with(".config/systemd/user")`, against whatever home the test
/// runner happened to have, which is true of that suffix joined onto anything:
/// the current directory, an empty path, `/`. Naming the base is what makes the
/// assertion about the join rather than about the constant.
#[test]
fn the_unit_directory_follows_the_mode() {
    let home = std::path::PathBuf::from("/home/operator");

    assert_eq!(
        unit_dir_for(true, Some(home.clone())).expect("a user unit directory resolves"),
        std::path::PathBuf::from("/home/operator/.config/systemd/user"),
    );
    assert_eq!(
        unit_dir_for(false, Some(home)).expect("a system unit directory always resolves"),
        std::path::PathBuf::from("/etc/systemd/system"),
        "a system install ignores the home it was handed",
    );
}

/// A host with no home directory can still take a system install, and cannot
/// take a user one.
///
/// The two halves are the point. `install` runs as root, usually through a
/// `sudo` that may carry no `HOME` at all, and that is precisely the invocation
/// a system install is for: making it fail on a home it never reads would break
/// the common case to guard the rare one. The user branch has nothing to join
/// onto and must say so rather than writing units under a bare relative path.
///
/// A single `unwrap_or_default` in place of the `?` passes neither: the user
/// case would answer `.config/systemd/user`, a relative path pointing at
/// whatever directory the operator happened to run from.
#[test]
fn a_missing_home_directory_stops_a_user_install_and_not_a_system_one() {
    let refused = unit_dir_for(true, None).expect_err("a user install needs a home directory");
    assert!(
        refused.to_string().contains("home directory"),
        "the message must name what was missing: {refused}"
    );

    assert_eq!(
        unit_dir_for(false, None).expect("a system install needs no home directory"),
        std::path::PathBuf::from("/etc/systemd/system"),
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

// --- The systemctl half ------------------------------------------------------
//
// `install` and `uninstall` used to spawn `systemctl` themselves, so neither
// could be driven by a test at all: the call would have reloaded the operator's
// own systemd and enabled a real timer in their session. Both now take a
// `SystemExecutor`, which is the abstraction the plugins already scan through,
// so a mock answers for systemd and records what it was asked.
//
// What these cannot see is the ordering between a `systemctl` call and a file
// being written: `remove_units` goes through `std::fs`, not the executor, so
// the mock's log holds the commands and nothing else. The order the two
// invocations arrive in is visible, and that is the one that matters.

use hardener_common::executor::MockExecutor;

fn ok() -> CommandOutput {
    CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    }
}

fn failed() -> CommandOutput {
    CommandOutput {
        stdout: String::new(),
        stderr: "Failed to enable unit: Unit file does not exist.\n".to_string(),
        exit_code: 1,
    }
}

/// A user-mode systemd with both invocations answering successfully.
fn user_systemd(enable: CommandOutput) -> MockExecutor {
    MockExecutor::new()
        .with_command("systemctl", &["--user", "daemon-reload"], ok())
        .with_command(
            "systemctl",
            &["--user", "enable", "--now", "linux-hardener.timer"],
            enable,
        )
}

/// An install reloads systemd and then enables the timer, in that order.
///
/// The order is not a preference. `enable --now` on a unit systemd has not read
/// fails, so a reload that moved after the enable would leave every install
/// reporting a timer that was never started, on a host where the units are
/// nonetheless present and correct.
///
/// The argument lists are asserted whole rather than by their verb, because the
/// `--user` that selects the instance is part of them: an invocation that lost
/// it would act on the system instance while the entry beside it says `user`.
#[tokio::test]
async fn an_install_reloads_systemd_before_enabling_the_timer() {
    let scratch = Scratch::new();
    let executor = user_systemd(ok());

    let outcome = write_and_install(&scratch, &executor, true).await;

    assert!(outcome.timer_enabled);
    assert_eq!(
        executor.log().commands_executed,
        vec![
            ("systemctl".to_string(), owned(&["--user", "daemon-reload"])),
            (
                "systemctl".to_string(),
                owned(&["--user", "enable", "--now", "linux-hardener.timer"])
            ),
        ]
    );
}

/// A timer that would not start is reported, and the units stay.
///
/// `.status()` used to be read for spawn failure only, so a non-zero exit was
/// discarded and the envelope claimed a running timer on the strength of having
/// asked. The paired assertion is that the install is not rolled back: the units
/// are on disk and correct, and an operator who can fix whatever refused the
/// enable should not have to write them again.
#[tokio::test]
async fn an_install_reports_a_timer_that_would_not_start() {
    let scratch = Scratch::new();
    let executor = user_systemd(failed());

    let outcome = write_and_install(&scratch, &executor, true).await;

    assert!(!outcome.timer_enabled);
    assert!(
        outcome.service_path.exists() && outcome.timer_path.exists(),
        "a timer that would not start does not undo the units"
    );
}

/// A system install talks to the system instance.
///
/// The `--user` flag is prepended in one place now, which is what makes this
/// assertable and also what makes it worth asserting: a mistake there sends
/// every system install to the operator's own systemd, where the units it
/// wrote to `/etc/systemd/system` are not visible at all. The install would
/// report a timer it had enabled somewhere else.
#[tokio::test]
async fn a_system_install_does_not_reach_the_user_instance() {
    let scratch = Scratch::new();
    let executor = MockExecutor::new()
        .with_command("systemctl", &["daemon-reload"], ok())
        .with_command(
            "systemctl",
            &["enable", "--now", "linux-hardener.timer"],
            ok(),
        );

    let outcome = write_and_install(&scratch, &executor, false).await;

    assert!(outcome.timer_enabled);
    for (_, args) in executor.log().commands_executed {
        assert!(
            !args.contains(&"--user".to_string()),
            "a system install must not carry --user: {args:?}"
        );
    }
}

/// A timer that was never enabled does not stop the uninstall.
///
/// `disable --now` fails on a host where nothing was installed, and that is
/// exactly the host with units to clear out after a half-finished install. The
/// three assertions pull apart: the failure is carried rather than raised, the
/// files still go, and every entry says the timer was not disabled, which is
/// the state an operator most needs to find later.
#[tokio::test]
async fn an_uninstall_proceeds_when_the_timer_was_never_enabled() {
    let scratch = Scratch::new();
    std::fs::create_dir_all(&scratch.units).expect("the unit directory");
    for unit in [service_name(), timer_name()] {
        std::fs::write(scratch.units.join(unit), "[Unit]\n").expect("seed the unit");
    }
    let executor = MockExecutor::new()
        .with_command(
            "systemctl",
            &["--user", "disable", "--now", "linux-hardener.timer"],
            failed(),
        )
        .with_command("systemctl", &["--user", "daemon-reload"], ok());

    let logger = scratch.logger().await;
    let outcome = uninstall_with(&executor, &scratch.units, logger.as_ref(), true)
        .await
        .expect("the uninstall runs");

    assert!(!outcome.timer_disabled);
    assert_eq!(outcome.removed.len(), 2, "both units still go");
    assert_eq!(
        executor.log().commands_executed.len(),
        2,
        "disable, then the reload that picks up their absence"
    );
}

/// Runs an install against `scratch`, with the generator every test here uses.
async fn write_and_install(
    scratch: &Scratch,
    executor: &MockExecutor,
    user_mode: bool,
) -> InstallOutcome {
    let logger = scratch.logger().await;
    install_with(
        executor,
        &scratch.units,
        &generator(),
        logger.as_ref(),
        user_mode,
        &[("schedule", "Mon *-*-* 03:00:00".to_string())],
    )
    .await
    .expect("the install runs")
}

fn owned(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| s.to_string()).collect()
}
