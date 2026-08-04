//! The global `--config` flag, driven through the built binary: whether the
//! commands that write honour the policy file they were handed, on one host and
//! on a fleet.
//!
//! The flag is declared once on the root `Cli` and then threaded into each
//! command by `main`, which no unit test can enter. A unit test that hands
//! `apply::run` a path directly stays green while `main` drops the flag on the
//! floor, and that is exactly how this went unnoticed: the loader's own tests
//! were green throughout. These run the binary instead.
//!
//! Nothing here writes to any host, and no run here is `--execute`. Every
//! refusal exits before a plugin runs and before a fleet run opens its first
//! connection, and the runs allowed to proceed are `--dry-run`, which validate
//! and write nothing. Every child is given a scratch `HOME` so the default
//! config locations are empty, which is what makes `--config` the only thing
//! deciding the run.
//!
//! One source is beyond a scratch `HOME`: `/etc/linux-hardener/config.toml` is
//! an absolute path, and `ConfigLoader::load` merges it before the file named
//! on the command line. On a host carrying a broken one, a load failure here
//! names that path rather than the fixture, so the assertions that quote the
//! fixture path would go red on a correct build.

use std::process::{Command, Output};

/// A scratch home for the children of this test binary. The default config
/// locations under it are absent, so a run that reads policy read it from the
/// path it was given.
fn scratch_home() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("hardener-config-flag-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a scratch home");
    dir
}

fn run(args: &[&str]) -> Output {
    let home = scratch_home();
    Command::new(env!("CARGO_BIN_EXE_hardener"))
        .args(args)
        .env("HOME", &home)
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CONFIG_HOME", home.join("config"))
        .output()
        .expect("the binary under test runs")
}

/// One plugin so the run is short, and `--dry-run` so no plugin can write.
const PREVIEW: [&str; 4] = ["apply", "--dry-run", "--plugin", "kernel-hardening"];

fn preview_with(config: &[&str]) -> Output {
    let mut argv: Vec<&str> = config.to_vec();
    argv.extend_from_slice(&PREVIEW);
    run(&argv)
}

#[test]
fn apply_refuses_a_config_path_that_does_not_exist() {
    let missing = "/nonexistent/hardener-no-such-config.toml";
    let out = preview_with(&["--config", missing]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !out.status.success(),
        "a --config path that cannot be read must not be silently ignored by the \
         one verb that writes; got exit {:?} with stderr: {stderr}",
        out.status.code()
    );
    assert!(
        stderr.contains(missing),
        "the refusal names the path it could not read; got: {stderr}"
    );

    // Positive control. Without the flag the same run does not refuse on
    // configuration at all, so the refusal above is `--config` being honoured
    // rather than `apply` refusing for some unrelated reason.
    //
    // Deliberately not asserted as exit 0. This run reaches the kernel plugin,
    // which legitimately fails on a host whose `/proc/sys` is read-only, and
    // `/etc/linux-hardener/config.toml` is read from an absolute path that no
    // scratch `HOME` can move, so a packaged site config could disable the
    // plugin and empty the selection. Neither is this test's subject, and
    // either would make it fail on a correct build.
    let control = preview_with(&[]);
    let control_stderr = String::from_utf8_lossy(&control.stderr);
    assert!(
        !control_stderr.contains(missing),
        "the control run was never given that path and must not name it; got: {control_stderr}"
    );
    assert!(
        !control_stderr.contains("Config error"),
        "without the flag there is no named policy to fail on, so a config \
         refusal here would mean the one above proves nothing; got: {control_stderr}"
    );
}

#[test]
fn apply_honours_policy_that_only_the_flag_points_at() {
    let path = scratch_home().join("disables-kernel.toml");
    std::fs::write(
        &path,
        "[global]\ndisabled_plugins = [\"kernel-hardening\"]\n",
    )
    .expect("the fixture policy is written");
    let path = path.to_str().expect("a UTF-8 scratch path");

    let out = preview_with(&["--config", path]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // The file disables the only selected plugin, so the run has nothing left
    // to do and `nothing_ran()` refuses. Reaching that refusal proves the file
    // was read: nothing at a default location says any of this.
    assert!(
        !out.status.success(),
        "a config disabling every selected plugin must refuse rather than exit 0 \
         having hardened nothing; got exit {:?} with stderr: {stderr}",
        out.status.code()
    );
    assert!(
        stderr.contains("disabled every selected plugin"),
        "the refusal says the config emptied the selection; got: {stderr}"
    );
}

/// A host that cannot resolve, so a run that gets past the config gate fails at
/// the connection rather than touching anything. Reserved by RFC 6761, so no
/// resolver is supposed to answer for it.
const UNREACHABLE: [&str; 4] = ["--ssh", "nosuchhost.invalid", "--ssh-timeout", "1"];

fn batch_apply_with(config: &[&str], execute: &[&str]) -> Output {
    let mut argv: Vec<&str> = config.to_vec();
    argv.extend_from_slice(&["batch", "apply", "--plugin", "kernel-hardening"]);
    argv.extend_from_slice(&UNREACHABLE);
    argv.extend_from_slice(execute);
    run(&argv)
}

#[test]
fn batch_apply_execute_refuses_a_config_path_that_does_not_exist() {
    let missing = "/nonexistent/hardener-no-such-batch-config.toml";
    let out = batch_apply_with(&["--config", missing], &["--execute"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);

    // Neither the exit code nor the path is enough on its own to prove a
    // refusal. This run cannot reach its host, so it exits 2 whether or not it
    // refuses, and the fallback warning names the path it fell back from. Only
    // the absence of that warning, and the absence of any host outcome,
    // separate a refusal from the fallback this issue is about.
    assert!(
        !stderr.contains("config load failed, using defaults"),
        "a fleet run told to use a policy it cannot read must refuse rather than \
         harden every host from compiled-in defaults; got: {stderr}"
    );
    assert!(
        stderr.contains("Config error") && stderr.contains(missing),
        "the refusal says what it is and names the path it could not read; \
         got: {stderr}"
    );
    assert!(
        !stdout.contains("nosuchhost.invalid"),
        "the refusal comes before the first connection, so no host outcome is \
         rendered; got stdout: {stdout}"
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "a fleet run told to use a policy it cannot read is a usage error, which \
         `batch` signals as 2 rather than the 1 a bail would give; got stderr: {stderr}"
    );

    // Positive control: the same fleet run without the flag must not refuse on
    // configuration, so the refusal above is `--config` being honoured rather
    // than `batch apply` refusing for some unrelated reason.
    //
    // Deliberately not `--execute`. This control cannot distinguish the
    // `config_path.is_some()` half of the guard anyway: with no flag and a
    // scratch `HOME`, the load succeeds, so it passes whether or not that half
    // is there. Running it under `--execute` bought nothing and reached
    // `get_checkpoint_manager`, which under a privileged run materialises
    // `/var/lib/linux-hardener/checkpoints.db` and the signing key at absolute
    // paths no scratch `HOME` can move. The parse-failure test below is what
    // actually pins the guard.
    let control = batch_apply_with(&[], &[]);
    let control_stderr = String::from_utf8_lossy(&control.stderr);
    assert!(
        !control_stderr.contains("Config error"),
        "without the flag there is no named policy to fail on, so a config \
         refusal here would mean the one above proves nothing; got: {control_stderr}"
    );
}

/// A `--config` file that exists and will not parse is refused too.
///
/// Without this the guard could be narrowed to "the named path does not exist"
/// and every assertion in the test above would stay green, while a fleet was
/// again hardened from the defaults whenever the named file was present but
/// broken. `ConfigLoader::load` fails for a parse error, a stat failure, a bad
/// environment override and a rejected directive alike, and all of them are the
/// same defect: policy the operator named did not decide the run.
#[test]
fn batch_apply_execute_refuses_a_config_file_that_will_not_parse() {
    let path = scratch_home().join("unparseable.toml");
    std::fs::write(&path, "[global\ndisabled_plugins = broken\n").expect("the fixture is written");
    let path = path.to_str().expect("a UTF-8 scratch path");

    let out = batch_apply_with(&["--config", path], &["--execute"]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !stderr.contains("config load failed, using defaults"),
        "a named policy that will not parse must refuse rather than harden the \
         fleet from defaults; got: {stderr}"
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "and refuses with the same usage tier as a path that is not there; \
         got stderr: {stderr}"
    );
}

#[test]
fn batch_apply_dry_run_still_falls_back_when_the_named_config_cannot_be_loaded() {
    let missing = "/nonexistent/hardener-no-such-batch-config.toml";
    let out = batch_apply_with(&["--config", missing], &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // The refusal is deliberately scoped to the verb that writes. A dry run
    // reads the fleet and writes nothing, so it keeps the fallback that shipped,
    // as `batch scan` and `batch report` do. This is the control against the
    // refusal being made too broad: a guard keyed on `--config` alone rather
    // than on `--config` and `--execute` together would take this test red.
    assert!(
        !stderr.contains("Config error"),
        "a dry run writes nothing and must not be refused for a config it can \
         fall back from; got: {stderr}"
    );
    assert!(
        stderr.contains("config load failed, using defaults"),
        "the fallback still says so on stderr, which is what proves this run \
         reached the config gate at all rather than exiting earlier; got: {stderr}"
    );
}

/// `-C` reaches the scheduler section too, not only the hardening policy.
///
/// `load_scheduler_config` took no path and searched the default locations
/// itself, so a single file carrying both a `[global]` and a `[scheduler]`
/// section was half honoured: `scan` read its policy from the named file and
/// then wrote its history to whatever database the default search happened to
/// find. The observable is where the database lands, which is the whole point
/// of the setting.
/// A config naming a scheduler database of this test's own, and that path.
///
/// The four scalar keys are written out although each now has a serde default,
/// because this fixture's subject is which database a named config selects, and
/// spelling the schedule out keeps that independent of what the defaults happen
/// to be. `partial_scheduler_section_reaches_the_loader` covers the omitting
/// case deliberately. The path is escaped rather than interpolated raw: a
/// `TMPDIR` containing a backslash or a quote would otherwise produce a fixture
/// that is not valid TOML.
fn scheduler_fixture(label: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let home = scratch_home();
    let db = home.join(format!("{label}-history.db"));
    let config = home.join(format!("{label}-scheduler.toml"));
    let _ = std::fs::remove_file(&db);
    let escaped = toml_escaped(&db);
    std::fs::write(
        &config,
        format!(
            "[scheduler]\nenabled = true\nschedule = \"0 0 3 * * *\"\nplugins = []\n\
             min_severity = \"low\"\n\n[scheduler.storage]\ndatabase_path = \"{escaped}\"\n"
        ),
    )
    .expect("the fixture config is written");
    (config, db)
}

/// Runs one verb with the fixture config and reports whether the database the
/// fixture named was the one opened. The location IS the observable: an empty
/// history renders identically whichever database answered.
fn opened_named_database(label: &str, verb: &[&str]) -> bool {
    let (config, db) = scheduler_fixture(label);
    let mut argv = vec!["--config", config.to_str().expect("a UTF-8 scratch path")];
    argv.extend_from_slice(verb);
    run(&argv);
    db.exists()
}

#[test]
fn the_scheduler_section_comes_from_the_named_config_too() {
    assert!(
        opened_named_database("history", &["history", "list"]),
        "the history database must be opened where the named config said, not \
         where the default search leads"
    );

    // The control. Without the flag the fixture's path is named by nothing, so
    // a database appearing there would mean the assertion above proves nothing.
    let (_, unnamed) = scheduler_fixture("history-control");
    run(&["history", "list"]);
    assert!(
        !unnamed.exists(),
        "a run that was never given the config must not open the database it names"
    );
}

/// One path in a TOML string literal, with the two characters that would end it
/// early escaped. A `TMPDIR` holding a backslash or a quote is legal.
fn toml_escaped(path: &std::path::Path) -> String {
    path.display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

/// Writes a scheduler config whose `[scheduler]` body is given verbatim, and
/// returns it beside the database path it names.
fn scheduler_config_with(label: &str, body: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let home = scratch_home();
    let db = home.join(format!("{label}-history.db"));
    let config = home.join(format!("{label}-scheduler.toml"));
    let _ = std::fs::remove_file(&db);
    let escaped = toml_escaped(&db);
    std::fs::write(
        &config,
        format!("[scheduler]\n{body}\n[scheduler.storage]\ndatabase_path = \"{escaped}\"\n"),
    )
    .expect("the fixture config is written");
    (config, db)
}

/// A `[scheduler]` section that omits keys still reaches the loader.
///
/// The unit tests prove `SchedulerConfig` deserialises from a partial table.
/// They cannot prove the CLI ever gets that far: the section is parsed through a
/// separate `ConfigFile` wrapper in `commands::daemon`, and a parse failure
/// there is returned rather than skipped, so the whole file was fatal. That is
/// where the severity lived, and nothing exercised it, so a refactor that
/// reintroduced a mandatory field at the wrapper would have left the suite
/// green. The observable is the database, exactly as in the tests above: it can
/// only appear if the file parsed and the section was honoured.
#[test]
fn partial_scheduler_section_reaches_the_loader() {
    // Both omissions at once, because both were the same defect: three of the
    // four scalar keys, and a webhook endpoint that does not name its format.
    let (config, db) = scheduler_config_with(
        "partial",
        "enabled = true\n\n\
         [[scheduler.notifications.webhooks.endpoints]]\n\
         name = \"ops\"\n\
         url = \"https://example.invalid/hook\"\n",
    );
    let out = run(&[
        "--config",
        config.to_str().expect("a UTF-8 scratch path"),
        "history",
        "list",
    ]);
    assert!(
        db.exists(),
        "a section naming only some of its keys must be honoured, not refused; \
         got exit {:?} with stderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    // The control. A section that genuinely cannot be parsed must still be
    // fatal, which is what proves the database's existence tracks the parse
    // outcome rather than appearing for any run at all.
    let (bad, unparsed) = scheduler_config_with("partial-control", "schedule = 5\n");
    let refused = run(&[
        "--config",
        bad.to_str().expect("a UTF-8 scratch path"),
        "history",
        "list",
    ]);
    assert!(
        !unparsed.exists() && !refused.status.success(),
        "a section whose value has the wrong type must still fail the run; got \
         exit {:?}",
        refused.status.code()
    );
}

/// A file that says nothing about the scheduler does not silence the file that
/// does.
///
/// `systemd generate`/`install` embed the `--config` path in the unit they
/// write, so an operator who installs a timer against a policy file had a
/// scheduled scan whose `[scheduler]` resolved to the compiled-in defaults:
/// disabled, on the default schedule, writing to the default database, while
/// their own config said otherwise and nothing said so. A section absent from a
/// file is not that file configuring the section, so the search continues.
#[test]
fn a_config_without_a_scheduler_section_does_not_shadow_the_one_that_has_it() {
    let home = scratch_home();
    let (_, configured) = scheduler_fixture("fallthrough");
    // The fixture's own file becomes this run's *user* config, so the named
    // policy file is the only thing that could shadow it.
    let user_config_dir = home.join("config").join("linux-hardener");
    std::fs::create_dir_all(&user_config_dir).expect("a user config directory");
    std::fs::copy(
        home.join("fallthrough-scheduler.toml"),
        user_config_dir.join("config.toml"),
    )
    .expect("the user config is installed");

    let policy = home.join("policy-only.toml");
    std::fs::write(
        &policy,
        "[global]\ndisabled_plugins = [\"mac-hardening\"]\n",
    )
    .expect("the policy fixture is written");

    let out = run(&[
        "--config",
        policy.to_str().expect("a UTF-8 scratch path"),
        "history",
        "list",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        configured.exists(),
        "a named file with no [scheduler] section must leave the operator's own \
         scheduler settings in force, not replace them with the compiled-in \
         defaults; got exit {:?} with stderr: {stderr}",
        out.status.code()
    );
}

/// `scan` persists its own history, and it reached `-C` for policy while its
/// history went wherever the default search led. One file, two halves,
/// disagreeing about where the run's results were recorded.
#[test]
fn scan_writes_its_history_where_the_named_config_says() {
    assert!(
        opened_named_database("scan", &["scan", "--plugin", "kernel-hardening"]),
        "a scan told which config to use must record its session in that \
         config's database"
    );
}

/// The fleet path opens the same database through its own helper, so covering
/// the single-host one proves nothing about it.
#[test]
fn a_fleet_scan_writes_its_history_where_the_named_config_says() {
    assert!(
        opened_named_database(
            "batch",
            &[
                "batch",
                "scan",
                "--ssh",
                "nosuchhost.invalid",
                "--ssh-timeout",
                "1"
            ],
        ),
        "a fleet scan told which config to use must record its hosts in that \
         config's database, even when every host fails to connect"
    );
}

/// The three `daemon` verbs read this section too, and each was passed nothing.
#[test]
fn daemon_reads_the_scheduler_section_from_the_named_config() {
    assert!(
        opened_named_database("daemon", &["daemon", "status"]),
        "a daemon verb told which config to use must read that config's database"
    );
}

/// The other half of honouring the flag: a path the operator named and that is
/// not there is an error rather than a silent fall-through to the defaults.
///
/// Driven through `daemon status` deliberately. `scan` and `report` reach
/// `ConfigLoader` first, which already refuses a missing named path, so they
/// would pass this whether or not the scheduler loader refuses anything. The
/// scheduler verbs read no policy, so the refusal here can only be its own.
#[test]
fn a_named_config_that_is_not_there_stops_a_scheduler_verb() {
    let missing = "/nonexistent/hardener-no-such-scheduler-config.toml";

    let out = run(&["--config", missing, "daemon", "status"]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !out.status.success(),
        "a scheduler verb told to use a config it cannot read must not continue \
         on the compiled-in defaults; got exit {:?} with stderr: {stderr}",
        out.status.code()
    );
    assert!(
        stderr.contains(missing),
        "and the refusal names the path it could not read; got: {stderr}"
    );

    // The control: the same verb without the flag is not refused for
    // configuration, so the refusal above is the flag being honoured.
    let control = run(&["daemon", "status"]);
    let control_stderr = String::from_utf8_lossy(&control.stderr);
    assert!(
        !control_stderr.contains("Config file not found"),
        "without the flag there is no named path to fail on; got: {control_stderr}"
    );
}
