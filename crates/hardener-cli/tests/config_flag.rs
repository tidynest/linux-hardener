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
//! Nothing here writes to any host. Every refusal exits before a plugin runs
//! and before a fleet run opens its first connection, and the runs that are
//! allowed to proceed are `--dry-run`, which validate and write nothing. Every
//! child is given a scratch `HOME` so the default config locations are empty,
//! which is what makes `--config` the only thing deciding the run.

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

    // Positive control. The same fleet run without the flag has no named policy
    // to fail on, so it must not refuse on configuration at all. Without this,
    // the assertion above would also pass on a `batch apply` that refused for
    // some unrelated reason, such as resolving the host or opening a database.
    let control = batch_apply_with(&[], &["--execute"]);
    let control_stderr = String::from_utf8_lossy(&control.stderr);
    assert!(
        !control_stderr.contains("Config error"),
        "without the flag there is no named policy to fail on, so a config \
         refusal here would mean the one above proves nothing; got: {control_stderr}"
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
