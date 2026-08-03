//! The global `--config` flag, driven through the built binary: whether the one
//! command that writes to the system honours the policy file it was handed.
//!
//! The flag is declared once on the root `Cli` and then threaded into each
//! command by `main`, which no unit test can enter. A unit test that hands
//! `apply::run` a path directly stays green while `main` drops the flag on the
//! floor, and that is exactly how this went unnoticed: the loader's own tests
//! were green throughout. These run the binary instead.
//!
//! Nothing here writes to the host. Both refusals exit before any plugin runs,
//! and the control run is `--dry-run`, which validates and writes nothing.
//! Every child is given a scratch `HOME` so the default config locations are
//! empty, which is what makes `--config` the only thing deciding the run.

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
