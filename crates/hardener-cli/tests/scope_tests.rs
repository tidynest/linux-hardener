//! `hardener scope`, driven through the built binary.
//!
//! The write itself, the validation and the audit entries are unit-tested
//! beside the module in `src/commands/scope/tests.rs`, where the audit-log path
//! can be injected. What no unit test can reach is `main`: `hardener-cli` is a
//! binary with no library target, so a test in this directory cannot call
//! `run_exclude` at all, and the dispatch arm, the `--config` threading and the
//! `--ssh` refusal gate all live there. Deleting any of them leaves every unit
//! test green.
//!
//! Every child is given a scratch `HOME`, `XDG_DATA_HOME` and `XDG_CONFIG_HOME`,
//! so the audit entry a run files lands in the temporary directory rather than
//! in the operator's own data directory.

use std::process::{Command, Output};

fn scratch_home(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "hardener-scope-tests-{}-{label}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("a scratch state directory");
    dir
}

fn run_in(home: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hardener"))
        .args(args)
        .env("HOME", home)
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CONFIG_HOME", home.join("config"))
        .output()
        .expect("the binary under test runs")
}

/// A scratch home holding a seeded `config.toml`, returned with its path.
fn seeded(label: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let home = scratch_home(label);
    let config = home.join("config.toml");
    std::fs::write(&config, "[global]\ndisabled_plugins = [\"mac\"]\n").expect("seed config");
    (home, config)
}

#[test]
fn exclude_writes_the_config_the_flag_named() {
    let (home, config) = seeded("exclude");
    let path = config.to_str().expect("utf-8 path");

    let output = run_in(
        &home,
        &[
            "--config",
            path,
            "scope",
            "exclude",
            "iso27001",
            "7.1",
            "--reason",
            "No physical premises",
            "--ticket",
            "SEC-412",
        ],
    );

    assert!(
        output.status.success(),
        "the run succeeded: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let written = std::fs::read_to_string(&config).expect("read back");
    assert!(
        written.contains(r#"[compliance.not_applicable.iso27001."7.1"]"#),
        "the table was written where --config pointed: {written}"
    );
    assert!(
        written.contains("disabled_plugins"),
        "and the rest of the file survived: {written}"
    );
}

#[test]
fn an_unknown_framework_exits_one_and_writes_nothing() {
    let (home, config) = seeded("unknown-framework");
    let path = config.to_str().expect("utf-8 path");

    let output = run_in(
        &home,
        &[
            "--config",
            path,
            "scope",
            "exclude",
            "not-a-framework",
            "7.1",
            "--reason",
            "reason",
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(1),
        "a refused exclusion is a failure, not a quiet success"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not-a-framework"),
        "the message names the id that was wrong: {stderr}"
    );
    let written = std::fs::read_to_string(&config).expect("read back");
    assert!(!written.contains("not_applicable"), "nothing was written");
}

/// The same exit code and the same empty file for a control id that belongs to
/// no catalogue. `A.7.1` is ISO 27001:2022's own Annex A notation and this
/// catalogue holds the bare clause number, so it is the typo an operator is
/// likeliest to make, and until it was refused it wrote a table that raised no
/// score and an audit entry that claimed it had.
#[test]
fn an_unknown_control_id_exits_one_and_writes_nothing() {
    let (home, config) = seeded("unknown-control");
    let path = config.to_str().expect("utf-8 path");

    let output = run_in(
        &home,
        &[
            "--config",
            path,
            "scope",
            "exclude",
            "iso27001",
            "A.7.1",
            "--reason",
            "No physical premises",
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(1),
        "an exclusion that could only be a no-op is a failure, not a quiet \
         success"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("A.7.1") && stderr.contains("report --framework iso27001"),
        "the message names the id and how to list the real ones: {stderr}"
    );
    let written = std::fs::read_to_string(&config).expect("read back");
    assert!(!written.contains("not_applicable"), "nothing was written");
}

#[test]
fn scope_refuses_ssh_before_it_edits_this_host() {
    let (home, config) = seeded("ssh-refusal");
    let path = config.to_str().expect("utf-8 path");

    let output = run_in(
        &home,
        &[
            "--ssh",
            "nobody@127.0.0.1",
            "--port",
            "1",
            "--config",
            path,
            "scope",
            "exclude",
            "iso27001",
            "7.1",
            "--reason",
            "No physical premises",
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(2),
        "a usage refusal exits 2, as the other refusals do"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("`scope`"),
        "the refusal names the command: {stderr}"
    );
    let written = std::fs::read_to_string(&config).expect("read back");
    assert!(
        !written.contains("not_applicable"),
        "and it refused before editing this host's own policy: {written}"
    );
}
