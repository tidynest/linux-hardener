//! The global SSH flags, driven through the built binary: which commands `--ssh`
//! reaches, and where `--port` lands.
//!
//! `Command::ssh_refusal` is unit-tested next to the parser, but the gate that
//! consults it lives in `main`, which no unit test can enter: deleting that
//! gate wholesale left every one of those unit tests green. These run the
//! binary instead, and they are here rather than in `src/` because a `#[test]`
//! inside a binary crate cannot execute it.
//!
//! Nothing here writes to the operator's own state. The refused commands exit
//! before doing anything at all, and `plugins` reads no file and touches no
//! database, but the `batch` runs below do open a fleet history database, so
//! every child process is given a scratch `HOME` and `XDG_DATA_HOME` and writes
//! its rows there. Without that they would file failed scans of `127.0.0.1`
//! into the maintainer's real history, and under `sudo` into `/var/lib`.

use std::process::{Command, Output};

/// An address that fails fast and reaches no host: the discard-adjacent port 1
/// on the loopback interface, where a connection is refused immediately rather
/// than waiting out a timeout.
const UNREACHABLE: [&str; 5] = ["--ssh", "nobody@127.0.0.1", "--port", "1", "--ssh-timeout"];

/// A scratch state directory for one child, so a `batch` run's history rows
/// land there rather than in the operator's own database.
fn scratch_home() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("hardener-ssh-flag-tests-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a scratch state directory");
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

fn unreachable(trailing: &[&str]) -> Vec<String> {
    let mut argv: Vec<String> = UNREACHABLE.iter().map(|a| a.to_string()).collect();
    argv.push("2".to_string());
    argv.extend(trailing.iter().map(|a| a.to_string()));
    argv
}

fn run_unreachable(trailing: &[&str]) -> Output {
    let argv = unreachable(trailing);
    let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
    run(&borrowed)
}

#[test]
fn a_refused_command_exits_two_without_opening_a_connection() {
    let out = run_unreachable(&["history", "list"]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert_eq!(
        out.status.code(),
        Some(2),
        "a usage refusal exits 2, as batch's own usage errors do: {stderr}"
    );
    assert!(
        stderr.contains("history list"),
        "the refusal names the command, so a five-word command line says which word was wrong: {stderr}"
    );
    assert!(
        !stderr.contains("Connecting to"),
        "and it is refused before the connection, or the round trip and the host-key decision \
         happen for a command that will not use them: {stderr}"
    );
    assert!(
        !stderr.contains("SSH connection failed"),
        "in particular the unreachable host must not be what stopped it: {stderr}"
    );
}

#[test]
fn the_refusal_still_speaks_under_quiet() {
    // --quiet silences the connection line, so before this gate existed the
    // whole misdirection happened without a word. The refusal is an error, and
    // errors are not non-essential output.
    let out = run_unreachable(&["--quiet", "daemon", "run-once"]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("daemon run-once"), "{stderr}");
}

#[test]
fn a_honoured_command_still_reaches_the_connection() {
    // The positive control. A gate that refused everything would pass every
    // assertion above; this proves --ssh still gets as far as the connection
    // for a command that uses it, and fails there rather than at the gate.
    let out = run_unreachable(&["scan"]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        stderr.contains("Connecting to"),
        "scan announces the connection it is about to make: {stderr}"
    );
    assert!(
        !stderr.contains("is not honoured by"),
        "and is not refused: {stderr}"
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "it fails at the unreachable host, which is exit 1 rather than the refusal's 2: {stderr}"
    );
}

#[test]
fn a_batch_ad_hoc_target_is_not_refused() {
    // The regression that nearly shipped: batch's own --ssh is the same clap
    // argument as the global one, so a refusal keyed on the flag being present
    // would refuse every ad-hoc fleet run, the desktop's included. Batch exits
    // 2 for host errors of its own, so the verdict here is the message rather
    // than the status.
    let out = run_unreachable(&["batch", "scan", "--format", "json"]);
    let merged = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(
        !merged.contains("is not honoured by"),
        "batch consumes this flag as an ad-hoc target rather than ignoring it: {merged}"
    );
    assert!(
        merged.contains("127.0.0.1"),
        "and the target reaches batch's own host list: {merged}"
    );
}

#[test]
fn without_the_flag_nothing_is_refused() {
    // The gate is conditioned on the flag, so a command in the refused family
    // runs untouched without it. `plugins` is the one that reads nothing and
    // writes nothing.
    let out = run(&["plugins"]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(!stderr.contains("is not honoured by"), "{stderr}");
}

/// Every fleet verb, because the fix threaded the port through four option
/// structs and a test of one of them proves three unbound call sites nothing.
const FLEET_VERBS: [&[&str]; 4] = [
    &["batch", "scan"],
    &["batch", "report", "--framework", "cis"],
    &["batch", "apply"],
    &["batch", "rollback"],
];

/// The JSON these runs emit names the host as `"target": "user@host:port"`, so
/// the closing quote is part of the needle: `:2` on its own also matches `:22`
/// and `:2222`, which is the prefix the defect used to produce.
fn target_field(target: &str) -> String {
    format!("\"{target}\"")
}

fn run_fleet(verb: &[&str], flags: &[&str]) -> String {
    let mut argv: Vec<&str> = flags.to_vec();
    argv.extend_from_slice(verb);
    argv.extend_from_slice(&["--format", "json"]);
    let out = run(&argv);
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn the_global_port_reaches_an_ad_hoc_target_of_every_fleet_verb() {
    // The port used to be a literal 22 at the one site that parses these
    // targets, so --port was accepted and dropped for exactly the command that
    // shares --ssh with the global flag. The parser has always taken a port and
    // its own tests have always passed one, which is why nothing caught it:
    // this asserts the call sites rather than the parser.
    //
    // Unconditional, so an empty verb list cannot pass this vacuously: the
    // whole point is that all four call sites are covered, and a table that
    // shrank would otherwise prove nothing while staying green.
    assert_eq!(FLEET_VERBS.len(), 4, "every fleet verb is exercised");

    // Two ports rather than one, because a single expected value cannot tell a
    // flag that arrived from a call site hardcoded to that same number: with
    // one port, `parse_inline(t, 2, ..)` passed both this test and the
    // precedence test below. That mutant survived the first version of this
    // file, and killing it is what the second port is for. Nothing listens on
    // 2 or 3, so every run fails at connect.
    for verb in FLEET_VERBS {
        for port in ["2", "3"] {
            let merged = run_fleet(
                verb,
                &[
                    "--ssh",
                    "nobody@127.0.0.1",
                    "--port",
                    port,
                    "--ssh-timeout",
                    "2",
                ],
            );

            assert!(
                merged.contains(&target_field(&format!("nobody@127.0.0.1:{port}"))),
                "{verb:?} --port {port}: the global port reaches an ad-hoc target naming none of its own: {merged}"
            );
            assert!(
                !merged.contains(&target_field("nobody@127.0.0.1:22")),
                "{verb:?} --port {port}: and 22 is not substituted for it: {merged}"
            );
        }
    }
}

#[test]
fn a_port_named_in_the_target_outranks_the_global_flag() {
    // Unconditional, so an empty verb list cannot pass this vacuously: the
    // whole point is that all four call sites are covered, and a table that
    // shrank would otherwise prove nothing while staying green.
    assert_eq!(FLEET_VERBS.len(), 4, "every fleet verb is exercised");

    // Documented precedence, and the positive control for the test above: a
    // change that ignored the target's own port would pass that one and fail
    // this one, and a call site hardcoded to either test's port fails the other.
    for verb in FLEET_VERBS {
        let merged = run_fleet(
            verb,
            &[
                "--ssh",
                "nobody@127.0.0.1:1",
                "--port",
                "65000",
                "--ssh-timeout",
                "2",
            ],
        );

        assert!(
            merged.contains(&target_field("nobody@127.0.0.1:1")),
            "{verb:?}: the target carries its own port: {merged}"
        );
        assert!(
            !merged.contains(&target_field("nobody@127.0.0.1:65000")),
            "{verb:?}: and the global flag does not override it: {merged}"
        );
    }
}
