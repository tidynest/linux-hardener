//! The `--ssh` refusal, driven through the built binary.
//!
//! `Command::ssh_refusal` is unit-tested next to the parser, but the gate that
//! consults it lives in `main`, which no unit test can enter: deleting that
//! gate wholesale left every one of those unit tests green. These run the
//! binary instead, and they are here rather than in `src/` because a `#[test]`
//! inside a binary crate cannot execute it.
//!
//! Nothing here writes to the host. The refused commands exit before doing
//! anything at all, the honoured one is pointed at a port nothing listens on,
//! and `plugins` reads no file and touches no database.

use std::process::{Command, Output};

/// An address that fails fast and reaches no host: the discard-adjacent port 1
/// on the loopback interface, where a connection is refused immediately rather
/// than waiting out a timeout.
const UNREACHABLE: [&str; 5] = ["--ssh", "nobody@127.0.0.1", "--port", "1", "--ssh-timeout"];

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hardener"))
        .args(args)
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
