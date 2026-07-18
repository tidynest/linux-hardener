//! End-to-end batch CLI tests against a live sshd fixture.
//!
//! The standard suite never exercises a *successful* `SshExecutor::connect`
//! (unit tests use `MockExecutor`; the loopback test connects to a closed
//! port). These tests drive the real binary against a real sshd, covering
//! arg parsing, remote execution, JSON rendering, and tiered exit codes for
//! all four batch verbs.
//!
//! Fixture: `scripts/containers/boot-ssh-test-container.sh` (or any key-reachable sshd),
//! the key loaded into `ssh-agent`, and:
//!
//! ```text
//! SSH_TEST_HOST=<addr> SSH_TEST_USER=root [SSH_TEST_PORT=22]
//! ```
//!
//! Run: `cargo test -p hardener-cli --test batch_ssh_integration -- --ignored`
//!
//! Auth is key/agent only; the SSH executor has no password path.

use std::process::{Command, Output};

/// Ad-hoc `--ssh` target from the fixture env, or `None` to skip.
fn target() -> Option<String> {
    let Ok(host) = std::env::var("SSH_TEST_HOST") else {
        eprintln!("skipping: SSH_TEST_HOST not set (see scripts/containers/boot-ssh-test-container.sh)");
        return None;
    };
    let user = std::env::var("SSH_TEST_USER").unwrap_or_else(|_| "root".to_string());
    let port = std::env::var("SSH_TEST_PORT").unwrap_or_else(|_| "22".to_string());
    Some(format!("{user}@{host}:{port}"))
}

fn run_batch(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hardener"))
        .args(args)
        .output()
        .expect("hardener binary runs")
}

/// Parses the JSON document from stdout, tolerating any preamble before the
/// first `open` delimiter, the same contract the desktop's fleet commands
/// rely on when they shell out to `batch`.
fn json_from(stdout: &[u8], open: char) -> serde_json::Value {
    let text = String::from_utf8_lossy(stdout);
    let start = text.find(open).unwrap_or_else(|| {
        panic!("stdout contains no '{open}': {text}");
    });
    serde_json::from_str(&text[start..]).expect("stdout tail is valid JSON")
}

fn exit_code(out: &Output) -> i32 {
    out.status.code().expect("exit code present")
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
#[ignore = "Requires SSH_TEST_HOST environment variable"]
fn batch_scan_over_ssh_succeeds_with_json() {
    let Some(t) = target() else { return };
    let out = run_batch(&["batch", "scan", "--ssh", &t, "--format", "json"]);
    let code = exit_code(&out);
    assert!(
        code == 0 || code == 1,
        "expected 0 (clean) or 1 (findings), got {code}: {}",
        stderr_of(&out)
    );

    let doc = json_from(&out.stdout, '{');
    let hosts = doc["hosts"].as_array().expect("hosts array");
    assert_eq!(hosts.len(), 1, "one host entry");
    assert!(
        hosts[0]["target"].as_str().is_some_and(|s| s.contains('@')),
        "target echoed as user@host:port"
    );
    // The load-bearing assertion: the connect *succeeded*.
    assert_eq!(
        doc["summary"]["hosts_scanned"], 1,
        "host was scanned, not failed"
    );
    assert_eq!(doc["summary"]["hosts_failed"], 0, "no host-level failure");
}

#[test]
#[ignore = "Requires SSH_TEST_HOST environment variable"]
fn batch_report_over_ssh_assesses_framework() {
    let Some(t) = target() else { return };
    let out = run_batch(&[
        "batch",
        "report",
        "--ssh",
        &t,
        "--framework",
        "cis",
        "--format",
        "json",
    ]);
    let code = exit_code(&out);
    assert!(
        code == 0 || code == 1,
        "expected 0 (compliant) or 1 (failing control), got {code}: {}",
        stderr_of(&out)
    );

    let doc = json_from(&out.stdout, '{');
    assert_eq!(
        doc["hosts"].as_array().map(Vec::len),
        Some(1),
        "one host report"
    );
    assert_eq!(doc["summary"]["hosts_assessed"], 1, "host was assessed");
    assert_eq!(doc["summary"]["hosts_failed"], 0, "no host-level failure");
}

#[test]
#[ignore = "Requires SSH_TEST_HOST environment variable"]
fn batch_apply_dry_run_over_ssh_validates() {
    let Some(t) = target() else { return };
    // Dry-run is the default: validates remotely, mutates nothing.
    let out = run_batch(&["batch", "apply", "--ssh", &t, "--format", "json"]);
    let code = exit_code(&out);
    assert!(
        code == 0 || code == 1,
        "dry-run must not hit the host-error tier (2), got {code}: {}",
        stderr_of(&out)
    );

    let outcomes = json_from(&out.stdout, '[');
    let host = &outcomes.as_array().expect("outcome array")[0];
    assert_eq!(host["status"]["state"], "validated", "dry-run validates");
    assert!(
        host["status"]["plugins"].as_u64().is_some_and(|n| n > 0),
        "validation covered at least one plugin"
    );
}

#[test]
#[ignore = "Requires SSH_TEST_HOST environment variable"]
fn batch_rollback_dry_run_over_ssh_previews() {
    let Some(t) = target() else { return };
    let out = run_batch(&["batch", "rollback", "--ssh", &t, "--format", "json"]);
    let code = exit_code(&out);
    assert!(
        code == 0 || code == 1,
        "dry-run must not hit the host-error tier (2), got {code}: {}",
        stderr_of(&out)
    );

    let outcomes = json_from(&out.stdout, '[');
    let state = &outcomes.as_array().expect("outcome array")[0]["status"]["state"];
    assert!(
        state == "previewed" || state == "nothingtodo",
        "dry-run previews or reports nothing to do, got {state}"
    );
}
