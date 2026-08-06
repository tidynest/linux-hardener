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
    scratch_home_named("shared")
}

/// A scratch state directory of a test's own. Tests in one binary run
/// concurrently, and two `--execute` children sharing one state directory
/// contend on the checkpoint database, which leaves a run with no host outcome
/// to print. A test that reads stdout would then fail for a reason that has
/// nothing to do with its subject, and only on a machine that happened to
/// interleave them.
fn scratch_home_named(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "hardener-ssh-flag-tests-{}-{label}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("a scratch state directory");
    dir
}

/// A scratch home whose ssh configuration resolves `127.0.0.1` to `root`.
///
/// The collision this exercises needs a bare target and an explicit `root@` one
/// to land on the same account, and a bare target is now resolved through
/// `ssh -G` rather than assumed. `run_in` already pins `HOME`, so the test can
/// own the configuration that resolution reads instead of depending on whose
/// machine it runs on.
fn scratch_home_resolving_to_root(label: &str) -> std::path::PathBuf {
    let home = scratch_home_named(label);
    let ssh = home.join(".ssh");
    std::fs::create_dir_all(&ssh).expect("a scratch ssh directory");
    std::fs::write(ssh.join("config"), "Host 127.0.0.1\n    User root\n")
        .expect("seed the ssh configuration the resolver reads");
    home
}

fn run(args: &[&str]) -> Output {
    run_in(scratch_home(), args)
}

fn run_in(home: std::path::PathBuf, args: &[&str]) -> Output {
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

/// A fleet run that would file two hosts' checkpoints under one key is refused
/// before it connects.
///
/// `SshExecutor::description` substitutes a literal `root` for a target that
/// named no user, and that string is the checkpoint host key, so `--ssh h` and
/// `--ssh root@h` are two targets with one key. Both capture a pre-apply
/// checkpoint under `(host_key, name)`, and the newest per key wins, so the
/// surviving pre-apply state can be content the other target already hardened.
///
/// Driven through the binary because the refusal has to sit on the path `main`
/// wires up: the pure check is unit-tested next to the parser, and a unit test
/// of it stays green whether or not any verb consults it.
#[test]
fn a_fleet_run_that_would_collide_two_checkpoints_is_refused_before_connecting() {
    let out = run_in(
        scratch_home_resolving_to_root("collision"),
        &[
            "batch",
            "apply",
            "--execute",
            // Under --quiet, because a refusal is an error rather than
            // progress: gating it on --quiet would silence the only thing that
            // says why the fleet was not touched. The rollback test below
            // leaves --quiet off, so both paths are covered.
            "--quiet",
            "--plugin",
            "kernel-hardening",
            "--ssh",
            "127.0.0.1",
            "--ssh",
            "root@127.0.0.1",
            "--port",
            "1",
            "--ssh-timeout",
            "2",
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert_eq!(
        out.status.code(),
        Some(2),
        "a selection that cannot file its checkpoints apart is a usage error, \
         which `batch` signals as 2; got stderr: {stderr}"
    );
    assert!(
        stderr.contains("ssh://root@127.0.0.1:1"),
        "the refusal names the single key both targets would have written under, \
         because that is the thing the operator has to change; got: {stderr}"
    );
    // The connection is what proves the refusal came first: a run that reached
    // the host would render a per-host outcome, failed or otherwise.
    assert!(
        !stdout.contains("status:"),
        "the refusal comes before the first connection, so no host outcome is \
         rendered; got stdout: {stdout}"
    );
}

/// The control against the refusal being made too broad: two accounts on one
/// machine are two keys and a legitimate fleet run, so this must get past the
/// check and fail at the connection instead.
#[test]
fn a_fleet_run_naming_two_real_accounts_is_not_refused() {
    let out = run_in(
        scratch_home_named("two-accounts"),
        &[
            "batch",
            "apply",
            "--execute",
            "--plugin",
            "kernel-hardening",
            "--ssh",
            "admin@127.0.0.1",
            "--ssh",
            "root@127.0.0.1",
            "--port",
            "1",
            "--ssh-timeout",
            "2",
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        !stderr.contains("would file their checkpoints"),
        "distinct accounts produce distinct keys and must not be refused; got: {stderr}"
    );
    assert!(
        stdout.contains("status:"),
        "this run gets past the check and reaches the connection, so it renders \
         a per-host outcome; got stdout: {stdout}"
    );
}

/// The same refusal on the other verb that writes. `batch rollback --execute`
/// takes the reversible-rollback snapshot through the same
/// `persist_signed_checkpoint`, and it also *reads* by host key, so a colliding
/// pair can restore one target from the other's checkpoint. A check wired only
/// into `apply` would leave that reachable, and the unit test of the pure
/// function stays green either way.
#[test]
fn a_fleet_rollback_that_would_collide_two_checkpoints_is_refused_before_connecting() {
    let out = run_in(
        scratch_home_resolving_to_root("collision-rollback"),
        &[
            "batch",
            "rollback",
            "--execute",
            "--ssh",
            "127.0.0.1",
            "--ssh",
            "root@127.0.0.1",
            "--port",
            "1",
            "--ssh-timeout",
            "2",
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert_eq!(
        out.status.code(),
        Some(2),
        "the refusal is the same usage error on either verb; got stderr: {stderr}"
    );
    assert!(
        stderr.contains("ssh://root@127.0.0.1:1"),
        "and names the same single key; got: {stderr}"
    );
    assert!(
        !stdout.contains("status:"),
        "the refusal comes before the first connection, so no host outcome is \
         rendered; got stdout: {stdout}"
    );
}

/// The control against the refusal reaching a run that cannot be bitten by the
/// collision. A dry run captures no checkpoint and restores nothing, and it is
/// how an operator discovers the problem in the first place, so a colliding
/// selection must get past the check and reach the hosts.
#[test]
fn a_dry_run_of_a_colliding_pair_is_not_refused() {
    let out = run_in(
        scratch_home_named("collision-dry-run"),
        &[
            "batch",
            "apply",
            "--plugin",
            "kernel-hardening",
            "--ssh",
            "127.0.0.1",
            "--ssh",
            "root@127.0.0.1",
            "--port",
            "1",
            "--ssh-timeout",
            "2",
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        !stderr.contains("would file their checkpoints"),
        "a dry run writes no checkpoint, so the pair must not be refused; got: {stderr}"
    );
    assert!(
        stdout.contains("status:"),
        "and it reaches the hosts, rendering a per-host outcome; got stdout: {stdout}"
    );
}

/// Every fleet verb judges `--output` before it contacts anything.
///
/// The check began at the point of writing, which meant a whole fleet was
/// scanned, or hardened, and only then told its destination named the wrong
/// document. It also exited 1 from there, where every other pre-connection
/// refusal in `batch` exits 2, the tier the reference documents for a batch
/// usage error. Judged up front it is neither.
///
/// `.pdf` is the needle because batch renders text and JSON only, so it
/// contradicts a fleet run whichever way `--format` is set, and all four verbs
/// can be driven with one path.
#[test]
fn every_fleet_verb_refuses_an_output_path_naming_another_document() {
    let home = scratch_home_named("output-contradiction");
    let mut refused = 0;
    for verb in FLEET_VERBS {
        let target = home.join("fleet.pdf");
        let target = target.to_str().expect("a UTF-8 scratch path");
        let mut argv: Vec<&str> = verb.to_vec();
        argv.extend_from_slice(&["--output", target, "--ssh", "127.0.0.1", "--port", "1"]);
        let out = run_in(home.clone(), &argv);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);

        assert_eq!(
            out.status.code(),
            Some(2),
            "{verb:?} must refuse a .pdf destination as the usage error it is; \
             got stderr: {stderr}"
        );
        assert!(
            !stdout.contains("status:"),
            "{verb:?} must refuse before it contacts a host, so no per-host \
             outcome is rendered; got stdout: {stdout}"
        );
        assert!(
            !std::path::Path::new(target).exists(),
            "{verb:?} must not create the file it refused"
        );
        refused += 1;
    }

    assert_eq!(
        refused,
        FLEET_VERBS.len(),
        "every fleet verb is covered, not whichever one the loop reached first"
    );

    // The control: a path agreeing with the selected format gets past the check
    // and reaches the hosts, so the refusal is the contradiction rather than
    // `--output` being refused wholesale.
    let ok = scratch_home_named("output-agreeing").join("fleet.json");
    let ok = ok.to_str().expect("a UTF-8 scratch path");
    let control = run_in(
        scratch_home_named("output-agreeing"),
        &[
            "batch",
            "scan",
            "--format",
            "json",
            "--output",
            ok,
            "--ssh",
            "127.0.0.1",
            "--port",
            "1",
        ],
    );
    let control_stderr = String::from_utf8_lossy(&control.stderr);
    assert!(
        !control_stderr.contains("names a"),
        "a .json path under --format json agrees and must not be refused; \
         got: {control_stderr}"
    );
}
