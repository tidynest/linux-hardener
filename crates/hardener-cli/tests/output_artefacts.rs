//! What a command reports about what it actually did, driven through the built
//! binary: whether the file it writes is the file its path asked for, and
//! whether a mutating verb distinguishes having acted from having found
//! nothing to act on.
//!
//! These run the binary rather than calling the checks directly, because a
//! validator tested on its own passes every assertion while nothing calls it.
//!
//! Every child is given a scratch `HOME`, so nothing of the operator's is read
//! and the state any run touches is its own.

use std::process::{Command, Output};

fn scratch_home() -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("hardener-output-artefacts-{}", std::process::id()));
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

/// No session by this id exists, which is deliberate: the extension is judged
/// before the database is consulted, so a run that gets as far as looking the
/// session up has already been let through the check under test.
const ABSENT_SESSION: &str = "00000000-0000-0000-0000-000000000000";

fn export_to(path: &str) -> String {
    let out = run(&["history", "export", ABSENT_SESSION, "-o", path]);
    assert!(
        !out.status.success(),
        "no session by this id exists, so no export can succeed; got exit {:?}",
        out.status.code()
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// What the refusal says, matched loosely so the wording can be revised.
const CANNOT_PRODUCE: &str = "cannot produce";

#[test]
fn history_export_refuses_a_path_whose_extension_it_cannot_produce() {
    let stderr = export_to("report.pdf");
    assert!(
        stderr.contains(CANNOT_PRODUCE),
        "the export is JSON, so a .pdf path asks for a document that will never \
         arrive and must be refused rather than filled with JSON; got: {stderr}"
    );

    // Nothing was written under that name. A refusal that still leaves the
    // misleading file behind has not fixed the defect.
    assert!(
        !std::path::Path::new("report.pdf").exists(),
        "the refused path must not have been created"
    );
}

#[test]
fn history_export_accepts_the_extension_it_does_produce() {
    let stderr = export_to("report.json");
    assert!(
        !stderr.contains(CANNOT_PRODUCE),
        "a .json path is exactly what this exporter writes and must pass the \
         check; got: {stderr}"
    );
}

#[test]
fn history_export_accepts_a_path_that_claims_nothing() {
    let stderr = export_to("report");
    assert!(
        !stderr.contains(CANNOT_PRODUCE),
        "a path with no extension promises no particular document, so there is \
         nothing to contradict; got: {stderr}"
    );
}

#[test]
fn history_export_accepts_a_dotted_name_that_is_not_a_document_type() {
    // `Path::extension` answers "what follows the last dot", which is not the
    // same question as "what document is this". A dated backup name and a
    // version-stamped one both have an extension by that definition, and
    // refusing them would break invocations that work and ask for nothing this
    // command cannot give.
    let dated = export_to("backups.2026.08.03");
    assert!(
        !dated.contains(CANNOT_PRODUCE),
        "a dated name has extension '03' by that definition and names no \
         document type, so there is nothing to refuse; got: {dated}"
    );

    let versioned = export_to("session-1.5.1");
    assert!(
        !versioned.contains(CANNOT_PRODUCE),
        "a version-stamped name has extension '1' and is not a document type \
         either; got: {versioned}"
    );
}

#[test]
fn checkpoint_delete_does_not_report_removing_a_row_that_was_not_there() {
    let out = run(&[
        "--format",
        "json",
        "checkpoint",
        "delete",
        "cp_0_doesnotexist",
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !out.status.success(),
        "deleting a checkpoint that does not exist removed nothing and must not \
         exit 0; got exit {:?} with stdout: {stdout}",
        out.status.code()
    );
    // The run must fail for this reason and not because the database could not
    // be opened at all, which would make the assertion above pass without
    // reaching the check under test.
    assert!(
        stderr.contains("no checkpoint with id") && stderr.contains("cp_0_doesnotexist"),
        "the refusal names the row it could not find, rather than reporting a \
         database that would not open; got: {stderr}"
    );
    assert!(
        !stdout.contains("deleted"),
        "nothing was deleted, so no success envelope may be printed; got: {stdout}"
    );
}

/// The global `--format json` promises JSON on stdout, and `systemd` emitted
/// human text regardless: `main` passed the four verbs no format at all and
/// `commands/systemd.rs` imported no `OutputFormat`. A caller parsing stdout as
/// JSON got a unit file beginning with `#`, or a systemctl status table.
///
/// `generate` without `--output` is the cheapest of the four to drive: it writes
/// to stdout, shells out to nothing and touches no unit on this host.
#[test]
fn systemd_generate_honours_the_global_json_format() {
    let out = run(&["--format", "json", "systemd", "generate"]);
    let stdout = String::from_utf8_lossy(&out.stdout);

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout must parse as JSON, got {e}: {stdout}"));
    // Asserted on content, not key presence: `Value::get` returns `Some(&Null)`
    // for a key holding null, so a `"service": null` envelope satisfied the
    // weaker form while carrying nothing a caller could use.
    let service = parsed["service"]["content"].as_str().unwrap_or_default();
    let timer = parsed["timer"]["content"].as_str().unwrap_or_default();
    assert!(
        service.contains("[Unit]") && service.contains("ExecStart="),
        "the envelope carries the service unit itself, so a caller need not \
         scrape it out of a comment header; got: {parsed}"
    );
    assert!(
        timer.contains("[Timer]"),
        "and the timer unit beside it; got: {parsed}"
    );

    // The control: without the flag the same run still prints the unit files as
    // text, so the change is the flag being honoured rather than the text
    // rendering being replaced.
    let control = run(&["systemd", "generate"]);
    let control_stdout = String::from_utf8_lossy(&control.stdout);
    assert!(
        control_stdout.contains("[Unit]"),
        "the text rendering is unchanged and still prints the unit files; \
         got: {control_stdout}"
    );
}

/// The refusal driven through the binary, not called directly.
///
/// This file's own header says why: a validator tested on its own passes every
/// assertion while nothing calls it. That is not hypothetical here. Replacing
/// the call in `report` with `let _ = refuse_extension_that_contradicts(..)`
/// compiles, passes clippy at `-D warnings`, leaves every unit test green, and
/// restores the defect in full.
///
/// It also pins that the refusal comes before the scan: eight plugins, or a
/// whole remote scan, must not be paid for before one argument is compared with
/// another.
#[test]
fn report_refuses_an_output_path_that_contradicts_the_format() {
    // Absolute, under the scratch home. A relative path is resolved against the
    // child's working directory, which is this crate's source directory, so a
    // run that failed to refuse would drop the file into the repository.
    let wrong = scratch_home().join("wrong-document.json");
    let _ = std::fs::remove_file(&wrong);
    let wrong = wrong.to_str().expect("a UTF-8 scratch path");

    let out = run(&["report", "--output", wrong]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !out.status.success(),
        "a text report must not be written into a path naming JSON; got exit {:?} \
         with stderr: {stderr}",
        out.status.code()
    );
    assert!(
        !std::path::Path::new(wrong).exists(),
        "and no file is left behind by the refused run"
    );
    assert!(
        !stderr.contains("Generating compliance report"),
        "the refusal comes before the scan, so nothing is scanned or generated \
         for a run that cannot write its result; got: {stderr}"
    );

    // The control: the same path with the format it names is accepted and
    // reaches the scan, so the refusal is the contradiction rather than
    // `--output` being broken.
    let control = run(&["report", "--report-format", "json", "--output", "/dev/null"]);
    let control_stderr = String::from_utf8_lossy(&control.stderr);
    assert!(
        !control_stderr.contains("names a json document"),
        "a path agreeing with the format is not refused; got: {control_stderr}"
    );
}

/// The wizard's chatter belongs on stderr, like every other command's.
///
/// `report --interactive` decorated its prompts with `println!`, so the banner,
/// the step headings, the progress lines and the completion summary all went to
/// stdout, and `print_summary` runs *after* the report body is written there.
/// Redirecting a JSON report to a file therefore produced something that is not
/// JSON. The non-interactive path is disciplined about exactly this.
///
/// Driven without a terminal, which is the one wizard state reachable from a
/// test: it refuses immediately, so any byte on stdout is chatter rather than a
/// report, and before the fix there were 585 of them.
#[test]
fn the_wizard_puts_no_chatter_on_stdout() {
    let out = run(&["report", "--interactive"]);

    assert!(
        !out.status.success(),
        "precondition: with no terminal the wizard cannot run, so nothing it \
         printed can be a report"
    );
    assert!(
        out.stdout.is_empty(),
        "stdout carried {} bytes before any report existed: {}",
        out.stdout.len(),
        String::from_utf8_lossy(&out.stdout)
    );
    // The control: the run really did produce output, so an empty stdout means
    // the chatter moved rather than that nothing ran.
    assert!(
        !out.stderr.is_empty(),
        "the refusal must still be reported, on stderr"
    );
}
