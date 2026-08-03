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
