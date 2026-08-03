//! What `--quiet` suppresses, driven through the built binary.
//!
//! `--quiet` is documented as suppressing non-essential output, and `apply`
//! gates every one of its status lines on it by hand. A line that forgets the
//! gate is invisible to a unit test, because the gating happens at the call
//! site rather than inside `output`, so nothing type-checks it: these run the
//! binary and read the stream the operator would.
//!
//! Nothing here writes to the host. Every run is `--dry-run`, which validates
//! and writes nothing, and each child is given a scratch `HOME` so no state of
//! the operator's is read or written.

use std::process::{Command, Output};

fn scratch_home() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("hardener-quiet-output-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a scratch home");
    dir
}

/// One plugin so the run is short, and `--dry-run` so no plugin can write.
fn preview(extra: &[&str]) -> Output {
    let home = scratch_home();
    let mut argv = vec!["apply", "--dry-run", "--plugin", "kernel-hardening"];
    argv.extend_from_slice(extra);
    Command::new(env!("CARGO_BIN_EXE_hardener"))
        .args(&argv)
        .env("HOME", &home)
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CONFIG_HOME", home.join("config"))
        .output()
        .expect("the binary under test runs")
}

/// The announcement `apply` prints before a dry run. Asserted as a substring so
/// the wording can be revised without this test having to be.
const DRY_RUN_NOTICE: &str = "Dry run";

#[test]
fn the_dry_run_notice_does_not_survive_quiet() {
    let quiet = preview(&["--quiet"]);
    let stdout = String::from_utf8_lossy(&quiet.stdout);

    assert!(
        !stdout.contains(DRY_RUN_NOTICE),
        "--quiet asks for no non-essential output and this is an announcement, \
         not a result; got stdout: {stdout}"
    );

    // The other half, and the one that stops the gate being widened by mistake.
    // `--quiet` suppresses chatter, never the answer the run was asked for, so
    // gating the dry run's own results on it would satisfy the assertion above
    // while destroying the command. Nothing else in the crate would notice.
    assert!(
        stdout.contains("kernel-hardening"),
        "the results of a dry run are what it was asked for and must survive \
         --quiet; got stdout: {stdout}"
    );

    // Positive control. The assertion above is an absence claim, so it would
    // pass just as well against a line that had been renamed or deleted
    // outright. Without the flag the notice is printed, which is what makes its
    // absence above the gate working rather than the message being gone.
    let loud = preview(&[]);
    let loud_stdout = String::from_utf8_lossy(&loud.stdout);
    assert!(
        loud_stdout.contains(DRY_RUN_NOTICE),
        "without --quiet the dry run announces itself; got stdout: {loud_stdout}"
    );
}
