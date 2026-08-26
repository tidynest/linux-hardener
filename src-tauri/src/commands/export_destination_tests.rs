#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Where the desktop writes a compliance export, and when it refuses to.
//!
//! `hardener report` has refused an `--output` path whose extension names a
//! different document since `refuse_extension_that_contradicts` was added: a
//! text report written into a file called `.json`, exit 0, is a lie the next
//! consumer acts on. The desktop reached the same fork in-process and wrote the
//! bytes. Choosing PDF and typing `audit.json` produced a PDF named
//! `audit.json` and reported it saved.

use super::*;

const STAMP: &str = "20260826-114500";

fn destination(path: &str, format: OutputFormat) -> Result<String, String> {
    export_destination(Some(path.to_string()), format, STAMP)
}

/// The disagreement with the CLI, in the direction that writes a wrong file.
#[test]
fn an_extension_naming_another_document_is_refused() {
    let refusal = destination("audit.json", OutputFormat::Pdf).expect_err("json is not pdf");

    assert!(refusal.contains("audit.json"), "got {refusal}");
    assert!(refusal.contains("json"), "got {refusal}");
    assert!(refusal.contains("pdf"), "got {refusal}");
}

/// The refusal is worded for a window, not for a command line.
///
/// The decision is shared with the CLI through `OutputFormat::contradicted_by`
/// and the sentence deliberately is not: the CLI's names `--output`, and there
/// is no such flag in front of a desktop operator to go and correct.
#[test]
fn the_refusal_names_no_command_line_flag() {
    let refusal = destination("audit.txt", OutputFormat::Html).expect_err("txt is not html");

    assert!(!refusal.contains("--"), "got {refusal}");
}

/// Matching extensions pass through untouched, including the `htm` spelling.
#[test]
fn a_matching_extension_is_kept_as_written() {
    assert_eq!(
        destination("audit.pdf", OutputFormat::Pdf).expect("pdf is pdf"),
        "audit.pdf",
    );
    assert_eq!(
        destination("audit.htm", OutputFormat::Html).expect("htm is html"),
        "audit.htm",
    );
    assert_eq!(
        destination("AUDIT.PDF", OutputFormat::Pdf).expect("case does not matter"),
        "AUDIT.PDF",
    );
}

/// A path with no extension gets the format's, which is the documented
/// behaviour and the one `report.rs` implements.
#[test]
fn a_bare_path_gains_the_formats_extension() {
    assert_eq!(
        destination("/home/op/audit", OutputFormat::Csv).expect("no extension"),
        "/home/op/audit.csv",
    );
}

/// A dated stem is not a document type, and is neither refused nor extended.
///
/// `q3.2026.08` has extension `08`, which names no format, so
/// `contradicted_by` raises no objection and the append branch does not fire
/// because an extension is present. The operator gets the name they typed.
/// This is the case a naive "does it end in the right extension" check would
/// mangle into `q3.2026.08.pdf`, and the case `from_extension`'s closed list
/// exists for.
#[test]
fn a_dated_stem_is_left_exactly_as_typed() {
    assert_eq!(
        destination("q3.2026.08", OutputFormat::Pdf).expect("08 names no format"),
        "q3.2026.08",
    );
}

/// No path at all builds one under Documents, stamped so a second export in
/// the same session does not overwrite the first.
#[test]
fn an_absent_path_is_built_from_the_timestamp_and_the_format() {
    let built =
        export_destination(None, OutputFormat::Html, STAMP).expect("a default is always available");

    assert!(
        built.ends_with(&format!("compliance-report-{STAMP}.html")),
        "got {built}",
    );
    assert!(
        std::path::Path::new(&built).is_absolute(),
        "a relative path would land wherever the desktop happened to start: {built}",
    );
}

/// Every format refuses every other, so no pair is covered only by argument.
///
/// A per-case check misses the case nobody thought of. A five-by-five sweep is
/// cheap, and it is what catches a sixth format added later with the comparison
/// wired the wrong way round.
///
/// The totals are asserted outside the loop, and not only to satisfy the
/// vacuity check that rejected the first draft of this test: they are the
/// stronger claim. Twenty-five pairs and exactly five accepted says the sweep
/// covered the whole matrix and that acceptance is the diagonal. The per-pair
/// assertion alone would pass just as happily over a `formats` array somebody
/// had shortened to one.
#[test]
fn every_format_refuses_every_other_and_accepts_its_own() {
    let formats = [
        OutputFormat::Text,
        OutputFormat::Json,
        OutputFormat::Csv,
        OutputFormat::Html,
        OutputFormat::Pdf,
    ];
    let mut pairs = 0;
    let mut accepted = 0;

    for chosen in formats {
        for named in formats {
            let path = format!("audit.{}", named.extension());
            let outcome = destination(&path, chosen);
            assert_eq!(
                outcome.is_ok(),
                named == chosen,
                "{path} against {}: {outcome:?}",
                chosen.extension(),
            );
            pairs += 1;
            accepted += usize::from(outcome.is_ok());
        }
    }

    assert_eq!(pairs, 25, "the sweep did not cover the whole matrix");
    assert_eq!(accepted, 5, "acceptance should be exactly the diagonal");
}
