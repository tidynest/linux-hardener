#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. Present so the file
// says what it is on its own terms, matching its siblings in this directory.

//! Tests for the refusal `run_scan` owes when the config disables everything.
//!
//! `run_scan` itself cannot be driven here: it opens the real history database
//! and resolves the config from the process environment. What decides whether
//! an operator is told anything is the predicate, and that is a pure function
//! of two values.
//!
//! **Why this exists.** `hardener scan` bails when the config disables every
//! selected plugin, and says how to leave that state. The desktop's local scan
//! returned an empty result set instead, which the Analysis tab renders as
//! "No findings yet. Run a Security Scan above", told to run a scan having
//! just run one. The deep-scan button, a few pixels away, shells out to the CLI
//! and inherited the refusal, so one host answered two ways.
//!
//! Ceiling: this pins the decision, not the wiring. That `run_scan` calls it,
//! and calls it inside `fail_session_on_err` so a refusal marks the session
//! Failed, is not asserted here and is visible only by reading the call site.

use super::*;

/// The state the refusal exists for.
#[test]
fn every_selected_plugin_disabled_is_refused() {
    let err = scan_selection_refusal(0, &["ssh-hardening".to_string()])
        .expect_err("nothing ran and the config is why");

    assert!(
        err.contains("Config disabled every selected plugin"),
        "got: {err}"
    );
}

/// The message has to name them, or it tells the operator a fact they cannot
/// act on. Every plugin the config turned off is listed, not just the first.
#[test]
fn the_refusal_names_every_disabled_plugin() {
    let err = scan_selection_refusal(
        0,
        &["ssh-hardening".to_string(), "kernel-hardening".to_string()],
    )
    .expect_err("nothing ran");

    assert!(err.contains("ssh-hardening"), "got: {err}");
    assert!(err.contains("kernel-hardening"), "got: {err}");
}

/// And it has to say what to do. The wording is the CLI's, deliberately: an
/// operator who meets this in the desktop and then opens a terminal should not
/// have to work out that the two messages describe one condition.
#[test]
fn the_refusal_says_how_to_leave_the_state() {
    let err = scan_selection_refusal(0, &["ssh-hardening".to_string()]).expect_err("nothing ran");

    assert!(err.contains("disabled_plugins"), "got: {err}");
    assert!(err.contains("enabled_plugins"), "got: {err}");
}

/// The green half, and the one that stops this refusing real scans.
///
/// A partial disable is not this state. Plugins ran, findings exist, and the
/// scan is a scan. What was skipped now travels beside the findings, as a
/// marker entry per disabled plugin, so the operator is told without this
/// refusal having to fire; refusing here would break every host with one
/// plugin turned off.
#[test]
fn a_partial_disable_is_not_refused() {
    scan_selection_refusal(3, &["ssh-hardening".to_string()])
        .expect("three plugins ran; that is a scan");
}

/// Nothing ran and nothing was disabled: a different fault with a different
/// remedy, and not this one to report.
///
/// An empty registry and a filter matching no plugin both land here. Claiming
/// the config disabled something would send the operator to edit a file that
/// says nothing about it. **`scanned == 0` alone must never be the trigger**,
/// which is the mutation this case exists to catch.
#[test]
fn nothing_scanned_and_nothing_disabled_is_not_this_error() {
    scan_selection_refusal(0, &[]).expect("no plugins and no config involvement");
}

/// The ordinary run, asserted so the predicate cannot become unconditional.
#[test]
fn a_full_scan_is_not_refused() {
    scan_selection_refusal(8, &[]).expect("eight plugins ran and none were disabled");
}
