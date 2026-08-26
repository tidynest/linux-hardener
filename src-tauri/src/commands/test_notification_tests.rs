#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! What the settings pane tells an operator who pressed "send test".
//!
//! `send_test` returns one result per configured channel and has exactly one
//! non-test consumer, this desktop command, so there is no CLI rendering of the
//! same data to disagree with. The reference is the results themselves, and the
//! summary used to drop two things out of them: which channel each verdict
//! belonged to, and any failure whose reason was not recorded.

use super::*;
use hardener_scheduler::notification::NotificationResult;

fn failed(channel: &str, error: &str) -> NotificationResult {
    NotificationResult::failed(channel, error)
}

fn silently_failed(channel: &str) -> NotificationResult {
    NotificationResult {
        channel: channel.to_string(),
        success: false,
        error: None,
    }
}

/// Nothing configured is not a failure to send, and says so distinctly.
#[test]
fn no_configured_channel_is_reported_as_nothing_to_send() {
    let verdict = test_notification_verdict(&[]);

    assert!(!verdict.success);
    assert_eq!(verdict.message, "No notification channels are enabled");
}

/// A working setup names what it reached, so the operator can confirm it was
/// the endpoint they just edited rather than a count that happens to match.
#[test]
fn every_channel_succeeding_names_them() {
    let verdict = test_notification_verdict(&[
        NotificationResult::ok("email"),
        NotificationResult::ok("webhook:slack"),
    ]);

    assert!(verdict.success);
    assert_eq!(verdict.message, "Test sent to email, webhook:slack");
}

/// The case the old message could not express.
///
/// Four channels, one broken. `Failed: connection refused` named neither the
/// channel that broke nor the three that worked, and both halves are what an
/// operator needs: whether to keep editing, and which endpoint to edit.
#[test]
fn a_partial_failure_names_the_channel_and_counts_the_rest() {
    let verdict = test_notification_verdict(&[
        NotificationResult::ok("email"),
        failed("webhook:slack", "connection refused"),
        NotificationResult::ok("webhook:pagerduty"),
        NotificationResult::ok("webhook:ops"),
    ]);

    assert!(!verdict.success);
    assert_eq!(
        verdict.message,
        "1 of 4 channels failed. webhook:slack: connection refused"
    );
}

/// Two failures are both named, in the order the dispatcher returned them.
#[test]
fn several_failures_are_all_named() {
    let verdict = test_notification_verdict(&[
        failed("email", "535 authentication failed"),
        failed("webhook:slack", "503 Service Unavailable"),
    ]);

    assert!(!verdict.success);
    assert_eq!(
        verdict.message,
        "2 of 2 channels failed. email: 535 authentication failed; \
         webhook:slack: 503 Service Unavailable"
    );
}

/// A failure carrying no reason is still a failure.
///
/// The reasons were collected with a `filter_map` over `error`, which drops a
/// row it cannot describe. Drop the only failure and the list is empty, which
/// is the branch that reports success: this exact input was answered
/// `success: true, "Test sent to 1 channel(s)"` before 2026-08-26.
///
/// `NotificationResult::failed` is the only constructor setting
/// `success: false` and it always records a reason, so nothing in the tree
/// builds this row. The fields are `pub`, so that is a fact about today's call
/// sites rather than about the type, and this is the direction that hides: a
/// channel that did not deliver, reported as one that did.
#[test]
fn a_failure_with_no_recorded_reason_is_not_reported_as_a_success() {
    let verdict = test_notification_verdict(&[silently_failed("webhook:slack")]);

    assert!(!verdict.success);
    assert_eq!(
        verdict.message,
        "1 of 1 channels failed. webhook:slack: failed, no reason recorded"
    );
}

/// And it is not hidden by a channel that did work alongside it.
#[test]
fn a_reasonless_failure_beside_a_success_still_fails_the_verdict() {
    let verdict = test_notification_verdict(&[
        NotificationResult::ok("email"),
        silently_failed("webhook:slack"),
    ]);

    assert!(!verdict.success);
    assert!(
        verdict.message.starts_with("1 of 2 channels failed."),
        "got {}",
        verdict.message
    );
}
