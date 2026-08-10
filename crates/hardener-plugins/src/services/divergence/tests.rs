#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a
// test module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`divergence`].

use super::*;
use hardener_common::executor::{CommandOutput, MockExecutor};
use std::sync::Arc;

/// A `systemctl list-unit-files <unit>` response for a unit that is not
/// installed: empty stdout, the same shape [`is_service_exists`] reads as
/// absent regardless of exit code.
fn absent() -> CommandOutput {
    CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 1,
    }
}

/// One host builder, the way `ssh/divergence/tests.rs:22` has one.
///
/// Every unit in [`super::super::UNNECESSARY_SERVICES`] other than `name` is
/// registered as not installed, so the probe's loop over the whole list skips
/// them without needing `is-active`/`is-enabled` mocked for units the test
/// under construction has no opinion about. `active`/`enabled` are the
/// trimmed stdout `systemctl is-active`/`is-enabled` would print for `name`;
/// their exit codes are set the way the real commands set them, non-zero for
/// "inactive"/"disabled" alike. The probe reads the printed word and ignores
/// the exit code entirely, so a caller here is free to pass an exit code that
/// disagrees with the word: `garbage_words_with_diverged_shaped_exit_codes_are_unverifiable`
/// below does exactly that, to prove the exit code is not what decides the
/// answer.
fn service_host(
    name: &str,
    active: &str,
    active_exit: i32,
    enabled: &str,
    enabled_exit: i32,
) -> Context {
    let unit = super::super::unit_name(name);
    let mut executor = MockExecutor::new()
        .with_command_exists("systemctl", true)
        .with_command(
            "systemctl",
            &["list-unit-files", &unit],
            CommandOutput {
                stdout: format!("{unit} static\n"),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", name],
            CommandOutput {
                stdout: active.to_string(),
                stderr: String::new(),
                exit_code: active_exit,
            },
        )
        .with_command(
            "systemctl",
            &["is-enabled", name],
            CommandOutput {
                stdout: enabled.to_string(),
                stderr: String::new(),
                exit_code: enabled_exit,
            },
        );

    for directive in super::super::UNNECESSARY_SERVICES {
        if directive.service_name != name {
            let other_unit = super::super::unit_name(directive.service_name);
            executor =
                executor.with_command("systemctl", &["list-unit-files", &other_unit], absent());
        }
    }

    Context::with_executor(Arc::new(executor))
}

/// A host where none of the managed units are installed at all: every
/// `list-unit-files` lookup comes back empty. Nothing was restored for any of
/// them to disagree with, so the probe has to say nothing rather than treat
/// absence as an unmeasured negative.
fn no_units_installed_host() -> Context {
    let mut executor = MockExecutor::new().with_command_exists("systemctl", true);
    for directive in UNNECESSARY_SERVICES {
        let unit = super::super::unit_name(directive.service_name);
        executor = executor.with_command("systemctl", &["list-unit-files", &unit], absent());
    }
    Context::with_executor(Arc::new(executor))
}

/// A unit whose restored files leave it disabled but which the service
/// manager reports running anyway: the rollback's undo did not reach the
/// running process, only the files that are meant to govern it.
#[tokio::test]
async fn a_disabled_but_running_unit_is_diverged() {
    let ctx = service_host("bluetooth", "active\n", 0, "disabled\n", 1);

    let rows = service_divergences(&ctx).await;

    assert_eq!(rows.len(), 1, "one subject, one row");
    assert_eq!(rows[0].divergence_subject, "bluetooth");
    assert_eq!(rows[0].divergence_state, DivergenceState::Diverged);
    assert!(
        rows[0].divergence_detail.contains("disabled")
            && rows[0].divergence_detail.contains("running"),
        "the reason has to name both readings that disagree: {}",
        rows[0].divergence_detail
    );
}

/// The reverse disagreement: restored files leave the unit enabled, but
/// nothing restarted it, so the service manager still reports it stopped.
/// This is the direction rollback's own `daemon-reload` (never a restart)
/// leaves behind whenever the pre-apply state was enabled and running.
#[tokio::test]
async fn an_enabled_but_stopped_unit_is_diverged() {
    let ctx = service_host("cups", "inactive\n", 3, "enabled\n", 0);

    let rows = service_divergences(&ctx).await;

    assert_eq!(rows.len(), 1, "one subject, one row");
    assert_eq!(rows[0].divergence_subject, "cups");
    assert_eq!(rows[0].divergence_state, DivergenceState::Diverged);
    assert!(
        rows[0].divergence_detail.contains("enabled")
            && rows[0].divergence_detail.contains("not running"),
        "the reason has to name both readings that disagree: {}",
        rows[0].divergence_detail
    );
}

/// Enabled and running agree with each other: this is exactly what a healthy
/// enabled service looks like, and the probe must not report it.
#[tokio::test]
async fn an_enabled_and_running_unit_reports_nothing() {
    let ctx = service_host("avahi-daemon", "active\n", 0, "enabled\n", 0);

    assert!(service_divergences(&ctx).await.is_empty());
}

/// Disabled and stopped also agree: the ordinary "successfully turned off"
/// host, and silence for the same reason.
#[tokio::test]
async fn a_disabled_and_stopped_unit_reports_nothing() {
    let ctx = service_host("xinetd", "inactive\n", 3, "disabled\n", 1);

    assert!(service_divergences(&ctx).await.is_empty());
}

/// `systemctl is-enabled` failing to run at all must not be read as
/// "disabled": the probe could not look, and has to say so rather than guess
/// the negative.
#[tokio::test]
async fn a_unit_with_unreadable_enablement_is_unverifiable() {
    let name = "ModemManager";
    let unit = super::super::unit_name(name);
    let mut executor = MockExecutor::new()
        .with_command_exists("systemctl", true)
        .with_command(
            "systemctl",
            &["list-unit-files", &unit],
            CommandOutput {
                stdout: format!("{unit} static\n"),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", name],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        );
    // No `is-enabled` registration: execute_command fails outright for that
    // call, distinct from succeeding with a non-zero exit.
    for directive in super::super::UNNECESSARY_SERVICES {
        if directive.service_name != name {
            let other_unit = super::super::unit_name(directive.service_name);
            executor =
                executor.with_command("systemctl", &["list-unit-files", &other_unit], absent());
        }
    }
    let ctx = Context::with_executor(Arc::new(executor));

    let rows = service_divergences(&ctx).await;

    assert_eq!(rows.len(), 1, "an unrunnable probe is one row, not silence");
    assert_eq!(rows[0].divergence_subject, "ModemManager");
    assert_eq!(rows[0].divergence_state, DivergenceState::Unverifiable);
}

/// `systemctl is-active` failing to run at all must not be read as "not
/// running": the same trap, on the other reading.
#[tokio::test]
async fn a_unit_with_unreadable_activity_is_unverifiable() {
    let name = "bluetooth";
    let unit = super::super::unit_name(name);
    let mut executor = MockExecutor::new()
        .with_command_exists("systemctl", true)
        .with_command(
            "systemctl",
            &["list-unit-files", &unit],
            CommandOutput {
                stdout: format!("{unit} static\n"),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-enabled", name],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        );
    // No `is-active` registration: execute_command fails outright.
    for directive in super::super::UNNECESSARY_SERVICES {
        if directive.service_name != name {
            let other_unit = super::super::unit_name(directive.service_name);
            executor =
                executor.with_command("systemctl", &["list-unit-files", &other_unit], absent());
        }
    }
    let ctx = Context::with_executor(Arc::new(executor));

    let rows = service_divergences(&ctx).await;

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].divergence_subject, "bluetooth");
    assert_eq!(rows[0].divergence_state, DivergenceState::Unverifiable);
}

/// A unit that is not installed on this host at all: there is nothing a
/// rollback could have restored, so there is nothing for a running process
/// to disagree with, and the probe must not spawn `is-active`/`is-enabled`
/// for it (neither is mocked here; a stray call would fail the test with a
/// "command not registered" panic rather than a wrong assertion).
#[tokio::test]
async fn a_unit_not_installed_reports_nothing() {
    let ctx = no_units_installed_host();

    assert!(service_divergences(&ctx).await.is_empty());
}

/// `systemctl list-unit-files` failing to run at all must not be read as
/// "not installed": the same trap as the enablement and activity readings,
/// one probe earlier. `is_service_exists` never inspects stderr or exit
/// code, so the same technique used above reaches the `Err` arm: leave the
/// command unregistered on the mock.
#[tokio::test]
async fn a_unit_with_unreadable_existence_is_unverifiable() {
    let name = "bluetooth";
    let mut executor = MockExecutor::new().with_command_exists("systemctl", true);
    // No `list-unit-files` registration for `name`'s unit: execute_command
    // fails outright for that call, distinct from succeeding with a non-zero
    // exit. `is-active`/`is-enabled` are never reached, so neither is mocked.
    for directive in super::super::UNNECESSARY_SERVICES {
        if directive.service_name != name {
            let other_unit = super::super::unit_name(directive.service_name);
            executor =
                executor.with_command("systemctl", &["list-unit-files", &other_unit], absent());
        }
    }
    let ctx = Context::with_executor(Arc::new(executor));

    let rows = service_divergences(&ctx).await;

    assert_eq!(rows.len(), 1, "an unrunnable probe is one row, not silence");
    assert_eq!(rows[0].divergence_subject, "bluetooth");
    assert_eq!(rows[0].divergence_state, DivergenceState::Unverifiable);
}

/// Two units diverging at once are two rows, not one merged row and not a
/// short-circuit after the first: `kernel/divergence.rs` emits one row per
/// parameter, and this probe emits one row per unit the same way.
#[tokio::test]
async fn two_diverging_units_are_two_rows() {
    let unit_a = super::super::unit_name("bluetooth");
    let unit_b = super::super::unit_name("cups");
    let executor = MockExecutor::new()
        .with_command_exists("systemctl", true)
        .with_command(
            "systemctl",
            &["list-unit-files", &unit_a],
            CommandOutput {
                stdout: format!("{unit_a} static\n"),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "bluetooth"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-enabled", "bluetooth"],
            CommandOutput {
                stdout: "disabled\n".to_string(),
                stderr: String::new(),
                exit_code: 1,
            },
        )
        .with_command(
            "systemctl",
            &["list-unit-files", &unit_b],
            CommandOutput {
                stdout: format!("{unit_b} static\n"),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "cups"],
            CommandOutput {
                stdout: "inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 3,
            },
        )
        .with_command(
            "systemctl",
            &["is-enabled", "cups"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["list-unit-files", &super::super::unit_name("avahi-daemon")],
            absent(),
        )
        .with_command(
            "systemctl",
            &["list-unit-files", &super::super::unit_name("ModemManager")],
            absent(),
        )
        .with_command(
            "systemctl",
            &["list-unit-files", &super::super::unit_name("xinetd")],
            absent(),
        );
    let ctx = Context::with_executor(Arc::new(executor));

    let rows = service_divergences(&ctx).await;

    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].divergence_subject, "bluetooth");
    assert_eq!(rows[0].divergence_state, DivergenceState::Diverged);
    assert_eq!(rows[1].divergence_subject, "cups");
    assert_eq!(rows[1].divergence_state, DivergenceState::Diverged);
}

/// `systemctl is-enabled` exits 0 for `static`, `indirect`, `enabled-runtime`,
/// `generated` and `alias`, not only for `enabled` (`ENABLED_STATES` in
/// `services/mod.rs` spells out all seven). A probe that reads the exit
/// status rather than the word turns a `static` unit into `Enablement::Enabled`,
/// and a static unit that is not running then reads as the enabled-but-stopped
/// divergence, which is false: a unit with no `[Install]` section was never
/// claiming to run, so nothing here disagrees with the restored files. The
/// probe must say it cannot tell, not assert a divergence that is not there.
#[tokio::test]
async fn a_static_unit_that_is_not_running_is_unverifiable_not_diverged() {
    let ctx = service_host("bluetooth", "inactive\n", 3, "static\n", 0);

    let rows = service_divergences(&ctx).await;

    assert_eq!(rows.len(), 1, "one subject, one row");
    assert_eq!(rows[0].divergence_subject, "bluetooth");
    assert_eq!(
        rows[0].divergence_state,
        DivergenceState::Unverifiable,
        "a static unit's enablement cannot be read as enabled or not enabled \
         from the word alone, so it must not be asserted as diverged: {}",
        rows[0].divergence_detail
    );
}

/// The conflation the whole branch exists to close: two reads that fail for a
/// non-spawn reason (empty stdout, non-zero exit, no error returned) must not
/// silently agree with each other. Reading the exit status turns this into
/// `NotEnabled` and `NotActive`, which agree and produce an EMPTY vector,
/// claiming the rollback left everything checked out when nothing was
/// actually readable.
#[tokio::test]
async fn unreadable_words_with_agreeing_exit_codes_are_not_silent_agreement() {
    let ctx = service_host("bluetooth", "", 3, "", 1);

    let rows = service_divergences(&ctx).await;

    assert_eq!(
        rows.len(),
        1,
        "two unreadable words must produce a row, not silent agreement"
    );
    assert_eq!(rows[0].divergence_subject, "bluetooth");
    assert_eq!(rows[0].divergence_state, DivergenceState::Unverifiable);
}

/// Proof the probe reads the printed word and not the exit code: every mocked
/// stdout word replaced with `GARBAGE`, exit codes left exactly as a genuine
/// diverged pair would set them (0 for is-active, non-zero for is-enabled,
/// the shape `an_enabled_but_stopped_unit_is_diverged` uses). A probe reading
/// the exit status alone would still call this diverged; this probe must
/// refuse to, because neither printed word says what state the unit is in.
#[tokio::test]
async fn garbage_words_with_diverged_shaped_exit_codes_are_unverifiable() {
    let ctx = service_host("cups", "GARBAGE\n", 0, "GARBAGE\n", 0);

    let rows = service_divergences(&ctx).await;

    assert_eq!(rows.len(), 1, "one subject, one row");
    assert_eq!(rows[0].divergence_subject, "cups");
    assert_eq!(
        rows[0].divergence_state,
        DivergenceState::Unverifiable,
        "GARBAGE is neither a recognised activity nor enablement word: {}",
        rows[0].divergence_detail
    );
}
