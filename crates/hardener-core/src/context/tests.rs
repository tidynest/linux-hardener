#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`context`](super).
//!
//! These sit beside `context.rs` because `SystemInfo`'s detectors,
//! `read_os_release` and `PluginAuditEntry::current_timestamp` are private and
//! `tests/context_tests.rs` cannot reach any of them. That file keeps the
//! public surface.
//!
//! Every detector here reads the host it runs on, so each is checked against a
//! **second, independent way of asking the same question**: a file where the
//! detector used a syscall, the standard library's own constant where it used
//! an environment lookup. Comparing a detector with itself would agree under
//! any constant body, which is exactly what let these survive.

use super::*;

/// A hand-parse of `/etc/os-release`, deliberately not the one under test.
fn raw_os_release() -> Option<Vec<(String, String)>> {
    let content = std::fs::read_to_string("/etc/os-release").ok()?;
    Some(
        content
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(key, value)| (key.to_string(), value.trim_matches('"').to_string()))
            .collect(),
    )
}

/// The audit timestamp is the clock, not a number.
///
/// Every `PluginAuditEntry` carries one, and they are what order an operator's
/// account of what a plugin did. As a constant the whole account collapses onto
/// one instant. Bracketed between two independent readings, since only an
/// independent reference can fail a constant.
#[test]
fn the_audit_entry_timestamp_is_read_from_the_clock() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let seconds = || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the system clock is after the epoch")
            .as_secs()
    };

    let before = seconds();
    let stamped = PluginAuditEntry::current_timestamp();
    let after = seconds();

    assert!(
        (before..=after).contains(&stamped),
        "the stamp must fall between two readings taken either side of it, got \
         {stamped} outside {before}..={after}"
    );
}

/// `/etc/os-release` is parsed into what it actually contains.
///
/// Five constant bodies survived here, an empty map and four single-entry ones,
/// and every plugin that behaves differently per distribution reads the result.
/// An empty map sends `detect_distribution` to its "Unknown Distribution"
/// fallback, so a Debian host is hardened as though its family were unknown.
///
/// The key count is what fails all five at once: any real `/etc/os-release`
/// carries more than one assignment. The value check is what stops a parser
/// that split on the wrong character passing the count.
#[test]
fn os_release_is_parsed_into_every_assignment_the_file_holds() {
    let Some(raw) = raw_os_release() else {
        eprintln!("unaskable: this host has no /etc/os-release");
        return;
    };
    assert!(
        raw.len() > 1,
        "the fixture is the host's own file and must carry several assignments \
         for the count below to mean anything, got {}",
        raw.len()
    );

    let parsed = SystemInfo::read_os_release().expect("the file exists, so it parses");
    assert_eq!(
        parsed.len(),
        raw.len(),
        "every assignment in the file must reach the map, or a plugin reads a \
         distribution that is not the one it is running on"
    );

    let (key, value) = raw.first().expect("at least one assignment");
    assert_eq!(
        parsed.get(key).map(|held| held.trim_matches('"')),
        Some(value.as_str()),
        "and `{key}` must carry the value the file gives it"
    );
}

/// Each detector agrees with a source that is not itself.
///
/// All five survived being replaced by `Ok("xyzzy")`. They are what
/// `SystemInfo` hands every plugin, so a constant distribution turns
/// distribution-specific hardening into a coin flip, and a constant kernel
/// version defeats every version-gated check.
#[test]
fn every_system_detector_agrees_with_an_independent_reading() {
    assert_eq!(
        SystemInfo::detect_architecture().expect("architecture"),
        std::env::consts::ARCH,
        "the architecture is the one this binary was built for"
    );

    // /proc/sys/kernel/osrelease is the file; `uname(2)` is the syscall the
    // detector uses. Two mechanisms, one answer.
    if let Ok(from_proc) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        assert_eq!(
            SystemInfo::detect_kernel_version().expect("kernel version"),
            from_proc.trim(),
            "uname and /proc must name the same kernel"
        );
    }

    if let Ok(from_proc) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        assert_eq!(
            SystemInfo::detect_hostname().expect("hostname"),
            from_proc.trim(),
            "the hostname syscall and /proc must name the same host"
        );
    }

    let Some(raw) = raw_os_release() else {
        eprintln!(
            "unaskable: this host has no /etc/os-release, so the two \
                   distribution detectors cannot be checked against it"
        );
        return;
    };
    let field = |name: &str| {
        raw.iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };

    // Written without a conditional on purpose. Guarding these on the field
    // being present made the version half vacuous on the machine this was
    // developed on: Arch is rolling and its `/etc/os-release` carries no
    // `VERSION_ID`, so the assertion never ran and the mutation runner reported
    // the survivor still alive. The documented fallback is part of the contract,
    // so it is asserted rather than skipped, and the case runs on every host.
    assert_eq!(
        SystemInfo::detect_distribution().expect("distribution"),
        field("ID")
            .or_else(|| field("NAME"))
            .unwrap_or_else(|| "Unknown Distribution".to_string()),
        "the distribution is ID, or NAME where the file gives no ID, or the \
         stated fallback where it gives neither"
    );
    assert_eq!(
        SystemInfo::detect_distribution_version().expect("version"),
        field("VERSION_ID")
            .or_else(|| field("VERSION"))
            .unwrap_or_else(|| "Unknown Distribution Version".to_string()),
        "and the version is VERSION_ID, or VERSION, or the stated fallback"
    );
}

async fn a_checkpoint_manager() -> CheckpointManager {
    let dir = tempfile::tempdir().expect("tempdir");
    let pool = hardener_state::init_db(Some(&dir.path().join("ctx.db")))
        .await
        .expect("init_db");
    let signer = hardener_state::CheckpointSigner::new_with_path(&dir.path().join("ctx.key"))
        .expect("signer");
    std::mem::forget(dir);
    CheckpointManager::new_with_signer(pool, signer).expect("manager")
}

/// Every way of attaching a checkpoint manager actually attaches it.
///
/// Two builders survived being replaced by `Default::default()` and the setter
/// survived being replaced by nothing, all three discarding the manager they
/// were handed; the accessor survived returning `None`, which hides one that
/// was attached. Either way `checkpoint_manager()` answers `None`, and a
/// plugin that finds none takes no checkpoint: an apply proceeds with nothing
/// to roll back to, and reports success.
///
/// The `with_executor_and_checkpoint` case also asserts the executor, because
/// `Default::default()` discards both and an assertion on the manager alone
/// would leave half the builder unpinned.
#[tokio::test]
async fn a_context_keeps_the_checkpoint_manager_it_was_given() {
    let built = Context::with_checkpoint_manager(a_checkpoint_manager().await);
    assert!(
        built.checkpoint_manager().is_some(),
        "the builder must keep what it was handed, or an apply runs with \
         nothing to roll back to and still reports success"
    );

    let remote: Arc<dyn SystemExecutor> = Arc::new(
        hardener_common::executor::MockExecutor::new()
            .remote()
            .with_description("root@web-01:22"),
    );
    let both = Context::with_executor_and_checkpoint(remote, a_checkpoint_manager().await);
    assert!(
        both.checkpoint_manager().is_some(),
        "and so must the builder that takes both"
    );
    assert!(
        both.executor().is_remote(),
        "which must also keep the executor, or a remote apply silently runs \
         against the controller"
    );

    let mut set_afterwards = Context::new();
    assert!(
        set_afterwards.checkpoint_manager().is_none(),
        "the control: a fresh context has none"
    );
    set_afterwards.set_checkpoint_manager(a_checkpoint_manager().await);
    assert!(
        set_afterwards.checkpoint_manager().is_some(),
        "and the setter attaches one"
    );
}

/// The audit logger is kept, and the in-memory audit log records what it is
/// given.
///
/// `set_audit_logger` survived being replaced by nothing and `audit_logger`
/// survived returning `None`, either of which silently drops persistent audit
/// logging for the whole run. `log_audit` survived being replaced by `Ok(())`,
/// which reports every entry as recorded while recording none.
#[tokio::test]
async fn a_context_keeps_its_audit_logger_and_records_what_it_is_told() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log_path = dir.path().join("audit.log");
    let logger = hardener_state::AuditLogger::new(log_path.to_str().expect("utf-8 path"))
        .await
        .expect("logger");

    let mut context = Context::new();
    assert!(
        context.audit_logger().is_none(),
        "the control: a fresh context has no persistent logger"
    );
    context.set_audit_logger(logger);
    assert!(
        context.audit_logger().is_some(),
        "the setter must attach it, or the run keeps no persistent audit trail \
         and nothing says so"
    );

    context
        .log_audit(PluginAuditEntry::new(
            "ssh-hardening",
            AuditOperation::Apply,
            "PermitRootLogin set to no",
            true,
        ))
        .expect("recording an entry does not fail");

    let recorded = context.audit_log.read().expect("audit log lock");
    assert_eq!(
        recorded.len(),
        1,
        "the entry must actually be held, not merely reported as held"
    );
    assert_eq!(
        recorded[0].entry_description, "PermitRootLogin set to no",
        "and it must be the entry that was given"
    );
}
