//! The one way this project writes a configuration file, and the one place it
//! decides where this host's audit trail lives.
//!
//! **Why a shared module rather than a helper in the CLI.** Four commands write
//! `/etc/linux-hardener/config.toml`, three more write user-scope state from the
//! desktop backend, and until this module existed the two groups could not share
//! a writer at all: `hardener-cli` is a binary, so nothing may depend on it. The
//! desktop's own writes were therefore unaudited and non-atomic, not by decision
//! but because the code that would have made them otherwise was unreachable.
//!
//! **Auditing is not optional here.** [`write_atomically`] takes a [`WriteAudit`]
//! and files the entry itself, so a caller cannot write a config file without
//! saying what to record. That is deliberate: before it, auditing was a habit
//! that some callers had and others did not, and the ones that did not were
//! writing the same file under the same privilege.
//!
//! **Where the entry lands is chosen by uid, once, in [`audit_logger`].** Root
//! writes `/var/log/linux-hardener/audit.log` in a `0700` directory; everyone
//! else writes `$XDG_DATA_HOME/linux-hardener/audit.log`. A user-scope change
//! therefore lands in a per-user chain that an auditor reading the host's log
//! will not see. That is a real limit of a desktop application that does not
//! escalate to change its own settings, and it is recorded in
//! `docs/reference/what-is-not-proven.md` rather than papered over.

use anyhow::{Context as _, Result, anyhow};
use hardener_state::audit::{ActionResult, ActionType, AuditLogger};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Root audit log directory for privileged operations.
const SYSTEM_LOG_DIR: &str = "/var/log/linux-hardener";

/// Returns the effective username for audit logging.
pub fn effective_user() -> String {
    nix::unistd::User::from_uid(nix::unistd::getuid())
        .ok()
        .flatten()
        .map(|user| user.name)
        .unwrap_or_else(|| format!("uid:{}", nix::unistd::getuid()))
}

/// Opens an [`AuditLogger`] writing `audit.log` under `dir`, creating the
/// directory (and restricting it to `mode`, when given) first.
///
/// Taking the directory as an argument is what makes this assertable: the
/// caller's own is absolute and privileged, so nothing unprivileged can
/// exercise it.
///
/// Every failure carries the path it was working on, because "audit logging
/// unavailable" with no location is not actionable.
async fn audit_logger_in(dir: &Path, mode: Option<u32>) -> Result<AuditLogger> {
    fs::create_dir_all(dir)
        .with_context(|| format!("creating audit log directory {}", dir.display()))?;
    if let Some(mode) = mode {
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(mode));
    }

    let path = dir.join("audit.log");
    AuditLogger::new(&path.to_string_lossy())
        .await
        .with_context(|| format!("opening audit log {}", path.display()))
}

/// Creates an [`AuditLogger`] at the appropriate path.
///
/// Root: `/var/log/linux-hardener/audit.log` (0700 directory)
/// Non-root: `$XDG_DATA_HOME/linux-hardener/audit.log`
pub async fn audit_logger() -> Result<AuditLogger> {
    if nix::unistd::getuid().is_root() {
        audit_logger_in(Path::new(SYSTEM_LOG_DIR), Some(0o700)).await
    } else {
        // The user data directory holds more than this log, so its mode is
        // left to whatever created it.
        let dir = dirs::data_local_dir()
            .map(|p| p.join("linux-hardener"))
            .unwrap_or_else(|| PathBuf::from(".linux-hardener"));
        audit_logger_in(&dir, None).await
    }
}

/// The audit logger, or `None` after telling the operator there will be no
/// audit trail.
///
/// Callers continue without one: refusing to harden a host because its log
/// directory is unwritable would be the worse failure. What must not happen is
/// the earlier behaviour, where every failure folded to `None` and a privileged
/// `apply`, `checkpoint` or `batch` ran with the audit trail silently absent.
/// The notice goes to stderr so `--format json` stdout stays parseable.
pub async fn get_audit_logger() -> Option<AuditLogger> {
    match audit_logger().await {
        Ok(logger) => Some(logger),
        Err(e) => {
            tracing::warn!("audit logging unavailable: {e:#}");
            eprintln!("⚠  Audit logging unavailable: {e:#}");
            eprintln!("   This operation will not be recorded in the audit trail.");
            None
        }
    }
}

/// An [`AuditLogger`] writing the named path.
///
/// **For tests.** The log a command writes is otherwise chosen by uid in
/// [`audit_logger`], and neither answer is a path a test may write, so a test
/// that wants to read back what was filed has to name its own. Shipping code
/// goes through [`get_audit_logger`]: a second production answer to where this
/// host's audit trail lives is exactly what this module exists to prevent.
///
/// Not feature-gated, because `AuditLogger::new` is public anyway and a gate
/// here would buy a build configuration rather than a guarantee.
pub async fn logger_at(audit_log_path: &str) -> Option<AuditLogger> {
    match AuditLogger::new(audit_log_path).await {
        Ok(logger) => Some(logger),
        Err(e) => {
            tracing::warn!("audit logging unavailable at {audit_log_path}: {e}");
            None
        }
    }
}

/// What an audit entry for a config write says.
///
/// Supplied by the caller because only the caller knows which policy act the
/// write serves: the same bytes reaching the same file are a `ConfigChange`
/// under `exception` and a `ScopeExclusion` under `scope`, and an auditor
/// filtering the second must not have the first mixed into it. That is the
/// whole reason [`ActionType::ScopeExclusion`] exists as a variant of its own
/// (`crates/hardener-state/src/audit.rs:44`).
///
/// A struct rather than four arguments so a new caller cannot satisfy the
/// signature by passing whatever happens to be in scope. Every part is named.
pub struct WriteAudit<'a> {
    /// `None` when the log could not be opened, which is what
    /// [`get_audit_logger`] returns on a host whose log directory is
    /// unwritable. Not an opt-out: that host still has to be usable, and the
    /// operator has already been told on stderr by the time this is `None`.
    pub logger: Option<&'a AuditLogger>,
    pub action: ActionType,
    pub target: String,
    pub details: HashMap<String, String>,
}

impl WriteAudit<'_> {
    /// Files the entry once the write has resolved, never before: an entry
    /// logged ahead of the rename claims a change that may not have landed.
    ///
    /// A logging failure never fails the write. The bytes are already in the
    /// file, and reporting the write as failed would be the worse lie. It is
    /// said out loud, though, because an operator who believes the act was
    /// recorded and finds nothing at the audit is in a worse position than one
    /// who was told.
    async fn record(self, outcome: &Result<()>) {
        let Some(logger) = self.logger else {
            return;
        };
        let user = effective_user();
        let filed = match outcome {
            Ok(()) => {
                logger
                    .log_action_with_details(
                        self.action,
                        user,
                        self.target,
                        ActionResult::Success,
                        self.details,
                    )
                    .await
            }
            // `log_failure`, not `log_action_with_details`.
            // [`AuditLogger::verify_integrity`] verifies a failure entry through
            // a branch of its own that hashes the single `error` detail and
            // nothing else (`crates/hardener-state/src/audit.rs:507`), so any
            // further detail written on a failure entry would sit outside the
            // hash chain and could be altered without detection. The cause
            // therefore goes into the message, which is hashed, and the target
            // is hashed either way.
            Err(e) => {
                logger
                    .log_failure(self.action, user, self.target, format!("{e:#}"))
                    .await
            }
        };
        if let Err(e) = filed {
            tracing::warn!("a config write was not audited: {e}");
            eprintln!("⚠  The audit entry for this change failed: {e}");
        }
    }
}

/// Writes the config and files the audit entry the caller described.
///
/// The two are one call because they were two habits, and only some callers had
/// acquired the second. Nothing was ever wrong with the writer. What was missing
/// was any reason a new caller would audit at all.
pub async fn write_atomically(path: &Path, contents: &str, audit: WriteAudit<'_>) -> Result<()> {
    let outcome = write_file_atomically(path, contents);
    audit.record(&outcome).await;
    outcome
}

/// Removes `path` if it is there, and files the audit entry the caller
/// described.
///
/// Answers whether the file was present, which is not the same question as
/// whether the call succeeded: uninstalling something that was never installed
/// is a success that removed nothing, and an entry saying so is worth more than
/// one implying a removal happened.
///
/// **Taking a file away is a change to host state exactly as writing one is**,
/// and it is the direction that reports itself least: a scheduled scan that
/// stops running produces no failure, no finding and no output at all. So it
/// takes the same mandatory descriptor [`write_atomically`] does.
///
/// `try_exists`, not `exists`. The latter is `metadata(..).is_ok()` and answers
/// `false` for a file this process may not stat, which would record a
/// successful removal that never touched anything.
pub async fn remove_file_audited(path: &Path, audit: WriteAudit<'_>) -> Result<bool> {
    let outcome = remove_if_present(path);
    // The descriptor's `record` takes the shape every write reports, so the
    // presence answer is set aside for the caller and only success or failure
    // reaches the log.
    audit
        .record(&outcome.as_ref().map(|_| ()).map_err(|e| anyhow!("{e:#}")))
        .await;
    outcome
}

/// Deletes `path` when it is there, answering whether it was.
fn remove_if_present(path: &Path) -> Result<bool> {
    let present = path
        .try_exists()
        .map_err(|e| anyhow!("Cannot check for {}: {e}", path.display()))?;
    if !present {
        return Ok(false);
    }
    std::fs::remove_file(path).map_err(|e| anyhow!("Cannot remove {}: {e}", path.display()))?;
    Ok(true)
}

/// The sibling temporary file a write to `path` goes through first.
///
/// Appended to the whole file name rather than replacing the extension. This
/// used to be `path.with_extension("toml.new")`, which was right for the only
/// two files that then existed and wrong in general twice over. It named a
/// `.service` file's temporary `linux-hardener.toml.new`, and, because it
/// replaces the extension rather than adding to it, every file sharing a stem
/// in one directory mapped to the same temporary path:
/// `linux-hardener.service` and `linux-hardener.timer` both became
/// `linux-hardener.toml.new`. The unit writes are sequential, so nothing was
/// corrupted, but the collision was one concurrent caller away from being real.
///
/// `config.toml` is unaffected either way: replacing `.toml` with `.toml.new`
/// and appending `.new` both give `config.toml.new`.
fn temporary_beside(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".new");
    path.with_file_name(name)
}

/// Write to a sibling temporary file and rename over the target, so an
/// interrupted write cannot leave a half-written file that the next reader
/// fails to parse.
///
/// Split from [`write_atomically`] so the filesystem behaviour stays a
/// synchronous function with no logger in it: the mode-preservation and
/// new-file tests exercise exactly this and need neither a runtime nor an
/// audit log to say what they say. Private, so the split cannot become a way
/// to write host state without recording it: every caller outside this module
/// goes through [`write_atomically`] and supplies a descriptor.
fn write_file_atomically(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow!("Cannot create {}: {e}", parent.display()))?;
    }
    let temporary = temporary_beside(path);
    std::fs::write(&temporary, contents)
        .map_err(|e| anyhow!("Cannot write {}: {e}", temporary.display()))?;

    // A rename over an existing file carries the temporary file's own mode,
    // not the target's: without this, whatever mode the operator set on
    // config.toml is silently replaced by the writer's umask default the moment
    // an exception is written. A target that does not exist yet has no mode to
    // preserve, so a fresh file keeps the default.
    if let Ok(existing) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(&temporary, existing.permissions());
    }

    std::fs::rename(&temporary, path).map_err(|e| {
        // The rename failed, so the temporary file is not the target: leaving
        // it behind would litter the directory with a `.new` for every failed
        // write. Best-effort, since the write itself already failed and this is
        // cleanup rather than the operation the caller asked for.
        let _ = std::fs::remove_file(&temporary);
        anyhow!("Cannot replace {}: {e}", path.display())
    })
}

/// A config file that does not exist yet is an empty document, not an error:
/// the first exception on a host may be the first line of its config.
pub fn read_or_empty(path: &Path) -> Result<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(anyhow!("Cannot read {}: {e}", path.display())),
    }
}

#[cfg(test)]
mod tests;
