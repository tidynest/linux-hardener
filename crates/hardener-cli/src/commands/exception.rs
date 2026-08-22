//! `hardener exception`: author a policy exception from the finding that needs
//! one.
//!
//! The exception itself is not new. Every plugin has honoured
//! [`PolicyException`] at apply for as long as one could be written, and a
//! declined one has reported itself since the exception-not-applied work. What
//! was missing is a way to write one without hand-editing a root-owned file
//! whose check ids nothing in the interface names.

pub mod document;

use anyhow::{Result, anyhow};
use hardener_compliance::OutputFormat;
use hardener_core::executor::SystemExecutor;
use hardener_core::{Context, Finding, HardenerConfig, PolicyException};
use hardener_state::audit::{ActionResult, ActionType, AuditLogger};
use hardener_types::PluginId;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Where an exception is written when `--config` names nothing.
///
/// Not a choice. `ConfigLoader::load` skips the user config when running as
/// root (`crates/hardener-core/src/config_loader.rs:61`), and apply runs as
/// root, so an exception written under `~/.config` would be shown by the
/// desktop and ignored by the apply it was created to change.
///
/// `hardener scope` writes the same file for the same reason, which is why the
/// three helpers below are `pub(crate)` rather than private.
const SYSTEM_CONFIG_PATH: &str = "/etc/linux-hardener/config.toml";

pub struct AddOptions<'a> {
    pub plugin_id: &'a str,
    pub key: &'a str,
    pub reason: &'a str,
    pub approved_by: Option<&'a str>,
    pub ticket: Option<&'a str>,
    pub expires: Option<&'a str>,
    pub config_path: Option<&'a PathBuf>,
    pub format: OutputFormat,
    pub quiet: bool,
    pub executor: Arc<dyn SystemExecutor>,
}

pub struct RemoveOptions<'a> {
    pub plugin_id: &'a str,
    pub key: &'a str,
    pub config_path: Option<&'a PathBuf>,
    pub format: OutputFormat,
    pub quiet: bool,
}

/// The finding this key names, or a refusal naming the key.
///
/// Separated from `add` so the match rule is testable without a host: it is the
/// step that decides both what value is pinned and whether a key reaching this
/// binary over IPC is one the host itself produced.
///
/// Takes the first match, which is not always the only one: the kernel plugin
/// emits two findings under one exception key for a parameter overridden after
/// boot, the runtime value (`kernel/mod.rs`) and the boot-override value
/// (`kernel/persistence.rs`), and the two can disagree. The runtime finding is
/// built first and wins here, which is right for apply, since apply reads the
/// runtime value too. It is not right for an operator who clicked Accept on the
/// boot-override row: the exception pins the runtime value instead of the one
/// they were looking at, and the next scan can report that row as
/// `ValueMismatch` even though the operator accepted what they saw.
pub fn pin_from_findings<'a>(findings: &'a [Finding], key: &str) -> Result<&'a Finding> {
    findings
        .iter()
        .find(|f| f.finding_exception_key.as_deref() == Some(key))
        .ok_or_else(|| {
            anyhow!(
                "No live finding is keyed '{key}'. Run `hardener scan` and use the \
                 key it prints beside the finding you want to accept."
            )
        })
}

/// An [`AuditLogger`] writing the named path, for tests only.
///
/// The audit log a command writes is otherwise chosen by uid
/// (`super::state::audit_logger`), root's under `/var/log` and everyone else's
/// under `$XDG_DATA_HOME`. Neither is a path a test may write, so a test that
/// wants to read back what was filed needs to name its own. `scope` takes the
/// same seam for the same reason; it lives here because this is where
/// [`WriteAudit`] lives.
#[cfg(test)]
pub(crate) async fn logger_at(audit_log_path: &str) -> Option<AuditLogger> {
    match AuditLogger::new(audit_log_path).await {
        Ok(logger) => Some(logger),
        Err(e) => {
            tracing::warn!("audit logging unavailable at {audit_log_path}: {e}");
            None
        }
    }
}

/// Refuses a malformed `--expires`, scans `plugin_id` to pin the value the
/// host has right now, and writes the exception.
pub async fn add(opts: AddOptions<'_>) -> Result<()> {
    add_with_logger(opts, super::state::get_audit_logger().await).await
}

/// [`add`] with the audit log named, so a test writes neither root's log nor
/// the invoking user's.
#[cfg(test)]
pub(crate) async fn add_at(opts: AddOptions<'_>, audit_log_path: &str) -> Result<()> {
    add_with_logger(opts, logger_at(audit_log_path).await).await
}

async fn add_with_logger(opts: AddOptions<'_>, logger: Option<AuditLogger>) -> Result<()> {
    if let Some(expires) = opts.expires {
        parse_expiry(expires)?;
    }
    let section = section_for(opts.plugin_id)?;
    let config = super::config_loader(opts.config_path)
        .load()
        .map_err(|e| anyhow!("Config error: {e}"))?;

    let registry = hardener_plugins::create_plugin_registry();
    let plugin = registry
        .get(&PluginId::new(opts.plugin_id))?
        .ok_or_else(|| anyhow!("Unknown plugin '{}'.", opts.plugin_id))?;
    let ctx = Context::with_executor(opts.executor.clone());
    let scan = plugin
        .scan(&ctx, config.get_plugin_config(opts.plugin_id))
        .await?;

    let finding = pin_from_findings(&scan.scan_findings, opts.key)?;

    let exception = PolicyException {
        value: finding.finding_current_value.clone(),
        allowed: true,
        reason: opts.reason.to_string(),
        approved_by: opts.approved_by.map(str::to_string),
        approved_date: None,
        ticket: opts.ticket.map(str::to_string),
        expires: opts.expires.map(str::to_string),
    };

    let path = write_path(opts.config_path.map(PathBuf::as_path));
    let existing = read_or_empty(&path)?;
    let written = document::upsert_exception(&existing, section, opts.key, &exception)?;
    write_atomically(
        &path,
        &written,
        WriteAudit {
            logger: logger.as_ref(),
            action: ActionType::ConfigChange,
            target: format!("{section}:{}", opts.key),
            details: exception_details(&exception),
        },
    )
    .await?;

    let written_exception = hardener_types::WrittenException {
        section: section.to_string(),
        key: opts.key.to_string(),
        value: exception.value.clone(),
        reason: exception.reason.clone(),
        approved_by: exception.approved_by.clone(),
        ticket: exception.ticket.clone(),
        expires: exception.expires.clone(),
    };
    report_add(opts.format, opts.quiet, &written_exception, &path);
    Ok(())
}

pub async fn remove(opts: RemoveOptions<'_>) -> Result<()> {
    remove_with_logger(opts, super::state::get_audit_logger().await).await
}

/// [`remove`] with the audit log named. Tests only, as [`add_at`].
#[cfg(test)]
pub(crate) async fn remove_at(opts: RemoveOptions<'_>, audit_log_path: &str) -> Result<()> {
    remove_with_logger(opts, logger_at(audit_log_path).await).await
}

async fn remove_with_logger(opts: RemoveOptions<'_>, logger: Option<AuditLogger>) -> Result<()> {
    let section = section_for(opts.plugin_id)?;
    let path = write_path(opts.config_path.map(PathBuf::as_path));
    let existing = read_or_empty(&path)?;
    let written = document::remove_exception(&existing, section, opts.key)?;
    // No copy of what was withdrawn. `remove` is given a key, not an exception,
    // and reading the table back to name the fields would describe the document
    // rather than the act. The `add` entry for the same target already carries
    // them, and the two are what an auditor reads together.
    write_atomically(
        &path,
        &written,
        WriteAudit {
            logger: logger.as_ref(),
            action: ActionType::ConfigChange,
            target: format!("{section}:{}", opts.key),
            details: HashMap::from([("operation".to_string(), "remove".to_string())]),
        },
    )
    .await?;

    report_remove(&opts, section, &path);
    Ok(())
}

/// The audit detail for an exception write.
///
/// Everything the exception carries, because these are the fields an auditor
/// gets months later with no access to whoever ran the command and no
/// guarantee that the `config.toml` they can read still says what it said on
/// the day. An entry naming only the key would need that file to mean
/// anything, and the file is exactly what an exception changes.
///
/// `reason` is unbounded operator text and goes in whole. It is the one field
/// that makes the deviation defensible rather than arbitrary, so truncating it
/// would drop the part worth keeping. It sits inside the hash, because a
/// success entry goes through `log_action_with_details`; only the failure path
/// is held to a single `error` detail. See [`WriteAudit::record`].
fn exception_details(exception: &PolicyException) -> HashMap<String, String> {
    let mut details = HashMap::from([
        ("operation".to_string(), "add".to_string()),
        ("reason".to_string(), exception.reason.clone()),
        ("value".to_string(), exception.value.clone()),
        ("allowed".to_string(), exception.allowed.to_string()),
    ]);
    // Written only when there is something to say, as `scope` builds its own
    // optional details: an absent ticket and an empty one are different claims,
    // and the entry that asserts neither is the honest one.
    for (key, field) in [
        ("approved_by", &exception.approved_by),
        ("approved_date", &exception.approved_date),
        ("ticket", &exception.ticket),
        ("expires", &exception.expires),
    ] {
        if let Some(text) = field {
            details.insert(key.to_string(), text.clone());
        }
    }
    details
}

/// Refuses an `--expires` value [`PolicyException::is_expired`] cannot parse.
///
/// That method treats an unparseable date as "never expires"
/// (`crates/hardener-core/src/config.rs:346`), so writing one silently fails
/// open in the one field whose purpose is to bound a deviation in time. Parsed
/// here, before anything is written, using the same `%Y-%m-%d` format so a
/// value that passes here is one `is_expired` can also read.
fn parse_expiry(expires: &str) -> Result<()> {
    chrono::NaiveDate::parse_from_str(expires, "%Y-%m-%d").map_err(|_| {
        anyhow!(
            "--expires '{expires}' is not a valid date. Use YYYY-MM-DD, for example 2027-01-31."
        )
    })?;
    Ok(())
}

/// The `config.toml` section a plugin's exceptions live under, which is not its
/// plugin id: the services plugin declares `service-minimisation` and is
/// configured under `[services]`.
fn section_for(plugin_id: &str) -> Result<&'static str> {
    HardenerConfig::config_section(plugin_id).ok_or_else(|| {
        anyhow!(
            "Unknown plugin id '{plugin_id}'. Run `hardener plugins` for the ids \
             this binary carries."
        )
    })
}

pub(crate) fn write_path(config_path: Option<&Path>) -> PathBuf {
    config_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(SYSTEM_CONFIG_PATH))
}

/// A config file that does not exist yet is an empty document, not an error:
/// the first exception on a host may be the first line of its config.
pub(crate) fn read_or_empty(path: &Path) -> Result<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(anyhow!("Cannot read {}: {e}", path.display())),
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
pub(crate) struct WriteAudit<'a> {
    /// `None` when the log could not be opened, which is what
    /// [`super::state::get_audit_logger`] returns on a host whose log directory
    /// is unwritable. Not an opt-out: that host still has to be hardenable, and
    /// the operator has already been told on stderr by the time this is `None`.
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
        let user = super::state::effective_user();
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
            eprintln!("W  The audit entry for this change failed: {e}");
        }
    }
}

/// Writes the config and files the audit entry the caller described.
///
/// The two are one call because they were two habits, and only two of the four
/// call sites had acquired the second: `scope exclude` and `scope include`
/// audited, `exception add` and `exception remove` wrote the same file under
/// the same privilege and left no trace. Nothing was wrong with the writer.
/// What was missing was any reason a fifth caller would audit either.
pub(crate) async fn write_atomically(
    path: &Path,
    contents: &str,
    audit: WriteAudit<'_>,
) -> Result<()> {
    let outcome = write_file_atomically(path, contents);
    audit.record(&outcome).await;
    outcome
}

/// Write to a sibling temporary file and rename over the target, so an
/// interrupted write cannot leave a half-written config that root then fails to
/// parse on the next scan.
///
/// Split from [`write_atomically`] so the filesystem behaviour stays a
/// synchronous function with no logger in it: the mode-preservation and
/// new-file tests exercise exactly this and need neither a runtime nor an
/// audit log to say what they say.
fn write_file_atomically(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow!("Cannot create {}: {e}", parent.display()))?;
    }
    let temporary = path.with_extension("toml.new");
    std::fs::write(&temporary, contents)
        .map_err(|e| anyhow!("Cannot write {}: {e}", temporary.display()))?;

    // A rename over an existing file carries the temporary file's own mode,
    // not the target's: without this, whatever mode the operator set on
    // config.toml is silently replaced by root's umask default the moment an
    // exception is written. A target that does not exist yet has no mode to
    // preserve, so a fresh file keeps the default.
    if let Ok(existing) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(&temporary, existing.permissions());
    }

    std::fs::rename(&temporary, path).map_err(|e| {
        // The rename failed, so the temporary file is not the config: leaving
        // it behind would litter root's config directory with a `.toml.new`
        // for every failed write. Best-effort, since the write itself already
        // failed and this is cleanup rather than the operation the caller asked for.
        let _ = std::fs::remove_file(&temporary);
        anyhow!("Cannot replace {}: {e}", path.display())
    })
}

/// Reports what `add` wrote, serialising from the same [`hardener_types::WrittenException`]
/// the Tauri command and the Leptos front end use, so a renamed field fails to
/// compile here rather than silently stopping arriving in the GUI.
///
/// `path` is not part of that shared struct: it names where the write landed,
/// not what was written, so it is appended to the serialised object rather than
/// carried on the type.
fn report_add(
    format: OutputFormat,
    quiet: bool,
    written: &hardener_types::WrittenException,
    path: &Path,
) {
    if matches!(format, OutputFormat::Json) {
        let mut payload =
            serde_json::to_value(written).expect("WrittenException always serialises");
        if let serde_json::Value::Object(ref mut map) = payload {
            map.insert(
                "path".to_string(),
                serde_json::Value::String(path.display().to_string()),
            );
        }
        println!("{payload}");
        return;
    }
    if !quiet {
        println!(
            "Accepted '{}' in [{}.exceptions] at value '{}'. Written to {}.",
            written.key,
            written.section,
            written.value,
            path.display()
        );
    }
}

fn report_remove(opts: &RemoveOptions<'_>, section: &str, path: &Path) {
    if matches!(opts.format, OutputFormat::Json) {
        let payload = serde_json::json!({
            "section": section,
            "key": opts.key,
            "removed": true,
            "path": path.display().to_string(),
        });
        println!("{payload}");
        return;
    }
    if !opts.quiet {
        println!(
            "Removed '{}' from [{section}.exceptions] in {}.",
            opts.key,
            path.display()
        );
    }
}

#[cfg(test)]
mod tests;
