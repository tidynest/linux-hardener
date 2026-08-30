use hardener_common::types::{ComplianceFramework, ComplianceProfile};
use hardener_compliance::{
    ComplianceReport, OutputFormat, ReportConfig, ReportGenerator, Scenario,
    output::{
        CsvFormatter, HtmlFormatter, JsonFormatter, PdfFormatter, ReportFormatter, TextFormatter,
    },
    resolve_profile,
};
use hardener_core::config::scope::ComplianceConfig;
use hardener_core::config_write::{WriteAudit, get_audit_logger, write_atomically};
use hardener_core::{
    ApplyResult, ConfigLoader, Context, Finding, HardenerConfig, PluginConfig, PluginMetadata,
    ScanResult, UncheckedCheck, ValidationReport,
};
use hardener_distro::Distribution;
use hardener_plugins::create_plugin_registry;
use hardener_state::audit::ActionType;
use hardener_state::{
    Checkpoint, CheckpointId, CheckpointManager, CheckpointSigner, FileState, RollbackResult,
    ScanHistoryManager, ScanSession, ScanSessionId, ScanStatus, init_db,
};
use hardener_types::{
    ApplyOutcome, CheckpointDetail, CheckpointFileInfo, CheckpointInfo, CheckpointList,
    ConfigSummary, ControlOutcome, FleetFrameworkPosture, FleetHostScan, FleetHostStatus, PluginId,
    RollbackOutcome, ScanSessionInfo, SeverityTallies, SkipReason, plugin_id_named_by,
    remote::{
        FLEET_PROGRESS_EVENT, FleetProgress, HostSessionInfo, HostsConfig, RemoteConnectionStatus,
        RemoteHostProfile,
    },
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::process::Command;
use tracing::error;

/// Strips internal filesystem paths from error messages before sending to the GUI.
///
/// Replaces absolute paths with generic descriptions to avoid leaking
/// system architecture details to the frontend (CWE-209).
fn sanitise_error(msg: &str) -> String {
    // Replace common internal paths with safe descriptions
    let sanitised = msg
        .replace("/etc/linux-hardener/", "[config]/")
        .replace("/var/lib/linux-hardener/", "[data]/")
        .replace("/var/log/linux-hardener/", "[log]/");

    // Strip remaining absolute paths (keep the basename for context)
    let mut result = String::with_capacity(sanitised.len());
    let mut i = 0;
    let chars: Vec<char> = sanitised.chars().collect();
    while i < chars.len() {
        if chars[i] == '/' && i + 1 < chars.len() && chars[i + 1].is_alphanumeric() {
            // Scan ahead to end of path
            let start = i;
            let mut last_slash = i;
            let mut j = i + 1;
            while j < chars.len() && (chars[j].is_alphanumeric() || "/-_.".contains(chars[j])) {
                if chars[j] == '/' {
                    last_slash = j;
                }
                j += 1;
            }
            // Only replace multi-segment absolute paths (at least 2 slashes)
            if last_slash > start {
                let basename = &sanitised[last_slash + 1..j];
                result.push_str(basename);
            } else {
                result.push_str(&sanitised[start..j]);
            }
            i = j;
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }
    result
}

/// Wraps an error into a sanitised string safe for the GUI frontend.
fn safe_err(e: impl std::fmt::Display) -> String {
    sanitise_error(&e.to_string())
}

/// Minimum seconds between consecutive privileged operations.
const PRIVILEGED_OP_COOLDOWN_SECS: u64 = 5;

/// Prevents concurrent privileged operations (apply, rollback, checkpoint
/// create/delete). Only one pkexec subprocess may run at a time.
static PRIVILEGED_OP_RUNNING: AtomicBool = AtomicBool::new(false);

/// Unix timestamp (seconds) when the last privileged operation completed.
static PRIVILEGED_OP_LAST_COMPLETED: AtomicU64 = AtomicU64::new(0);

/// RAII guard that enforces both mutual exclusion and rate limiting
/// for privileged operations.
struct PrivilegedOpGuard;

impl PrivilegedOpGuard {
    fn acquire() -> Result<Self, String> {
        // Enforce cooldown since last completed operation
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let last = PRIVILEGED_OP_LAST_COMPLETED.load(Ordering::SeqCst);
        let elapsed = now.saturating_sub(last);
        if last > 0 && elapsed < PRIVILEGED_OP_COOLDOWN_SECS {
            return Err(format!(
                "Rate limit: please wait {} seconds before the next privileged operation.",
                PRIVILEGED_OP_COOLDOWN_SECS - elapsed
            ));
        }

        // Enforce mutual exclusion
        PRIVILEGED_OP_RUNNING
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| {
                "Another privileged operation is already in progress. Please wait.".to_string()
            })?;
        Ok(Self)
    }
}

/// Starts the cooldown. Called where a privileged subprocess actually ran.
///
/// Not from the guard's `Drop`, which is where it used to be. Every command
/// takes the guard before it validates its arguments, so arming on drop paced
/// the next privileged operation after a mistyped plugin name, an id in neither
/// checkpoint database, or any other refusal that raised no authentication
/// prompt at all. The limit exists to pace prompts, so it begins when one has
/// been raised.
fn mark_privileged_operation_completed() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    PRIVILEGED_OP_LAST_COMPLETED.store(now, Ordering::SeqCst);
}

impl Drop for PrivilegedOpGuard {
    fn drop(&mut self) {
        // Only the mutual exclusion. Whether this run earned a cooldown is not
        // something the guard can see from here.
        PRIVILEGED_OP_RUNNING.store(false, Ordering::SeqCst);
    }
}

use crate::validation::{
    validate_checkpoint_id, validate_checkpoint_name, validate_ipc_string, validate_output_path,
    validate_plugin_ids, validate_privileged_config_path, validate_ssh_key_path,
    validate_user_config_path,
};

/// Managed state for remote SSH connections.
///
/// Uses `tokio::sync::Mutex` to avoid blocking the async runtime if the
/// lock is held across await points.
pub struct RemoteState {
    pub active_connection: tokio::sync::Mutex<Option<ActiveConnection>>,
}

/// An active SSH connection with its executor and metadata.
pub struct ActiveConnection {
    pub executor: std::sync::Arc<hardener_core::SshExecutor>,
}

/// Returns the path to the main hardener config file.
///
/// Checks the user config directory first, then falls back to the system-wide
/// location. Returns the user path even if it doesn't exist yet (for creation).
fn hardener_config_path() -> Result<std::path::PathBuf, String> {
    let user_config = dirs::config_dir().map(|p| p.join("linux-hardener").join("config.toml"));
    if let Some(ref path) = user_config
        && path.exists()
    {
        return Ok(path.clone());
    }

    let system_config = std::path::PathBuf::from("/etc/linux-hardener/config.toml");
    if system_config.exists() {
        return Ok(system_config);
    }

    user_config.ok_or_else(|| "Cannot determine config directory".to_string())
}

/// Returns the user-writable config path (~/.config/linux-hardener/config.toml).
///
/// For write operations (scheduler save, etc.), we always target the user
/// config directory. The system config at /etc/linux-hardener/ is read-only.
fn writable_config_path() -> Result<std::path::PathBuf, String> {
    dirs::config_dir()
        .map(|p| p.join("linux-hardener").join("config.toml"))
        .ok_or_else(|| "Cannot determine config directory".to_string())
}

/// Loads host profiles from the shared inventory file.
fn load_hosts_config() -> Result<HostsConfig, String> {
    hardener_core::inventory::load().map_err(|e| safe_err(e.to_string()))
}

/// The shared inventory file both front ends read and write.
///
/// The one production answer to where it lives. Named here rather than left
/// inside `save_audited` because the two commands that write it now hand the
/// path to a function a test can also call, and a second answer resolved
/// somewhere else is exactly what the inventory module exists to prevent.
fn inventory_path() -> Result<std::path::PathBuf, String> {
    hardener_core::inventory::default_path().map_err(|e| safe_err(e.to_string()))
}

/// The audit detail for a host joining or leaving the inventory.
///
/// `host_key_checking` is here because it is the one field on a profile that
/// weakens a security decision: a host saved with it off accepts any key the
/// far end presents, and an operator turning it off for one host should not be
/// the only record that it happened.
fn host_details(operation: &str, profile: &RemoteHostProfile) -> HashMap<String, String> {
    HashMap::from([
        ("operation".to_string(), operation.to_string()),
        ("hostname".to_string(), profile.hostname.clone()),
        ("port".to_string(), profile.port.to_string()),
        (
            "host_key_checking".to_string(),
            profile.host_key_checking.to_string(),
        ),
        (
            "user".to_string(),
            profile
                .user
                .clone()
                .unwrap_or_else(|| "(current)".to_string()),
        ),
    ])
}

/// Formats a Unix timestamp as a human-readable string.
fn format_timestamp(timestamp: i64) -> String {
    chrono::DateTime::from_timestamp(timestamp, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| format!("Invalid timestamp: {}", timestamp))
}

/// Returns the canonical absolute path to the hardener CLI binary.
///
/// Searches in order: sibling of current exe, dev workspace target,
/// then PATH via `which`. Every candidate is resolved to a canonical
/// absolute path before being returned; bare command names are never
/// returned to prevent PATH-based privilege escalation through pkexec.
fn get_hardener_binary_path() -> Result<String, String> {
    // Check sibling directory of current executable (works in dev and production)
    if let Ok(exe) = std::env::current_exe() {
        let candidate = exe.with_file_name("hardener");
        if let Ok(canonical) = std::fs::canonicalize(&candidate) {
            return Ok(canonical.to_string_lossy().to_string());
        }
    }

    // In dev builds, check workspace target directory
    #[cfg(debug_assertions)]
    {
        let workspace_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(|root| root.join("target").join("debug").join("hardener"));
        if let Some(path) = workspace_path
            && let Ok(canonical) = std::fs::canonicalize(&path)
        {
            return Ok(canonical.to_string_lossy().to_string());
        }
    }

    // Resolve via PATH: capture the actual absolute path from `which`
    if let Ok(output) = std::process::Command::new("/usr/bin/which")
        .arg("hardener")
        .output()
        && output.status.success()
    {
        let resolved = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if let Ok(canonical) = std::fs::canonicalize(&resolved) {
            return Ok(canonical.to_string_lossy().to_string());
        }
    }

    Err("Could not find hardener CLI binary. \
         In development, run: cargo build -p hardener-cli"
        .to_string())
}

/// Validates that a binary path is safe for privileged execution.
///
/// Rejects symlinks, world-writable files, and (in release builds)
/// binaries not owned by root. This closes the TOCTOU window between
/// path resolution and pkexec invocation.
fn validate_binary_path(path: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let p = std::path::Path::new(path);

    // Must be absolute
    if !p.is_absolute() {
        return Err(safe_err(format!("Binary path is not absolute: {path}")));
    }

    // Must not be a symlink at the final component
    let meta =
        std::fs::symlink_metadata(p).map_err(|e| safe_err(format!("Cannot stat binary: {e}")))?;

    if meta.file_type().is_symlink() {
        return Err(safe_err(format!("Binary path is a symlink: {path}")));
    }

    if !meta.is_file() {
        return Err(safe_err(format!(
            "Binary path is not a regular file: {path}"
        )));
    }

    // Must not be world-writable
    if meta.permissions().mode() & 0o002 != 0 {
        return Err(safe_err(format!("Binary is world-writable: {path}")));
    }

    // In release builds, require root ownership
    #[cfg(not(debug_assertions))]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != 0 {
            return Err(safe_err(format!("Binary is not owned by root: {path}")));
        }
    }

    Ok(())
}

/// Error types for privileged command execution.
#[derive(Debug)]
enum PrivilegedCommandError {
    /// No polkit authentication agent available.
    NoAuthAgent,
    /// User cancelled the authentication.
    AuthCancelled,
    /// Command execution failed.
    ExecutionFailed(String),
}

impl std::fmt::Display for PrivilegedCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::NoAuthAgent => write!(
                f,
                "No Polkit authentication agent found.\n\n\
                Install one with:\n  \
                Arch: sudo pacman -S polkit-gnome\n  \
                Debian: sudo apt install policykit-1-gnome\n  \
                Fedora: sudo dnf install polkit-gnome\n\n\
                Then add to your window manager startup:\n  \
                exec /usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1"
            ),
            Self::AuthCancelled => write!(
                f,
                "Authentication cancelled. Root privileges are required for this operation."
            ),
            Self::ExecutionFailed(msg) => write!(f, "Command failed: {}", sanitise_error(msg)),
        }
    }
}

/// Raw result of a hardener CLI call, before the caller interprets what a
/// non-auth-related exit code means for that verb.
///
/// Named for the CLI rather than for pkexec because `run_apply_dry_run` builds
/// one from an unprivileged spawn. It reads the same stream by the same rule,
/// and the reason that command escalates nothing has no bearing on how its
/// answer is parsed.
struct CliOutput {
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
}

/// Runs the hardener CLI under pkexec, resolving the auth-specific outcomes
/// (no polkit agent, user cancelled) but deferring interpretation of every
/// other exit code to the caller. Some verbs (`apply`, `rollback`) print a
/// partial-result JSON payload to stdout before exiting 1 on partial failure,
/// so "non-zero exit" alone cannot mean "no usable output" for them.
async fn run_privileged(args: &[&str]) -> Result<CliOutput, PrivilegedCommandError> {
    let binary = get_hardener_binary_path().map_err(PrivilegedCommandError::ExecutionFailed)?;
    validate_binary_path(&binary).map_err(PrivilegedCommandError::ExecutionFailed)?;

    tracing::info!("=== Running pkexec {} {:?} ===", binary, args);

    let output = Command::new("/usr/bin/pkexec")
        .arg(&binary)
        .args(args)
        .output()
        .await
        .map_err(|e| PrivilegedCommandError::ExecutionFailed(e.to_string()))?;

    // pkexec ran, so an authentication prompt was reachable from here whatever
    // it went on to return. A refused or cancelled one counts: pacing retries
    // is the point. A failure to spawn it at all does not, and returns above.
    mark_privileged_operation_completed();

    match output.status.code() {
        Some(126) => {
            // pkexec: not authorised or auth dialogue dismissed
            Err(PrivilegedCommandError::AuthCancelled)
        }
        Some(127) => {
            // Command not found (pkexec or hardener)
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("polkit") || stderr.contains("authority") {
                Err(PrivilegedCommandError::NoAuthAgent)
            } else {
                Err(PrivilegedCommandError::ExecutionFailed(stderr.to_string()))
            }
        }
        exit_code => Ok(CliOutput {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            exit_code,
        }),
    }
}

/// True for exit codes this project's JSON-emitting CLI verbs may legitimately
/// pair with a valid payload: 0 for full success, 1 for verbs that print a
/// partial-result payload before `bail!`ing on partial failure (see `apply`,
/// `rollback` in `hardener-cli`). Any other code never carries a payload.
fn exit_code_may_carry_json(exit_code: Option<i32>) -> bool {
    matches!(exit_code, Some(0) | Some(1))
}

/// Interprets a JSON-emitting command's raw output: accepts the payload on
/// exit 0 always, and on exit 1 only when stdout still parses as `T` (a
/// partial-failure payload). Anything else is a genuine error carrying stderr,
/// sanitised by `PrivilegedCommandError`'s `Display` impl.
///
/// Parses the whole of stdout, and deliberately. Every JSON-emitting verb
/// prints the payload and nothing else there: `output::info`, `warning` and
/// `error` all write to stderr in JSON mode, which is what closed the
/// "Extra data" defect their own comment records. A parser that skipped
/// forward to the first `[` would accept a stream this project does not
/// produce, and would go on accepting one if a verb ever started producing it.
fn accept_json_output<T: serde::de::DeserializeOwned>(
    raw: &CliOutput,
) -> Result<T, PrivilegedCommandError> {
    if exit_code_may_carry_json(raw.exit_code)
        && let Ok(parsed) = serde_json::from_str(&raw.stdout)
    {
        return Ok(parsed);
    }
    if raw.stderr.is_empty() {
        let code = raw
            .exit_code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        return Err(PrivilegedCommandError::ExecutionFailed(format!(
            "CLI exited {code} but its output could not be parsed as results"
        )));
    }
    Err(PrivilegedCommandError::ExecutionFailed(raw.stderr.clone()))
}

/// Executes a command with root privileges via pkexec, treating anything but
/// exit 0 as failure. Used by verbs whose stdout carries no payload worth
/// recovering on a non-zero exit (checkpoint create/delete).
async fn run_privileged_command(args: &[&str]) -> Result<String, PrivilegedCommandError> {
    let raw = run_privileged(args).await?;
    match raw.exit_code {
        Some(0) => Ok(raw.stdout),
        _ => Err(PrivilegedCommandError::ExecutionFailed(raw.stderr)),
    }
}

/// Returns the path to the user-local database.
fn get_user_db_path() -> std::path::PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("linux-hardener")
        .join("checkpoints.db")
}

/// Returns the path to the system-wide database (used by privileged CLI).
fn get_system_db_path() -> std::path::PathBuf {
    std::path::PathBuf::from("/var/lib/linux-hardener/checkpoints.db")
}

/// Creates a CheckpointManager with database connection.
///
/// Derives the signing key from the database location:
/// system DB uses the separated key in `/etc/linux-hardener/`,
/// use DB uses a sibling key in the same directory.
async fn create_checkpoint_manager(db_path: &std::path::Path) -> Result<CheckpointManager, String> {
    let pool = init_db(Some(db_path)).await.map_err(safe_err)?;

    let key_path = if db_path.starts_with("/var/lib/linux-hardener") {
        std::path::PathBuf::from("/etc/linux-hardener/signing.key")
    } else {
        db_path
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join("signing.key")
    };

    let signer = CheckpointSigner::new_with_path(&key_path).map_err(safe_err)?;
    CheckpointManager::new_with_signer(pool, signer).map_err(safe_err)
}

/// Creates a ScanHistoryManager with database connection.
///
/// Uses the user-local database for scan history persistence.
async fn create_scan_history_manager() -> Result<ScanHistoryManager, String> {
    let db_path = get_user_db_path();

    let pool = init_db(Some(db_path.as_path())).await.map_err(safe_err)?;

    Ok(ScanHistoryManager::new(pool))
}

/// Persists a completed scan's results into an already-started history
/// session.
///
/// Storage and completion failures are logged rather than propagated: by
/// the time this runs the scan itself has already succeeded, and a fully
/// executed result should not be discarded over a persistence hiccup
/// unrelated to the scan. Session creation (`create_scan_history_manager`,
/// `start_session`) stays fallible in each caller so a genuinely unavailable
/// history database is still reported rather than silently swallowed.
async fn persist_scan_results(
    history_manager: &ScanHistoryManager,
    session_id: &ScanSessionId,
    results: &[ScanResult],
) {
    let total_findings: i32 = results.iter().map(|r| r.scan_findings.len() as i32).sum();
    let total_plugins = results.len() as i32;

    if let Err(e) = history_manager.store_results(session_id, results).await {
        error!("Failed to persist scan results: {}", e);
    }

    if let Err(e) = history_manager
        .complete_session(
            session_id,
            ScanStatus::Completed,
            total_findings,
            total_plugins,
        )
        .await
    {
        error!("Failed to complete scan session: {}", e);
    }
}

/// Runs a fallible scan step, marking `session_id` Failed in history if it
/// aborts before results ever reach `persist_scan_results`.
///
/// Without this, an early `?` between `start_session` and
/// `persist_scan_results` (a cancelled pkexec prompt, an unreadable config)
/// orphans the session's 'running' row forever. The original error is
/// always what gets returned; a failure to persist the Failed status itself
/// is only logged, never masking the real cause.
async fn fail_session_on_err<T, Fut>(
    history_manager: &ScanHistoryManager,
    session_id: &ScanSessionId,
    op: Fut,
) -> Result<T, String>
where
    Fut: std::future::Future<Output = Result<T, String>>,
{
    match op.await {
        Ok(value) => Ok(value),
        Err(err) => {
            if let Err(fail_err) = history_manager.fail_session(session_id).await {
                error!(
                    "Failed to mark scan session {} as failed: {}",
                    session_id.as_str(),
                    fail_err
                );
            }
            Err(err)
        }
    }
}

/// Refuses a scan whose every selected plugin the config disables.
///
/// `hardener scan` bails on this state and says how to leave it. `run_scan` did
/// not, so the same host answered two ways depending on which button was
/// pressed: the deep scan shells out and inherited the CLI's refusal, while the
/// local scan returned an empty result set. The Analysis tab renders that as
/// "No findings yet. Run a Security Scan above", so an operator who had just
/// run one was told to run one.
///
/// **`scanned == 0` alone is not this state.** A registry that hands back
/// nothing, or a filter matching no plugin, also produces no results and is a
/// different fault with a different remedy. The refusal needs both halves:
/// nothing ran, and the reason is that the config disabled what was asked for.
///
/// The wording follows the CLI's rather than paraphrasing it. An operator who
/// hits this in the desktop and then reaches for the terminal should not have
/// to work out that the two messages describe one condition.
fn scan_selection_refusal(scanned: usize, skipped_by_config: &[String]) -> Result<(), String> {
    if scanned > 0 || skipped_by_config.is_empty() {
        return Ok(());
    }
    Err(format!(
        "Config disabled every selected plugin ({}). Nothing was scanned. \
         Remove them from [global] disabled_plugins, add them to \
         [global] enabled_plugins, or select a plugin the config enables.",
        skipped_by_config.join(", ")
    ))
}

// Domain submodules, split from the flat file this used to be.
mod checkpoint;
mod compliance;
mod config;
mod exception;
mod fleet;
mod history;
mod remote;
mod scan;
mod scheduler;

pub use checkpoint::*;
pub use compliance::*;
pub use config::*;
pub use exception::*;
pub use fleet::*;
pub use history::*;
pub use remote::*;
pub use scan::*;
pub use scheduler::*;

#[cfg(test)]
mod fleet_tests;

/// Tests for the guard that decides whether deleting a checkpoint is worth an
/// authentication prompt.
#[cfg(test)]
mod delete_escalation_tests;

/// Tests for the rule that narrows the checkpoint list to this host.
#[cfg(test)]
mod checkpoint_host_tests;

/// Tests for `fail_session_on_err`, the helper `run_scan`/`run_deep_scan`
/// use to mark an aborted scan's history row Failed instead of orphaning
/// it as 'running' forever. The commands themselves are thin wrappers over
/// real system state with no test seam, but this helper is the load-bearing
/// piece, and it is fully exercisable against a real (tempdir-backed) scan
/// history database.
#[cfg(test)]
mod fail_session_on_err_tests;

#[cfg(test)]
mod compliance_source_tests;

#[cfg(test)]
mod webhook_shape_tests;

/// Tests for `exception_add_args`, the flag construction behind
/// `add_policy_exception`.
#[cfg(test)]
mod exception_args_tests;

/// Tests for `apply_args`, the argv `run_apply` and `run_apply_dry_run` share,
/// and for the `--dry-run` flag that is now all that separates them.
#[cfg(test)]
mod apply_args_tests;

/// Tests for `scan_history_rows`, the row count `get_scan_history` asks for,
/// and for the ceiling it now shares with `get_host_history`.
#[cfg(test)]
mod history_limit_tests;

/// Tests for `scan_selection_refusal`, the refusal `run_scan` owes when the
/// config disables every plugin the operator selected. The CLI has always
/// bailed on that state; the desktop's local scan returned an empty list.
#[cfg(test)]
mod scan_selection_tests;

/// Tests for the audit detail the desktop's own config writes carry.
#[cfg(test)]
mod config_write_detail_tests;

#[cfg(test)]
mod config_summary_tests;

/// Tests for `checkpoint_to_detail`, the mapping behind the history expander.
#[cfg(test)]
mod checkpoint_detail_tests;

/// Tests for `test_notification_verdict`, the line the settings pane shows
/// after a test send.
#[cfg(test)]
mod test_notification_tests;

/// Tests for `export_destination`, where a compliance export is written and
/// when the path is refused.
#[cfg(test)]
mod export_destination_tests;
