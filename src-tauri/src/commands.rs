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
    RollbackOutcome, ScanSessionInfo, SeverityTallies, plugin_id_named_by,
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

/// Executes a security scan across all enabled plugins.
///
/// Persists results to the database for GUI state restoration.
/// Returns a vector of scan results, one per plugin.
#[tauri::command]
pub async fn run_scan(
    plugin_ids: Option<Vec<String>>,
    config_path: Option<String>,
) -> Result<Vec<ScanResult>, String> {
    if let Some(ref ids) = plugin_ids {
        validate_plugin_ids(ids)?;
    }
    if let Some(ref path) = config_path {
        validate_user_config_path(path)?;
    }

    // Create scan history manager for persistence
    let history_manager = create_scan_history_manager().await?;

    // Start a new scan session
    let session_id = history_manager.start_session().await.map_err(safe_err)?;

    // Everything fallible from here marks the session Failed on abort
    // instead of orphaning its 'running' row.
    let results = fail_session_on_err(&history_manager, &session_id, async {
        // Load config if custom path provided
        let config = if let Some(ref path) = config_path {
            ConfigLoader::new()
                .with_cli_config(std::path::PathBuf::from(path))
                .load()
                .map_err(|e| safe_err(format!("Failed to load config: {}", e)))?
        } else {
            ConfigLoader::new().load().unwrap_or_default()
        };
        let ctx = Context::new();
        let registry = create_plugin_registry();

        let mut results = Vec::new();

        // Get list of all plugin metadata
        let plugin_list = registry.list().map_err(safe_err)?;

        for metadata in plugin_list {
            // Skip plugins not in the filter list (if a filter was provided).
            // `plugin_id_named_by` is the CLI's `--plugin` rule: this used to be
            // its own copy of the expression, which is how the Leptos label
            // lookup came to be missing the hyphen that makes a short id a
            // whole segment.
            if let Some(ref ids) = plugin_ids
                && !ids.is_empty()
                && !ids
                    .iter()
                    .any(|id| plugin_id_named_by(metadata.plugin_id.as_str(), id))
            {
                continue;
            }

            // Skip plugins disabled by config
            if !config.is_plugin_enabled(metadata.plugin_id.as_str()) {
                continue;
            }
            // Retrieve the actual plugin
            if let Ok(Some(plugin)) = registry.get(&metadata.plugin_id) {
                let plugin_config = config.get_plugin_config(metadata.plugin_id.as_str());
                let outcome = plugin.scan(&ctx, plugin_config).await;
                // Recorded, not merely logged. These results are what gets
                // persisted and later built into a compliance report, so a
                // plugin dropped here is a plugin whose controls pass on the
                // silence its own failure caused.
                if let Err(ref e) = outcome {
                    error!("Scan failed for plugin {}: {}", metadata.plugin_id, e);
                }
                results.push(recorded_scan(&metadata.plugin_id, outcome));
            }
        }

        Ok(results)
    })
    .await?;

    persist_scan_results(&history_manager, &session_id, &results).await;

    Ok(results)
}

/// Executes a security scan with root privileges via pkexec.
///
/// Shells out to the CLI exactly like `run_apply`, so the results match
/// `sudo hardener scan`. Persists results as a new session so restored
/// state reflects the deep scan.
#[tauri::command]
pub async fn run_deep_scan(
    plugin_ids: Option<Vec<String>>,
    config_path: Option<String>,
) -> Result<Vec<ScanResult>, String> {
    let _guard = PrivilegedOpGuard::acquire()?;
    if let Some(ref ids) = plugin_ids {
        validate_plugin_ids(ids)?;
    }
    if let Some(ref path) = config_path {
        validate_privileged_config_path(path)?;
    }

    // Same fallible session-creation contract as run_scan, and in the same
    // pre-flight position: an unavailable history database is reported
    // before the pkexec prompt runs, so a user never pays for a completed
    // root scan only to have it discarded on a persistence failure.
    let history_manager = create_scan_history_manager().await?;
    let session_id = history_manager.start_session().await.map_err(safe_err)?;

    // Everything fallible from here (the pkexec prompt included) marks the
    // session Failed on abort instead of orphaning its 'running' row.
    let results = fail_session_on_err(&history_manager, &session_id, async {
        let mut args: Vec<&str> = vec!["scan", "--format", "json"];
        let plugin_args: Vec<String> = plugin_ids
            .iter()
            .flatten()
            .flat_map(|id| vec!["--plugin".to_string(), id.clone()])
            .collect();
        let plugin_refs: Vec<&str> = plugin_args.iter().map(|s| s.as_str()).collect();
        args.extend(plugin_refs);
        let config_flag;
        if let Some(ref path) = config_path {
            config_flag = path.clone();
            args.push("--config");
            args.push(&config_flag);
        }

        let raw = run_privileged(&args).await.map_err(safe_err)?;
        let entries: Vec<CliScanEntry> = accept_json_output(&raw).map_err(safe_err)?;
        let results: Vec<ScanResult> = entries
            .into_iter()
            .map(CliScanEntry::into_scan_result)
            .collect();
        Ok(results)
    })
    .await?;

    persist_scan_results(&history_manager, &session_id, &results).await;

    Ok(results)
}

/// One per-plugin entry of the CLI's `scan --format json` output.
#[derive(serde::Deserialize)]
struct CliScanEntry {
    plugin_id: String,
    #[serde(default)]
    findings: Vec<Finding>,
    #[serde(default)]
    unchecked: Vec<UncheckedCheck>,
    /// Absent only in output from a CLI predating the field. Defaulting to
    /// `false` there keeps the fail-closed direction: an unknown outcome is
    /// reported as unverified rather than silently claimed as a pass.
    #[serde(default)]
    scan_success: bool,
    #[serde(default)]
    scan_error: Option<String>,
}

impl CliScanEntry {
    /// The CLI shape omits duration, so that alone is synthesised. The scan
    /// outcome is read from the payload: assuming success here was how a
    /// failed plugin scan reached the desktop as a clean result.
    fn into_scan_result(self) -> ScanResult {
        ScanResult {
            scan_plugin_id: PluginId::new(self.plugin_id),
            scan_success: self.scan_success,
            scan_findings: self.findings,
            scan_unchecked: self.unchecked,
            scan_duration_us: 0,
            scan_error: self.scan_error,
        }
    }
}

/// Applies hardening changes for the specified plugins.
///
/// Uses pkexec to run the CLI with root privileges.
/// The user will be prompted for their password via the polkit agent.
/// The argv for `hardener apply`, previewed or real.
///
/// One builder for both commands, which differed in `--dry-run` and in nothing
/// else that mattered. Two hand-written copies of an argv whose most
/// consequential flag is the one deciding whether the host is modified is a
/// pair worth not keeping, and `--dry-run` leads the vector for the reason
/// `enabled` leads `scheduler_details`: it is the entry a reader must not skim.
///
/// Returns owned strings. `apply`'s flags are all optional and all take values
/// the caller owns, so a borrowed vector only pushes the buffer that keeps them
/// alive back out to the call site, which is what both copies were doing.
fn apply_args(dry_run: bool, plugin_ids: &[String], config_path: Option<&str>) -> Vec<String> {
    let mut args = vec!["apply".to_string()];
    if dry_run {
        args.push("--dry-run".to_string());
    }
    args.push("--format".to_string());
    args.push("json".to_string());
    for id in plugin_ids {
        args.push("--plugin".to_string());
        args.push(id.clone());
    }
    if let Some(path) = config_path {
        args.push("--config".to_string());
        args.push(path.to_string());
    }
    args
}

#[tauri::command]
pub async fn run_apply(
    plugin_ids: Vec<String>,
    config_path: Option<String>,
) -> Result<Vec<ApplyResult>, String> {
    let _guard = PrivilegedOpGuard::acquire()?;
    validate_plugin_ids(&plugin_ids)?;
    if let Some(ref path) = config_path {
        validate_privileged_config_path(path)?;
    }

    tracing::info!("=== run_apply called with plugins: {:?} ===", plugin_ids);

    let owned = apply_args(false, &plugin_ids, config_path.as_deref());
    let args: Vec<&str> = owned.iter().map(String::as_str).collect();

    // Execute with root privileges. Exit 1 with a parseable payload is a
    // partial-failure result, not a transport error: the CLI already printed
    // per-plugin JSON before `bail!`ing, and the UI renders per-change status.
    let raw = run_privileged(&args).await.map_err(safe_err)?;
    let parsed: Vec<(PluginMetadata, ApplyResult)> = accept_json_output(&raw).map_err(safe_err)?;
    let results: Vec<ApplyResult> = parsed.into_iter().map(|(_, r)| r).collect();

    Ok(results)
}

/// Performs a dry-run of hardening changes for preview.
///
/// Unlike run_apply, this does NOT use pkexec because dry-run doesn't
/// modify the system. Returns estimated changes for user review.
#[tauri::command]
pub async fn run_apply_dry_run(
    plugin_ids: Vec<String>,
    config_path: Option<String>,
) -> Result<Vec<ValidationReport>, String> {
    validate_plugin_ids(&plugin_ids)?;
    if let Some(ref path) = config_path {
        validate_user_config_path(path)?;
    }

    tracing::info!(
        "=== run_apply_dry_run called with plugins: {:?} ===",
        plugin_ids
    );

    let binary = get_hardener_binary_path()?;
    let args = apply_args(true, &plugin_ids, config_path.as_deref());

    // Execute without root privileges (dry-run is read-only)
    let output = Command::new(&binary)
        .args(&args)
        .output()
        .await
        .map_err(|e| safe_err(format!("Failed to execute dry-run: {}", e)))?;

    // Read by the same rule as every other JSON verb, which is the point of it
    // being a rule. Exit 1 with a parseable report array is a partial-failure
    // result, not a transport error: `apply --dry-run` prints the array before
    // `bail!`ing when a plugin's validation errors.
    //
    // This used to skip forward to the first `[`, described in a comment as
    // stepping over a leading `{"info": "Dry run..."}` line. That line has gone
    // to stderr since `output::info`'s JSON arm was fixed, so the skip stepped
    // over nothing and the tolerance was the only difference left between this
    // path and the three that share the helper.
    accept_json_output(&CliOutput {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        exit_code: output.status.code(),
    })
    .map_err(safe_err)
}

/// The argv for a privileged `hardener rollback`.
///
/// The checkpoint id goes last, behind `--`, so an id that begins with a hyphen
/// cannot be read as a flag. That also means **nothing may be appended after
/// it**: everything past `--` is a positional, and `rollback` takes exactly one,
/// so an appended flag is not ignored, it makes clap refuse the command. A
/// `--config` used to be pushed there.
fn rollback_args(checkpoint_id: &str) -> Vec<&str> {
    vec!["rollback", "--format", "json", "--", checkpoint_id]
}

/// Rolls back to a previous checkpoint.
///
/// Uses pkexec to run the CLI with root privileges.
/// Takes a checkpoint ID and restores the system state to that point.
///
/// Takes no config path, and deliberately. `rollback` restores the files a
/// checkpoint captured and consults no directive, exception or plugin list, so
/// there is no policy for one to decide, exactly as `batch rollback` reads no
/// `config.toml` at all. Passing one was worse than useless: it went into the
/// argv after the `--` that separates the checkpoint id, so clap read `--config`
/// as a second positional and refused the whole command with "unexpected
/// argument", exit 2. Every rollback from the desktop failed for any operator
/// who had set a config file.
#[tauri::command]
pub async fn run_rollback(checkpoint_id: String) -> Result<RollbackResult, String> {
    let _guard = PrivilegedOpGuard::acquire()?;
    validate_checkpoint_id(&checkpoint_id)?;

    let args = rollback_args(&checkpoint_id);

    // Exit 1 with a parseable result is a partial-failure rollback, not a
    // transport error: the CLI prints the result before `bail!`ing when any
    // file failed to restore.
    let raw = run_privileged(&args).await.map_err(safe_err)?;
    accept_json_output(&raw).map_err(safe_err)
}

/// Whether one checkpoint database could be consulted.
///
/// `Absent` and `Unreadable` were one case while this used `Path::exists`,
/// which is `metadata(..).is_ok()` and so answers `false` for a file it merely
/// may not stat. They are not the same: one means there is nothing to show, the
/// other means there may be something that cannot be shown.
#[derive(Debug, PartialEq, Eq)]
enum DatabaseReach {
    /// Definitely not there, so nothing is missing from the list.
    Absent,
    /// Opened and listed. Its rows, if any, are in the list.
    Read,
    /// Present, or impossible to ask about, and not readable from here.
    Unreadable,
}

/// Adds one database's checkpoints to `entries`, skipping ids already present.
///
/// De-duplicating on the id matters because the same checkpoint can be reached
/// through either database, and the first database consulted keeps the row.
async fn collect_checkpoints(
    db: &std::path::Path,
    entries: &mut Vec<(Checkpoint, CheckpointManager)>,
) -> DatabaseReach {
    if matches!(db.try_exists(), Ok(false)) {
        return DatabaseReach::Absent;
    }
    let Ok(manager) = create_checkpoint_manager(db).await else {
        return DatabaseReach::Unreadable;
    };
    let Ok(checkpoints) = manager.list_checkpoints().await else {
        return DatabaseReach::Unreadable;
    };
    for checkpoint in checkpoints {
        if !entries
            .iter()
            .any(|(seen, _)| seen.checkpoint_id == checkpoint.checkpoint_id)
        {
            entries.push((checkpoint, manager.clone()));
        }
    }
    DatabaseReach::Read
}

/// Splits collected rows into the ones a rollback here could restore and a
/// count of the ones it could not.
///
/// Every checkpoint records the host it captured. `CheckpointManager::rollback`
/// refuses to restore one host's state onto another, so a row whose key is not
/// this host's is not a restore point this desktop can offer: the red button
/// beside it could only ever fail.
///
/// It is reachable, and not rarely. **`batch apply --execute` runs unprivileged
/// and writes every remote host's pre-apply checkpoints into the local user
/// database**, which is the first source this list reads. The database on the
/// machine this was found on holds 84 such rows and no local one.
///
/// The operator does not even reach the cross-host refusal, because
/// `run_rollback` escalates through `pkexec` first and the root CLI resolves to
/// the system database alone, where a user-database row is simply absent. So
/// the sequence was: pick a remote host's checkpoint from a list headed as this
/// machine's, read a preview of that host's files, authenticate, and be told
/// the checkpoint does not exist. `resolve_delete` states the principle for the
/// neighbouring verb: raising an authentication dialog for an operation that
/// cannot succeed is a prompt the operator can do nothing with.
///
/// Split out and taking the key as an argument so the rule can be tested
/// without a database, an executor or a pkexec prompt. Generic in what travels
/// beside the checkpoint for the same reason it is split out at all: the
/// decision reads `host_key` and nothing else, and a `CheckpointManager` in the
/// signature would have made that only testable against a real database.
fn restorable_here<T>(
    entries: Vec<(Checkpoint, T)>,
    local_key: &str,
) -> (Vec<(Checkpoint, T)>, usize) {
    let total = entries.len();
    let kept: Vec<_> = entries
        .into_iter()
        .filter(|(cp, _)| cp.host_key == local_key)
        .collect();
    let dropped = total - kept.len();
    (kept, dropped)
}

/// Retrieves the checkpoints of THIS host from both user and system databases.
///
/// The system database holds what privileged operations captured, the desktop's
/// own `create_checkpoint` included, since it goes through `pkexec`. The user
/// database holds what an unprivileged CLI run captured, which today means the
/// remote hosts `batch apply` reached. Both are merged and then narrowed to this
/// host by `restorable_here`, which is where the reasoning for the narrowing is.
#[tauri::command]
pub async fn get_checkpoints() -> Result<CheckpointList, String> {
    let mut entries: Vec<(Checkpoint, CheckpointManager)> = Vec::new();

    collect_checkpoints(&get_user_db_path(), &mut entries).await;

    // The system database is root-owned, so an unprivileged desktop often
    // cannot read it, and a list silently missing every privileged checkpoint
    // looks exactly like a host that has none. Report it to the caller as
    // well as the log: the log is not where the operator is looking.
    let system_db = get_system_db_path();
    let system_unreadable =
        collect_checkpoints(&system_db, &mut entries).await == DatabaseReach::Unreadable;
    if system_unreadable {
        tracing::warn!(
            "system checkpoint database at {} could not be read; any checkpoint \
             it holds is missing from this list",
            system_db.display()
        );
    }

    // Narrowed before the signature pass, not after: verifying a checkpoint
    // this host can never restore is a database read and a signing-key lookup
    // spent on a row nobody will be shown.
    let (entries, other_host_count) = restorable_here(
        entries,
        &hardener_common::executor::host_key_for(&hardener_core::LocalExecutor::new()),
    );

    // Sort by timestamp descending (newest first)
    let mut entries = entries;
    entries.sort_by_key(|(cp, _)| std::cmp::Reverse(cp.checkpoint_timestamp));

    // Verify each checkpoint's signature and build response
    let mut result = Vec::with_capacity(entries.len());
    for (cp, manager) in &entries {
        let verified = manager.verify_checkpoint(&cp.checkpoint_id).await.is_ok();

        result.push(CheckpointInfo {
            checkpoint_id: cp.checkpoint_id.as_str().to_string(),
            checkpoint_name: cp.checkpoint_name.clone(),
            checkpoint_created: format_timestamp(cp.checkpoint_timestamp),
            checkpoint_user: cp.checkpoint_username.clone(),
            checkpoint_verified: verified,
        });
    }

    Ok(CheckpointList {
        checkpoints: result,
        system_unreadable,
        other_host_count,
    })
}

/// Creates a manual checkpoint of the current system state.
///
/// Requires root privileges via pkexec since it reads protected system files.
///
/// The name goes last, behind `--`, so one beginning with a hyphen cannot be
/// read as a flag, and nothing may be appended after it. `rollback_args`
/// records what happens when something is: clap refuses the whole command.
///
/// Deserialised into `CheckpointCreated` rather than indexed out of an untyped
/// `Value`. This was the one CLI payload the desktop read by a key spelled at
/// both ends, and the shape it invited is a bad one: renaming the CLI's key
/// still creates the checkpoint, and the desktop reports a failure for an
/// operation that succeeded, whose obvious remedy is to make a second one.
/// `hardener-cli` is a binary and cannot be depended on, so the struct lives in
/// `hardener-state`, which both ends already use.
#[tauri::command]
pub async fn create_checkpoint(name: String) -> Result<String, String> {
    let _guard = PrivilegedOpGuard::acquire()?;
    validate_checkpoint_name(&name)?;

    let args = vec!["checkpoint", "create", "--format", "json", "--", &name];

    let output = run_privileged_command(&args).await.map_err(safe_err)?;

    let created: hardener_state::CheckpointCreated = serde_json::from_str(output.trim())
        .map_err(|e| safe_err(format!("Failed to parse response: {e}")))?;

    Ok(created.checkpoint_id)
}

/// Deletes a checkpoint by ID.
///
/// Tries the user database first, which needs no privilege. A row it does not
/// hold escalates through `pkexec` unless the system database is readable and
/// positively lacks the id; see `resolve_delete` for why absence of an answer
/// still escalates.
#[tauri::command]
pub async fn delete_checkpoint(checkpoint_id: String) -> Result<bool, String> {
    let _guard = PrivilegedOpGuard::acquire()?;
    validate_checkpoint_id(&checkpoint_id)?;

    let cp_id = CheckpointId::new(&checkpoint_id);

    match resolve_delete(&get_user_db_path(), &get_system_db_path(), &cp_id).await {
        DeleteResolution::Removed => Ok(true),
        DeleteResolution::NotFound => Err(format!("no checkpoint with id '{checkpoint_id}'")),
        DeleteResolution::NeedsPrivilege => {
            let args = vec!["checkpoint", "delete", &checkpoint_id];
            run_privileged_command(&args)
                .await
                .map(|_| true)
                .map_err(safe_err)
        }
    }
}

/// The argument vector for `hardener exception add`.
///
/// Separated from the command so the flag construction is testable without a
/// pkexec prompt: an optional field that became an empty flag would write an
/// empty approver into the operator's configuration, and nothing downstream
/// could tell that from one they typed.
fn exception_add_args<'a>(
    plugin_id: &'a str,
    exception_key: &'a str,
    reason: &'a str,
    approved_by: Option<&'a str>,
    ticket: Option<&'a str>,
    expires: Option<&'a str>,
) -> Vec<&'a str> {
    let mut args = vec![
        "--format",
        "json",
        "exception",
        "add",
        plugin_id,
        exception_key,
        "--reason",
        reason,
    ];
    for (flag, field) in [
        ("--approved-by", approved_by),
        ("--ticket", ticket),
        ("--expires", expires),
    ] {
        // Blank counts as absent, not as a flag paired with an empty string:
        // `Some("")` reaches here whenever the caller trims a field and hands
        // back an empty string rather than `None`, and `--ticket ""` would
        // write an empty ticket into the operator's config.
        if let Some(supplied) = field.filter(|s| !s.trim().is_empty()) {
            args.push(flag);
            args.push(supplied);
        }
    }
    args
}

/// Writes a policy exception for one finding, as root.
///
/// The desktop sends the plugin id, the key and the operator's text, and
/// nothing describing the host: the CLI re-reads the host and pins the value it
/// observes. A key that no live finding carries is refused there, which is also
/// why no allow-list is needed here.
#[tauri::command]
pub async fn add_policy_exception(
    plugin_id: String,
    exception_key: String,
    reason: String,
    approved_by: Option<String>,
    ticket: Option<String>,
    expires: Option<String>,
) -> Result<hardener_types::WrittenException, String> {
    let _guard = PrivilegedOpGuard::acquire()?;
    validate_plugin_ids(std::slice::from_ref(&plugin_id))?;
    validate_ipc_string(&exception_key, "exception_key")?;
    validate_ipc_string(&reason, "reason")?;
    for (field, name) in [
        (&approved_by, "approved_by"),
        (&ticket, "ticket"),
        (&expires, "expires"),
    ] {
        if let Some(text) = field {
            validate_ipc_string(text, name)?;
        }
    }
    if reason.trim().is_empty() {
        return Err("A reason is required: an undocumented deviation is what an exception exists to prevent.".to_string());
    }

    let args = exception_add_args(
        &plugin_id,
        &exception_key,
        &reason,
        approved_by.as_deref(),
        ticket.as_deref(),
        expires.as_deref(),
    );

    let output = run_privileged_command(&args).await.map_err(safe_err)?;
    serde_json::from_str(&output).map_err(|e| {
        safe_err(format!(
            "Could not read what the exception write reported: {e}"
        ))
    })
}

/// Removes a policy exception, as root.
#[tauri::command]
pub async fn remove_policy_exception(
    plugin_id: String,
    exception_key: String,
) -> Result<(), String> {
    let _guard = PrivilegedOpGuard::acquire()?;
    validate_plugin_ids(std::slice::from_ref(&plugin_id))?;
    validate_ipc_string(&exception_key, "exception_key")?;

    run_privileged_command(&[
        "--format",
        "json",
        "exception",
        "remove",
        &plugin_id,
        &exception_key,
    ])
    .await
    .map(|_| ())
    .map_err(safe_err)
}

/// What a delete should do, decided without escalating anything.
///
/// Split out so the decision can be tested. Everything the branch turns on is a
/// pair of databases and an id; only the consequence of `NeedsPrivilege` needs
/// `pkexec`, and that is exactly what a test must not run. Returning the
/// decision rather than acting on it means an inverted branch is a failing test
/// rather than a defect nobody can reach.
#[derive(Debug, PartialEq, Eq)]
enum DeleteResolution {
    /// The user database held the row and it is gone.
    Removed,
    /// Neither database has it, so escalating could only fail.
    NotFound,
    /// It may be a root-owned row, or the system database could not be asked.
    NeedsPrivilege,
}

/// Decides a delete from the two databases alone.
///
/// The user database is tried first because the desktop's own checkpoints live
/// there and need no privilege. Failing that, the fallback exists for root-owned
/// rows and is right, but an id in NEITHER database is what a stale list, a
/// double click, or a row already removed from the CLI produces, and raising an
/// authentication dialog for an operation that cannot succeed is a prompt the
/// operator can do nothing with.
async fn resolve_delete(
    user_db: &std::path::Path,
    system_db: &std::path::Path,
    checkpoint_id: &CheckpointId,
) -> DeleteResolution {
    if user_db.exists()
        && let Ok(manager) = create_checkpoint_manager(user_db).await
        && manager.delete_checkpoint(checkpoint_id).await.is_ok()
    {
        return DeleteResolution::Removed;
    }

    if system_database_denies(system_db, checkpoint_id).await {
        return DeleteResolution::NotFound;
    }
    DeleteResolution::NeedsPrivilege
}

/// Whether the system database is readable and positively lacks this row.
///
/// `false` whenever the question cannot be answered, which is the safe
/// direction: it means "escalate and let the privileged run decide", which is
/// what happened unconditionally before.
async fn system_database_denies(system_db: &std::path::Path, checkpoint_id: &CheckpointId) -> bool {
    // `try_exists`, not `exists`. `Path::exists` is `metadata(..).is_ok()`, so
    // it answers `false` for a file it merely may not stat, and the system
    // database lives under a root-owned directory that an unprivileged desktop
    // frequently cannot search: this host's is `drwx------ root`. Reading that
    // `false` as "no such database" would make every root-owned checkpoint
    // undeletable, which is the precise opposite of leaving the fallback
    // reachable.
    match system_db.try_exists() {
        // Definitely not there: the answer this guard exists to act on.
        Ok(false) => return true,
        // Cannot even be asked. Not an answer, so the privileged run decides.
        Err(_) => return false,
        Ok(true) => {}
    }
    let Ok(manager) = create_checkpoint_manager(system_db).await else {
        return false;
    };
    let Ok(checkpoints) = manager.list_checkpoints().await else {
        return false;
    };
    !checkpoints
        .iter()
        .any(|c| &c.checkpoint_id == checkpoint_id)
}

/// Parses framework name strings into `ComplianceFramework` enum values.
/// Unknown spellings are silently dropped rather than surfaced as errors,
/// matching the existing GUI contract for these call sites.
fn parse_frameworks(frameworks: &[String]) -> Vec<ComplianceFramework> {
    frameworks
        .iter()
        .filter_map(|f| ComplianceFramework::from_id(f))
        .collect()
}

/// Parses a format string into an `OutputFormat`.
fn parse_output_format(format: &str) -> Result<OutputFormat, String> {
    match format.to_lowercase().as_str() {
        "text" | "txt" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        "csv" => Ok(OutputFormat::Csv),
        "html" => Ok(OutputFormat::Html),
        "pdf" => Ok(OutputFormat::Pdf),
        _ => Err(sanitise_error(&format!(
            "Unsupported format '{}'. Use text, json, csv, html, or pdf.",
            format
        ))),
    }
}

/// Scans all plugins and collects findings and unchecked checks for
/// compliance reporting. A control whose covering check landed in the
/// unchecked list must never auto-pass on the mere absence of a finding.
/// Honours the local system/user config (directives and exceptions), the
/// same as `run_scan`, so a compliance report matches a manual scan.
async fn collect_findings() -> Result<Vec<ScanResult>, String> {
    let ctx = Context::new();
    let registry = create_plugin_registry();
    let plugin_list = registry.list().map_err(safe_err)?;

    // Same loader `run_scan` uses for its no-custom-path case: this call site
    // has no config_path of its own, so system/user config applies, falling
    // back to defaults rather than failing a background compliance refresh.
    let config = ConfigLoader::new().load().unwrap_or_default();

    let mut results = Vec::new();
    for metadata in plugin_list {
        // A plugin the config disables contributes no result at all, and
        // `scan_evidence::flatten`, inside `ReportGenerator::generate`, reads
        // that absence as "not assessed" rather than as a clean pass.
        if !config.is_plugin_enabled(metadata.plugin_id.as_str()) {
            continue;
        }
        let Ok(Some(plugin)) = registry.get(&metadata.plugin_id) else {
            continue;
        };
        // A scan that errored used to be swallowed by an `if let Ok`, which is
        // indistinguishable from a plugin that found nothing.
        let outcome = plugin
            .scan(&ctx, config.get_plugin_config(metadata.plugin_id.as_str()))
            .await;
        results.push(recorded_scan(&metadata.plugin_id, outcome));
    }
    Ok(results)
}

/// One plugin's scan outcome as a result the caller can record either way.
///
/// A scan that errored becomes a failed result rather than being dropped.
/// Dropping it is indistinguishable from a plugin that found nothing, and the
/// two are scored differently: `scan_evidence::flatten` reads an absent plugin
/// as `NotCovered` and a failed one as `ScanIncomplete` carrying its reason. On
/// a remote host the `Err` arm is a transport failure part-way through, so the
/// distinction is between "this host has no firewall backend" and "the
/// connection dropped whilst asking".
fn recorded_scan<E: std::fmt::Display>(
    plugin_id: &PluginId,
    outcome: Result<ScanResult, E>,
) -> ScanResult {
    outcome.unwrap_or_else(|e| hardener_plugins::failed_scan(plugin_id, &e.to_string()))
}

// `flatten_scan_results` used to live here, wrapping
// `hardener_plugins::flatten_persisted_scans`. It kept its own copy of a rule
// the CLI had already corrected and so passed controls nobody assessed. The
// flatten is inside `ReportGenerator::generate` now, which takes raw scan
// results, so there is nothing left here to get wrong.

/// Decides whether a persisted scan session's results should stand as the
/// report source.
///
/// `None` covers both "no completed session exists" and "a completed
/// session exists but carries zero results" - the latter happens when
/// `persist_scan_results` logs a `store_results` failure but still marks
/// the session Completed (see its doc comment), so the session row exists
/// while `scan_results` is empty. Even a clean host produces one
/// `ScanResult` per plugin, so an empty result set is never a legitimate
/// full scan; treating it as "no session" sends the caller to the fresh-scan
/// fallback instead of scoring it into a false-green zero-finding report.
fn persisted_scan_source(
    persisted: Option<(ScanSession, Vec<ScanResult>)>,
) -> Option<Vec<ScanResult>> {
    match persisted {
        Some((_, results)) if !results.is_empty() => Some(results),
        Some(_) | None => None,
    }
}

/// Sources compliance inputs from the latest persisted completed scan
/// session, so reports and the score reflect the scan the user actually
/// ran - including a privileged deep scan's root-only results, which a
/// fresh in-process scan could never see. Falls back to a fresh
/// unprivileged scan when no completed session exists (fresh install,
/// compliance tab opened before any scan), a completed session has no
/// results (see `persisted_scan_source`), or the history database cannot
/// be read; a read failure is logged, never propagated. Neither path can
/// trigger a privilege prompt.
async fn latest_or_fresh_findings() -> Result<Vec<ScanResult>, String> {
    let persisted = match create_scan_history_manager().await {
        Ok(manager) => manager.get_latest_scan().await.map_err(safe_err),
        Err(e) => Err(e),
    };
    match persisted {
        Ok(persisted) => match persisted_scan_source(persisted) {
            Some(results) => Ok(results),
            None => collect_findings().await,
        },
        Err(e) => {
            error!("Scan history unavailable, compliance report falling back to a fresh scan: {e}");
            collect_findings().await
        }
    }
}

/// Resolves the compliance profile of the machine this desktop runs on:
/// the local report commands always assess the local system. Detection
/// failure falls back to `Generic`, never an error.
fn local_profile() -> ComplianceProfile {
    Distribution::detect()
        .ok()
        .map(|distro| resolve_profile(&distro))
        .unwrap_or_default()
}

/// Reads the operator's declared-not-applicable set for the local system.
///
/// Same loader and same fallback as the local scan path: the desktop has no
/// `--config` of its own, so system and user config apply, and an unreadable
/// config leaves the set empty rather than failing a report. An empty set only
/// ever costs score, never fabricates one.
fn local_exclusions() -> ComplianceConfig {
    ConfigLoader::new().load().unwrap_or_default().compliance
}

/// Generates compliance reports for the specified frameworks.
///
/// Takes a list of framework names and returns compliance reports built
/// from the latest persisted scan session (fresh-scan fallback).
#[tauri::command]
pub async fn generate_compliance_report(
    frameworks: Vec<String>,
) -> Result<Vec<ComplianceReport>, String> {
    let results = latest_or_fresh_findings().await?;
    let parsed_frameworks = parse_frameworks(&frameworks);

    let config = ReportConfig {
        scenario: Scenario::Custom(parsed_frameworks),
        formats: vec![OutputFormat::Text],
        output_dir: None,
        profile: local_profile(),
    };

    let generator = ReportGenerator::new(
        config,
        hardener_plugins::plugin_inventory(),
        local_exclusions(),
    );
    Ok(generator.generate(&results, &[]))
}

/// Where an export is written, given the operator's path and the chosen format.
///
/// Three decisions, none of which needs a report, a scan or a filesystem, and
/// all three of which an operator sees the consequence of.
///
/// **A path whose extension names a different document is refused**, in the
/// wording of a window rather than of a flag. `hardener report` has refused
/// this since `refuse_extension_that_contradicts` was added, because writing a
/// text report into a file named `.json` and exiting 0 is a lie a consumer will
/// act on. The desktop reached the same fork in-process and wrote the bytes,
/// so choosing PDF and typing `audit.json` produced a PDF called `audit.json`
/// and reported it saved. Both now decide through
/// `OutputFormat::contradicted_by`, which is the only part of a refusal that
/// can be shared: the CLI's sentence names `--output` and this one has no flag
/// to name.
///
/// **An extension is appended only when the path has none**, matching
/// `report.rs`. A dated stem like `q3.2026.08` has extension `08`, names no
/// document, and is left alone rather than being read as a format.
///
/// **A path that was not given is built under Documents**, falling back to the
/// home directory and then to the working directory, with a local timestamp so
/// two exports in one session do not overwrite each other.
fn export_destination(
    output_path: Option<String>,
    output_format: OutputFormat,
    timestamp: &str,
) -> Result<String, String> {
    let Some(path) = output_path else {
        let dir = dirs::document_dir()
            .or_else(dirs::home_dir)
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let name = format!(
            "compliance-report-{timestamp}.{}",
            output_format.extension()
        );
        return Ok(dir.join(name).to_string_lossy().to_string());
    };

    let as_path = std::path::Path::new(&path);
    if let Some(named) = output_format.contradicted_by(as_path) {
        return Err(format!(
            "'{path}' names a {} file, but the chosen format is {}. \
             Give the file the {} extension, or none at all, or export as {}.",
            named.extension(),
            output_format.extension(),
            output_format.extension(),
            named.extension(),
        ));
    }

    if as_path.extension().is_none() {
        return Ok(format!("{path}.{}", output_format.extension()));
    }
    Ok(path)
}

/// Exports compliance reports to a file in the specified format.
///
/// Generates reports, formats them, and writes to the output path.
/// Returns the final file path used (extension may be appended).
#[tauri::command]
pub async fn export_compliance_report(
    frameworks: Vec<String>,
    format: String,
    output_path: Option<String>,
) -> Result<String, String> {
    for f in &frameworks {
        validate_ipc_string(f, "framework")?;
    }
    validate_ipc_string(&format, "format")?;
    if let Some(ref path) = output_path {
        validate_output_path(path)?;
    }

    let output_format = parse_output_format(&format)?;
    // Resolved before anything is rendered: a contradicting extension is
    // refused, and scanning a host to build a report nobody may write is work
    // done for a message.
    let final_path = export_destination(
        output_path,
        output_format,
        &chrono::Local::now().format("%Y%m%d-%H%M%S").to_string(),
    )?;

    // Same sourcing as generate_compliance_report: an exported report must
    // match the one on screen.
    let results = latest_or_fresh_findings().await?;
    let parsed_frameworks = parse_frameworks(&frameworks);

    let config = ReportConfig {
        scenario: Scenario::Custom(parsed_frameworks),
        formats: vec![output_format],
        output_dir: None,
        profile: local_profile(),
    };

    let generator = ReportGenerator::new(
        config,
        hardener_plugins::plugin_inventory(),
        local_exclusions(),
    );
    let reports = generator.generate(&results, &[]);

    // One arm per format, one render, one write. PDF used to be special-cased
    // around a `String` match that had already rendered it: `format_all` into a
    // lossy `String` which was then discarded, and `format_all_bytes` again for
    // the bytes written. Every formatter answers `format_all_bytes`, the four
    // text ones through the trait's default, so there is no case to except and
    // no arm left over to make unreachable.
    let bytes = match output_format {
        OutputFormat::Text => TextFormatter::new().format_all_bytes(&reports),
        OutputFormat::Json => JsonFormatter::pretty().format_all_bytes(&reports),
        OutputFormat::Csv => CsvFormatter::new().format_all_bytes(&reports),
        OutputFormat::Html => HtmlFormatter::new().format_all_bytes(&reports),
        OutputFormat::Pdf => PdfFormatter::new().format_all_bytes(&reports),
    };
    std::fs::write(&final_path, bytes)
        .map_err(|e| safe_err(format!("Failed to write report: {}", e)))?;

    Ok(final_path)
}

/// Converts a stored `ScanSession` into the frontend's session metadata.
///
/// A free function rather than `impl From`: both types are now foreign to this
/// crate, so the coherence rules reject the trait impl (E0117).
fn session_to_info(s: ScanSession) -> ScanSessionInfo {
    ScanSessionInfo {
        session_id: s.session_id.as_str().to_string(),
        started_at: format_timestamp(s.session_started_at),
        completed_at: s.session_completed_at.map(format_timestamp),
        total_findings: s.session_total_findings,
        total_plugins: s.session_total_plugins,
        status: s.session_status.as_str().to_string(),
    }
}

/// Lists recent scan history sessions (metadata only).
#[tauri::command]
pub async fn get_scan_history(limit: Option<i32>) -> Result<Vec<ScanSessionInfo>, String> {
    let manager = create_scan_history_manager().await?;
    let sessions = manager
        .list_sessions(limit.unwrap_or(20))
        .await
        .map_err(safe_err)?;

    Ok(sessions.into_iter().map(session_to_info).collect())
}

/// Retrieves full scan results for a specific session.
#[tauri::command]
pub async fn get_scan_session(session_id: String) -> Result<Vec<ScanResult>, String> {
    validate_ipc_string(&session_id, "session_id")?;

    let manager = create_scan_history_manager().await?;
    let id = ScanSessionId::new(session_id);

    manager.get_session_results(&id).await.map_err(safe_err)
}

/// Lists available hardening plugins with their metadata.
#[tauri::command]
pub async fn list_plugins() -> Result<Vec<PluginMetadata>, String> {
    let registry = create_plugin_registry();
    registry.list().map_err(safe_err)
}

/// Converts a `Checkpoint` and its `FileState` entries into frontend detail.
fn checkpoint_to_detail(cp: Checkpoint, files: Vec<FileState>) -> CheckpointDetail {
    CheckpointDetail {
        checkpoint_id: cp.checkpoint_id.as_str().to_string(),
        checkpoint_name: cp.checkpoint_name,
        checkpoint_created: format_timestamp(cp.checkpoint_timestamp),
        checkpoint_user: cp.checkpoint_username,
        file_count: files.len(),
        files: files
            .into_iter()
            .map(|f| CheckpointFileInfo {
                // `restore_mode_string`, not the raw mode: `file_permissions`
                // carries the type field, so a file captured at 0644 read
                // `100644` under a column headed "permissions", and the number
                // the operator saw was not the one a rollback would chmod.
                permissions: f.restore_mode_string(),
                path: f.file_path,
                has_content: f.file_content.is_some(),
            })
            .collect(),
    }
}

/// Retrieves detailed checkpoint information including captured files.
///
/// Searches both user and system databases.
#[tauri::command]
pub async fn get_checkpoint_detail(checkpoint_id: String) -> Result<CheckpointDetail, String> {
    validate_checkpoint_id(&checkpoint_id)?;

    let cp_id = CheckpointId::new(&checkpoint_id);

    // Try user database first
    let user_db = get_user_db_path();
    if user_db.exists()
        && let Ok(manager) = create_checkpoint_manager(&user_db).await
        && let Ok((cp, files)) = manager.get_checkpoint(&cp_id).await
    {
        return Ok(checkpoint_to_detail(cp, files));
    }

    // Try system database
    let system_db = get_system_db_path();
    if system_db.exists()
        && let Ok(manager) = create_checkpoint_manager(&system_db).await
        && let Ok((cp, files)) = manager.get_checkpoint(&cp_id).await
    {
        return Ok(checkpoint_to_detail(cp, files));
    }

    Err(format!("Checkpoint '{}' not found", checkpoint_id))
}

/// Retrieves the most recent scan results from the database.
///
/// Used to restore GUI state on app startup or page refresh.
/// Returns None if no completed scans exist.
#[tauri::command]
pub async fn get_latest_scan() -> Result<Option<Vec<ScanResult>>, String> {
    let history_manager = create_scan_history_manager().await?;

    match history_manager.get_latest_scan().await {
        Ok(Some((_, results))) => Ok(Some(results)),
        Ok(None) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Remote host profile CRUD
// ---------------------------------------------------------------------------

/// Lists all saved remote host profiles from the TOML config.
#[tauri::command]
pub async fn list_remote_hosts() -> Result<Vec<RemoteHostProfile>, String> {
    let config = load_hosts_config()?;
    Ok(config.hosts)
}

/// Creates or updates a remote host profile (upsert by name).
#[tauri::command]
pub async fn save_remote_host(profile: RemoteHostProfile) -> Result<(), String> {
    validate_ipc_string(&profile.name, "profile_name")?;
    validate_ipc_string(&profile.hostname, "hostname")?;
    if let Some(ref user) = profile.user {
        validate_ipc_string(user, "user")?;
    }
    if let Some(ref key) = profile.key_file {
        validate_ssh_key_path(key)?;
    }

    let path = inventory_path()?;
    let config = load_hosts_config()?;
    let logger = get_audit_logger().await;
    upsert_host(&path, config, profile, logger.as_ref()).await
}

/// Folds `profile` into `config` and writes the result to `path`, recording
/// what changed.
///
/// Split from [`save_remote_host`] on the same reasoning as
/// [`write_scheduler_config`]: that command resolves the inventory path and the
/// audit log path from the process environment, and moving environment
/// variables under `cargo test`'s threads is the race that put
/// `crates/hardener-core/tests/inventory_shared_path.rs` in a binary of its
/// own. Here the fold, the write and the entry are all observable at once.
///
/// Upsert by name, not append: a profile re-saved under a name already in the
/// inventory replaces it. Appending would leave two rows claiming the same
/// name, and every lookup in this file takes the first match, so the edit would
/// appear to have been ignored.
async fn upsert_host(
    path: &std::path::Path,
    mut config: HostsConfig,
    profile: RemoteHostProfile,
    logger: Option<&hardener_state::audit::AuditLogger>,
) -> Result<(), String> {
    let details = host_details("save", &profile);
    let target = format!("host:{}", profile.name);
    if let Some(existing) = config.hosts.iter_mut().find(|h| h.name == profile.name) {
        *existing = profile;
    } else {
        config.hosts.push(profile);
    }
    hardener_core::inventory::save_audited_to(
        path,
        &config,
        WriteAudit {
            logger,
            action: ActionType::ConfigChange,
            target,
            details,
        },
    )
    .await
    .map_err(|e| safe_err(e.to_string()))
}

/// Deletes a remote host profile by name.
#[tauri::command]
pub async fn delete_remote_host(name: String) -> Result<(), String> {
    validate_ipc_string(&name, "profile_name")?;

    let path = inventory_path()?;
    let config = load_hosts_config()?;
    let logger = get_audit_logger().await;
    remove_host(&path, config, &name, logger.as_ref()).await
}

/// Drops the host named `name` from `config` and writes the result to `path`,
/// recording what left.
///
/// The counterpart to [`upsert_host`], split for the same reason.
///
/// A name that matches nothing writes the file unchanged and is still recorded
/// as an attempt. That is deliberate: the operator asked for a host to stop
/// being scanned, and an unrecorded no-op leaves nothing to read when it turns
/// out the name was a typo and the host is still in the fleet.
async fn remove_host(
    path: &std::path::Path,
    mut config: HostsConfig,
    name: &str,
    logger: Option<&hardener_state::audit::AuditLogger>,
) -> Result<(), String> {
    // Read off the profile before it goes, so the entry says what left rather
    // than only that something did.
    let details = config.hosts.iter().find(|h| h.name == name).map_or_else(
        || HashMap::from([("operation".to_string(), "delete".to_string())]),
        |profile| host_details("delete", profile),
    );
    config.hosts.retain(|h| h.name != name);
    hardener_core::inventory::save_audited_to(
        path,
        &config,
        WriteAudit {
            logger,
            action: ActionType::ConfigChange,
            target: format!("host:{name}"),
            details,
        },
    )
    .await
    .map_err(|e| safe_err(e.to_string()))
}

/// Connects to a remote host by profile name.
///
/// Looks up the profile from the TOML config, builds an `SshConfig`,
/// and establishes the SSH session. The active connection is stored in
/// managed `RemoteState` so subsequent commands can reuse it.
#[tauri::command]
pub async fn connect_remote(
    name: String,
    state: tauri::State<'_, RemoteState>,
) -> Result<RemoteConnectionStatus, String> {
    validate_ipc_string(&name, "profile_name")?;

    let config = load_hosts_config()?;
    let profile = config
        .hosts
        .iter()
        .find(|h| h.name == name)
        .ok_or_else(|| format!("Host profile '{}' not found", name))?
        .clone();

    let ssh_config = ssh_config_for(&profile);

    match hardener_core::SshExecutor::connect(ssh_config).await {
        Ok(executor) => {
            // The executor's own answer, not a guess at it. This read
            // `profile.user.clone().unwrap_or_else(whoami::username)` until
            // 2026-08-26, which is the local account rather than the remote
            // one: a profile naming no user against a host whose `~/.ssh/config`
            // says `User deploy` connects as `deploy` and files every checkpoint
            // under `ssh://deploy@host:22`, while the banner claimed the
            // operator's own name. `effective_user` is the same string
            // `description` embeds, so the two cannot disagree again.
            let user_display = executor.effective_user();
            let mut connection = state.active_connection.lock().await;
            *connection = Some(ActiveConnection {
                executor: std::sync::Arc::new(executor),
            });
            Ok(RemoteConnectionStatus::Connected {
                host: profile.hostname,
                user: user_display,
            })
        }
        Err(e) => Ok(RemoteConnectionStatus::Failed { error: safe_err(e) }),
    }
}

/// Disconnects the active remote SSH session.
///
/// Drops the `SshExecutor` (which closes the underlying SSH session)
/// and clears the managed state.
#[tauri::command]
pub async fn disconnect_remote(state: tauri::State<'_, RemoteState>) -> Result<(), String> {
    let mut connection = state.active_connection.lock().await;
    *connection = None;
    Ok(())
}

/// Runs every (optionally filtered) plugin's scan over the given executor.
///
/// Shared by single-host `run_remote_scan` and the fleet scan. A per-plugin
/// scan error is logged and skipped so one bad plugin never aborts the scan.
async fn scan_with_executor(
    executor: std::sync::Arc<dyn hardener_core::SystemExecutor>,
    plugin_ids: Option<&[String]>,
) -> Result<Vec<ScanResult>, String> {
    let ctx = Context::with_executor(executor);
    let registry = create_plugin_registry();
    let mut results = Vec::new();
    let plugin_list = registry.list().map_err(safe_err)?;
    let default_config = PluginConfig::default();

    for metadata in plugin_list {
        if let Some(ids) = plugin_ids
            && !ids.is_empty()
            && !ids
                .iter()
                .any(|id| plugin_id_named_by(metadata.plugin_id.as_str(), id))
        {
            continue;
        }

        if let Ok(Some(plugin)) = registry.get(&metadata.plugin_id) {
            let outcome = plugin.scan(&ctx, &default_config).await;
            if let Err(ref e) = outcome {
                error!("Scan failed for plugin {}: {}", metadata.plugin_id, e);
            }
            results.push(recorded_scan(&metadata.plugin_id, outcome));
        }
    }

    Ok(results)
}

/// Best-effort per-host profile resolution: reads `/etc/os-release` through
/// the host's own executor and resolves it. Any failure (unreadable file,
/// unparseable content) falls back to `Generic` and never fails the scan.
async fn detect_host_profile(executor: &dyn hardener_core::SystemExecutor) -> ComplianceProfile {
    if let Ok(content) = executor
        .read_file(std::path::Path::new("/etc/os-release"))
        .await
        && let Ok(distro) = Distribution::from_os_release(&content)
    {
        resolve_profile(&distro)
    } else {
        ComplianceProfile::Generic
    }
}

/// Number of hosts scanned concurrently in a fleet scan.
const FLEET_CONCURRENCY: usize = 8;

/// Scans many hosts concurrently, isolating per-host failure and preserving
/// input order. `scan_one` produces one host's resolved compliance profile and
/// scan results (or an error that becomes a `Failed` row). Each row carries the
/// profile it was scanned under in `FleetHostScan::profile`: it drives posture
/// scoring, travels to the UI as the scheme that scored the row, and is
/// `Generic` for failed hosts. `on_progress` fires once per completed host, in
/// completion order, with (host row, completed count, total): the UI's live
/// progress hook. Generic so the orchestration is unit-testable without real
/// SSH or a Tauri app handle.
///
/// ponytail: a spawned task that *panics* (rather than returning `Err`) keeps
/// its pre-filled `Failed` slot, so the result always has exactly one row per
/// input host in input order, never a silently dropped host (panicked tasks
/// emit no progress event; the scan still ends because the invoke resolves).
async fn scan_fleet<F, Fut>(
    host_names: Vec<String>,
    scan_one: F,
    mut on_progress: impl FnMut(&FleetHostScan, usize, usize),
) -> Vec<FleetHostScan>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<(ComplianceProfile, Vec<ScanResult>), String>>
        + Send
        + 'static,
{
    let total = host_names.len();
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(FLEET_CONCURRENCY));
    let mut set = tokio::task::JoinSet::new();

    // One placeholder row per host, overwritten as tasks complete. A panicked
    // task leaves its placeholder, preserving the one-row-per-host contract.
    let mut ordered: Vec<FleetHostScan> = host_names
        .iter()
        .map(|name| FleetHostScan {
            host_name: name.clone(),
            status: FleetHostStatus::Failed("scan task panicked".to_string()),
            tallies: SeverityTallies::default(),
            scan_results: Vec::new(),
            compliance: Vec::new(),
            profile: ComplianceProfile::Generic,
        })
        .collect();

    for (index, name) in host_names.into_iter().enumerate() {
        let permits = semaphore.clone();
        let task = scan_one(name.clone());
        set.spawn(async move {
            let _permit = permits.acquire_owned().await;
            let (profile, status, scan_results) = match task.await {
                Ok((profile, results)) => (profile, FleetHostStatus::Ok, results),
                Err(e) => (
                    ComplianceProfile::Generic,
                    FleetHostStatus::Failed(e),
                    Vec::new(),
                ),
            };
            (
                index,
                FleetHostScan {
                    host_name: name,
                    tallies: SeverityTallies::from_results(&scan_results),
                    status,
                    scan_results,
                    compliance: Vec::new(),
                    profile,
                },
            )
        });
    }

    let mut completed = 0;
    while let Some(joined) = set.join_next().await {
        if let Ok((index, scan)) = joined {
            completed += 1;
            on_progress(&scan, completed, total);
            ordered[index] = scan;
        }
    }
    ordered
}

/// Scans a remote host using the active SSH connection.
///
/// Uses the `SshExecutor` from `RemoteState` instead of the local executor.
/// Results are returned in-memory only (not persisted to scan history).
#[tauri::command]
pub async fn run_remote_scan(
    plugin_ids: Option<Vec<String>>,
    state: tauri::State<'_, RemoteState>,
) -> Result<Vec<ScanResult>, String> {
    if let Some(ref ids) = plugin_ids {
        validate_plugin_ids(ids)?;
    }

    // Clone the Arc<SshExecutor> out of the mutex before any async work.
    let executor = {
        let connection = state.active_connection.lock().await;
        match connection.as_ref() {
            Some(conn) => conn.executor.clone(),
            None => return Err("No active remote connection".to_string()),
        }
    };

    scan_with_executor(executor, plugin_ids.as_deref()).await
}

/// Frameworks the fleet view scores against.
/// ISO 27001 is deliberately omitted; add it here to include it.
const FLEET_FRAMEWORKS: [ComplianceFramework; 9] = [
    ComplianceFramework::CIS,
    ComplianceFramework::STIG,
    ComplianceFramework::NIST,
    ComplianceFramework::PCIDSS,
    ComplianceFramework::HIPAA,
    ComplianceFramework::GDPR,
    ComplianceFramework::SOC2,
    ComplianceFramework::NIST800171,
    ComplianceFramework::FedRAMP,
];

/// Builds the report generator used for fleet compliance scoring (all
/// `FLEET_FRAMEWORKS` in one pass) under one host's resolved profile and
/// identity. Built per host: profiles differ across a mixed fleet, so callers
/// fetch coverage once and clone it per host (cheap at fleet scale).
///
/// `exclusions` is this controller's `[compliance]` section: one file
/// describing a fleet. `ScopeExclusion` carries a `hosts` list precisely
/// because an exclusion is a claim about particular systems, so the set is
/// handed over whole and `host` decides which of its entries reach this
/// report. An untargeted declaration is a claim about the estate and applies
/// everywhere; a targeted one reaches only the hosts it names.
fn fleet_report_generator(
    profile: ComplianceProfile,
    inventory: hardener_types::PluginInventory,
    exclusions: ComplianceConfig,
    host: &RemoteHostProfile,
) -> ReportGenerator {
    let config = ReportConfig {
        scenario: Scenario::Custom(FLEET_FRAMEWORKS.to_vec()),
        formats: vec![OutputFormat::Text],
        output_dir: None,
        profile,
    };
    ReportGenerator::new(config, inventory, exclusions).for_host(
        host.target(),
        host.hostname.clone(),
        host.name.clone(),
    )
}

/// Derives slim per-framework posture for one host's findings and the checks
/// its scan could not evaluate (which must not auto-pass). In-memory; no SSH.
fn posture_for_findings(
    generator: &ReportGenerator,
    results: &[ScanResult],
) -> Vec<FleetFrameworkPosture> {
    generator
        .generate(results, &[])
        .into_iter()
        .map(|r| FleetFrameworkPosture {
            framework: r.report_framework,
            // Built before `summary` is moved out, and from the same report, so
            // the rows and the counts describe one generation rather than two.
            controls: r.report_controls.iter().map(ControlOutcome::from).collect(),
            summary: r.report_summary,
        })
        .collect()
}

/// Parses and validates one ad-hoc `user@host[:port]` target. Rejects an empty
/// hostname, a leading `-` (which ssh would otherwise read as an option), and
/// stray punctuation (space/comma) via `RemoteHostProfile::is_valid_hostname` -
/// the same predicate the desktop client uses, so both guards stay mirrored.
fn adhoc_profile(target: &str) -> Result<RemoteHostProfile, String> {
    validate_ipc_string(target, "adhoc_target")?;
    let profile = RemoteHostProfile::from_target(target.trim(), 22, None, true);
    if !RemoteHostProfile::is_valid_hostname(&profile.hostname) {
        return Err(format!(
            "Invalid ad-hoc target '{target}': invalid hostname"
        ));
    }
    Ok(profile)
}

/// How long a remote connection may take to establish, for every host the
/// desktop reaches: one saved profile or eight fleet hosts at once.
const REMOTE_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Builds the core SSH config for one host profile. The single place the
/// desktop turns a profile into a connection, shared by `connect_remote` and
/// the fleet scan: `host_key_checking` decides `Strict` against `Accept`, and
/// no caller can drift on which way round that goes.
fn ssh_config_for(profile: &RemoteHostProfile) -> hardener_core::SshConfig {
    hardener_core::SshConfig {
        host: profile.hostname.clone(),
        port: profile.port,
        user: profile.user.clone(),
        identity_file: profile.key_file.clone(),
        known_hosts: if profile.host_key_checking {
            hardener_core::KnownHosts::Strict
        } else {
            hardener_core::KnownHosts::Accept
        },
        connect_timeout: REMOTE_CONNECT_TIMEOUT,
    }
}

/// Resolves a fleet scan's targets into one profile per row, keyed the way the
/// rows are named: inventory hosts by their profile name, ad-hoc ones by the
/// full `user@host[:port]` string as typed, which is also the history key.
///
/// An inventory host keeps precedence over an ad-hoc target that happens to
/// spell its name, because the saved profile carries the real hostname, port,
/// user and key file that parsing a bare name cannot recover. An unparseable
/// ad-hoc target fails the whole scan rather than being dropped: a silently
/// skipped host reads as a host with nothing to report.
fn fleet_targets(
    hosts: Vec<RemoteHostProfile>,
    adhoc: &[String],
) -> Result<std::collections::HashMap<String, RemoteHostProfile>, String> {
    let mut profiles: std::collections::HashMap<String, RemoteHostProfile> =
        hosts.into_iter().map(|h| (h.name.clone(), h)).collect();
    for target in adhoc {
        let profile = adhoc_profile(target)?;
        profiles.entry(target.clone()).or_insert(profile);
    }
    Ok(profiles)
}

/// The rows a fleet scan produces: in order, and one per host rather than one
/// per mention of a host.
///
/// [`fleet_targets`] has already decided that an inventory host and an ad-hoc
/// target spelling its name are the same host, and
/// `fleet_targets_lets_an_inventory_host_win_a_name_collision` pins that
/// decision. The names reaching [`scan_fleet`] used to carry a different one:
/// the two lists were chained, so a host named in both appeared twice, was
/// connected to twice, scanned twice over two SSH sessions, counted twice in
/// the progress total, and rendered as two rows a reader had no way to tell
/// apart. `scan_fleet` builds one row per entry and calls that "the
/// one-row-per-host contract", which holds only when the entries are hosts.
///
/// Inventory names come first, so the spelling that survives is the one whose
/// profile `fleet_targets` kept, and the row is named the way its profile is
/// keyed.
fn fleet_row_names(host_names: Vec<String>, adhoc: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    host_names
        .into_iter()
        .chain(adhoc)
        .filter(|name| seen.insert(name.clone()))
        .collect()
}

/// Derives each scanned host's compliance posture from the findings already in
/// hand: in memory, with no second trip over SSH. A host that failed keeps an
/// empty posture, because a score derived from no findings is a claim about a
/// host nobody assessed rather than a clean bill of health.
///
/// Flattening goes through `flatten_scan_results`, the same path the local
/// compliance tab uses, and not a hand-written pass over `scan_results`. A
/// fleet scan does not always come back with every plugin: the caller may have
/// filtered to a subset with `plugin_ids`, and `scan_with_executor` skips one
/// whose registry lookup does not return it. Those plugins report nothing, and
/// nothing is exactly what a control needs to look clean, so every registered
/// plugin missing from a row contributes an unassessed entry and its controls
/// report ManualReview. Flattened by hand this said nothing, and a row scanned
/// with one plugin reported the same 38 passing CIS controls as a row scanned
/// with all eight.
///
/// **A plugin whose scan errored is not one of those cases**, though this said
/// it was until 2026-08-28. `scan_with_executor` records the failure through
/// `recorded_scan` and pushes it, so it is present with `scan_success` false,
/// and `scan_evidence::flatten` gives it a `ScanIncomplete` entry carrying its
/// error rather than the `NotCovered` it gives an absent one. The same wrong
/// sentence was corrected in the fleet test's doc on 2026-08-27 and left
/// standing here, which is what a second copy does.
///
/// `coverage` and `exclusions` are passed in rather than read here, so the
/// caller does the one disk read and this stays a pure function of its inputs.
/// Each host is scored under its own resolved `ComplianceProfile` and its own
/// identity: the identity decides which host-targeted exclusions apply, so a
/// row scored under the wrong one silently gains or loses its operator's
/// declarations. A row exists because `profiles` produced the profile it was
/// scanned with, so the lookup resolves; the fallback keeps the arm gated by
/// the display name rather than leaving it ungated.
fn attach_compliance(
    results: &mut [FleetHostScan],
    profiles: &std::collections::HashMap<String, RemoteHostProfile>,
    inventory: hardener_types::PluginInventory,
    exclusions: ComplianceConfig,
) {
    for host in results
        .iter_mut()
        .filter(|h| matches!(h.status, FleetHostStatus::Ok))
    {
        let identity = profiles
            .get(&host.host_name)
            .cloned()
            .unwrap_or_else(|| RemoteHostProfile::from_target(&host.host_name, 22, None, true));
        let generator = fleet_report_generator(
            host.profile,
            inventory.clone(),
            exclusions.clone(),
            &identity,
        );
        host.compliance = posture_for_findings(&generator, &host.scan_results);
    }
}

/// Scans several hosts concurrently and returns each host's severity posture:
/// saved inventory hosts by name plus ad-hoc `user@host[:port]` targets.
/// Read-only: opens a short-lived SSH connection per host, scans, and drops it.
/// Per-host failure is isolated: a failed host is a `Failed` row whilst the
/// others still complete.
#[tauri::command]
pub async fn run_fleet_scan(
    host_names: Vec<String>,
    adhoc: Option<Vec<String>>,
    plugin_ids: Option<Vec<String>>,
    app: tauri::AppHandle,
) -> Result<Vec<FleetHostScan>, String> {
    if let Some(ref ids) = plugin_ids {
        validate_plugin_ids(ids)?;
    }
    for name in &host_names {
        validate_ipc_string(name, "host_name")?;
    }
    let adhoc = adhoc.unwrap_or_default();

    // One profile lookup, built once and shared, because the scan closure takes
    // ownership of what it captures and the compliance pass below needs the
    // same identities to resolve host-targeted exclusions.
    let config = load_hosts_config()?;
    let profiles = fleet_targets(config.hosts, &adhoc)?;

    let plugin_ids = std::sync::Arc::new(plugin_ids);
    let profiles = std::sync::Arc::new(profiles);
    let scan_profiles = profiles.clone();

    // Ad-hoc rows keep the full target string as their display name, and a host
    // named in both lists gets one row, matching the single key `fleet_targets`
    // gave it.
    let all_names = fleet_row_names(host_names, adhoc);

    // Best-effort live progress: a dead listener must never fail the scan.
    let on_progress = move |scan: &FleetHostScan, done: usize, total: usize| {
        use tauri::Emitter;
        let _ = app.emit(
            FLEET_PROGRESS_EVENT,
            FleetProgress {
                host: scan.host_name.clone(),
                done,
                total,
                failed: matches!(scan.status, FleetHostStatus::Failed(_)),
            },
        );
    };

    let mut results = scan_fleet(
        all_names,
        move |name| {
            let profile = scan_profiles.get(&name).cloned();
            let plugin_ids = plugin_ids.clone();
            async move {
                let profile =
                    profile.ok_or_else(|| format!("Host profile '{}' not found", name))?;

                let ssh_config = ssh_config_for(&profile);

                let executor = std::sync::Arc::new(
                    hardener_core::SshExecutor::connect(ssh_config)
                        .await
                        .map_err(safe_err)?,
                );

                let results = scan_with_executor(executor.clone(), plugin_ids.as_deref()).await?;
                // The connection is still open: resolve the host's own
                // compliance profile from its /etc/os-release while it is.
                Ok((detect_host_profile(executor.as_ref()).await, results))
            }
        },
        on_progress,
    )
    .await;

    attach_compliance(
        &mut results,
        &profiles,
        hardener_plugins::plugin_inventory(),
        local_exclusions(),
    );

    Ok(results)
}

// ---------------------------------------------------------------------------
// Scheduler configuration
// ---------------------------------------------------------------------------

/// Reads the [scheduler] section from config.toml and returns it as SchedulerUiConfig.
#[tauri::command]
pub async fn get_scheduler_config() -> Result<hardener_types::scheduler::SchedulerUiConfig, String>
{
    let path = hardener_config_path()?;
    if !path.exists() {
        return Ok(hardener_types::scheduler::SchedulerUiConfig::default());
    }

    let content = std::fs::read_to_string(&path)
        .map_err(|e| safe_err(format!("Failed to read config: {e}")))?;

    #[derive(serde::Deserialize)]
    struct ConfigFile {
        #[serde(default)]
        scheduler: hardener_types::scheduler::SchedulerUiConfig,
    }

    let config: ConfigFile =
        toml::from_str(&content).map_err(|e| safe_err(format!("Failed to parse config: {e}")))?;

    Ok(config.scheduler)
}

/// Saves the scheduler section to config.toml without disturbing other sections.
///
/// Uses `toml_edit` to perform a targeted update of only the `[scheduler]` table,
/// preserving comments, formatting, and unrelated sections.
#[tauri::command]
pub async fn save_scheduler_config(
    config: hardener_types::scheduler::SchedulerUiConfig,
) -> Result<String, String> {
    validate_ipc_string(&config.schedule, "schedule")?;
    for plugin in &config.plugins {
        validate_ipc_string(plugin, "scheduler_plugin")?;
    }
    validate_ipc_string(&config.notifications.webhooks.url, "webhook_url")?;
    validate_ipc_string(&config.notifications.email.from_address, "from_address")?;
    for recipient in &config.notifications.email.recipients {
        validate_ipc_string(recipient, "email_recipient")?;
    }
    crate::validation::validate_notification_channels(&config.notifications)?;

    let write_path = writable_config_path()?;

    if let Some(parent) = write_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| safe_err(format!("Failed to create config directory: {e}")))?;
    }

    // Read existing config (user file first, fall back to system config as template)
    let content = if write_path.exists() {
        std::fs::read_to_string(&write_path)
            .map_err(|e| safe_err(format!("Failed to read config: {e}")))?
    } else {
        hardener_config_path()
            .ok()
            .filter(|p| p.exists())
            .and_then(|p| std::fs::read_to_string(p).ok())
            .unwrap_or_default()
    };

    let logger = get_audit_logger().await;
    write_scheduler_config(&write_path, &content, &config, logger.as_ref()).await?;

    Ok("Configuration saved".to_string())
}

/// Rewrites `[scheduler]` inside `existing` and writes the result to
/// `write_path`, filing the entry that says what changed.
///
/// Takes the path, the document it is editing and the logger as arguments
/// rather than resolving any of them, which is the whole reason this is
/// separate from [`save_scheduler_config`]. That command reads both paths from
/// the process environment, so a test driving it would have to move
/// `XDG_CONFIG_HOME` while every other test in this binary is running in a
/// thread beside it. Here the join between the descriptor and the write is
/// observable without touching the environment at all.
async fn write_scheduler_config(
    write_path: &std::path::Path,
    existing: &str,
    config: &hardener_types::scheduler::SchedulerUiConfig,
    logger: Option<&hardener_state::audit::AuditLogger>,
) -> Result<(), String> {
    let mut document: toml_edit::DocumentMut = existing
        .parse()
        .map_err(|e| safe_err(format!("Failed to parse config: {e}")))?;

    // Remove existing scheduler section, serialise the rest, then append
    // a properly grouped [scheduler] block at the end.  toml_edit scatters
    // dotted subtables ([scheduler.notifications.*]) between unrelated
    // sections when assigned via the Table API, so we build the block as
    // a plain string instead.
    document.remove("scheduler");
    let mut output = document.to_string();

    output.push_str(&render_scheduler_section(config, existing)?);

    // Through the shared writer, which is what makes this atomic, makes it
    // preserve the target's mode, and files the audit entry. Before the writer
    // moved into `hardener-core` this was a bare `std::fs::write` recording
    // nothing, not by decision but because `hardener-cli` is a binary and the
    // code that would have done otherwise could not be reached from here.
    write_atomically(
        write_path,
        &output,
        WriteAudit {
            logger,
            action: ActionType::ConfigChange,
            target: "scheduler".to_string(),
            details: scheduler_details(config),
        },
    )
    .await
    .map_err(|e| safe_err(format!("Failed to write config: {e:#}")))
}

/// The audit detail for a scheduler change.
///
/// What an auditor needs is which scans this host now runs unattended and who
/// hears about them, so the schedule, the plugin set and the reporting
/// thresholds all go in. `enabled` first, because turning the scheduler off is
/// the change most easily mistaken for nothing having happened.
///
/// Recipient addresses and the webhook URL are deliberately left out. Whether a
/// channel is on is what changed; the addresses are in the config file, and
/// copying them into an append-only log spreads personal data for no audit
/// question they answer.
fn scheduler_details(
    config: &hardener_types::scheduler::SchedulerUiConfig,
) -> std::collections::HashMap<String, String> {
    std::collections::HashMap::from([
        ("enabled".to_string(), config.enabled.to_string()),
        ("schedule".to_string(), config.schedule.clone()),
        ("plugins".to_string(), config.plugins.join(",")),
        ("min_severity".to_string(), config.min_severity.clone()),
        (
            "notify_min_severity".to_string(),
            config.notifications.notify_min_severity.clone(),
        ),
        (
            "email_enabled".to_string(),
            config.notifications.email.enabled.to_string(),
        ),
        (
            "webhook_enabled".to_string(),
            config.notifications.webhooks.enabled.to_string(),
        ),
    ])
}

/// The `[scheduler]` table already in a config file, or an empty one.
///
/// Fails closed. Returning an empty table on a parse error would be the very
/// defect this merge exists to fix, silently and with no bad input required:
/// every key the form does not model would be dropped on the next save. The
/// caller has already parsed the same text with `toml_edit`, so an error here
/// means the two parsers disagree, and refusing the save is the only answer
/// that cannot lose the operator's settings.
///
/// Empty content is not an error, it is a new file with nothing to preserve.
fn existing_scheduler_table(content: &str) -> Result<toml::Value, String> {
    let document: toml::Value = toml::from_str(content).map_err(|e| {
        safe_err(format!(
            "Failed to read the existing scheduler section: {e}"
        ))
    })?;
    Ok(document
        .get("scheduler")
        .cloned()
        .filter(toml::Value::is_table)
        .unwrap_or_else(|| toml::Value::Table(toml::map::Map::new())))
}

/// Writes `incoming` over `destination`, keeping keys `incoming` does not name.
///
/// Deliberately generic rather than a list of fields to carry across. The whole
/// defect was that the desktop's type models a subset of the scheduler's and the
/// save replaced the section wholesale, so a hardcoded list would have to be
/// remembered every time the backend gains a key, which is the same failure one
/// step later. A key the form does not emit is a key the form does not own.
///
/// Tables merge; every other value, arrays included, is replaced. That is what
/// makes `plugins`, `recipients` and the webhook `endpoints` list editable: the
/// form does emit those, including as an empty array, so clearing one in the GUI
/// clears it in the file.
fn overlay(destination: &mut toml::Value, incoming: toml::Value) {
    match incoming {
        toml::Value::Table(incoming_table) if destination.is_table() => {
            let destination_table = destination
                .as_table_mut()
                .expect("the guard above proved this is a table");
            for (key, value) in incoming_table {
                match destination_table.get_mut(&key) {
                    Some(slot) => overlay(slot, value),
                    None => {
                        destination_table.insert(key, value);
                    }
                }
            }
        }
        other => *destination = other,
    }
}

/// Renders the desktop's scheduler settings as a `[scheduler]` block.
///
/// A seam, not decoration: what the desktop writes has to be what the scheduler
/// reads, and until now nothing checked that. `WebhookUiConfig` rendered a flat
/// `url`/`format` pair into a table whose backend struct expects `endpoints`,
/// nothing rejects an unknown key, and so a saved webhook reached the daemon as
/// an empty list. Testing it through the real `SchedulerConfig` is the only
/// assertion that could have failed.
fn render_scheduler_section(
    config: &hardener_types::scheduler::SchedulerUiConfig,
    existing: &str,
) -> Result<String, String> {
    let mut merged = existing_scheduler_table(existing)?;
    let incoming = toml::Value::try_from(config)
        .map_err(|e| safe_err(format!("Failed to serialise scheduler config: {e}")))?;
    overlay(&mut merged, incoming);
    drop_superseded_webhook_keys(&mut merged);

    // Serialised nested under its own key, so the serialiser emits
    // `[scheduler]` and `[scheduler.notifications.email]` itself. This replaced
    // a pass that re-prefixed each rendered header textually, which could not
    // tell a header from a line of a multi-line string beginning with `[`: it
    // rewrote those too, and since the merge now carries every existing string
    // through, each save nested the mangled value one level deeper than the
    // last. Letting the serialiser name the tables removes the question.
    let mut wrapper = toml::map::Map::new();
    wrapper.insert("scheduler".to_string(), merged);
    let rendered = toml::to_string_pretty(&toml::Value::Table(wrapper))
        .map_err(|e| safe_err(format!("Failed to serialise scheduler config: {e}")))?;

    Ok(format!("\n{rendered}"))
}

/// Removes the flat webhook keys earlier desktop builds wrote.
///
/// `WebhookWire` stopped emitting `url`/`format`, which was enough to retire
/// them while the save replaced the whole section. Under the merge it is not:
/// a key the form does not emit is a key the form keeps, so they would survive
/// every save, and the read path prefers them whenever the endpoint list is
/// empty. Clearing the URL in the GUI wrote `endpoints = []`, the next load
/// showed the deleted URL again, and the save after that promoted it back to a
/// live endpoint the daemon posts to.
///
/// Narrow on purpose: these two are the desktop's own historical spelling of a
/// setting it still owns, and nothing in `hardener-scheduler` has ever read
/// them. They are the exception that proves the ownership rule rather than a
/// hole in it.
fn drop_superseded_webhook_keys(scheduler: &mut toml::Value) {
    let Some(webhooks) = scheduler
        .get_mut("notifications")
        .and_then(|notifications| notifications.get_mut("webhooks"))
        .and_then(toml::Value::as_table_mut)
    else {
        return;
    };
    webhooks.remove("url");
    webhooks.remove("format");
}

/// Reduces one result per channel to the single line the settings pane shows.
///
/// A plain function over plain types, for the reason `summarise_config` is one:
/// the command around it needs a config file, a temporary database and a live
/// dispatcher, and none of that is the decision. The decision is what to tell
/// an operator who pressed "send test" and is waiting to learn whether their
/// notification setup works.
///
/// **Every message names its channels.** `NotificationResult::channel` is
/// populated by both notifiers, and by the webhook one per endpoint, which is
/// only worth doing if a reader sees it. It was dropped here until 2026-08-26,
/// so a host with email and three webhooks configured was told
/// "Failed: connection refused" and could not tell which of the four it was.
///
/// **A failure with no reason recorded is still a failure.** The reasons used
/// to be collected with a `filter_map` over `error`, which drops a row it
/// cannot describe, so a channel that failed without a message would have been
/// counted into `results.len()` and reported as sent. Nothing builds such a row
/// today, because `NotificationResult::failed` is the only constructor that
/// sets `success: false` and it always carries a reason. The fields are `pub`
/// though, so that is a property of the current call sites rather than of the
/// type, and the failing direction is the one that hides.
fn test_notification_verdict(
    results: &[hardener_scheduler::notification::NotificationResult],
) -> hardener_types::scheduler::TestNotificationResult {
    if results.is_empty() {
        return hardener_types::scheduler::TestNotificationResult {
            success: false,
            message: "No notification channels are enabled".into(),
        };
    }

    let failures: Vec<String> = results
        .iter()
        .filter(|r| !r.success)
        .map(|r| {
            let reason = r.error.as_deref().unwrap_or("failed, no reason recorded");
            format!("{}: {reason}", r.channel)
        })
        .collect();

    if failures.is_empty() {
        let names: Vec<&str> = results.iter().map(|r| r.channel.as_str()).collect();
        return hardener_types::scheduler::TestNotificationResult {
            success: true,
            message: format!("Test sent to {}", names.join(", ")),
        };
    }

    hardener_types::scheduler::TestNotificationResult {
        success: false,
        message: format!(
            "{} of {} channels failed. {}",
            failures.len(),
            results.len(),
            failures.join("; ")
        ),
    }
}

/// Sends a test notification through all enabled channels.
///
/// Creates a temporary database so the test doesn't pollute real scan history.
/// Returns a success/failure summary suitable for display in the GUI.
#[tauri::command]
pub async fn test_notification() -> Result<hardener_types::scheduler::TestNotificationResult, String>
{
    let _guard = PrivilegedOpGuard::acquire()?;
    let path = hardener_config_path()?;
    let scheduler_config = if path.exists() {
        let content = std::fs::read_to_string(&path)
            .map_err(|e| safe_err(format!("Failed to read config: {e}")))?;

        #[derive(serde::Deserialize)]
        struct ConfigFile {
            #[serde(default)]
            scheduler: hardener_scheduler::SchedulerConfig,
        }

        let config: ConfigFile = toml::from_str(&content)
            .map_err(|e| safe_err(format!("Failed to parse config: {e}")))?;
        config.scheduler
    } else {
        hardener_scheduler::SchedulerConfig::default()
    };

    // Create temporary database for notification logging
    let tmp_dir =
        tempfile::tempdir().map_err(|e| safe_err(format!("Failed to create temp dir: {e}")))?;
    let db_manager = hardener_scheduler::ScanHistoryManager::new(&tmp_dir.path().join("test.db"))
        .await
        .map_err(|e| safe_err(format!("Failed to create temp DB: {e}")))?;

    let summary = hardener_scheduler::ScanSummary {
        session_id: "test-notification".into(),
        host: hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".into()),
        plugins_scanned: vec!["test".into()],
        total_findings: 1,
        critical_count: 0,
        high_count: 1,
        medium_count: 0,
        low_count: 0,
        info_count: 0,
        json_path: None,
        json_hash: None,
        had_errors: false,
        regression: None,
    };

    let dispatcher = hardener_scheduler::NotificationDispatcher::new(
        &scheduler_config.notifications,
        std::sync::Arc::new(db_manager),
    );

    Ok(test_notification_verdict(
        &dispatcher.send_test(&summary).await,
    ))
}

/// The config file's own eight plugin sections, each under the plugin id that
/// owns it.
///
/// These are fields of `HardenerConfig` rather than a second copy of the
/// registry, so naming them here is the only way to walk them. The ids must
/// still match `get_plugin_config`'s arms, which is what
/// `every_section_id_resolves_to_its_own_section` pins: an id that drifts
/// falls through to that function's empty default, which reports enabled
/// whatever the file says.
fn plugin_sections(config: &HardenerConfig) -> [(&'static str, &PluginConfig); 8] {
    [
        ("kernel-hardening", &config.kernel),
        ("ssh-hardening", &config.ssh),
        ("firewall-hardening", &config.firewall),
        ("pam-hardening", &config.pam),
        ("service-minimisation", &config.services),
        ("audit-hardening", &config.audit),
        ("permissions-hardening", &config.permissions),
        ("mac-hardening", &config.mac),
    ]
}

/// Describes a loaded config the way the picker card reports it.
///
/// Split from the command so the decision can be driven: the command itself
/// only resolves a path and reads a file.
///
/// **The enabled set is the one that will actually run.** It used to be each
/// section's own `enabled` flag, which is one of the three things the real
/// gate reads: `is_plugin_enabled` also honours `global.disabled_plugins` and
/// the `global.enabled_plugins` allow list. So a config narrowing the set
/// globally still reported all eight, and the card an operator reads to
/// confirm they picked the right file said "8 plugins" for a file that runs
/// one. It could only ever over-report, never claim a plugin was off while it
/// ran, because a section disabled by its own flag fails the wider gate too.
///
/// `apply_accepts` is passed in rather than asked here, for the reason
/// `write_scheduler_config` takes its logger as an argument. The question is
/// answered by `validate_privileged_config_path`, which canonicalises and reads
/// `dirs::config_dir()`, so asking it inside this function would tie every test
/// of the summary to the filesystem and to `$HOME`. **A ceiling worth naming:
/// the refusing direction is drivable and the accepting one is not.** Any path
/// a test can create lies outside both allowed directories, so proving the
/// `true` arm end to end would mean moving `HOME` while the rest of this
/// binary's tests run in threads beside it. The join is one line in
/// `validate_config`.
fn summarise_config(path: String, config: &HardenerConfig, apply_accepts: bool) -> ConfigSummary {
    let sections = plugin_sections(config);

    ConfigSummary {
        config_path: path,
        config_is_valid: true,
        config_error: None,
        config_apply_accepts: apply_accepts,
        config_enabled_plugins: sections
            .iter()
            .filter(|(id, _)| config.is_plugin_enabled(id))
            .map(|(id, _)| (*id).to_string())
            .collect(),
        // Counts describe what the file declares, enabled or not: this is the
        // "3 directives" on the card, not a prediction of what will apply.
        config_directive_count: sections
            .iter()
            .map(|(_, section)| section.directives.len() as u32)
            .sum(),
        config_exception_count: sections
            .iter()
            .map(|(_, section)| section.exceptions.len() as u32)
            .sum(),
    }
}

/// Validates a config file and returns a summary of its contents.
///
/// Parses the TOML file using `ConfigLoader` and counts plugins, directives
/// and exceptions. Returns error details if invalid. The summary itself is
/// built by [`summarise_config`], which is where the decisions live.
///
/// Validates by the user rule and reports the privileged one. The card an
/// operator reads before pressing anything is the only place both answers are
/// available at once, and asking the escalating commands' own validator is what
/// stops this becoming a third statement of where a config may live.
#[tauri::command]
pub async fn validate_config(path: String) -> Result<ConfigSummary, String> {
    validate_user_config_path(&path)?;
    let apply_accepts = validate_privileged_config_path(&path).is_ok();

    use hardener_core::ConfigLoader;

    let file_path = std::path::PathBuf::from(&path);

    // Carried into both failure arms as well, so the field never says "apply
    // would refuse this path" on the strength of a `Default` when the reason
    // the summary failed is the file's contents. A broken config inside
    // `~/.config/linux-hardener/` is one the escalating commands accept by path
    // and reject by parse, and those are different sentences.
    if !file_path.exists() {
        return Ok(ConfigSummary {
            config_path: path,
            config_is_valid: false,
            config_error: Some("File not found".to_string()),
            config_apply_accepts: apply_accepts,
            ..Default::default()
        });
    }

    let loader = ConfigLoader::new()
        .skip_defaults()
        .with_cli_config(file_path);

    match loader.load() {
        Ok(config) => Ok(summarise_config(path, &config, apply_accepts)),
        Err(e) => Ok(ConfigSummary {
            config_path: path,
            config_is_valid: false,
            config_error: Some(e.to_string()),
            config_apply_accepts: apply_accepts,
            ..Default::default()
        }),
    }
}

/// Opens a native file dialog for selecting a TOML config file.
///
/// Returns the selected file path, or None if the dialog was cancelled.
#[tauri::command]
pub async fn pick_config_file(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;

    let file_path = app
        .dialog()
        .file()
        .add_filter("TOML Config", &["toml"])
        .set_title("Select Configuration File")
        .blocking_pick_file();

    Ok(file_path.map(|p| p.to_string()))
}

// ---------------------------------------------------------------------------
// Per-host history (scheduler database)
// ---------------------------------------------------------------------------

/// Resolves the scheduler history database path: the `[scheduler]` section of
/// the hardener config when present, else the scheduler default. Matches the
/// CLI's resolution so the GUI reads the history `batch scan` writes.
fn scheduler_db_path() -> Result<std::path::PathBuf, String> {
    #[derive(serde::Deserialize)]
    struct ConfigFile {
        #[serde(default)]
        scheduler: hardener_scheduler::SchedulerConfig,
    }

    let path = hardener_config_path()?;
    if path.exists()
        && let Ok(content) = std::fs::read_to_string(&path)
        && let Ok(config) = toml::from_str::<ConfigFile>(&content)
    {
        return Ok(config.scheduler.storage.database_path);
    }
    Ok(hardener_scheduler::SchedulerConfig::default()
        .storage
        .database_path)
}

/// Maps newest-first completed sessions to display rows, each carrying a
/// severity-priority direction against the next-older scan. `take` bounds the
/// rows returned; the slice may hold one extra session so the oldest shown row
/// still gets a direction.
fn sessions_to_info(
    sessions: &[hardener_scheduler::db::ScanSession],
    take: usize,
) -> Vec<HostSessionInfo> {
    use hardener_scheduler::db::is_worse;

    sessions
        .iter()
        .take(take)
        .enumerate()
        .map(|(i, s)| {
            let direction = sessions.get(i + 1).map(|prev| {
                if is_worse(prev.severity_tuple(), s.severity_tuple()) {
                    "worse"
                } else if is_worse(s.severity_tuple(), prev.severity_tuple()) {
                    "better"
                } else {
                    "same"
                }
                .to_string()
            });
            HostSessionInfo {
                started: s
                    .started_at_utc()
                    .with_timezone(&chrono::Local)
                    .format("%Y-%m-%d %H:%M")
                    .to_string(),
                status: s.status.clone(),
                total_findings: s.total_findings,
                critical: s.critical_count,
                high: s.high_count,
                medium: s.medium_count,
                low: s.low_count,
                info: s.info_count,
                direction,
            }
        })
        .collect()
}

/// Per-host scan history from the scheduler database. Written by `batch scan`
/// and scheduled scans; GUI fleet scans are in-memory and do not persist
/// here. `host` is the inventory name or the canonical ad-hoc target.
#[tauri::command]
pub async fn get_host_history(
    host: String,
    limit: Option<u32>,
) -> Result<Vec<HostSessionInfo>, String> {
    validate_ipc_string(&host, "host")?;
    let take = limit.unwrap_or(10).min(100);

    let db = hardener_scheduler::ScanHistoryManager::new(&scheduler_db_path()?)
        .await
        .map_err(safe_err)?;
    let filter = hardener_scheduler::db::SessionFilter {
        host: Some(host),
        status: Some("completed".to_string()),
        // One extra row so the oldest displayed scan still gets a direction.
        limit: Some(take + 1),
        ..Default::default()
    };
    let sessions = db.list_sessions(&filter).await.map_err(safe_err)?;
    Ok(sessions_to_info(&sessions, take as usize))
}

// ---------------------------------------------------------------------------
// Fleet apply / rollback
// ---------------------------------------------------------------------------

/// Runs a fleet apply via the audited CLI. `execute = false` is a dry-run
/// (preview); `true` mutates. JSON is read regardless of exit code: tiered
/// exit codes carry per-host results.
#[tauri::command]
pub async fn run_fleet_apply(
    hosts: Vec<String>,
    adhoc: Option<Vec<String>>,
    plugins: Vec<String>,
    execute: bool,
) -> Result<Vec<ApplyOutcome>, String> {
    run_fleet_mutation("apply", hosts, adhoc.unwrap_or_default(), plugins, execute).await
}

/// Runs a fleet rollback via the audited CLI. `execute = false` previews.
#[tauri::command]
pub async fn run_fleet_rollback(
    hosts: Vec<String>,
    adhoc: Option<Vec<String>>,
    plugins: Vec<String>,
    execute: bool,
) -> Result<Vec<RollbackOutcome>, String> {
    run_fleet_mutation(
        "rollback",
        hosts,
        adhoc.unwrap_or_default(),
        plugins,
        execute,
    )
    .await
}

/// Spawns `hardener batch <verb>` and parses its outcome JSON. Shared by apply
/// and rollback. No pkexec: remote hosts authenticate over SSH via the saved
/// inventory profiles (or the ad-hoc targets) the CLI reads, so the local
/// `PrivilegedOpGuard` (which serialises local pkexec mutations) deliberately
/// does not apply here.
async fn run_fleet_mutation<T: serde::de::DeserializeOwned>(
    verb: &str,
    hosts: Vec<String>,
    adhoc: Vec<String>,
    plugins: Vec<String>,
    execute: bool,
) -> Result<Vec<T>, String> {
    if hosts.is_empty() && adhoc.is_empty() {
        return Err("No hosts selected".to_string());
    }
    for h in &hosts {
        validate_ipc_string(h, "host_name")?;
    }
    for t in &adhoc {
        adhoc_profile(t)?;
    }
    validate_plugin_ids(&plugins)?;
    let binary = get_hardener_binary_path()?;
    let args = build_batch_args(verb, &hosts, &adhoc, &plugins, execute);
    let output = Command::new(&binary)
        .args(&args)
        .output()
        .await
        .map_err(|e| safe_err(format!("Failed to run fleet {verb}: {e}")))?;
    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| safe_err(format!("Invalid UTF-8 in CLI output: {e}")))?;
    // Exit code is intentionally NOT checked: tiered codes accompany valid JSON.
    parse_outcomes(&stdout).map_err(|e| {
        let stderr = String::from_utf8_lossy(&output.stderr);
        sanitise_error(&format!("{e}; stderr: {stderr}"))
    })
}

/// Builds the `hardener batch <verb> …` argument vector. `verb` is "apply" or
/// "rollback". Inventory hosts route to `--host`, ad-hoc targets to `--ssh`;
/// all are repeated flags (robust to commas in names). Empty `plugins` ⇒ no
/// `--plugin` (CLI default = all). `--format json` is always set; `--execute`
/// only when `execute`.
fn build_batch_args(
    verb: &str,
    hosts: &[String],
    adhoc: &[String],
    plugins: &[String],
    execute: bool,
) -> Vec<String> {
    let mut args = vec!["batch".to_string(), verb.to_string()];
    for h in hosts {
        args.push("--host".to_string());
        args.push(h.clone());
    }
    for t in adhoc {
        args.push("--ssh".to_string());
        args.push(t.clone());
    }
    for p in plugins {
        args.push("--plugin".to_string());
        args.push(p.clone());
    }
    if execute {
        args.push("--execute".to_string());
    }
    args.push("--format".to_string());
    args.push("json".to_string());
    args
}

/// Parses the JSON outcome array from CLI stdout.
///
/// Exit-code agnostic by design, which is why this is not `accept_json_output`:
/// `batch apply/rollback` exit non-zero on per-host failures yet still print the
/// array, so the array is the source of truth. That is the one difference, and
/// it is why the two cannot merge.
///
/// The leading-bytes skip is tolerance, not a step over anything `batch`
/// writes: it prints the rendered payload to stdout and every message it has to
/// stderr. The comment here used to name "leading info lines" as the reason,
/// which stopped being true when `output::info` moved to stderr. Left in place
/// rather than tightened because the fleet path cannot be exercised outside a
/// container, and a stricter parser is not worth an untested change to the one
/// verb that reaches every host at once.
fn parse_outcomes<T: serde::de::DeserializeOwned>(stdout: &str) -> Result<Vec<T>, String> {
    let start = stdout.find('[').ok_or("No JSON array in CLI output")?;
    serde_json::from_str(&stdout[start..]).map_err(|e| format!("Failed to parse CLI output: {e}"))
}

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
