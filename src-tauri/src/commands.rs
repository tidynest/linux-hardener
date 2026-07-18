use hardener_common::types::{ComplianceFramework, ComplianceMapping, ComplianceProfile};
use hardener_compliance::{
    ComplianceReport, OutputFormat, ReportConfig, ReportGenerator, Scenario,
    output::{
        CsvFormatter, HtmlFormatter, JsonFormatter, PdfFormatter, ReportFormatter, TextFormatter,
    },
    resolve_profile,
};
use hardener_core::{
    ApplyResult, ConfigLoader, Context, Finding, PluginMetadata, ScanResult, ValidationReport,
};
use hardener_distro::Distribution;
use hardener_plugins::create_plugin_registry;
use hardener_state::{
    Checkpoint, CheckpointId, CheckpointManager, CheckpointSigner, FileState, RollbackResult,
    ScanHistoryManager, ScanSession, ScanSessionId, ScanStatus, init_db,
};
use hardener_types::{
    ApplyOutcome, ConfigSummary, FleetFrameworkPosture, FleetHostScan, FleetHostStatus,
    RollbackOutcome, SeverityTallies,
    remote::{
        FLEET_PROGRESS_EVENT, FleetProgress, HostSessionInfo, HostsConfig, RemoteConnectionInfo,
        RemoteConnectionStatus, RemoteHostProfile,
    },
};
use serde::Serialize;
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

impl Drop for PrivilegedOpGuard {
    fn drop(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        PRIVILEGED_OP_LAST_COMPLETED.store(now, Ordering::SeqCst);
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
    #[allow(dead_code)]
    pub info: RemoteConnectionInfo,
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

/// Saves host profiles to the shared inventory file.
fn save_hosts_config(config: &HostsConfig) -> Result<(), String> {
    hardener_core::inventory::save(config).map_err(|e| safe_err(e.to_string()))
}

/// Checkpoint information returned to the frontend.
#[derive(Clone, Debug, Serialize)]
pub struct CheckpointInfo {
    pub checkpoint_id: String,
    pub checkpoint_name: String,
    pub checkpoint_created: String,
    pub checkpoint_user: String,
    /// Whether the checkpoint's signature was successfully verified.
    /// `false` indicates potential tampering or a missing signing key.
    pub checkpoint_verified: bool,
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

/// Raw result of a pkexec-invoked hardener CLI call, before the caller
/// interprets what a non-auth-related exit code means for that verb.
struct PrivilegedOutput {
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
}

/// Runs the hardener CLI under pkexec, resolving the auth-specific outcomes
/// (no polkit agent, user cancelled) but deferring interpretation of every
/// other exit code to the caller. Some verbs (`apply`, `rollback`) print a
/// partial-result JSON payload to stdout before exiting 1 on partial failure,
/// so "non-zero exit" alone cannot mean "no usable output" for them.
async fn run_privileged(args: &[&str]) -> Result<PrivilegedOutput, PrivilegedCommandError> {
    let binary = get_hardener_binary_path().map_err(PrivilegedCommandError::ExecutionFailed)?;
    validate_binary_path(&binary).map_err(PrivilegedCommandError::ExecutionFailed)?;

    tracing::info!("=== Running pkexec {} {:?} ===", binary, args);

    let output = Command::new("/usr/bin/pkexec")
        .arg(&binary)
        .args(args)
        .output()
        .await
        .map_err(|e| PrivilegedCommandError::ExecutionFailed(e.to_string()))?;

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
        exit_code => Ok(PrivilegedOutput {
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

/// Interprets a privileged JSON-emitting command's raw output: accepts the
/// payload on exit 0 always, and on exit 1 only when stdout still parses as
/// `T` (a partial-failure payload). Anything else is a genuine error carrying
/// stderr, sanitised by `PrivilegedCommandError`'s `Display` impl.
fn accept_json_output<T: serde::de::DeserializeOwned>(
    raw: &PrivilegedOutput,
) -> Result<T, PrivilegedCommandError> {
    if exit_code_may_carry_json(raw.exit_code)
        && let Ok(parsed) = serde_json::from_str(&raw.stdout)
    {
        return Ok(parsed);
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
        // Skip plugins not in the filter list (if a filter was provided)
        if let Some(ref ids) = plugin_ids
            && !ids.is_empty()
            && !ids.iter().any(|id| {
                metadata.plugin_id == (*id).clone().into()
                    || metadata.plugin_id.as_str().starts_with(&format!("{}-", id))
            })
        {
            continue;
        }

        // Skip plugins disabled by config
        if !config.is_plugin_enabled(metadata.plugin_id.as_str()) {
            continue;
        }
        // Retrieve the actual plugin
        if let Ok(Some(plugin)) = registry.get(&metadata.plugin_id) {
            match plugin.scan(&ctx).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    error!("Scan failed for plugin {}: {}", metadata.plugin_id, e);
                }
            }
        }
    }

    // Calculate totals for the session
    let total_findings: i32 = results.iter().map(|r| r.scan_findings.len() as i32).sum();
    let total_plugins = results.len() as i32;

    // Persist results to database
    if let Err(e) = history_manager.store_results(&session_id, &results).await {
        error!("Failed to persist scan results: {}", e);
        // Continue anyway - return results even if persistence fails
    }

    // Complete the session
    if let Err(e) = history_manager
        .complete_session(
            &session_id,
            ScanStatus::Completed,
            total_findings,
            total_plugins,
        )
        .await
    {
        error!("Failed to complete scan session: {}", e);
    }

    Ok(results)
}

/// Applies hardening changes for the specified plugins.
///
/// Uses pkexec to run the CLI with root privileges.
/// The user will be prompted for their password via the polkit agent.
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

    // Build CLI arguments
    let mut args: Vec<&str> = vec!["apply", "--format", "json"];

    // Convert plugin_ids to &str for the args
    let plugin_args: Vec<String> = plugin_ids
        .iter()
        .flat_map(|id| vec!["--plugin".to_string(), id.clone()])
        .collect();

    let plugin_refs: Vec<&str> = plugin_args.iter().map(|s| s.as_str()).collect();
    args.extend(plugin_refs);

    // Inject config file path if set
    let config_flag;
    if let Some(ref path) = config_path {
        config_flag = path.clone();
        args.push("--config");
        args.push(&config_flag);
    }

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

    // Build CLI arguments - no pkexec needed for dry-run
    let mut args = vec!["apply", "--dry-run", "--format", "json"];

    // Add plugin arguments
    for id in &plugin_ids {
        args.push("--plugin");
        args.push(id);
    }

    // Inject config file path if set
    let config_flag;
    if let Some(ref path) = config_path {
        config_flag = path.clone();
        args.push("--config");
        args.push(&config_flag);
    }

    // Execute without root privileges (dry-run is read-only)
    let output = Command::new(&binary)
        .args(&args)
        .output()
        .await
        .map_err(|e| safe_err(format!("Failed to execute dry-run: {}", e)))?;

    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| safe_err(format!("Invalid UTF-8 in output: {}", e)))?;

    // Exit 1 with a parseable report array is a partial-failure result, not a
    // transport error: `apply --dry-run` prints the array (skipping any
    // leading info lines, e.g. `{"info": "Dry run..."}`) before `bail!`ing
    // when a plugin's validation errors.
    if exit_code_may_carry_json(output.status.code())
        && let Some(json_start) = stdout.find('[')
        && let Ok(results) = serde_json::from_str::<Vec<ValidationReport>>(&stdout[json_start..])
    {
        return Ok(results);
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(sanitise_error(&format!("Dry-run failed: {}", stderr)))
}

/// Rolls back to a previous checkpoint.
///
/// Uses pkexec to run the CLI with root privileges.
/// Takes a checkpoint ID and restores the system state to that point.
#[tauri::command]
pub async fn run_rollback(
    checkpoint_id: String,
    config_path: Option<String>,
) -> Result<RollbackResult, String> {
    let _guard = PrivilegedOpGuard::acquire()?;
    validate_checkpoint_id(&checkpoint_id)?;
    if let Some(ref path) = config_path {
        validate_privileged_config_path(path)?;
    }

    let mut args: Vec<&str> = vec!["rollback", "--format", "json", "--", &checkpoint_id];

    // Inject config file path if set
    let config_flag;
    if let Some(ref path) = config_path {
        config_flag = path.clone();
        args.push("--config");
        args.push(&config_flag);
    }

    // Exit 1 with a parseable result is a partial-failure rollback, not a
    // transport error: the CLI prints the result before `bail!`ing when any
    // file failed to restore.
    let raw = run_privileged(&args).await.map_err(safe_err)?;
    accept_json_output(&raw).map_err(safe_err)
}

/// Retrieves a list of all available checkpoints from both user and system databases.
///
/// Checkpoints created by the GUI are in the user database, while checkpoints
/// created by privileged CLI operations (via pkexec) are in the system database.
/// This function merges both sources for a complete view.
#[tauri::command]
pub async fn get_checkpoints() -> Result<Vec<CheckpointInfo>, String> {
    let mut entries: Vec<(Checkpoint, CheckpointManager)> = Vec::new();

    // Collect checkpoints from user database
    let user_db = get_user_db_path();
    if user_db.exists()
        && let Ok(manager) = create_checkpoint_manager(&user_db).await
        && let Ok(checkpoints) = manager.list_checkpoints().await
    {
        for cp in checkpoints {
            let Ok(mgr) = create_checkpoint_manager(&user_db).await else {
                continue;
            };
            entries.push((cp, mgr));
        }
    }

    // Collect checkpoints from system database
    let system_db = get_system_db_path();
    if system_db.exists()
        && let Ok(manager) = create_checkpoint_manager(&system_db).await
        && let Ok(checkpoints) = manager.list_checkpoints().await
    {
        for cp in checkpoints {
            if !entries
                .iter()
                .any(|(e, _)| e.checkpoint_id == cp.checkpoint_id)
            {
                let Ok(mgr) = create_checkpoint_manager(&system_db).await else {
                    continue;
                };
                entries.push((cp, mgr));
            }
        }
    }

    // Sort by timestamp descending (newest first)
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

    Ok(result)
}

/// Creates a manual checkpoint of the current system state.
///
/// Requires root privileges via pkexec since it reads protected system files.
#[tauri::command]
pub async fn create_checkpoint(name: String) -> Result<String, String> {
    let _guard = PrivilegedOpGuard::acquire()?;
    validate_checkpoint_name(&name)?;

    let args = vec!["checkpoint", "create", "--format", "json", "--", &name];

    let output = run_privileged_command(&args).await.map_err(safe_err)?;

    // CLI outputs JSON: {"checkpoint_id": "..."}
    let parsed: serde_json::Value = serde_json::from_str(&output)
        .map_err(|e| safe_err(format!("Failed to parse response: {}", e)))?;

    parsed["checkpoint_id"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "Missing checkpoint_id in response".to_string())
}

/// Deletes a checkpoint by ID.
///
/// Tries the user database first, then the system database.
/// Does not require root privileges.
#[tauri::command]
pub async fn delete_checkpoint(checkpoint_id: String) -> Result<bool, String> {
    let _guard = PrivilegedOpGuard::acquire()?;
    validate_checkpoint_id(&checkpoint_id)?;

    let cp_id = CheckpointId::new(&checkpoint_id);

    // Try user database first
    let user_db = get_user_db_path();
    if user_db.exists()
        && let Ok(manager) = create_checkpoint_manager(&user_db).await
        && manager.delete_checkpoint(&cp_id).await.is_ok()
    {
        return Ok(true);
    }

    // Fall back to system database (needs pkexec for root-owned checkpoints)
    let args = vec!["checkpoint", "delete", &checkpoint_id];
    run_privileged_command(&args)
        .await
        .map(|_| true)
        .map_err(safe_err)
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

/// Scans all plugins and collects findings for compliance reporting.
async fn collect_findings() -> Result<Vec<Finding>, String> {
    let ctx = Context::new();
    let registry = create_plugin_registry();
    let plugin_list = registry.list().map_err(safe_err)?;

    let mut findings = Vec::new();
    for metadata in plugin_list {
        if let Ok(Some(plugin)) = registry.get(&metadata.plugin_id)
            && let Ok(result) = plugin.scan(&ctx).await
        {
            findings.extend(result.scan_findings);
        }
    }
    Ok(findings)
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

/// Generates compliance reports for the specified frameworks.
///
/// Takes a list of framework names and returns compliance reports.
#[tauri::command]
pub async fn generate_compliance_report(
    frameworks: Vec<String>,
) -> Result<Vec<ComplianceReport>, String> {
    let all_findings = collect_findings().await?;
    let parsed_frameworks = parse_frameworks(&frameworks);

    let config = ReportConfig {
        scenario: Scenario::Custom(parsed_frameworks),
        formats: vec![OutputFormat::Text],
        output_dir: None,
        profile: local_profile(),
    };

    let generator = ReportGenerator::new(config, hardener_plugins::compliance_coverage());
    Ok(generator.generate(&all_findings))
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
    let all_findings = collect_findings().await?;
    let parsed_frameworks = parse_frameworks(&frameworks);

    let config = ReportConfig {
        scenario: Scenario::Custom(parsed_frameworks),
        formats: vec![output_format],
        output_dir: None,
        profile: local_profile(),
    };

    let generator = ReportGenerator::new(config, hardener_plugins::compliance_coverage());
    let reports = generator.generate(&all_findings);

    // Format reports
    let formatted: String = match output_format {
        OutputFormat::Text => TextFormatter::new().format_all(&reports),
        OutputFormat::Json => JsonFormatter::pretty().format_all(&reports),
        OutputFormat::Csv => CsvFormatter::new().format_all(&reports),
        OutputFormat::Html => HtmlFormatter::new().format_all(&reports),
        OutputFormat::Pdf => PdfFormatter::new().format_all(&reports),
    };

    // Determine output file path
    let timestamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let default_name = format!(
        "compliance-report-{}.{}",
        timestamp,
        output_format.extension()
    );

    let final_path = match output_path {
        Some(path) => {
            if std::path::Path::new(&path).extension().is_none() {
                format!("{}.{}", path, output_format.extension())
            } else {
                path
            }
        }
        None => {
            // Save to user's Documents or home directory
            let dir = dirs::document_dir()
                .or_else(dirs::home_dir)
                .unwrap_or_else(|| std::path::PathBuf::from("."));
            dir.join(&default_name).to_string_lossy().to_string()
        }
    };

    // Write file (PDF needs binary handling)
    if output_format == OutputFormat::Pdf {
        let bytes = PdfFormatter::new().format_bytes(&reports[0]);
        std::fs::write(&final_path, bytes)
            .map_err(|e| safe_err(format!("Failed to write PDF: {}", e)))?;
    } else {
        std::fs::write(&final_path, &formatted)
            .map_err(|e| safe_err(format!("Failed to write report: {}", e)))?;
    }

    Ok(final_path)
}

/// Scan session info returned to the frontend.
#[derive(Clone, Debug, Serialize)]
pub struct ScanSessionInfo {
    pub session_id: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub total_findings: i32,
    pub total_plugins: i32,
    pub status: String,
}

impl From<ScanSession> for ScanSessionInfo {
    fn from(s: ScanSession) -> ScanSessionInfo {
        ScanSessionInfo {
            session_id: s.session_id.as_str().to_string(),
            started_at: format_timestamp(s.session_started_at),
            completed_at: s.session_completed_at.map(format_timestamp),
            total_findings: s.session_total_findings,
            total_plugins: s.session_total_plugins,
            status: s.session_status.as_str().to_string(),
        }
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

    Ok(sessions.into_iter().map(ScanSessionInfo::from).collect())
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

/// Checkpoint detail info returned to the frontend.
#[derive(Clone, Debug, Serialize)]
pub struct CheckpointDetail {
    pub checkpoint_id: String,
    pub checkpoint_name: String,
    pub checkpoint_created: String,
    pub checkpoint_user: String,
    pub file_count: usize,
    pub files: Vec<CheckpointFileInfo>,
}

/// Individual file state within a checkpoint.
#[derive(Clone, Debug, Serialize)]
pub struct CheckpointFileInfo {
    pub path: String,
    pub permissions: String,
    pub has_content: bool,
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
                path: f.file_path,
                permissions: format!("{:o}", f.file_permissions),
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

    let mut config = load_hosts_config()?;
    if let Some(existing) = config.hosts.iter_mut().find(|h| h.name == profile.name) {
        *existing = profile;
    } else {
        config.hosts.push(profile);
    }
    save_hosts_config(&config)
}

/// Deletes a remote host profile by name.
#[tauri::command]
pub async fn delete_remote_host(name: String) -> Result<(), String> {
    validate_ipc_string(&name, "profile_name")?;

    let mut config = load_hosts_config()?;
    config.hosts.retain(|h| h.name != name);
    save_hosts_config(&config)
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

    let ssh_config = hardener_core::SshConfig {
        host: profile.hostname.clone(),
        port: profile.port,
        user: profile.user.clone(),
        identity_file: profile.key_file.clone(),
        known_hosts: if profile.host_key_checking {
            hardener_core::KnownHosts::Strict
        } else {
            hardener_core::KnownHosts::Accept
        },
        connect_timeout: std::time::Duration::from_secs(30),
    };

    match hardener_core::SshExecutor::connect(ssh_config).await {
        Ok(executor) => {
            let user_display = profile.user.clone().unwrap_or_else(whoami::username);
            let info = RemoteConnectionInfo {
                profile_name: name,
                host: profile.hostname.clone(),
                user: user_display.clone(),
            };
            let mut connection = state.active_connection.lock().await;
            *connection = Some(ActiveConnection {
                executor: std::sync::Arc::new(executor),
                info,
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

    for metadata in plugin_list {
        if let Some(ids) = plugin_ids
            && !ids.is_empty()
            && !ids.iter().any(|id| {
                metadata.plugin_id == (*id).clone().into()
                    || metadata.plugin_id.as_str().starts_with(&format!("{}-", id))
            })
        {
            continue;
        }

        if let Ok(Some(plugin)) = registry.get(&metadata.plugin_id) {
            match plugin.scan(&ctx).await {
                Ok(result) => results.push(result),
                Err(e) => error!("Scan failed for plugin {}: {}", metadata.plugin_id, e),
            }
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
/// scan results (or an error that becomes a `Failed` row). Each returned row
/// pairs the host's profile with its scan: the profile drives posture scoring
/// and is `Generic` for failed hosts. `on_progress` fires once per completed
/// host, in completion order, with (host row, completed count, total): the
/// UI's live progress hook. Generic so the orchestration is unit-testable
/// without real SSH or a Tauri app handle.
///
/// ponytail: a spawned task that *panics* (rather than returning `Err`) keeps
/// its pre-filled `Failed` slot, so the result always has exactly one row per
/// input host in input order, never a silently dropped host (panicked tasks
/// emit no progress event; the scan still ends because the invoke resolves).
async fn scan_fleet<F, Fut>(
    host_names: Vec<String>,
    scan_one: F,
    mut on_progress: impl FnMut(&FleetHostScan, usize, usize),
) -> Vec<(ComplianceProfile, FleetHostScan)>
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
    let mut ordered: Vec<(ComplianceProfile, FleetHostScan)> = host_names
        .iter()
        .map(|name| {
            (
                ComplianceProfile::Generic,
                FleetHostScan {
                    host_name: name.clone(),
                    status: FleetHostStatus::Failed("scan task panicked".to_string()),
                    tallies: SeverityTallies::default(),
                    scan_results: Vec::new(),
                    compliance: Vec::new(),
                },
            )
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
                profile,
                FleetHostScan {
                    host_name: name,
                    tallies: SeverityTallies::from_results(&scan_results),
                    status,
                    scan_results,
                    compliance: Vec::new(),
                },
            )
        });
    }

    let mut completed = 0;
    while let Some(joined) = set.join_next().await {
        if let Ok((index, profile, scan)) = joined {
            completed += 1;
            on_progress(&scan, completed, total);
            ordered[index] = (profile, scan);
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
/// `FLEET_FRAMEWORKS` in one pass) under one host's resolved profile.
/// Built per host: profiles differ across a mixed fleet, so callers fetch
/// coverage once and clone it per host (cheap at fleet scale).
fn fleet_report_generator(
    profile: ComplianceProfile,
    coverage: Vec<ComplianceMapping>,
) -> ReportGenerator {
    let config = ReportConfig {
        scenario: Scenario::Custom(FLEET_FRAMEWORKS.to_vec()),
        formats: vec![OutputFormat::Text],
        output_dir: None,
        profile,
    };
    ReportGenerator::new(config, coverage)
}

/// Derives slim per-framework posture for one host's findings. In-memory; no SSH.
fn posture_for_findings(
    generator: &ReportGenerator,
    findings: &[Finding],
) -> Vec<FleetFrameworkPosture> {
    generator
        .generate(findings)
        .into_iter()
        .map(|r| FleetFrameworkPosture {
            framework: r.report_framework,
            summary: r.report_summary,
        })
        .collect()
}

/// Parses and validates one ad-hoc `user@host[:port]` target. Rejects an empty
/// hostname and a leading `-` (which ssh would otherwise read as an option).
fn adhoc_profile(target: &str) -> Result<RemoteHostProfile, String> {
    validate_ipc_string(target, "adhoc_target")?;
    let profile = RemoteHostProfile::from_target(target.trim(), 22, None, true);
    if profile.hostname.is_empty() || profile.hostname.starts_with('-') {
        return Err(format!("Invalid ad-hoc target '{target}'"));
    }
    Ok(profile)
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
    let mut adhoc_profiles = std::collections::HashMap::new();
    for target in &adhoc {
        adhoc_profiles.insert(target.clone(), adhoc_profile(target)?);
    }

    let config = load_hosts_config()?;
    let plugin_ids = std::sync::Arc::new(plugin_ids);
    let adhoc_profiles = std::sync::Arc::new(adhoc_profiles);

    // Ad-hoc rows keep the full target string as their display name.
    let all_names: Vec<String> = host_names.into_iter().chain(adhoc).collect();

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
            let profile = config
                .hosts
                .iter()
                .find(|h| h.name == name)
                .or_else(|| adhoc_profiles.get(&name))
                .cloned();
            let plugin_ids = plugin_ids.clone();
            async move {
                let profile =
                    profile.ok_or_else(|| format!("Host profile '{}' not found", name))?;

                let ssh_config = hardener_core::SshConfig {
                    host: profile.hostname.clone(),
                    port: profile.port,
                    user: profile.user.clone(),
                    identity_file: profile.key_file.clone(),
                    known_hosts: if profile.host_key_checking {
                        hardener_core::KnownHosts::Strict
                    } else {
                        hardener_core::KnownHosts::Accept
                    },
                    connect_timeout: std::time::Duration::from_secs(30),
                };

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

    // Derive each host's compliance posture from the findings already scanned:
    // in-memory, no extra SSH. Each host gets a generator carrying its own
    // resolved profile; the coverage set is fetched once and cloned per host.
    let coverage = hardener_plugins::compliance_coverage();
    for (profile, host) in &mut results {
        if matches!(host.status, FleetHostStatus::Ok) {
            let findings: Vec<Finding> = host
                .scan_results
                .iter()
                .flat_map(|r| r.scan_findings.iter().cloned())
                .collect();
            let generator = fleet_report_generator(*profile, coverage.clone());
            host.compliance = posture_for_findings(&generator, &findings);
        }
    }

    Ok(results.into_iter().map(|(_, host)| host).collect())
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

    let mut document: toml_edit::DocumentMut = content
        .parse()
        .map_err(|e| safe_err(format!("Failed to parse config: {e}")))?;

    // Remove existing scheduler section, serialise the rest, then append
    // a properly grouped [scheduler] block at the end.  toml_edit scatters
    // dotted subtables ([scheduler.notifications.*]) between unrelated
    // sections when assigned via the Table API, so we build the block as
    // a plain string instead.
    document.remove("scheduler");
    let mut output = document.to_string();

    let scheduler_toml = toml::to_string_pretty(&config)
        .map_err(|e| safe_err(format!("Failed to serialise scheduler config: {e}")))?;

    // Split serialised scheduler into top-level keys and subtable sections,
    // prefixing each [table] header with "scheduler.".
    let mut top_keys = String::new();
    let mut subtables = String::new();
    for line in scheduler_toml.lines() {
        if line.starts_with('[') || !subtables.is_empty() {
            if line.starts_with('[') {
                subtables.push_str(&line.replacen('[', "[scheduler.", 1));
            } else {
                subtables.push_str(line);
            }
            subtables.push('\n');
        } else {
            top_keys.push_str(line);
            top_keys.push('\n');
        }
    }

    output.push_str("\n[scheduler]\n");
    output.push_str(&top_keys);
    if !subtables.is_empty() {
        output.push('\n');
        output.push_str(&subtables);
    }

    std::fs::write(&write_path, output)
        .map_err(|e| safe_err(format!("Failed to write config: {e}")))?;

    Ok("Configuration saved".to_string())
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

    let results = dispatcher.send_test(&summary).await;

    if results.is_empty() {
        return Ok(hardener_types::scheduler::TestNotificationResult {
            success: false,
            message: "No notification channels are enabled".into(),
        });
    }

    let failures: Vec<&str> = results
        .iter()
        .filter(|r| !r.success)
        .filter_map(|r| r.error.as_deref())
        .collect();

    if failures.is_empty() {
        Ok(hardener_types::scheduler::TestNotificationResult {
            success: true,
            message: format!("Test sent to {} channel(s)", results.len()),
        })
    } else {
        Ok(hardener_types::scheduler::TestNotificationResult {
            success: false,
            message: format!("Failed: {}", failures.join("; ")),
        })
    }
}

/// Validates a config file and returns a summary of its contents.
///
/// Parses the TOML file using ConfigLoader and counts plugins,
/// directives, and exceptions. Returns error details if invalid.
#[tauri::command]
pub async fn validate_config(path: String) -> Result<ConfigSummary, String> {
    validate_user_config_path(&path)?;

    use hardener_core::ConfigLoader;

    let file_path = std::path::PathBuf::from(&path);

    if !file_path.exists() {
        return Ok(ConfigSummary {
            config_path: path,
            config_is_valid: false,
            config_error: Some("File not found".to_string()),
            ..Default::default()
        });
    }

    let loader = ConfigLoader::new()
        .skip_defaults()
        .with_cli_config(file_path);

    match loader.load() {
        Ok(config) => {
            let plugin_sections = [
                ("kernel", &config.kernel),
                ("ssh", &config.ssh),
                ("firewall", &config.firewall),
                ("pam", &config.pam),
                ("services", &config.services),
                ("audit", &config.audit),
                ("permissions", &config.permissions),
                ("mac", &config.mac),
            ];

            let enabled_plugins: Vec<String> = plugin_sections
                .iter()
                .filter(|(_, plugin_config)| plugin_config.enabled)
                .map(|(name, _)| (*name).to_string())
                .collect();

            let directive_count: u32 = plugin_sections
                .iter()
                .map(|(_, plugin_config)| {
                    (plugin_config.directives.len() + plugin_config.custom_directives.len()) as u32
                })
                .sum();

            let exception_count: u32 = plugin_sections
                .iter()
                .map(|(_, plugin_config)| plugin_config.exceptions.len() as u32)
                .sum();

            Ok(ConfigSummary {
                config_path: path,
                config_is_valid: true,
                config_error: None,
                config_enabled_plugins: enabled_plugins,
                config_directive_count: directive_count,
                config_exception_count: exception_count,
            })
        }
        Err(e) => Ok(ConfigSummary {
            config_path: path,
            config_is_valid: false,
            config_error: Some(e.to_string()),
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

/// Parses the JSON outcome array from CLI stdout, skipping any leading info
/// lines. Exit-code agnostic by design: `batch apply/rollback` exit non-zero on
/// per-host failures yet still print the array, so the array is the source of
/// truth. Returns `Err` only when no array is present.
fn parse_outcomes<T: serde::de::DeserializeOwned>(stdout: &str) -> Result<Vec<T>, String> {
    let start = stdout.find('[').ok_or("No JSON array in CLI output")?;
    serde_json::from_str(&stdout[start..]).map_err(|e| format!("Failed to parse CLI output: {e}"))
}

#[cfg(test)]
mod fleet_tests {
    use super::*;

    fn privileged_output(exit_code: Option<i32>, stdout: &str, stderr: &str) -> PrivilegedOutput {
        PrivilegedOutput {
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
            exit_code,
        }
    }

    #[test]
    fn exit_code_may_carry_json_accepts_only_zero_and_one() {
        assert!(exit_code_may_carry_json(Some(0)));
        assert!(exit_code_may_carry_json(Some(1)));
        assert!(!exit_code_may_carry_json(Some(2)));
        assert!(!exit_code_may_carry_json(Some(126)));
        assert!(!exit_code_may_carry_json(None));
    }

    #[test]
    fn accept_json_output_parses_exit_zero() {
        let raw = privileged_output(Some(0), r#"{"a":1}"#, "");
        let parsed: serde_json::Value = accept_json_output(&raw).expect("exit 0 must parse");
        assert_eq!(parsed["a"], 1);
    }

    #[test]
    fn accept_json_output_parses_exit_one_with_a_partial_failure_payload() {
        // Mirrors `apply`/`rollback`: the CLI prints per-plugin JSON, then
        // `bail!`s with exit 1 because one plugin failed.
        let raw = privileged_output(Some(1), r#"[{"apply_success":false}]"#, "plugin error");
        let parsed: serde_json::Value =
            accept_json_output(&raw).expect("exit 1 with JSON must parse");
        assert_eq!(parsed[0]["apply_success"], false);
    }

    #[test]
    fn accept_json_output_rejects_exit_one_with_unparseable_stdout() {
        let raw = privileged_output(Some(1), "", "root privileges required");
        let err = accept_json_output::<serde_json::Value>(&raw).unwrap_err();
        assert!(
            matches!(err, PrivilegedCommandError::ExecutionFailed(msg) if msg == "root privileges required")
        );
    }

    #[test]
    fn accept_json_output_rejects_other_exit_codes_even_with_valid_json() {
        let raw = privileged_output(Some(2), r#"{"a":1}"#, "unexpected failure");
        let err = accept_json_output::<serde_json::Value>(&raw).unwrap_err();
        assert!(
            matches!(err, PrivilegedCommandError::ExecutionFailed(msg) if msg == "unexpected failure")
        );
    }

    #[test]
    fn posture_for_findings_returns_one_per_framework() {
        let generator = fleet_report_generator(
            ComplianceProfile::Generic,
            hardener_plugins::compliance_coverage(),
        );
        let scores = posture_for_findings(&generator, &[]);
        assert_eq!(scores.len(), FLEET_FRAMEWORKS.len());
        assert!(
            scores
                .iter()
                .any(|s| s.framework == ComplianceFramework::CIS),
            "fleet posture must include CIS"
        );
    }

    #[tokio::test]
    async fn detect_host_profile_resolves_rocky_10_and_defaults_generic() {
        use hardener_core::MockExecutor;
        let rocky = MockExecutor::new().with_file(
            "/etc/os-release",
            "NAME=\"Rocky Linux\"\nID=\"rocky\"\nVERSION_ID=\"10.0\"\n",
        );
        assert_eq!(detect_host_profile(&rocky).await, ComplianceProfile::Rhel10);
        assert_eq!(
            detect_host_profile(&MockExecutor::new()).await,
            ComplianceProfile::Generic,
            "no os-release on the host resolves to Generic, never an error"
        );
    }

    #[tokio::test]
    async fn fleet_isolates_failures_and_preserves_order() {
        let hosts = vec!["a".to_string(), "b".to_string(), "c".to_string()];

        let results = scan_fleet(
            hosts,
            |name| async move {
                if name == "b" {
                    Err("connection refused".to_string())
                } else {
                    Ok((ComplianceProfile::Generic, Vec::new()))
                }
            },
            |_, _, _| {},
        )
        .await;

        assert_eq!(results.len(), 3);
        assert_eq!(results[0].1.host_name, "a");
        assert_eq!(results[1].1.host_name, "b");
        assert_eq!(results[2].1.host_name, "c");
        assert!(matches!(results[0].1.status, FleetHostStatus::Ok));
        assert!(matches!(results[1].1.status, FleetHostStatus::Failed(_)));
        assert!(matches!(results[2].1.status, FleetHostStatus::Ok));
    }

    #[tokio::test]
    async fn fleet_carries_per_host_profile_and_failed_hosts_stay_generic() {
        let results = scan_fleet(
            vec!["rocky10".to_string(), "down".to_string()],
            |name| async move {
                if name == "down" {
                    Err("connection refused".to_string())
                } else {
                    Ok((ComplianceProfile::Rhel10, Vec::new()))
                }
            },
            |_, _, _| {},
        )
        .await;

        assert_eq!(
            results[0].0,
            ComplianceProfile::Rhel10,
            "a scanned host's resolved profile rides alongside its row"
        );
        assert_eq!(
            results[1].0,
            ComplianceProfile::Generic,
            "a failed host scores under Generic"
        );
    }

    #[tokio::test]
    async fn fleet_progress_fires_once_per_host_with_monotonic_count() {
        let hosts = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let mut events: Vec<(String, usize, usize, bool)> = Vec::new();

        scan_fleet(
            hosts,
            |name| async move {
                if name == "b" {
                    Err("connection refused".to_string())
                } else {
                    Ok((ComplianceProfile::Generic, Vec::new()))
                }
            },
            |scan, done, total| {
                events.push((
                    scan.host_name.clone(),
                    done,
                    total,
                    matches!(scan.status, FleetHostStatus::Failed(_)),
                ));
            },
        )
        .await;

        assert_eq!(events.len(), 3, "one event per host");
        assert!(events.iter().all(|(_, _, total, _)| *total == 3));
        let counts: Vec<usize> = events.iter().map(|(_, done, _, _)| *done).collect();
        assert_eq!(counts, vec![1, 2, 3], "done count is monotonic");
        let failed: Vec<&(String, usize, usize, bool)> =
            events.iter().filter(|(_, _, _, f)| *f).collect();
        assert_eq!(failed.len(), 1, "exactly one failed host");
        assert_eq!(failed[0].0, "b", "the failed event names the failed host");
    }

    #[test]
    fn build_batch_args_apply_dry_run_and_execute() {
        let dry = build_batch_args(
            "apply",
            &["web-1".into(), "web-2".into()],
            &[],
            &["ssh".into()],
            false,
        );
        assert_eq!(
            dry,
            vec![
                "batch", "apply", "--host", "web-1", "--host", "web-2", "--plugin", "ssh",
                "--format", "json"
            ]
        );
        let exec = build_batch_args("apply", &["web-1".into()], &[], &[], true);
        assert_eq!(
            exec,
            vec![
                "batch",
                "apply",
                "--host",
                "web-1",
                "--execute",
                "--format",
                "json"
            ]
        );
    }

    // The scheduler's session row: distinct from hardener_state::ScanSession.
    fn session(
        started_at: i64,
        counts: (i32, i32, i32, i32, i32),
    ) -> hardener_scheduler::db::ScanSession {
        hardener_scheduler::db::ScanSession {
            id: format!("s{started_at}"),
            started_at,
            completed_at: Some(started_at + 60),
            status: "completed".to_string(),
            trigger_type: "batch".to_string(),
            host_identifier: "web-1".to_string(),
            plugins_scanned: "[]".to_string(),
            total_findings: counts.0 + counts.1 + counts.2 + counts.3 + counts.4,
            critical_count: counts.0,
            high_count: counts.1,
            medium_count: counts.2,
            low_count: counts.3,
            info_count: counts.4,
            error_message: None,
            json_file_path: None,
            hash: None,
        }
    }

    #[test]
    fn sessions_to_info_directions_follow_severity_priority() {
        // Newest-first: latest gained a critical (worse), the middle improved
        // on the oldest (better), the oldest has no comparator.
        let sessions = vec![
            session(300, (1, 0, 0, 0, 0)),
            session(200, (0, 1, 0, 0, 0)),
            session(100, (0, 2, 0, 0, 0)),
        ];
        let rows = sessions_to_info(&sessions, 3);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].direction.as_deref(), Some("worse"));
        assert_eq!(rows[1].direction.as_deref(), Some("better"));
        assert_eq!(rows[2].direction, None, "oldest scan has no comparator");
        assert_eq!(rows[0].critical, 1);
    }

    #[test]
    fn sessions_to_info_take_bounds_rows_but_keeps_last_direction() {
        // The +1 over-fetch: two sessions, take 1, the single shown row still
        // gets its direction from the older, hidden session.
        let sessions = vec![session(200, (0, 0, 1, 0, 0)), session(100, (0, 0, 1, 0, 0))];
        let rows = sessions_to_info(&sessions, 1);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].direction.as_deref(), Some("same"));
    }

    #[test]
    fn build_batch_args_routes_adhoc_targets_to_ssh_flag() {
        let args = build_batch_args(
            "rollback",
            &["web-1".into()],
            &["root@10.0.0.5:2222".into()],
            &[],
            false,
        );
        assert_eq!(
            args,
            vec![
                "batch",
                "rollback",
                "--host",
                "web-1",
                "--ssh",
                "root@10.0.0.5:2222",
                "--format",
                "json"
            ]
        );
    }

    #[test]
    fn adhoc_profile_parses_and_guards() {
        let p = adhoc_profile("admin@web-01:2222").unwrap();
        assert_eq!(p.hostname, "web-01");
        assert_eq!(p.port, 2222);
        assert!(
            adhoc_profile("-oProxyCommand=x").is_err(),
            "a leading dash must be rejected: ssh would read it as an option"
        );
        assert!(adhoc_profile("").is_err(), "empty target rejected");
        assert!(
            adhoc_profile("admin@").is_err(),
            "empty hostname after user split rejected"
        );
    }

    #[test]
    fn parse_outcomes_reads_array_after_info_line() {
        let stdout = "info: assessing 1 host\n[{\"name\":\"web-1\",\"target\":\"u@web-1\",\"status\":{\"state\":\"applied\",\"ok\":2,\"failed\":0}}]";
        let parsed: Vec<ApplyOutcome> = parse_outcomes(stdout).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "web-1");
    }

    #[test]
    fn parse_outcomes_errors_without_array() {
        let parsed: Result<Vec<ApplyOutcome>, String> = parse_outcomes("usage error: no hosts");
        assert!(parsed.is_err());
    }

    #[test]
    fn every_canonical_framework_id_parses() {
        // The UI builds pickers and auto-report requests from
        // ComplianceFramework::ALL; every canonical id must stay accepted by
        // this command layer or a framework silently drops from GUI reports.
        for framework in ComplianceFramework::ALL {
            let parsed = parse_frameworks(&[framework.id().to_string()]);
            assert_eq!(
                parsed,
                vec![framework],
                "canonical id '{}' must parse to its framework",
                framework.id()
            );
        }
    }

    #[test]
    fn parse_frameworks_accepts_legacy_aliases() {
        // Every spelling this command layer historically accepted must keep
        // working now that parsing delegates to ComplianceFramework::from_id.
        let aliases = [
            "PCIDSS",
            "PCI-DSS",
            "PCI",
            "ISO27001",
            "ISO-27001",
            "SOC2",
            "SOC-2",
            "800-171",
            "NIST800171",
            "NIST-800-171",
            "FEDRAMP",
            "FED-RAMP",
        ]
        .map(String::from);
        let parsed = parse_frameworks(&aliases);
        assert_eq!(
            parsed,
            vec![
                ComplianceFramework::PCIDSS,
                ComplianceFramework::PCIDSS,
                ComplianceFramework::PCIDSS,
                ComplianceFramework::ISO27001,
                ComplianceFramework::ISO27001,
                ComplianceFramework::SOC2,
                ComplianceFramework::SOC2,
                ComplianceFramework::NIST800171,
                ComplianceFramework::NIST800171,
                ComplianceFramework::NIST800171,
                ComplianceFramework::FedRAMP,
                ComplianceFramework::FedRAMP,
            ]
        );
    }

    #[test]
    fn parse_frameworks_drops_unknown_silently() {
        let parsed = parse_frameworks(&["nonsense".to_string(), "CIS".to_string()]);
        assert_eq!(parsed, vec![ComplianceFramework::CIS]);
    }
}
