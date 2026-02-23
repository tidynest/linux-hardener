use hardener_common::types::ComplianceFramework;
use hardener_compliance::{
    ComplianceReport, OutputFormat, ReportConfig, ReportGenerator, Scenario,
};
use hardener_core::{ApplyResult, Context, PluginMetadata, ScanResult, ValidationReport};
use hardener_plugins::create_plugin_registry;
use hardener_state::{CheckpointManager, RollbackResult, ScanHistoryManager, ScanStatus, init_db};
use serde::Serialize;
use tokio::process::Command;
use tracing::error;

/// Checkpoint information returned to the frontend.
#[derive(Clone, Debug, Serialize)]
pub struct CheckpointInfo {
    pub checkpoint_id: String,
    pub checkpoint_name: String,
    pub checkpoint_created: String,
    pub checkpoint_user: String,
}

/// Formats a Unix timestamp as a human-readable string.
fn format_timestamp(timestamp: i64) -> String {
    chrono::DateTime::from_timestamp(timestamp, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| format!("Invalid timestamp: {}", timestamp))
}

/// Returns the path to the hardener CLI binary.
///
/// In development, uses the debug build. In production, expects
/// the binary in standard locations or PATH.
fn get_hardener_binary_path() -> Result<String, String> {
    // Check sibling directory of current executable (works in dev and production)
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name("hardener");
        if sibling.exists() {
            return Ok(sibling.to_string_lossy().to_string());
        }
    }

    // In dev builds, check workspace target directory
    #[cfg(debug_assertions)]
    {
        let workspace_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(|root| root.join("target").join("debug").join("hardener"));
        if let Some(path) = workspace_path
            && path.exists()
        {
            return Ok(path.to_string_lossy().to_string());
        }
    }

    // Try PATH lookup
    if std::process::Command::new("which")
        .arg("hardener")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return Ok("hardener".to_string());
    }

    Err("Could not find hardener CLI binary. \
         In development, run: cargo build -p hardener-cli"
        .to_string())
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
    /// Failed to parse command output.
    ParseError(String),
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
            Self::ExecutionFailed(msg) => write!(f, "Command failed: {}", msg),
            Self::ParseError(msg) => write!(f, "Failed to parse output: {}", msg),
        }
    }
}

/// Executes a command with root privileges via pkexec.
///
/// Returns the command's stdout on success or an appropriate error.
async fn run_privileged_command(args: &[&str]) -> Result<String, PrivilegedCommandError> {
    let binary = get_hardener_binary_path().map_err(PrivilegedCommandError::ExecutionFailed)?;

    tracing::info!("=== Running pkexec {} {:?} ===", binary, args);

    let output = Command::new("pkexec")
        .arg(&binary)
        .args(args)
        .output()
        .await
        .map_err(|e| PrivilegedCommandError::ExecutionFailed(e.to_string()))?;

    // Check exit codes
    match output.status.code() {
        Some(0) => {
            // Success
            String::from_utf8(output.stdout)
                .map_err(|e| PrivilegedCommandError::ParseError(e.to_string()))
        }
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
        _ => {
            // Other error
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(PrivilegedCommandError::ExecutionFailed(stderr.to_string()))
        }
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
/// Uses a user-local database path to avoid requiring root for reads.
async fn create_checkpoint_manager(db_path: &std::path::Path) -> Result<CheckpointManager, String> {
    let pool = init_db(Some(db_path)).await.map_err(|e| e.to_string())?;

    CheckpointManager::new(pool).map_err(|e| e.to_string())
}

/// Creates a ScanHistoryManager with database connection.
///
/// Uses the user-local database for scan history persistence.
async fn create_scan_history_manager() -> Result<ScanHistoryManager, String> {
    let db_path = get_user_db_path();

    let pool = init_db(Some(db_path.as_path()))
        .await
        .map_err(|e| e.to_string())?;

    Ok(ScanHistoryManager::new(pool))
}

/// Executes a security scan across all enabled plugins.
///
/// Persists results to the database for GUI state restoration.
/// Returns a vector of scan results, one per plugin.
#[tauri::command]
pub async fn run_scan() -> Result<Vec<ScanResult>, String> {
    // Create scan history manager for persistence
    let history_manager = create_scan_history_manager().await?;

    // Start a new scan session
    let session_id = history_manager
        .start_session()
        .await
        .map_err(|e| e.to_string())?;

    let ctx = Context::new();
    let registry = create_plugin_registry();

    let mut results = Vec::new();

    // Get list of all plugin metadata
    let plugin_list = registry.list().map_err(|e| e.to_string())?;

    for metadata in plugin_list {
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
pub async fn run_apply(plugin_ids: Vec<String>) -> Result<Vec<ApplyResult>, String> {
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

    // Execute with root privileges
    let output = run_privileged_command(&args)
        .await
        .map_err(|e| e.to_string())?;

    // Parse JSON output from CLI
    let parsed: Vec<(PluginMetadata, ApplyResult)> = serde_json::from_str(&output)
        .map_err(|e| format!("Failed to parse apply results: {}", e))?;
    let results: Vec<ApplyResult> = parsed.into_iter().map(|(_, r)| r).collect();

    Ok(results)
}

/// Performs a dry-run of hardening changes for preview.
///
/// Unlike run_apply, this does NOT use pkexec because dry-run doesn't
/// modify the system. Returns estimated changes for user review.
#[tauri::command]
pub async fn run_apply_dry_run(plugin_ids: Vec<String>) -> Result<Vec<ValidationReport>, String> {
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

    // Execute without root privileges (dry-run is read-only)
    let output = Command::new(&binary)
        .args(&args)
        .output()
        .await
        .map_err(|e| format!("Failed to execute dry-run: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Dry-run failed: {}", stderr));
    }

    let stdout =
        String::from_utf8(output.stdout).map_err(|e| format!("Invalid UTF-8 in output: {}", e))?;

    // Find the JSON array in output (skip any info lines)
    let json_start = stdout.find('[').ok_or("No JSON array found in output")?;
    let json_str = &stdout[json_start..];

    // Parse JSON array
    let results: Vec<ValidationReport> = serde_json::from_str(json_str)
        .map_err(|e| format!("Failed to parse dry-run results: {}", e))?;

    Ok(results)
}

/// Rolls back to a previous checkpoint.
///
/// Uses pkexec to run the CLI with root privileges.
/// Takes a checkpoint ID and restores the system state to that point.
#[tauri::command]
pub async fn run_rollback(checkpoint_id: String) -> Result<RollbackResult, String> {
    let args = vec!["rollback", "--format", "json", &checkpoint_id];

    let output = run_privileged_command(&args)
        .await
        .map_err(|e| e.to_string())?;

    serde_json::from_str(&output)
        .map_err(|e| format!("Failed to parse rollback result: {}", e))
}

/// Retrieves a list of all available checkpoints from both user and system databases.
///
/// Checkpoints created by the GUI are in the user database, while checkpoints
/// created by privileged CLI operations (via pkexec) are in the system database.
/// This function merges both sources for a complete view.
#[tauri::command]
pub async fn get_checkpoints() -> Result<Vec<CheckpointInfo>, String> {
    let mut all_checkpoints = Vec::new();

    // Try user database first
    let user_db = get_user_db_path();
    if user_db.exists()
        && let Ok(manager) = create_checkpoint_manager(&user_db).await
        && let Ok(checkpoints) = manager.list_checkpoints().await
    {
        all_checkpoints.extend(checkpoints);
    }

    // Try system database (checkpoints from pkexec apply operations)
    let system_db = get_system_db_path();
    if system_db.exists()
        && let Ok(manager) = create_checkpoint_manager(&system_db).await
        && let Ok(checkpoints) = manager.list_checkpoints().await
    {
        // Add only checkpoints not already in the list (by ID)
        for cp in checkpoints {
            if !all_checkpoints
                .iter()
                .any(|c| c.checkpoint_id == cp.checkpoint_id)
            {
                all_checkpoints.push(cp);
            }
        }
    }

    // Sort by timestamp descending (newest first)
    all_checkpoints.sort_by(|a, b| b.checkpoint_timestamp.cmp(&a.checkpoint_timestamp));

    Ok(all_checkpoints
        .into_iter()
        .map(|cp| CheckpointInfo {
            checkpoint_id: cp.checkpoint_id.as_str().to_string(),
            checkpoint_name: cp.checkpoint_name,
            checkpoint_created: format_timestamp(cp.checkpoint_timestamp),
            checkpoint_user: cp.checkpoint_username,
        })
        .collect())
}

/// Generates compliance reports for the specified frameworks.
///
/// Takes a list of framework names and returns compliance reports.
#[tauri::command]
pub async fn generate_compliance_report(
    frameworks: Vec<String>,
) -> Result<Vec<ComplianceReport>, String> {
    // First run a scan to get findings
    let ctx = Context::new();
    let registry = create_plugin_registry();

    let mut all_findings = Vec::new();
    let plugin_list = registry.list().map_err(|e| e.to_string())?;

    for metadata in plugin_list {
        if let Ok(Some(plugin)) = registry.get(&metadata.plugin_id)
            && let Ok(result) = plugin.scan(&ctx).await
        {
            all_findings.extend(result.scan_findings);
        }
    }

    // Parse framework names into ComplianceFramework enum
    let parsed_frameworks: Vec<ComplianceFramework> = frameworks
        .iter()
        .filter_map(|f| match f.to_uppercase().as_str() {
            "CIS" => Some(ComplianceFramework::CIS),
            "STIG" => Some(ComplianceFramework::STIG),
            "NIST" => Some(ComplianceFramework::NIST),
            "PCIDSS" | "PCI-DSS" | "PCI" => Some(ComplianceFramework::PCIDSS),
            "HIPAA" => Some(ComplianceFramework::HIPAA),
            "GDPR" => Some(ComplianceFramework::GDPR),
            _ => None,
        })
        .collect();

    // Create report config with custom frameworks
    let config = ReportConfig {
        scenario: Scenario::Custom(parsed_frameworks),
        formats: vec![OutputFormat::Text],
        output_dir: None,
    };

    // Generate reports
    let generator = ReportGenerator::new(config);
    let reports = generator.generate(&all_findings);

    Ok(reports)
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
