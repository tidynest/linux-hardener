//! Split from the former flat `commands.rs` along the seams its test files
//! had already named. Shared plumbing lives in the parent; each domain here
//! keeps its own commands and their private helpers.

use super::*;

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
        // Collected rather than counted: the refusal names them, which is the
        // difference between "nothing was scanned" and a message the operator
        // can act on.
        let mut skipped_by_config: Vec<String> = Vec::new();

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

            // Skip plugins disabled by config, remembering which, so a run that
            // scanned nothing can say why instead of returning an empty list.
            if !config.is_plugin_enabled(metadata.plugin_id.as_str()) {
                skipped_by_config.push(metadata.plugin_id.to_string());
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

        // Inside fail_session_on_err, so the refusal marks the session Failed
        // rather than leaving a 'running' row behind. A refused scan is a scan
        // that did not happen, which is what that row should say.
        scan_selection_refusal(results.len(), &skipped_by_config)?;

        // One marker entry per skipped plugin, appended after the refusal so
        // its count stays "plugins that scanned". The marker carries the
        // reason into the UI and, through persist_scan_results below, into
        // the history the compliance report reads: without it, a disabled
        // plugin is indistinguishable from one that scanned clean.
        for plugin_id in &skipped_by_config {
            results.push(ScanResult {
                scan_plugin_id: PluginId::new(plugin_id.clone()),
                scan_success: false,
                scan_findings: Vec::new(),
                scan_unchecked: Vec::new(),
                scan_duration_us: 0,
                scan_error: None,
                scan_skipped: Some(SkipReason::DisabledByConfig),
            });
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
pub(crate) struct CliScanEntry {
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
    /// Why the entry ran no checks, on entries the config skipped. Absent
    /// from output predating the marker, and `None` there, same as on every
    /// entry a plugin actually produced.
    #[serde(default)]
    scan_skipped: Option<SkipReason>,
}

impl CliScanEntry {
    /// The CLI shape omits duration, so that alone is synthesised. The scan
    /// outcome is read from the payload: assuming success here was how a
    /// failed plugin scan reached the desktop as a clean result.
    pub(crate) fn into_scan_result(self) -> ScanResult {
        ScanResult {
            scan_plugin_id: PluginId::new(self.plugin_id),
            scan_success: self.scan_success,
            scan_findings: self.findings,
            scan_unchecked: self.unchecked,
            scan_duration_us: 0,
            scan_error: self.scan_error,
            scan_skipped: self.scan_skipped,
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
pub(crate) fn apply_args(
    dry_run: bool,
    plugin_ids: &[String],
    config_path: Option<&str>,
) -> Vec<String> {
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
/// Runs through the same pkexec channel as `run_apply`, because the preview
/// has to estimate what the privileged apply would actually do. The
/// unprivileged dry-run this command used to spawn reads the host as the
/// desktop user, and on a privilege-gated host that estimate is zero in
/// every area (root-only config files, a firewall ruleset that needs root
/// to read), which left the wizard's confirm step gated on nothing while
/// the real apply had work waiting: found on the release host on 2026-08-30
/// as nine findings and a permanently disabled apply button.
///
/// Still read-only under root. `apply --dry-run` takes no checkpoint and
/// runs each plugin's `validate` only, never `apply` (crates/hardener-cli
/// `commands/apply.rs`), so the elevation buys the preview the apply's
/// reading of the host and not a write.
#[tauri::command]
pub async fn run_apply_dry_run(
    plugin_ids: Vec<String>,
    config_path: Option<String>,
) -> Result<Vec<ValidationReport>, String> {
    let _guard = PrivilegedOpGuard::acquire()?;
    validate_plugin_ids(&plugin_ids)?;
    if let Some(ref path) = config_path {
        validate_privileged_config_path(path)?;
    }

    tracing::info!(
        "=== run_apply_dry_run called with plugins: {:?} ===",
        plugin_ids
    );

    let owned = apply_args(true, &plugin_ids, config_path.as_deref());
    let args: Vec<&str> = owned.iter().map(String::as_str).collect();

    // Read by the same rule as every other JSON verb, which is the point of it
    // being a rule. Exit 1 with a parseable report array is a partial-failure
    // result, not a transport error: `apply --dry-run` prints the array before
    // `bail!`ing when a plugin's validation errors. (This path used to build
    // its own `CliOutput` from a direct, unprivileged spawn; moving onto
    // `run_privileged` changed who runs the CLI, not how its output is read.)
    let raw = run_privileged(&args).await.map_err(safe_err)?;
    accept_json_output(&raw).map_err(safe_err)
}

/// The argv for a privileged `hardener rollback`.
///
/// The checkpoint id goes last, behind `--`, so an id that begins with a hyphen
/// cannot be read as a flag. That also means **nothing may be appended after
/// it**: everything past `--` is a positional, and `rollback` takes exactly one,
/// so an appended flag is not ignored, it makes clap refuse the command. A
/// `--config` used to be pushed there.
pub(crate) fn rollback_args(checkpoint_id: &str) -> Vec<&str> {
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

/// Lists available hardening plugins with their metadata.
#[tauri::command]
pub async fn list_plugins() -> Result<Vec<PluginMetadata>, String> {
    let registry = create_plugin_registry();
    registry.list().map_err(safe_err)
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
