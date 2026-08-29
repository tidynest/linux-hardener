//! Split from the former flat `commands.rs` along the seams its test files
//! had already named. Shared plumbing lives in the parent; each domain here
//! keeps its own commands and their private helpers.

use super::*;

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
pub(crate) async fn upsert_host(
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
pub(crate) async fn remove_host(
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
pub(crate) async fn scan_with_executor(
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
pub(crate) async fn detect_host_profile(
    executor: &dyn hardener_core::SystemExecutor,
) -> ComplianceProfile {
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
