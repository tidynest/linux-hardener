pub mod audit;
pub mod firewall;
pub mod kernel;
pub mod mac;
pub mod macros;
pub mod pam;
pub mod permissions;
pub mod scan_outcome;
pub mod services;
pub mod ssh;
pub(crate) mod strictness;

pub use scan_outcome::{
    Unassessed, failed_scan, flatten_persisted_scans, flatten_scans, unassessed_check,
};

/// Common rollback helper for plugins.
///
/// The blocker to record when a probe reported something that looked like a
/// refusal, decided by asking whether this session is already root.
///
/// Four plugins used to assert that a privileged re-run would reach these
/// checks, without observing anything. That is right on an unprivileged host
/// and wrong on a privileged one, where whatever stopped the probe will stop it
/// again: a capability the process does not hold, a tool it cannot spawn, a
/// namespace it cannot see into. `systemd-nspawn` is where it was caught,
/// granting `CAP_NET_ADMIN` only to a container with its own network
/// namespace, so the firewall plugin at uid 0 told an operator to try again as
/// root.
///
/// It deliberately does NOT ask whether the session could elevate. A session
/// that is not root but holds passwordless sudo still has a privileged re-run
/// to offer, which is exactly what `Privilege` means here.
///
/// The probe fails closed towards `Privilege`: a session whose uid could not be
/// read is treated as not-root, so an operator is offered a remedy that may not
/// help rather than denied one that would.
pub async fn refusal_blocker(ctx: &hardener_core::Context) -> hardener_core::UncheckedBlocker {
    match hardener_core::session_is_root(ctx.executor().as_ref()).await {
        true => hardener_core::UncheckedBlocker::Environment,
        false => hardener_core::UncheckedBlocker::Privilege,
    }
}

/// Creates a checkpoint before applying changes.
///
/// This function captures the current state of the specified files so they can
/// be restored later via rollback. Returns the checkpoint ID if successful.
///
/// # Arguments
/// * `ctx` - Execution context containing the checkpoint manager
/// * `checkpoint_name` - Checkpoint name. MUST be `{plugin_id}-pre-apply` so
///   `hardener batch rollback` (which derives this name from the plugin id) can
///   select it; a mismatch makes rollback a silent no-op for that plugin.
/// * `file_paths` - List of file paths to capture in the checkpoint
pub async fn create_checkpoint_for_apply(
    ctx: &hardener_core::Context,
    checkpoint_name: &str,
    file_paths: &[&std::path::Path],
) -> hardener_common::error::Result<Option<String>> {
    // Get the checkpoint manager from context
    let manager = match ctx.checkpoint_manager() {
        Some(m) => m.clone(),
        None => {
            tracing::debug!("CheckpointManager not available - skipping checkpoint creation");
            return Ok(None);
        }
    };

    let checkpoint_id = manager
        .create_checkpoint(ctx.executor().as_ref(), checkpoint_name, file_paths)
        .await?;

    tracing::info!("Created checkpoint: {}", checkpoint_id.as_str());

    Ok(Some(checkpoint_id.as_str().to_string()))
}

/// Creates a metadata-only checkpoint before applying permission changes.
///
/// Captures only mode/uid/gid for each path: no file contents, no recursion.
/// Suitable for plugins that only modify permissions or ownership.
pub async fn create_checkpoint_metadata_only_for_apply(
    ctx: &hardener_core::Context,
    checkpoint_name: &str,
    file_paths: &[&std::path::Path],
) -> hardener_common::error::Result<Option<String>> {
    let manager = match ctx.checkpoint_manager() {
        Some(m) => m.clone(),
        None => {
            tracing::debug!("CheckpointManager not available - skipping checkpoint creation");
            return Ok(None);
        }
    };

    let checkpoint_id = manager
        .create_checkpoint_metadata_only(ctx.executor().as_ref(), checkpoint_name, file_paths)
        .await?;

    tracing::info!(
        "Created metadata-only checkpoint: {}",
        checkpoint_id.as_str()
    );

    Ok(Some(checkpoint_id.as_str().to_string()))
}

/// Builds the bookkeeping [`Change`](hardener_core::Change) that records a
/// rollback checkpoint in an apply result, or `None` when no checkpoint was
/// created (e.g. no checkpoint manager in context).
///
/// Every plugin records the same entry after creating its pre-apply
/// checkpoint, so this is the single source for it. It is typed
/// [`ChangeType::Checkpoint`](hardener_core::ChangeType::Checkpoint) so the
/// `ApplyResult` count helpers never treat checkpoint creation as a hardening
/// change. Call sites append it with `changes.extend(checkpoint_change(&id))`.
pub fn checkpoint_change(checkpoint_id: &Option<String>) -> Option<hardener_core::Change> {
    checkpoint_id.as_ref().map(|_| hardener_core::Change {
        change_description: "Created checkpoint for rollback".to_string(),
        change_type: hardener_core::ChangeType::Checkpoint,
        change_success: true,
        change_error: None,
    })
}

/// Creates `dir` if it may be missing, returning the reason it could not be
/// created and `None` when it is there or was made.
///
/// `write_file` cannot create a missing parent: it lands its content through a
/// temporary file in the target directory, so an absent directory fails the
/// write with an error naming only the file. Distributions disagree about which
/// package owns which of these directories, so a plugin writing into one that a
/// minimal install may not have calls this first.
///
/// The mkdir runs wherever the probe does not positively confirm the directory
/// is present: a probe that cannot answer is treated as "may be missing",
/// because `mkdir -p` on an existing directory does nothing, while skipping the
/// creation on the one host that needs it costs the write. The exit code is
/// checked because `execute_command` returns `Ok` for a command that ran and
/// failed, and an unchecked one would let a failed mkdir be followed by a write
/// that cannot land.
///
/// Where the directory is itself captured by the calling plugin's checkpoint,
/// the call has to run above that checkpoint: a checkpoint stores an absent
/// path with a zero mode, which a rollback reads as "remove this", so a
/// directory created after the capture turns a clean rollback into a refusal.
/// The call site owns that decision; this helper does not.
pub(crate) async fn ensure_directory(ctx: &hardener_core::Context, dir: &str) -> Option<String> {
    if matches!(
        ctx.executor().path_exists(std::path::Path::new(dir)).await,
        Ok(true)
    ) {
        return None;
    }

    match ctx.executor().execute_command("mkdir", &["-p", dir]).await {
        Ok(output) if output.success() => None,
        Ok(output) => Some(format!(
            "Failed to create {dir}: mkdir exited {} ({})",
            output.exit_code,
            output.stderr.trim(),
        )),
        Err(e) => Some(format!("Failed to create {dir}: {e}")),
    }
}

pub use audit::AuditHardeningPlugin;
pub use firewall::FirewallHardeningPlugin;

/// Re-export dependencies for macro use.
#[doc(hidden)]
pub use hardener_common;
#[doc(hidden)]
pub use hardener_core;
pub use kernel::KernelHardeningPlugin;
pub use mac::MacHardeningPlugin;
pub use pam::PamHardeningPlugin;
pub use permissions::PermissionsHardeningPlugin;
pub use services::ServicesHardeningPlugin;
pub use ssh::SshHardeningPlugin;

/// Creates a plugin registry with all available hardening plugins registered.
///
/// Canonically creates a fully-populated registry.
/// Used by CLI commands, Tauri backend, and tests.
pub fn create_plugin_registry() -> hardener_core::PluginRegistry {
    let registry = hardener_core::PluginRegistry::new();
    registry
        .register(Box::new(AuditHardeningPlugin::new()))
        .expect("failed to register audit plugin");
    registry
        .register(Box::new(FirewallHardeningPlugin::new()))
        .expect("failed to register firewall plugin");
    registry
        .register(Box::new(KernelHardeningPlugin::new()))
        .expect("failed to register kernel plugin");
    registry
        .register(Box::new(MacHardeningPlugin::new()))
        .expect("failed to register mac plugin");
    registry
        .register(Box::new(PamHardeningPlugin::new()))
        .expect("failed to register pam plugin");
    registry
        .register(Box::new(PermissionsHardeningPlugin::new()))
        .expect("failed to register permissions plugin");
    registry
        .register(Box::new(ServicesHardeningPlugin::new()))
        .expect("failed to register services plugin");
    registry
        .register(Box::new(SshHardeningPlugin::new()))
        .expect("failed to register ssh plugin");
    registry
}

/// The complete set of compliance controls the engine automatically assesses.
///
/// This is the union of every `(framework, control)` mapping any plugin can
/// emit, deduplicated by `(framework, control_id)`. It is the single source of
/// truth for the report generator: a control present here is assessed (so it can
/// report `Pass`/`Fail`), while one absent is reported as `ManualReview` rather
/// than fabricating a pass. Callers (CLI, Tauri, scheduler) pass this into
/// `ReportGenerator` so the compliance crate stays independent of the plugins.
pub fn compliance_coverage() -> Vec<hardener_common::types::ComplianceMapping> {
    let mut seen = std::collections::HashSet::new();
    coverage_table()
        .into_iter()
        .flat_map(|(_, mappings)| mappings)
        .filter(|m| seen.insert((m.compliance_framework, m.compliance_control_id.clone())))
        .collect()
}

/// The controls one named plugin declares it assesses, or `None` for an id no
/// plugin answers to.
///
/// `compliance_coverage` answers "which controls does the engine assess at
/// all". This answers the narrower question the failure path needs: which
/// controls stop being assessable when *this* plugin's scan does not complete.
/// Without it a failed scan is indistinguishable from a clean one, because the
/// generator reads coverage statically and a control with no finding passes.
pub fn coverage_for(plugin_id: &str) -> Option<Vec<hardener_common::types::ComplianceMapping>> {
    coverage_table()
        .into_iter()
        .find(|(id, _)| *id == plugin_id)
        .map(|(_, mappings)| mappings)
}

/// Every plugin id paired with the coverage its module declares.
///
/// One list, so `compliance_coverage` and `coverage_for` can never disagree
/// about which plugin assesses which control.
/// `every_registered_plugin_declares_its_coverage` keeps it in step with the
/// registry.
fn coverage_table() -> [(&'static str, Vec<hardener_common::types::ComplianceMapping>); 8] {
    [
        ("audit-hardening", audit::coverage()),
        ("firewall-hardening", firewall::coverage()),
        ("kernel-hardening", kernel::coverage()),
        ("mac-hardening", mac::coverage()),
        ("pam-hardening", pam::coverage()),
        ("permissions-hardening", permissions::coverage()),
        ("service-minimisation", services::coverage()),
        ("ssh-hardening", ssh::coverage()),
    ]
}

/// Reloads every plugin whose configuration a rollback just restored.
///
/// Each plugin is asked once, however many of its paths were restored, and a
/// plugin matching nothing is not asked at all. A plugin that reports there
/// was nothing to reload produces no result, so the rows an operator reads are
/// the reloads that actually happened.
///
/// Failures are recorded rather than propagated: one subsystem refusing to
/// come back must not hide what the others did. The same rule covers the
/// registry itself: a listing that cannot be produced, or a plugin the
/// listing named but `get` could not retrieve, is recorded as a failed
/// reload rather than silently dropped. See `plugins_or_reload_failure` and
/// `plugin_or_reload_failure`.
pub async fn reload_plugins_after_rollback(
    ctx: &hardener_core::Context,
    registry: &hardener_core::PluginRegistry,
    restored: &[std::path::PathBuf],
) -> Vec<hardener_types::ReloadResult> {
    let metadata = match plugins_or_reload_failure(registry.list()) {
        Ok(metadata) => metadata,
        Err(failure) => return vec![failure],
    };

    let mut results = Vec::new();

    for meta in metadata {
        let plugin = match plugin_or_reload_failure(registry.get(&meta.plugin_id), &meta.plugin_id)
        {
            Ok(plugin) => plugin,
            Err(failure) => {
                results.push(failure);
                continue;
            }
        };
        if !restored.iter().any(|path| plugin.reloads_for_path(path)) {
            continue;
        }
        let (action, success, error) = match plugin.reload_after_rollback(ctx).await {
            Ok(None) => continue,
            Ok(Some(action)) => (action, true, None),
            Err(e) => ("reload failed".to_string(), false, Some(e.to_string())),
        };
        results.push(hardener_types::ReloadResult {
            reload_plugin_id: meta.plugin_id.as_str().to_string(),
            reload_action: action,
            reload_success: success,
            reload_error: error,
        });
    }

    results
}

/// The registry's plugin listing, or the dispatch's own record that it could
/// not be consulted.
///
/// Discarding the error here used to leave an empty `Vec`, which reads
/// exactly like a rollback that reloaded nothing:
/// `RollbackResult::reloads_ok` cannot tell a poisoned registry lock apart
/// from a clean run once the list is empty either way. Naming the registry
/// as the thing that failed gives the operator something to see instead of
/// silence.
fn plugins_or_reload_failure(
    listed: hardener_common::error::Result<Vec<hardener_core::PluginMetadata>>,
) -> std::result::Result<Vec<hardener_core::PluginMetadata>, hardener_types::ReloadResult> {
    listed.map_err(|error| {
        tracing::warn!("rollback could not enumerate plugins to reload: {error}");
        hardener_types::ReloadResult {
            reload_plugin_id: "plugin-registry".to_string(),
            reload_action: "reload skipped".to_string(),
            reload_success: false,
            reload_error: Some(format!("plugin registry could not be enumerated: {error}")),
        }
    })
}

/// A plugin the listing just named, or the dispatch's own record that it
/// could not be retrieved.
///
/// The listing and the fetch are two separate calls against the same
/// registry: a failed fetch, or one that comes back empty for an id the
/// listing just produced, used to be skipped rather than recorded, leaving
/// the same blind spot for one plugin that `plugins_or_reload_failure`
/// closes for the registry as a whole.
fn plugin_or_reload_failure(
    fetched: hardener_common::error::Result<
        Option<std::sync::Arc<dyn hardener_core::HardeningPlugin>>,
    >,
    plugin_id: &hardener_common::types::PluginId,
) -> std::result::Result<
    std::sync::Arc<dyn hardener_core::HardeningPlugin>,
    hardener_types::ReloadResult,
> {
    let reason = match fetched {
        Ok(Some(plugin)) => return Ok(plugin),
        Ok(None) => "plugin was listed but could not be found".to_string(),
        Err(error) => error.to_string(),
    };
    tracing::warn!("could not retrieve plugin {plugin_id} for reload: {reason}");
    Err(hardener_types::ReloadResult {
        reload_plugin_id: plugin_id.as_str().to_string(),
        reload_action: "reload skipped".to_string(),
        reload_success: false,
        reload_error: Some(reason),
    })
}

#[cfg(test)]
mod reload_tests;
#[cfg(test)]
mod tests;
