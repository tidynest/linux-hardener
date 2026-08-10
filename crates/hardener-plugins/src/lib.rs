pub mod audit;
pub mod firewall;
pub mod kernel;
pub mod mac;
// Gated, because `define_plugin!` carries `#[macro_export]` and an ungated
// `pub mod` puts it at the crate root for every downstream build. Its
// generated `divergences_after_rollback` returns an empty vector, which means
// "everything checkable came back": a plugin written through this macro would
// take that answer with nothing but a comment to warn its author, which is the
// #142 defect the trait default was just deleted to remove. `cfg(test)` is not
// propagated to dependents, so the macro stays available to this crate's own
// tests, its only caller, and exists nowhere else.
#[cfg(test)]
pub mod macros;
pub mod pam;
pub mod permissions;
pub mod scan_outcome;
pub mod services;
pub(crate) mod shell_config;
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

/// How many timestamped copies of a configuration file survive an apply,
/// counting the one that apply just took.
///
/// Three, and the number is a judgement rather than a measurement. A backup
/// exists so an operator can undo a bad apply by hand, which argues for keeping
/// several; the checkpoint already holds the pre-apply state and is the actual
/// recovery path, which argues for keeping very few. Three leaves the last
/// apply and the two before it.
///
/// Nothing pruned any of them until #154, and the accumulation was measured on
/// the development host on 2026-08-11: 17 in `/etc/audit/rules.d`, 17 in
/// `/etc/ssh`, 16 across `/etc/security` and `/etc/pam.d`. The cost is not the
/// disk. Each plugin's checkpoint captures the directory its backups sit in, so
/// every copy is written into every later checkpoint and restored by every
/// rollback: a rollback of one `audit-hardening` apply reported 24 files of
/// which 17 were dead backups.
pub(crate) const BACKUPS_KEPT: usize = 3;

/// Removes every backup carrying `prefix` beyond the newest [`BACKUPS_KEPT`].
///
/// `prefix` is the whole of what makes a path a candidate, and it is a full
/// path rather than a directory and a pattern: the directory to read is the
/// prefix's own parent. The file being backed up never matches its own backups'
/// prefix, so the three call sites cannot delete the thing they just copied,
/// and nor can they touch a neighbour some other tool owns.
///
/// The names sort chronologically as text because the timestamp is the last
/// component of each. That holds across the two shapes `/etc/ssh` still carries
/// side by side, unix seconds and `%Y%m%d_%H%M%S`, for as long as the seconds
/// are ten digits beginning with a 1, which is until 2033; the plugins generate
/// neither shape any more and both are still on disk to be removed.
///
/// Never fails an apply, and returns nothing to record. The configuration is
/// written either way, the operator keeps every copy they already had, and the
/// next apply prunes again; refusing an apply, or reporting a failure the
/// operator cannot act on, would be a larger harm than the disk the copies
/// occupy.
///
/// **A rollback of the apply that pruned brings the pruned copies back**, and
/// that is correct rather than a hole. Every caller runs below its plugin's
/// pre-apply checkpoint, which captured the directory as it was, so a rollback
/// restores the state before the prune along with everything else it restores.
/// The count converges anyway: the next apply prunes what the rollback put
/// back. Moving the prune above the checkpoint would fix the count and break
/// the rollback's contract, which is to return the host to what it was.
pub(crate) async fn prune_timestamped_backups(
    ctx: &hardener_core::Context,
    prefix: &str,
    keep: usize,
) {
    use std::path::Path;
    use tracing::{info, warn};

    let Some(directory) = Path::new(prefix).parent() else {
        warn!("Not pruning backups of {prefix}: it names no directory to read");
        return;
    };
    let entries = match ctx.executor().read_dir(directory).await {
        Ok(entries) => entries,
        Err(e) => {
            warn!(
                "Could not list {} to prune old backups of {prefix}: {e}",
                directory.display()
            );
            return;
        }
    };

    let mut backups: Vec<String> = entries
        .iter()
        .filter_map(|path| path.to_str())
        .filter(|path| path.starts_with(prefix))
        .map(str::to_string)
        .collect();
    if backups.len() <= keep {
        return;
    }
    backups.sort_unstable();
    backups.truncate(backups.len() - keep);

    // `--` because `rm` reads a leading dash as a flag. Every path here is
    // absolute and cannot begin with one, but the guard costs a word and the
    // argument list is built from directory contents.
    let mut args = vec!["-f", "--"];
    args.extend(backups.iter().map(String::as_str));
    match ctx.executor().execute_command("rm", &args).await {
        // execute_command returns Ok for a command that ran and failed.
        Ok(output) if output.success() => info!(
            "Pruned {} old backup(s) of {prefix}, keeping the newest {keep}",
            backups.len()
        ),
        Ok(output) => warn!(
            "Could not prune old backups of {prefix}: rm exited {} ({})",
            output.exit_code,
            output.stderr.trim()
        ),
        Err(e) => warn!("Could not prune old backups of {prefix}: {e}"),
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

/// What one rollback's reconciliation produced: what came back, and what did
/// not.
pub struct RollbackReconciliation {
    /// Per-plugin reload rows, in registry order.
    pub reloads: Vec<hardener_types::ReloadResult>,
    /// What the reloads could not fix, and what could not be checked.
    pub divergences: Vec<hardener_types::RollbackDivergence>,
}

/// Reloads every plugin whose configuration a rollback just restored, then
/// asks each of them what is still diverged.
///
/// Each plugin is asked once, however many of its paths were restored, and a
/// plugin matching nothing is not asked at all. A plugin that reports there
/// was nothing to reload produces no reload row, so the rows an operator
/// reads are the reloads that actually happened. It is still asked for
/// divergences: the two questions are independent, and a plugin with nothing
/// to reload can diverge anyway.
///
/// **Order is fixed: reload first, probe second.** Probing before the reload
/// would report every restored setting as diverged.
///
/// Failures are recorded rather than propagated: one subsystem refusing to
/// come back must not hide what the others did. The same rule covers the
/// registry itself: a listing that cannot be produced, or a plugin the
/// listing named but `get` could not retrieve, is recorded as a failed
/// reload rather than silently dropped. See `plugins_or_reload_failure` and
/// `plugin_or_reload_failure`.
pub async fn reconcile_plugins_after_rollback(
    ctx: &hardener_core::Context,
    registry: &hardener_core::PluginRegistry,
    restored: &[std::path::PathBuf],
) -> RollbackReconciliation {
    let metadata = match plugins_or_reload_failure(registry.list()) {
        Ok(metadata) => metadata,
        Err(failure) => {
            return RollbackReconciliation {
                reloads: vec![failure],
                divergences: Vec::new(),
            };
        }
    };

    let mut reloads = Vec::new();
    let mut divergences = Vec::new();

    for meta in metadata {
        let plugin = match plugin_or_reload_failure(registry.get(&meta.plugin_id), &meta.plugin_id)
        {
            Ok(plugin) => plugin,
            Err(failure) => {
                reloads.push(failure);
                continue;
            }
        };
        // The reload is gated on the path predicate, because a reload is work
        // and doing it for a subsystem nothing restored touched is wasted at
        // best. The divergence question is not gated, because the predicate
        // answers a different question: `permissions-hardening` and
        // `pam-hardening` override it for no path, so a gated probe could
        // never ask them and their answer could never be measured (#142).
        // Scoping belongs to the probe, which receives `restored` for it.
        if restored.iter().any(|path| plugin.reloads_for_path(path)) {
            match plugin.reload_after_rollback(ctx).await {
                Ok(None) => {}
                Ok(Some(action)) => reloads.push(hardener_types::ReloadResult {
                    reload_plugin_id: meta.plugin_id.as_str().to_string(),
                    reload_action: action,
                    reload_success: true,
                    reload_error: None,
                }),
                Err(e) => reloads.push(hardener_types::ReloadResult {
                    reload_plugin_id: meta.plugin_id.as_str().to_string(),
                    reload_action: "reload failed".to_string(),
                    reload_success: false,
                    reload_error: Some(e.to_string()),
                }),
            }
        }
        divergences.extend(plugin.divergences_after_rollback(ctx, restored).await);
    }

    RollbackReconciliation {
        reloads,
        divergences,
    }
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
