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
/// This function handles the common pattern of restoring files from a checkpoint.
/// Plugins can call this and then perform any additional service restarts needed.
pub fn rollback_files_from_checkpoint(
    ctx: &hardener_core::Context,
    checkpoint: &hardener_core::Checkpoint,
) -> hardener_common::error::Result<()> {
    // Get the checkpoint manager from context
    let manager = ctx.checkpoint_manager().ok_or_else(|| {
        hardener_common::error::HardeningError::State(
            "CheckpointManager not available in context".to_string(),
        )
    })?;

    // Run async rollback to restore configuration files
    let checkpoint_id = checkpoint.checkpoint_id.clone();
    let manager = manager.clone();

    let rt = tokio::runtime::Runtime::new().map_err(|e| {
        hardener_common::error::HardeningError::State(format!(
            "Failed to create tokio runtime: {}",
            e
        ))
    })?;

    rt.block_on(async {
        manager
            .rollback(ctx.executor().as_ref(), &checkpoint_id)
            .await
    })?;

    Ok(())
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

#[cfg(test)]
mod tests {
    use hardener_core::plugin::HardeningPlugin;

    use crate::define_plugin;

    // Use the macro to define a test plugin
    define_plugin! {
        TestPlugin {
            id: "test-plugin",
            name: "Test Plugin",
            version: "0.1.0",
            description: "A test plugin for macro validation",
            category: Kernel,
            dependencies: [],
        }
    }

    #[test]
    fn test_macro_generates_plugin() {
        // Create an instance
        let plugin = TestPlugin;

        // Test metadata
        let meta = plugin.metadata();
        assert_eq!(meta.plugin_id.to_string(), "test-plugin");
        assert_eq!(meta.plugin_name, "Test Plugin");
        assert_eq!(meta.plugin_version, "0.1.0");
        assert_eq!(
            meta.plugin_description,
            "A test plugin for macro validation"
        );

        // Test dependencies
        let deps = plugin.dependencies();
        assert_eq!(deps.len(), 0);
    }

    /// `coverage_for` returning `None` for a real plugin would silently strip
    /// that plugin's controls from the failure path, handing them back the Pass
    /// this table exists to prevent. A new plugin must therefore appear here,
    /// and this test is what says so.
    #[test]
    fn every_registered_plugin_declares_its_coverage() {
        let registry = crate::create_plugin_registry();
        for metadata in registry.list().unwrap() {
            assert!(
                crate::coverage_for(metadata.plugin_id.as_str()).is_some(),
                "plugin '{}' is registered but absent from coverage_table",
                metadata.plugin_id.as_str()
            );
        }
    }

    /// A plugin the registry lists but `get_plugin_config` does not name falls
    /// through to one shared empty default whose `enabled` is `true`. The
    /// operator's `enabled = false`, directive overrides and policy exceptions
    /// for that plugin are then read as absent rather than as unroutable, so
    /// the plugin runs unconfigured, applies baseline values the operator
    /// overrode, and reports the deviations its exceptions document as
    /// violations.
    ///
    /// The routing is a hand-written match over eight literals because
    /// `HardenerConfig` names its sections as struct fields, leaving nothing to
    /// derive it from; the registry is the only thing that can say the match is
    /// complete. `hardener-core` cannot see the registry, which is why this
    /// guard lives here rather than beside the code it guards.
    #[test]
    fn every_registered_plugin_routes_to_its_own_config_section() {
        let config = hardener_core::HardenerConfig::default();
        // Every unroutable id gets the one shared static, so identity with it
        // is precisely the fell-through state and nothing else.
        let fallback = config.get_plugin_config("no-plugin-answers-to-this-id");

        for metadata in crate::create_plugin_registry().list().unwrap() {
            let id = metadata.plugin_id.as_str();
            assert!(
                !std::ptr::eq(config.get_plugin_config(id), fallback),
                "plugin '{id}' is registered but HardenerConfig::get_plugin_config \
                 does not route it, so its configuration is silently ignored"
            );
        }
    }

    #[test]
    fn compliance_coverage_spans_multiple_frameworks() {
        use std::collections::HashSet;
        let coverage = crate::compliance_coverage();
        assert!(!coverage.is_empty(), "plugins must declare coverage");

        // Entries are deduplicated by (framework, control_id).
        let unique: HashSet<_> = coverage
            .iter()
            .map(|m| (m.compliance_framework, m.compliance_control_id.as_str()))
            .collect();
        assert_eq!(
            unique.len(),
            coverage.len(),
            "coverage must be deduplicated"
        );

        // CIS is fully wired; at least one non-CIS framework must also be covered
        // or the multi-framework reports would all collapse to manual review.
        let frameworks: HashSet<_> = coverage.iter().map(|m| m.compliance_framework).collect();
        assert!(
            frameworks.len() >= 2,
            "coverage must span multiple frameworks"
        );
    }

    /// The 11 curated CIS controls wired off ManualReview in the
    /// 2026-06-29 CIS-coverage work must all reach `compliance_coverage()`.
    /// Each is a catalogued control, so its presence here flips it to Pass/Fail.
    #[test]
    fn newly_wired_cis_controls_are_all_covered() {
        use hardener_common::types::ComplianceFramework;
        let required = [
            "6.1.2", "6.1.3", "6.1.4", "6.1.5", // permissions
            "3.2.2", "3.2.3", "3.2.4",   // kernel
            "2.1.1",   // services (xinetd)
            "3.4.1.1", // firewall
            "5.3.2", "5.3.3", // pam
        ];
        let covered: Vec<String> = crate::compliance_coverage()
            .into_iter()
            .filter(|m| m.compliance_framework == ComplianceFramework::CIS)
            .map(|m| m.compliance_control_id)
            .collect();
        for id in required {
            assert!(
                covered.contains(&id.to_string()),
                "CIS {id} missing from coverage"
            );
        }
    }
}
