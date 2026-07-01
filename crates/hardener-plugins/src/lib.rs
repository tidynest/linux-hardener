pub mod audit;
pub mod firewall;
pub mod kernel;
pub mod mac;
pub mod macros;
pub mod pam;
pub mod permissions;
pub mod services;
pub mod ssh;

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
/// Captures only mode/uid/gid for each path — no file contents, no recursion.
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
    [
        audit::coverage(),
        firewall::coverage(),
        kernel::coverage(),
        mac::coverage(),
        pam::coverage(),
        permissions::coverage(),
        services::coverage(),
        ssh::coverage(),
    ]
    .into_iter()
    .flatten()
    .filter(|m| seen.insert((m.compliance_framework, m.compliance_control_id.clone())))
    .collect()
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
