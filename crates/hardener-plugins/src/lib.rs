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

    rt.block_on(async { manager.rollback(&checkpoint_id).await })?;

    Ok(())
}

/// Creates a checkpoint before applying changes.
///
/// This function captures the current state of the specified files so they can
/// be restored later via rollback. Returns the checkpoint ID if successful.
///
/// # Arguments
/// * `ctx` - Execution context containing the checkpoint manager
/// * `checkpoint_name` - Human-readable name for the checkpoint
/// * `file_paths` - List of file paths to capture in the checkpoint
pub fn create_checkpoint_for_apply(
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

    let rt = tokio::runtime::Runtime::new().map_err(|e| {
        hardener_common::error::HardeningError::State(format!(
            "Failed to create tokio runtime: {}",
            e
        ))
    })?;

    let checkpoint_id = rt.block_on(async {
        manager.create_checkpoint(checkpoint_name, file_paths).await
    })?;

    tracing::info!("Created checkpoint: {}", checkpoint_id.as_str());

    Ok(Some(checkpoint_id.as_str().to_string()))
}

// Re-export dependencies for macro use
#[doc(hidden)]
pub use audit::AuditHardeningPlugin;
pub use firewall::FirewallHardeningPlugin;
pub use hardener_common;
pub use hardener_core;
pub use kernel::KernelHardeningPlugin;
pub use mac::MacHardeningPlugin;
pub use pam::PamHardeningPlugin;
pub use permissions::PermissionsHardeningPlugin;
pub use services::ServicesHardeningPlugin;
pub use ssh::SshHardeningPlugin;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
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
}
