//! Core plugin trait and related types.
//!
//! Defines the HardeningPlugin trait that all security plugins must implement.

use async_trait::async_trait;
use hardener_common::error::Result;

// Re-export types from hardener-types for backwards compatibility
pub use hardener_types::{
    ApplyResult, Change, ChangeType, Finding, PluginMetadata,
    ScanResult, ValidationIssue, ValidationReport,
};

// Also re-export commonly used types from hardener-common
pub use hardener_common::types::{
    ComplianceMapping, FindingCategory, FindingPolicyException, PluginId, Severity,
};

// Context is only available with the system feature
#[cfg(feature = "system")]
pub(crate) use crate::context::Context;

// Re-export checkpoint types from hardener-state
#[cfg(feature = "system")]
pub use hardener_state::{Checkpoint, CheckpointId, CheckpointManager};

#[cfg(feature = "system")]
#[derive(Default)]
pub struct Config;

/// Core trait that all hardening plugins must implement.
///
/// This trait defines the contract for security hardening plugins.
/// Each plugin is responsible for:
/// - Scanning the system for security issues in its domain
/// - Applying hardening changes based on configuration
/// - Rolling back changes if needed
/// - Validating configurations before applying
///
/// # Plugin Lifecycle
///
/// 1. **Registration**: Plugin is registered with the PluginRegistry
/// 2. **Dependency Resolution**: Dependencies are checked and ordered
/// 3. **Scanning**: `scan()` is called to detect current security state
/// 4. **Validation**: `validate()` checks configuration before changes
/// 5. **Application**: `apply()` makes changes to harden the system
/// 5. **Rollback**: `rollback()` restores previous state if needed
///
/// # Thread Safety
///
/// Plugins must be `Send + Sync` as they may be called from async contexts
/// and share across threads.
///
/// This trait is only available with the `system` feature enabled.
#[cfg(feature = "system")]
#[async_trait]
pub trait HardeningPlugin: Send + Sync {
    /// Returns metadata describing this plugin.
    fn metadata(&self) -> PluginMetadata;

    /// Returns a list of plugin IDs that this plugin depends on.
    ///
    /// Dependencies will be processed before this plugin during operations.
    fn dependencies(&self) -> Vec<PluginId>;

    /// Scans the system for security issues in this plugin's domain.
    ///
    /// This method should not modify the system (read-only operation).
    async fn scan(&self, ctx: &Context) -> Result<ScanResult>;

    /// Applies hardening changes based on the provided configuration.
    ///
    /// Should create a checkpoint before making changes.
    async fn apply(&self, ctx: &mut Context, config: &Config) -> Result<ApplyResult>;

    /// Rolls back changes to a previous checkpoint
    async fn rollback(&self, ctx: &mut Context, checkpoint: &Checkpoint) -> Result<()>;

    /// Validates configuration without applying changes (dry-run).
    async fn validate(&self, ctx: &Context, config: &Config) -> Result<ValidationReport>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_change_type_display() {
        assert_eq!(ChangeType::ConfigFile.to_string(), "Config File");
        assert_eq!(ChangeType::FirewallRule.to_string(), "Firewall Rule");
        assert_eq!(ChangeType::KernelParameter.to_string(), "Kernel Parameter");
    }
}
