//! Core plugin trait and related types.
//!
//! Defines the HardeningPlugin trait that all security plugins must implement.

#[cfg(feature = "system")]
use crate::config::PluginConfig;
#[cfg(feature = "system")]
use async_trait::async_trait;
#[cfg(feature = "system")]
use hardener_common::error::Result;
#[cfg(feature = "system")]
use std::path::Path;
#[cfg(feature = "system")]
use std::path::PathBuf;

// Re-export types from hardener-types for backwards compatibility
pub use hardener_types::{
    ApplyResult, Change, ChangeType, ExceptionOutcome, Finding, PluginMetadata, RollbackDivergence,
    ScanResult, UncheckedBlocker, UncheckedCheck, ValidationIssue, ValidationReport,
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
/// 6. **Rollback**: `rollback()` restores previous state if needed
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
    async fn scan(&self, ctx: &Context, config: &PluginConfig) -> Result<ScanResult>;

    /// Applies hardening changes based on the provided configuration.
    ///
    /// Should create a checkpoint before making changes.
    async fn apply(&self, ctx: &mut Context, config: &PluginConfig) -> Result<ApplyResult>;

    /// Whether a rollback that restored `path` needs this plugin to reload.
    ///
    /// The question is about the reload, not about ownership. A plugin that
    /// owns a path but needs no reload for it answers `false`, which is why
    /// the permissions plugin, whose paths come from operator directives at
    /// runtime and cannot be enumerated, takes the default.
    fn reloads_for_path(&self, _path: &Path) -> bool {
        false
    }

    /// Re-reads configuration this plugin owns, after a rollback restored it.
    ///
    /// Returns what was done, for the operator: `Some("sshd restarted")`.
    /// `None` means there was nothing to reload and produces no row in the
    /// rollback output.
    async fn reload_after_rollback(&self, _ctx: &Context) -> Result<Option<String>> {
        Ok(None)
    }

    /// What this plugin's subsystem still disagrees with, after the restore
    /// and its own reload have both run.
    ///
    /// Asked of every plugin, and asked after the reload, because a
    /// divergence is by definition what the reload could not fix. Asked
    /// independently of whether there was anything to reload: a plugin can
    /// have nothing to reload and diverge anyway, which is exactly the sysctl
    /// case.
    ///
    /// **Scoping belongs here, not to the caller.** `restored` is the list of
    /// paths the rollback put back, and an implementation returns an empty
    /// vector when none of them are its business. The dispatch gated this on
    /// `reloads_for_path` until #142, which meant the two plugins that
    /// override that predicate for no path could never be asked.
    ///
    /// **Reporting only.** An implementation must not change system state
    /// here. It returns a `Vec` rather than a `Result` on purpose: a probe
    /// that cannot answer says so with an `Unverifiable` row, and a fallible
    /// signature would give it a second way to say nothing.
    async fn divergences_after_rollback(
        &self,
        _ctx: &Context,
        _restored: &[PathBuf],
    ) -> Vec<RollbackDivergence> {
        Vec::new()
    }

    /// Validates configuration without applying changes (dry-run).
    async fn validate(&self, ctx: &Context, config: &PluginConfig) -> Result<ValidationReport>;
}

#[cfg(test)]
mod tests;
