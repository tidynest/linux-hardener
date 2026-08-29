//! Core crate for the Linux system hardener.
//!
//! Provides the plugin trait, the configuration system, the plugin registry,
//! the dependency-ordered plugin manager, and the two real executors,
//! [`LocalExecutor`] and [`SshExecutor`].
//!
//! **It does not define the executor abstraction.** `SystemExecutor` and
//! `MockExecutor` live in `hardener-common`; this crate implements the trait
//! and re-exports it beside its implementations, which is why a consumer can
//! take everything executor-shaped from here. The header used to claim the
//! abstraction itself, which pointed a reader at the wrong crate.

// Core modules that work without system dependencies
pub mod plugin;

// System-specific modules (require hostname, nix, petgraph)
pub mod config;
pub mod config_loader;
pub mod config_validation;
/// Needs `hardener-state` for the audit log and `nix` for the effective user,
/// both of which arrive with `system`, so a `default-features = false` build
/// gets the config loader without the writer.
#[cfg(feature = "system")]
pub mod config_write;
#[cfg(feature = "system")]
pub mod context;
pub mod executor;
pub mod inventory;
#[cfg(feature = "system")]
pub mod plugin_manager;
#[cfg(feature = "system")]
pub mod registry;
#[cfg(feature = "system")]
pub mod testing;

// Re-export commonly used types (always available)
pub use plugin::{
    ApplyResult, Change, ChangeType, ExceptionOutcome, Finding, PluginMetadata, ScanResult,
    UncheckedBlocker, UncheckedCheck, ValidationIssue, ValidationReport,
};

// Re-export config types (always available)
pub use config::{GlobalConfig, HardenerConfig, PluginConfig, PolicyException};
pub use config_loader::ConfigLoader;

// Re-export testing (requires system feature)
#[cfg(all(feature = "system", test))]
pub use testing::MockPlugin;

// Re-export system-specific plugin types
#[cfg(feature = "system")]
pub use plugin::{Checkpoint, CheckpointId, CheckpointManager, HardeningPlugin};

// Re-export system-specific types only when feature is enabled
#[cfg(feature = "system")]
pub use context::{Context, PluginAuditEntry, SystemInfo};

// Re-export executor types
pub use executor::{
    local::LocalExecutor,
    {CommandOutput, FileMetadata, SystemExecutor, session_is_root},
};
// Gated beside its definition: the mock is test infrastructure, and a
// release build that re-exported it would ship a pretend executor it can
// never reach.
#[cfg(feature = "test-support")]
pub use executor::MockExecutor;

#[cfg(feature = "system")]
pub use executor::ssh::{SshConfig, SshExecutor};

// Re-export openssh types needed by consumers of SshConfig
#[cfg(feature = "system")]
pub use openssh::KnownHosts;

#[cfg(feature = "system")]
pub use plugin_manager::PluginManager;

#[cfg(feature = "system")]
pub use registry::PluginRegistry;
