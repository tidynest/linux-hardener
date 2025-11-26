// Core modules that work without system dependencies
pub mod plugin;

// System-specific modules (require hostname, nix, petgraph)
#[cfg(feature = "system")]
pub mod context;
#[cfg(feature = "system")]
pub mod plugin_manager;
#[cfg(feature = "system")]
pub mod registry;

// Re-export commonly used types (always available)
pub use plugin::{
    ApplyResult, Change, ChangeType, Finding, PluginMetadata, ScanResult, ValidationIssue,
    ValidationReport,
};

// Re-export system-specific plugin types
#[cfg(feature = "system")]
pub use plugin::{Checkpoint, CheckpointId, CheckpointManager, Config, HardeningPlugin};

// Re-export system-specific types only when feature is enabled
#[cfg(feature = "system")]
pub use context::{Context, PluginAuditEntry, SystemInfo};
#[cfg(feature = "system")]
pub use plugin_manager::PluginManager;
#[cfg(feature = "system")]
pub use registry::PluginRegistry;
