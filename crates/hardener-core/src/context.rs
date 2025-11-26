//! Execution context for hardening operations.
//!
//! Provides system information, state management, and audit logging
//! that plugins use during their lifecycle.

use hardener_common::{error::Result, types::PluginId};
use hardener_state::CheckpointManager;
use hostname;
use nix;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

/// Execution context provided to plugins.
///
/// Contains system information, state management for rollback,
/// audit logging, and shared data between plugins.
pub struct Context {
    /// Audit log for tracking all operations.
    audit_log: Arc<RwLock<Vec<PluginAuditEntry>>>,
    /// Checkpoint manager for creating and restoring system state snapshots.
    checkpoint_manager: Option<Arc<CheckpointManager>>,
    /// Shared data that plugins can use to communicate
    #[allow(dead_code)]
    shared_data: Arc<RwLock<HashMap<String, String>>>,
    /// Information about the current system.
    system_info: SystemInfo,
}

/// Plugin audit log entry for tracking plugin operations in context.
///
/// Records plugin operations for in-memory tracking during execution.
/// For persistent tamper-proof auditing, see hardener_state::audit::AuditEntry.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PluginAuditEntry {
    /// Timestamp when the operation occurred (Unix timestamp in seconds).
    pub entry_timestamp: u64,
    /// Plugin that performed the operation.
    pub entry_plugin_id: PluginId,
    /// Type of operation (scan, apply, rollback).
    pub entry_operation: AuditOperation,
    /// Description of what was done.
    pub entry_description: String,
    /// Whether the operation succeeded.
    pub entry_success: bool,
    /// Optional error message if operation failed.
    pub entry_error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum AuditOperation {
    /// System scan operation.
    Scan,
    /// Apply hardening changes.
    Apply,
    /// Rollback to previous state.
    Rollback,
    /// Configuration validation.
    Validate,
}

impl PluginAuditEntry {
    /// Creates a new audit entry with the current timestamp.
    pub fn new(
        plugin_id: impl Into<String>,
        operation: AuditOperation,
        description: impl Into<String>,
        success: bool,
    ) -> PluginAuditEntry {
        Self {
            entry_timestamp: Self::current_timestamp(),
            entry_plugin_id: PluginId::from(plugin_id.into()),
            entry_operation: operation,
            entry_description: description.into(),
            entry_success: success,
            entry_error: None,
        }
    }

    /// Creates a new audit entry with an error.
    pub fn with_error(
        plugin_id: impl Into<PluginId>,
        operation: AuditOperation,
        description: impl Into<String>,
        error: impl Into<String>,
    ) -> PluginAuditEntry {
        Self {
            entry_timestamp: Self::current_timestamp(),
            entry_plugin_id: plugin_id.into(),
            entry_operation: operation,
            entry_description: description.into(),
            entry_success: false,
            entry_error: Some(error.into()),
        }
    }

    /// Gets the current Unix timestamp in seconds.
    fn current_timestamp() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};

        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Information about the current system.
///
/// Provides distribution details, kernel version, and other
/// system-level information that plugins need.
#[derive(Clone, Debug)]
pub struct SystemInfo {
    /// Architecture (e.g., "x86_64", "aarch64").
    pub system_architecture: String,
    /// Operating system distribution name (e.g. "Ubuntu", "RHEL"),
    pub system_distribution: String,
    /// Distribution version (e.g., "22.04, "9").
    pub system_distribution_version: String,
    /// System hostname.
    pub system_hostname: String,
    /// Kernel version string.
    pub system_kernel_version: String,
}

impl SystemInfo {
    /// Detects system information from the current environment.
    ///
    /// Reads from `/etc/os-release` for distribution info and uses
    /// system calls for kernel and hostname.
    pub fn detect() -> Result<SystemInfo> {
        Ok(Self {
            system_architecture: Self::detect_architecture()?,
            system_distribution: Self::detect_distribution()?,
            system_distribution_version: Self::detect_distribution_version()?,
            system_hostname: Self::detect_hostname()?,
            system_kernel_version: Self::detect_kernel_version()?,
        })
    }

    /// Helper function: Reads and parses /etc/os-release file.
    fn read_os_release() -> Result<HashMap<String, String>> {
        use std::fs;

        let content = fs::read_to_string("/etc/os-release")
            .map_err(hardener_common::error::HardeningError::System)?;

        let mut map = HashMap::new();
        for line in content.lines() {
            if let Some((key, value)) = line.split_once("=") {
                map.insert(key.to_string(), value.to_string());
            }
        }

        Ok(map)
    }

    /// Placeholder detection methods
    fn detect_architecture() -> Result<String> {
        Ok(std::env::consts::ARCH.to_string())
    }

    fn detect_distribution() -> Result<String> {
        let os_release = Self::read_os_release()?;

        // Try ID first (e.g., "ubuntu", "rhel"), fallback to NAME
        if let Some(id) = os_release.get("ID") {
            return Ok(id.trim_matches('"').to_string());
        }

        if let Some(name) = os_release.get("NAME") {
            return Ok(name.trim_matches('"').to_string());
        }

        Ok("Unknown Distribution".to_string())
    }

    fn detect_distribution_version() -> Result<String> {
        let os_release = Self::read_os_release()?;

        // Try VERSION_ID first, fallback to VERSION
        if let Some(version_id) = os_release.get("VERSION_ID") {
            return Ok(version_id.trim_matches('"').to_string());
        }

        if let Some(version) = os_release.get("VERSION") {
            return Ok(version.trim_matches('"').to_string());
        }

        Ok("Unknown Distribution Version".to_string())
    }

    fn detect_hostname() -> Result<String> {
        let hostname = hostname::get()
            .map_err(hardener_common::error::HardeningError::System)?
            .to_string_lossy()
            .to_string();
        Ok(hostname)
    }

    fn detect_kernel_version() -> Result<String> {
        let uname = nix::sys::utsname::uname().map_err(|e| {
            hardener_common::error::HardeningError::System(std::io::Error::other(e.to_string()))
        })?;

        Ok(uname.release().to_string_lossy().to_string())
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

impl Context {
    /// Creates a new Context with default system information.
    ///
    /// This will be used during normal operations.
    pub fn new() -> Context {
        Self {
            audit_log: Arc::new(RwLock::new(Vec::new())),
            checkpoint_manager: None,
            shared_data: Arc::new(RwLock::new(HashMap::new())),
            system_info: SystemInfo::detect().unwrap_or_else(|_| SystemInfo {
                system_architecture: "Unknown".to_string(),
                system_distribution: "Unknown".to_string(),
                system_distribution_version: "Unknown".to_string(),
                system_hostname: "Unknown".to_string(),
                system_kernel_version: "Unknown".to_string(),
            }),
        }
    }

    /// Creates a new Context with a checkpoint manager.
    ///
    /// Use this when you need checkpoint/rollback functionality.
    pub fn with_checkpoint_manager(checkpoint_manager: CheckpointManager) -> Context {
        Self {
            audit_log: Arc::new(RwLock::new(Vec::new())),
            checkpoint_manager: Some(Arc::new(checkpoint_manager)),
            shared_data: Arc::new(RwLock::new(HashMap::new())),
            system_info: SystemInfo::detect().unwrap_or_else(|_| SystemInfo {
                system_architecture: "Unknown".to_string(),
                system_distribution: "Unknown".to_string(),
                system_distribution_version: "Unknown".to_string(),
                system_hostname: "Unknown".to_string(),
                system_kernel_version: "Unknown".to_string(),
            }),
        }
    }

    /// Sets the checkpoint manager for this context.
    pub fn set_checkpoint_manager(&mut self, checkpoint_manager: CheckpointManager) {
        self.checkpoint_manager = Some(Arc::new(checkpoint_manager));
    }

    /// Returns a reference to the checkpoint manager, if available.
    pub fn checkpoint_manager(&self) -> Option<&Arc<CheckpointManager>> {
        self.checkpoint_manager.as_ref()
    }

    /// Logs an audit entry for tracking operations.
    ///
    /// # Errors
    /// Returns an error if the audit log lock is poisoned.
    pub fn log_audit(&self, entry: PluginAuditEntry) -> Result<()> {
        let mut log = self.audit_log.write().map_err(|e| {
            hardener_common::error::HardeningError::State(format!(
                "Failed to acquire audit log lock: {}",
                e
            ))
        })?;

        log.push(entry);
        Ok(())
    }

    /// Returns a reference to the system information.
    pub fn system_info(&self) -> &SystemInfo {
        &self.system_info
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_info_detection() {
        let info = SystemInfo::detect().unwrap();

        // Print what we detected (useful for debugging)
        println!("Distribution: {}", info.system_distribution);
        println!("Version: {}", info.system_distribution_version);
        println!("Kernel: {}", info.system_kernel_version);
        println!("Hostname: {}", info.system_hostname);
        println!("Architecture: {}", info.system_architecture);

        // Basic sanity checks
        assert!(!info.system_distribution.is_empty());
        assert!(!info.system_architecture.is_empty());
    }

    #[test]
    fn test_audit_entry_creation() {
        let entry =
            PluginAuditEntry::new("test_plugin", AuditOperation::Scan, "Scanning system", true);

        assert_eq!(entry.entry_plugin_id, PluginId::from("test_plugin"));
        assert_eq!(entry.entry_description, "Scanning system");
        assert!(entry.entry_success);
        assert!(entry.entry_error.is_none());
        assert!(entry.entry_timestamp > 0);
    }

    #[test]
    fn test_audit_entry_with_error() {
        let entry = PluginAuditEntry::with_error(
            "test_plugin",
            AuditOperation::Apply,
            "Failed to apply changes",
            "Permission denied",
        );

        assert_eq!(entry.entry_plugin_id, PluginId::from("test_plugin"));
        assert!(!entry.entry_success);
        assert_eq!(entry.entry_error, Some("Permission denied".to_string()));
    }

    #[test]
    fn test_context_logs_audit() {
        let ctx = Context::new();
        let entry =
            PluginAuditEntry::new("test_plugin", AuditOperation::Scan, "Test operation", true);

        let result = ctx.log_audit(entry);
        assert!(result.is_ok());
    }
}
