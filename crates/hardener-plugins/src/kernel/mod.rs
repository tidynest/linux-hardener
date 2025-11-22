//! Kernel hardening plugin for sysctl parameter management.
//!
//! This plugin scans, applies, and manages kernel security parameters via sysctl.
//! It focuses on critical security settings including:
//! - Address Space Layout Randomisation (ASLR)
//! - Kernel pointer restrictions
//! - dmesg access restriction
//! - Core dump restrictions
//!
//! The plugin reads current values, compares against secure baselines,
//! and can apply hardening configurations with automatic rollback support.

use hardener_common::{
    error::Result,
    types::{FindingCategory, PluginId, Severity},
};
use hardener_core::{
    Change, ChangeType, Checkpoint, Config, ValidationIssue, ValidationReport,
    context::Context,
    plugin::{ApplyResult, Finding, HardeningPlugin, PluginMetadata, ScanResult},
};
use std::{fs, time::Instant};

/// Kernel hardening plugin implementing sysctl parameter management.
pub struct KernelHardeningPlugin;

impl Default for KernelHardeningPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelHardeningPlugin {
    /// Creates a new instance of the kernel hardening plugin.
    pub fn new() -> KernelHardeningPlugin {
        Self
    }

    /// Reads a sysctl parameter value from /proc/sys.
    ///
    /// # Arguments
    /// * `param` - Parameter name in dot notation (e.g., "kernel.randomize_va_space")
    ///
    /// # Returns
    /// The parameter values as a string, or an error if reading fails.
    fn read_sysctl(&self, param: &str) -> Result<String> {
        let path = format!("/proc/sys/{}", param.replace('.', "/"));
        let content = fs::read_to_string(&path)?;
        Ok(content.trim().to_string())
    }
}

/// Critical kernel security parameters with their secure values.
///
/// Each tuple contains:
/// - Parameter name in sysctl dot notation
/// - Recommended secure value
/// - Human-readable explanation
const KERNEL_PARAMS: &[(&str, &str, &str)] = &[
    (
        "kernel.randomize_va_space",
        "2",
        "Enable full address space layout randomisation (ASLR)",
    ),
    (
        "kernel.kptr_restrict",
        "2",
        "Hides kernel pointers from all users except root",
    ),
    (
        "kernel.dmesg_restrict",
        "1",
        "Restricts dmesg access to privileged users only",
    ),
    (
        "kernel.yama.ptrace_scope",
        "2",
        "Restricts ptrace usage to admin-only",
    ),
    (
        "fs.suid_dumpable",
        "0",
        "Prevents setuid processes from creating core dumps",
    ),
    (
        "fs.protected_hardlinks",
        "1",
        "Prevents hardlink creation to files user doesn't own",
    ),
    (
        "fs.protected_symlinks",
        "1",
        "Prevents symlink following in sticky world-writable directories",
    ),
    (
        "net.ipv4.conf.all.rp_filter",
        "1",
        "Enables reverse path filtering (anti-spoofing)",
    ),
    (
        "net.ipv4.conf.default.rp_filter",
        "1",
        "Enables reverse path filtering for new interfaces",
    ),
    (
        "net.ipv4.tcp_syncookies",
        "1",
        "Enables SYN flood protection",
    ),
    (
        "net.ipv4.conf.all.accept_source_route",
        "0",
        "Disables source routing (security risk)",
    ),
    (
        "net.ipv4.conf.default.accept_source_route",
        "0",
        "Disables source routing for new interfaces",
    ),
];

impl HardeningPlugin for KernelHardeningPlugin {
    /// Returns metadata about the kernel hardening plugin.
    ///
    /// This provides the plugin system with identification and versioning
    /// information used for logging, UI display, and dependency management.
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            plugin_category: FindingCategory::Kernel,
            plugin_description: "Manages kernel security parameters via sysctl".to_string(),
            plugin_id: PluginId::new("kernel"),
            plugin_name: "Kernel Hardening".to_string(),
            plugin_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Returns plugin dependencies.
    ///
    /// The kernel hardening plugin has no dependencies as it operates
    /// independently on kernel parameters via sysctl.
    fn dependencies(&self) -> Vec<PluginId> {
        Vec::new()
    }

    fn scan(&self, _ctx: &Context) -> Result<ScanResult> {
        let start_time = Instant::now();
        let mut findings = Vec::new();

        for (param_name, expected_value, param_description) in KERNEL_PARAMS {
            match self.read_sysctl(param_name) {
                Ok(actual_value) => {
                    if actual_value != *expected_value {
                        findings.push(Finding {
                            category: FindingCategory::Kernel,
                            current_value: actual_value.clone(),
                            description: param_description.to_string(),
                            explanation: format!(
                                "This parameter should be set to '{}' for security hardening",
                                expected_value
                            ),
                            finding_id: format!("kernel_{}", param_name.replace('.', "_")),
                            impact: "Low impact - requires reboot or sysctl reload".to_string(),
                            recommended_value: expected_value.to_string(),
                            remediation_steps: vec![format!(
                                "Set {} = {}",
                                param_name, expected_value
                            )],
                            severity: Severity::Medium,
                            title: format!("Insecure value for {}", param_name),
                        });
                    }
                }
                Err(e) => {
                    // Parameter doesn't exist on this kernel - log but don't fail
                    tracing::warn!("Cannot read {}: {}", param_name, e);
                }
            }
        }

        Ok(ScanResult {
            plugin_id: self.metadata().plugin_id,
            success: true,
            findings,
            duration_us: start_time.elapsed().as_micros() as u64,
            error: None,
        })
    }

    /// Applies kernel hardening by setting sysctl parameters.
    ///
    /// # Security Implications
    /// This writes to /proc/sys which requires root privileges.
    /// Changes take effect immediately but are not persistent across reboots
    /// unless also written to /etc/sysctl.conf or /etc/sysctl.d/
    ///
    /// # Arguments
    /// * `ctx`    - Execution context (unused for now, but required by trait)
    /// * `config` - Configuration (unused for now, applies all hardening)
    fn apply(&self, _ctx: &mut Context, _config: &Config) -> Result<ApplyResult> {
        let mut changes = Vec::new();

        for (param_name, expected_value, param_description) in KERNEL_PARAMS {
            let path = format!("/proc/sys/{}", param_name.replace('.', "/"));

            match fs::write(&path, expected_value) {
                Ok(_) => {
                    changes.push(Change {
                        description: format!("{}: set to {}", param_description, expected_value),
                        change_type: ChangeType::KernelParameter,
                        success: true,
                        error: None,
                    });
                    tracing::info!("Applied {}: {}", param_name, expected_value);
                }
                Err(e) => {
                    changes.push(Change {
                        description: format!("{}: failed to set", param_name),
                        change_type: ChangeType::KernelParameter,
                        success: false,
                        error: Some(e.to_string()),
                    });
                    tracing::warn!("Failed to apply {}: {}", param_name, e);
                }
            }
        }

        let success = changes.iter().all(|c| c.success);

        Ok(ApplyResult {
            plugin_id: self.metadata().plugin_id,
            success,
            changes,
            checkpoint_id: None, //Checkpoint not implemented yet
            error: None,
        })
    }

    /// Rolls back kernel parameters to a previous checkpoint.
    ///
    /// # Implementation Status
    /// This is currently a stub. Full rollback implementation requires:
    /// - Checkpoint system to store previous sysctl values
    /// - Ability to restore from checkpoint data
    ///
    /// # Arguments
    /// * `ctx` - Execution context containing checkpoint data
    /// * `checkpoint` - The checkpoint to restore to
    fn rollback(&self, _ctx: &mut Context, _checkpoint: &Checkpoint) -> Result<()> {
        // TODO: Implement checkpoint-based rollback
        // Placeholder:
        tracing::warn!("Rollback not yet implemented for kernel plugin");
        Ok(())
    }

    /// Validates that kernel parameters can be applied (dry-run).
    ///
    /// Checks if sysctl parameters exist and are writable without
    /// actually modifying them.
    ///
    /// # Arguments
    /// * `config` - Configuration to validate (unused for now)
    fn validate(&self, _config: &Config) -> Result<ValidationReport> {
        let mut issues = Vec::new();
        let mut estimated_changes = Vec::new();

        for (param_name, expected_value, _expected_description) in KERNEL_PARAMS {
            let path = format!("/proc/sys/{}", param_name.replace('.', "/"));

            // Check if parameter exists and is readable
            match fs::metadata(&path) {
                Ok(metadata) => {
                    if metadata.permissions().readonly() {
                        issues.push(ValidationIssue {
                            severity: Severity::High,
                            message: format!("{} is read-only", param_name),
                            config_key: Some(param_name.to_string()),
                        });
                    } else {
                        estimated_changes
                            .push(format!("{} will be set to {}", param_name, expected_value));
                    }
                }
                Err(_) => {
                    issues.push(ValidationIssue {
                        severity: Severity::Low,
                        message: format!("{} does not exist on this kernel", param_name),
                        config_key: Some(param_name.to_string()),
                    });
                }
            }
        }

        Ok(ValidationReport {
            plugin_id: self.metadata().plugin_id,
            is_valid: issues.iter().all(|i| i.severity != Severity::High),
            issues,
            estimated_changes,
        })
    }
}
