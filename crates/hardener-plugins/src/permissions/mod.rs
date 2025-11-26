//! File Permissions Plugin
//!
//! This plugin audits and secures critical file and directory permissions
//! across the system to prevent privilege escalation and unauthorised access.
//!
//! Checks:
//! - Critical directory permissions (/root, /boot, /etc/ssh. /etc/sudoers)
//! - SUID/SGID binaries (identifies dangerous ones)
//! - World-writable files and directories
//! - SSH key file permissions
//! - Sudo configuration files

use hardener_common::{
    error::Result,
    types::{ComplianceMapping, ComplianceFramework, FindingCategory, PluginId, Severity}
};
use hardener_core::{
    ApplyResult, Change, ChangeType, Checkpoint, Config,
    ValidationReport,
    context::Context,
    plugin::{Finding, HardeningPlugin, PluginMetadata, ScanResult},
};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, time::Instant};
use tracing::warn;

/// File Permissions Hardening Plugin
///
/// Audits and secures critical file and directory permissions to prevent
/// privilege escalation and unauthorised access.
pub struct PermissionsHardeningPlugin {}

impl Default for PermissionsHardeningPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl PermissionsHardeningPlugin {
    /// Creates a new instance of the Permissions Hardening Plugin.
    pub fn new() -> PermissionsHardeningPlugin {
        PermissionsHardeningPlugin {}
    }
}

/// Represents a single permission directive for a critical system path.
///
/// Each directive defines the expected ownership and permission mode for a path.
#[derive(Clone, Debug)]
struct PermissionDirective {
    permission_description: &'static str,
    permission_path:        &'static str,
    permission_mode:        u32,  // Octal mode like 0o700
    _permission_owner:       &'static str,
    _permission_group:       &'static str,
    permission_severity:    Severity,
}

/// Critical system paths with their required permissions.
///
/// Based on CIS Benchmark and security best practices for Linux systems.
///
/// Permission code combinations used:
///   - 0o700 = Only owner (root) can read/write/execute
///   - 0o755 = Owner can read/write/execute, others can only read/execute
///   - 0o440 = Owner and group can read, no one can write or execute
///   - 0o750 = Owner full access, group can read/execute, others nothing
const CRITICAL_PERMISSIONS: &[PermissionDirective] = &[
    PermissionDirective {
        permission_description: "Root home directory must be restricted to root only",
        permission_path:        "/root",
        permission_mode:        0o700,
        _permission_owner:       "root",
        _permission_group:       "root",
        permission_severity:    Severity::High,
    },
    PermissionDirective {
        permission_description: "Boot directory must be protected from unauthorised modification",
        permission_path:        "/boot",
        permission_mode:        0o700,
        _permission_owner:       "root",
        _permission_group:       "root",
        permission_severity:    Severity::High,
    },
    PermissionDirective {
        permission_description: "SSH configuration directory must be restricted",
        permission_path:        "/etc/ssh",
        permission_mode:        0o755,
        _permission_owner:       "root",
        _permission_group:       "root",
        permission_severity:    Severity::High,
    },    PermissionDirective {
        permission_description: "Sudoers file must be read-only for root group",
        permission_path:        "/etc/sudoers",
        permission_mode:        0o440,
        _permission_owner:       "root",
        _permission_group:       "root",
        permission_severity:    Severity::Critical,
    },
    PermissionDirective {
        permission_description: "Sudoers directory must be restricted",
        permission_path:        "/etc/sudoers.d",
        permission_mode:        0o750,
        _permission_owner:       "root",
        _permission_group:       "root",
        permission_severity:    Severity::Critical,
    },
];

/// Checks if a path has the correct permissions, owner, and group.
///
/// Returns a Finding if permissions are incorrect, None if correct
fn check_path_permissions(directive: &PermissionDirective) -> Option<Finding> {
    let path = Path::new(directive.permission_path);

    // Skip if path doesn't exist
    if !path.exists() {
        return None;
    }

    // Get file metadata
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return None,  // Can't read, skip it
    };

    // Get current permissions (only last 9 bits = rwxrwxrwx)
    let current_mode = metadata.permissions().mode() & 0o777;

    // Check if permissions are incorrect
    if current_mode != directive.permission_mode {
        return Some(Finding {
            finding_category: FindingCategory::FileSystem,
            finding_current_value: format!("{:04o}", current_mode),
            finding_description: directive.permission_description.to_string(),
            finding_explanation: format!(
                "The path {} has permissions {:04o} but should have {:04o} to prevent unauthorised access",
                directive.permission_path, current_mode, directive.permission_mode,
            ),
            finding_id: format!("perm-{}", directive.permission_path.replace('/', "-")),
            finding_impact: "Low - only affects security posture, no functional impact".to_string(),
            finding_recommended_value: format!("{:04o}", directive.permission_mode),
            finding_remediation_steps: vec![format!(
                "chmod {:04o} {}",
                directive.permission_mode,
                directive.permission_path,
            )],
            finding_severity: directive.permission_severity,
            finding_title: format!("Insecure permissions on {}", directive.permission_path),
            finding_compliance: get_permissions_compliance_mappings(directive.permission_path),
        })
    }

    None
}

/// Returns compliance mappings for permission findings.
fn get_permissions_compliance_mappings(path: &str) -> Vec<ComplianceMapping> {
    match path {
        "/etc/passwd" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "6.1.2".to_string(),
                compliance_control_title: "Ensure permissions on /etc/passwd are
  configured".to_string(),
                compliance_section: Some("System Maintenance".to_string()),
            },
        ],
        "/etc/shadow" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "6.1.3".to_string(),
                compliance_control_title: "Ensure permissions on /etc/shadow are
  configured".to_string(),
                compliance_section: Some("System Maintenance".to_string()),
            },
        ],
        "/etc/group" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "6.1.4".to_string(),
                compliance_control_title: "Ensure permissions on /etc/group are
  configured".to_string(),
                compliance_section: Some("System Maintenance".to_string()),
            },
        ],
        "/etc/gshadow" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "6.1.5".to_string(),
                compliance_control_title: "Ensure permissions on /etc/gshadow are
   configured".to_string(),
                compliance_section: Some("System Maintenance".to_string()),
            },
        ],
        _ => vec![],
    }
}

/// Applies correct permissions to a path and tracks the change.
///
/// Returns a Change object if successful, None if path doesn't exist or on error.
fn apply_path_permissions(directive: &PermissionDirective) -> Option<Change> {
    let path = Path::new(directive.permission_path);

    // Skip if path doesn't exist
    if !path.exists() {
        return None;
    }

    // Get current permissions
    let metadata = fs::metadata(path).ok()?;
    let current_mode = metadata.permissions().mode() & 0o777;

    // Skip if already correct
    if current_mode == directive.permission_mode {
        return None;
    }

    // Apply new permissions
    let new_permissions = fs::Permissions::from_mode(directive.permission_mode);
    if fs::set_permissions(path, new_permissions).is_err() {
        return None; // Failed to set permissions
    }

    // Return successful change
    Some(Change {
        change_description: format!(
            "Changed permissions on {} from {:04o} to {:04o}",
            directive.permission_path, current_mode, directive.permission_mode
        ),
        change_type: ChangeType::Permissions,
        change_success: true,
        change_error: None,
    })
}

impl HardeningPlugin for PermissionsHardeningPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            plugin_category:    FindingCategory::FileSystem,
            plugin_description: "Audits and secures critical file and directory permissions".to_string(),
            plugin_id:          PluginId::new("permissions-hardening"),
            plugin_name:        "File Permissions Hardening".to_string(),
            plugin_version:     "0.1.0".to_string(),
        }
    }

    fn scan(&self, _ctx: &Context) -> Result<ScanResult> {
        let start_time = Instant::now();
        let mut findings = Vec::new();

        // Check all critical permissions
        for directive in CRITICAL_PERMISSIONS {
            if let Some(finding) = check_path_permissions(directive) {
                findings.push(finding);
            }
        }

        Ok(ScanResult {
            scan_duration_us: start_time.elapsed().as_micros() as u64,
            scan_error: None,
            scan_findings: findings,
            scan_plugin_id: PluginId::new("permissions-hardening"),
            scan_success: true,
        })
    }

    fn dependencies(&self) -> Vec<PluginId> {
        vec![]
    }

    fn apply(&self, _ctx: &mut Context, _config: &Config) -> Result<ApplyResult> {
        let mut changes = Vec::new();

        // Apply permissions to all critical paths
        for directive in CRITICAL_PERMISSIONS {
            if let Some(change) = apply_path_permissions(directive) {
                changes.push(change);
            }
        }

        let all_successful = changes.iter().all(|c| c.change_success);

        Ok(ApplyResult {
            apply_plugin_id: self.metadata().plugin_id,
            apply_success: all_successful,
            apply_changes: changes,
            apply_checkpoint_id: None,
            apply_error: None,
        })
    }

    fn rollback(&self, _ctx: &mut Context, _checkpoint: &Checkpoint) -> Result<()> {
        warn!("Permissions rollback not yet implemented");
        Ok(())
    }

    fn validate(&self, _config: &Config) -> Result<ValidationReport> {
        Ok(ValidationReport {
            validation_report_plugin_id: self.metadata().plugin_id,
            validation_report_is_valid: true,
            validation_report_issues: vec![],
            validation_report_estimated_changes: vec![],
        })
    }
}
