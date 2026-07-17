//! File Permissions Plugin
//!
//! This plugin audits and secures critical file and directory permissions
//! across the system to prevent privilege escalation and unauthorised access.
//!
//! Checks:
//! - Critical directory permissions (/root, /boot, /etc/ssh, /etc/sudoers)
//! - SUID/SGID binaries (identifies dangerous ones)
//! - World-writable files and directories
//! - SSH key file permissions
//! - Sudo configuration files

use async_trait::async_trait;
use hardener_common::{
    error::Result,
    types::{ComplianceFramework, ComplianceMapping, FindingCategory, PluginId, Severity},
};
use hardener_core::{
    ApplyResult, Change, ChangeType, Checkpoint, PluginConfig, ValidationReport,
    context::Context,
    plugin::{Finding, HardeningPlugin, PluginMetadata, ScanResult},
};
use std::os::unix::fs::OpenOptionsExt;
use std::{path::Path, time::Instant};
use tracing::info;

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
    permission_path: &'static str,
    permission_mode: u32, // Octal mode like 0o700
    _permission_owner: &'static str,
    _permission_group: &'static str,
    permission_severity: Severity,
    /// When true, `permission_mode` is an *allowed-bits mask*: the path is
    /// compliant if it sets no bit outside the mask (so a stricter mode passes),
    /// and apply only ever strips disallowed bits. When false, exact-match.
    permission_max_mask: bool,
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
        permission_path: "/root",
        permission_mode: 0o700,
        _permission_owner: "root",
        _permission_group: "root",
        permission_severity: Severity::High,
        permission_max_mask: false,
    },
    PermissionDirective {
        permission_description: "Boot directory must be protected from unauthorised modification",
        permission_path: "/boot",
        permission_mode: 0o700,
        _permission_owner: "root",
        _permission_group: "root",
        permission_severity: Severity::High,
        permission_max_mask: false,
    },
    PermissionDirective {
        permission_description: "SSH configuration directory must be restricted",
        permission_path: "/etc/ssh",
        permission_mode: 0o755,
        _permission_owner: "root",
        _permission_group: "root",
        permission_severity: Severity::High,
        permission_max_mask: false,
    },
    PermissionDirective {
        permission_description: "Sudoers file must be read-only for root group",
        permission_path: "/etc/sudoers",
        permission_mode: 0o440,
        _permission_owner: "root",
        _permission_group: "root",
        permission_severity: Severity::Critical,
        permission_max_mask: false,
    },
    PermissionDirective {
        permission_description: "Sudoers directory must be restricted",
        permission_path: "/etc/sudoers.d",
        permission_mode: 0o750,
        _permission_owner: "root",
        _permission_group: "root",
        permission_severity: Severity::Critical,
        permission_max_mask: false,
    },
    PermissionDirective {
        permission_description: "World-readable account file must not be writable by others",
        permission_path: "/etc/passwd",
        permission_mode: 0o644,
        _permission_owner: "root",
        _permission_group: "root",
        permission_severity: Severity::High,
        permission_max_mask: false,
    },
    PermissionDirective {
        permission_description: "Group file must not be writable by others",
        permission_path: "/etc/group",
        permission_mode: 0o644,
        _permission_owner: "root",
        _permission_group: "root",
        permission_severity: Severity::High,
        permission_max_mask: false,
    },
    PermissionDirective {
        permission_description: "Shadow file must not be readable/writable by group or others",
        permission_path: "/etc/shadow",
        permission_mode: 0o640, // allowed-bits mask (0000 and 0640 both compliant)
        _permission_owner: "root",
        _permission_group: "root",
        permission_severity: Severity::Critical,
        permission_max_mask: true,
    },
    PermissionDirective {
        permission_description: "Group shadow file must not be readable/writable by group or others",
        permission_path: "/etc/gshadow",
        permission_mode: 0o640, // allowed-bits mask
        _permission_owner: "root",
        _permission_group: "root",
        permission_severity: Severity::Critical,
        permission_max_mask: true,
    },
];

/// True when `current_mode` violates the directive. Exact directives require an
/// exact match; max-mask directives flag only when a bit outside the allowed
/// mask (`permission_mode`) is set — so a stricter mode is compliant.
fn violates(directive: &PermissionDirective, current_mode: u32) -> bool {
    if directive.permission_max_mask {
        current_mode & !directive.permission_mode != 0
    } else {
        current_mode != directive.permission_mode
    }
}

/// The concrete mode apply should set. Exact directives target `permission_mode`;
/// max-mask directives strip disallowed bits (`current & mask`), never adding any.
fn target_mode(directive: &PermissionDirective, current_mode: u32) -> u32 {
    if directive.permission_max_mask {
        current_mode & directive.permission_mode
    } else {
        directive.permission_mode
    }
}

/// Checks if a path has the correct permissions, owner, and group.
///
/// Returns a Finding if permissions are incorrect, None if correct
async fn check_path_permissions(ctx: &Context, directive: &PermissionDirective) -> Option<Finding> {
    let path = Path::new(directive.permission_path);

    // Skip if path doesn't exist
    if !ctx.executor().path_exists(path).await.unwrap_or(false) {
        return None;
    }

    // Get file metadata
    let metadata = match ctx.executor().file_metadata(path).await {
        Ok(metadata) => metadata,
        Err(_) => return None, // Can't read, skip it
    };

    // Get current permissions (only last 9 bits = rwxrwxrwx)
    let current_mode = metadata.mode & 0o777;

    // Check if permissions are incorrect
    if violates(directive, current_mode) {
        let target = target_mode(directive, current_mode);
        return Some(Finding {
            finding_category: FindingCategory::FileSystem,
            finding_current_value: format!("{:04o}", current_mode),
            finding_description: directive.permission_description.to_string(),
            finding_explanation: format!(
                "The path {} has permissions {:04o} but should have {:04o} to prevent unauthorised access",
                directive.permission_path, current_mode, target,
            ),
            finding_id: format!("perm-{}", directive.permission_path.replace('/', "-")),
            finding_impact: "Low - only affects security posture, no functional impact".to_string(),
            finding_recommended_value: format!("{:04o}", target),
            finding_remediation_steps: vec![format!(
                "chmod {:04o} {}",
                target, directive.permission_path,
            )],
            finding_severity: directive.permission_severity,
            finding_title: format!("Insecure permissions on {}", directive.permission_path),
            finding_compliance: get_permissions_compliance_mappings(directive.permission_path),
            finding_policy_exception: None,
        });
    }

    None
}

/// Returns compliance mappings for permission findings.
///
/// Multi-framework mappings are sourced from ComplianceAsCode/SSG rule
/// `references:` blocks (see `// SSG:` comments). NIST IDs are 800-53 Rev 5;
/// PCI-DSS is v4.0. STIG is deliberately omitted for the account files below:
/// the SSG rules `file_permissions_etc_{passwd,shadow,group,gshadow}` declare
/// no `stigid@` — DISA covers them only via the parent SRG
/// (`SRG-OS-000480-GPOS-00227`), so there is no concrete STIG control ID to
/// cite without inventing one.
/// Every compliance mapping this plugin can emit, across all critical paths it
/// assesses. Aggregated into the engine's automated-coverage set.
pub fn coverage() -> Vec<ComplianceMapping> {
    CRITICAL_PERMISSIONS
        .iter()
        .flat_map(|p| get_permissions_compliance_mappings(p.permission_path))
        .collect()
}

/// Builds a SOC 2 mapping. `id` is a 2017 Trust Services Criteria common
/// criterion (e.g. `CC6.1`); `title` tracks the published criterion text. The
/// section is the criterion's TSC series, derived from the id prefix.
fn soc2(id: &str, title: &str) -> ComplianceMapping {
    let series = if id.starts_with("CC7") {
        "System Operations"
    } else {
        "Logical and Physical Access Controls"
    };
    ComplianceMapping {
        compliance_framework: ComplianceFramework::SOC2,
        compliance_control_id: id.to_string(),
        compliance_control_title: title.to_string(),
        compliance_section: Some(series.to_string()),
    }
}

/// Builds a NIST SP 800-171 Revision 3 mapping. `id` is the requirement
/// number (e.g. `3.1.5`); `title` the published requirement name; the
/// section is the requirement's official family. Every id is translated from
/// this plugin's 800-53 entries via the r3 source-control table — never
/// invented.
fn nist171(id: &str, title: &str) -> ComplianceMapping {
    ComplianceMapping {
        compliance_framework: ComplianceFramework::NIST800171,
        compliance_control_id: id.to_string(),
        compliance_control_title: title.to_string(),
        compliance_section: Some("Access Control".to_string()),
    }
}

fn get_permissions_compliance_mappings(path: &str) -> Vec<ComplianceMapping> {
    match path {
        // SSG: file_permissions_etc_passwd (nist: AC-6(1),CM-6(a); pcidss: Req-8.7.c)
        "/etc/passwd" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "6.1.2".to_string(),
                compliance_control_title: "Ensure permissions on /etc/passwd are configured"
                    .to_string(),
                compliance_section: Some("System Maintenance".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::NIST,
                compliance_control_id: "AC-6(1)".to_string(),
                compliance_control_title:
                    "Least Privilege - Authorize Access to Security Functions".to_string(),
                compliance_section: Some("Access Control".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::PCIDSS,
                compliance_control_id: "8.7.c".to_string(),
                compliance_control_title: "Restrict access to system component databases and files"
                    .to_string(),
                compliance_section: Some("Identify and Authenticate Access".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.312(a)(1)".to_string(),
                compliance_control_title: "Access Control".to_string(),
                compliance_section: Some("Technical Safeguards".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-AC".to_string(),
                compliance_control_title: "Access Control".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.3".to_string(),
                compliance_control_title: "Information access restriction".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            // SOC 2: CC6.1 mirrors the AC-6(1) least-privilege file-access intent.
            soc2(
                "CC6.1",
                "Logical access security software, infrastructure, and architectures",
            ),
            // 800-171r3 3.1.5 ← 800-53 AC-6(1) (SP 800-171r3 source-control table).
            nist171("3.1.5", "Least Privilege"),
        ],
        // SSG: file_permissions_etc_shadow (nist: AC-6(1),CM-6(a); pcidss: Req-8.7.c)
        "/etc/shadow" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "6.1.3".to_string(),
                compliance_control_title: "Ensure permissions on /etc/shadow are configured"
                    .to_string(),
                compliance_section: Some("System Maintenance".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::NIST,
                compliance_control_id: "AC-6(1)".to_string(),
                compliance_control_title:
                    "Least Privilege - Authorize Access to Security Functions".to_string(),
                compliance_section: Some("Access Control".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::PCIDSS,
                compliance_control_id: "8.7.c".to_string(),
                compliance_control_title: "Restrict access to system component databases and files"
                    .to_string(),
                compliance_section: Some("Identify and Authenticate Access".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.312(a)(1)".to_string(),
                compliance_control_title: "Access Control".to_string(),
                compliance_section: Some("Technical Safeguards".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-AC".to_string(),
                compliance_control_title: "Access Control".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.3".to_string(),
                compliance_control_title: "Information access restriction".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            // SOC 2: CC6.1 mirrors the AC-6(1) least-privilege file-access intent.
            soc2(
                "CC6.1",
                "Logical access security software, infrastructure, and architectures",
            ),
            // 800-171r3 3.1.5 ← 800-53 AC-6(1) (SP 800-171r3 source-control table).
            nist171("3.1.5", "Least Privilege"),
        ],
        // SSG: file_permissions_etc_group (nist: AC-6(1),CM-6(a); pcidss: Req-8.7.c)
        "/etc/group" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "6.1.4".to_string(),
                compliance_control_title: "Ensure permissions on /etc/group are configured"
                    .to_string(),
                compliance_section: Some("System Maintenance".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::NIST,
                compliance_control_id: "AC-6(1)".to_string(),
                compliance_control_title:
                    "Least Privilege - Authorize Access to Security Functions".to_string(),
                compliance_section: Some("Access Control".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::PCIDSS,
                compliance_control_id: "8.7.c".to_string(),
                compliance_control_title: "Restrict access to system component databases and files"
                    .to_string(),
                compliance_section: Some("Identify and Authenticate Access".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.312(a)(1)".to_string(),
                compliance_control_title: "Access Control".to_string(),
                compliance_section: Some("Technical Safeguards".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-AC".to_string(),
                compliance_control_title: "Access Control".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.3".to_string(),
                compliance_control_title: "Information access restriction".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            // SOC 2: CC6.1 mirrors the AC-6(1) least-privilege file-access intent.
            soc2(
                "CC6.1",
                "Logical access security software, infrastructure, and architectures",
            ),
            // 800-171r3 3.1.5 ← 800-53 AC-6(1) (SP 800-171r3 source-control table).
            nist171("3.1.5", "Least Privilege"),
        ],
        // SSG: file_permissions_etc_gshadow (nist: AC-6(1),CM-6(a); no pcidss declared)
        "/etc/gshadow" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "6.1.5".to_string(),
                compliance_control_title: "Ensure permissions on /etc/gshadow are configured"
                    .to_string(),
                compliance_section: Some("System Maintenance".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::NIST,
                compliance_control_id: "AC-6(1)".to_string(),
                compliance_control_title:
                    "Least Privilege - Authorize Access to Security Functions".to_string(),
                compliance_section: Some("Access Control".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.312(a)(1)".to_string(),
                compliance_control_title: "Access Control".to_string(),
                compliance_section: Some("Technical Safeguards".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-AC".to_string(),
                compliance_control_title: "Access Control".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.3".to_string(),
                compliance_control_title: "Information access restriction".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            // SOC 2: CC6.1 mirrors the AC-6(1) least-privilege file-access intent.
            soc2(
                "CC6.1",
                "Logical access security software, infrastructure, and architectures",
            ),
            // 800-171r3 3.1.5 ← 800-53 AC-6(1) (SP 800-171r3 source-control table).
            nist171("3.1.5", "Least Privilege"),
        ],
        // SSG: directory_permissions_sshd_config_d (nist: AC-17(a),AC-6(1),CM-6(a);
        // no stigid/pcidss declared). This is a live-scanned path; the prior
        // implementation returned no mappings for it.
        "/etc/ssh" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::NIST,
                compliance_control_id: "AC-17(a)".to_string(),
                compliance_control_title: "Remote Access - Usage Restrictions and Configuration"
                    .to_string(),
                compliance_section: Some("Access Control".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.312(a)(1)".to_string(),
                compliance_control_title: "Access Control".to_string(),
                compliance_section: Some("Technical Safeguards".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-AC".to_string(),
                compliance_control_title: "Access Control".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            // Privileged sshd config directory → ISO 8.2 (privileged access rights).
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.2".to_string(),
                compliance_control_title: "Privileged access rights".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            // SOC 2: CC6.1 mirrors the AC-17(a) remote-access config-protection intent.
            soc2(
                "CC6.1",
                "Logical access security software, infrastructure, and architectures",
            ),
            // 800-171r3 3.1.12 ← 800-53 AC-17 (SP 800-171r3 source-control table).
            nist171("3.1.12", "Remote Access"),
        ],
        _ => vec![],
    }
}

/// Applies correct permissions to a path and tracks the change.
///
/// For local execution: uses `O_NOFOLLOW` open + `fchmod` to operate on
/// the real inode, eliminating the TOCTOU window between check and chmod.
/// For remote execution: falls back to the executor's `execute_command`.
///
/// Returns a Change object if successful, None if path doesn't exist or on error.
async fn apply_path_permissions(ctx: &Context, directive: &PermissionDirective) -> Option<Change> {
    let path = Path::new(directive.permission_path);

    // Skip if path doesn't exist
    if !ctx.executor().path_exists(path).await.unwrap_or(false) {
        return None;
    }

    // Get current permissions via executor (works for both local and remote)
    let metadata = ctx.executor().file_metadata(path).await.ok()?;
    let current_mode = metadata.mode & 0o777;

    if !violates(directive, current_mode) {
        return None;
    }

    // Use TOCTOU-safe fchmod for local targets, executor for remote
    if !ctx.executor().is_remote() {
        apply_local_fchmod(directive, current_mode)
    } else {
        apply_remote_chmod(ctx, directive, current_mode).await
    }
}

/// TOCTOU-safe local permission change via `O_NOFOLLOW` + `fchmod`.
fn apply_local_fchmod(directive: &PermissionDirective, current_mode: u32) -> Option<Change> {
    use nix::sys::stat::{Mode, fchmod};

    let path = Path::new(directive.permission_path);
    let flags = if path.is_dir() {
        nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY
    } else {
        nix::libc::O_NOFOLLOW
    };

    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
    {
        Ok(f) => f,
        Err(e) => {
            return Some(Change {
                change_description: format!(
                    "Failed to open {} for chmod",
                    directive.permission_path
                ),
                change_type: ChangeType::Permissions,
                change_success: false,
                change_error: Some(e.to_string()),
            });
        }
    };

    let target = target_mode(directive, current_mode);
    let target_bits = Mode::from_bits_truncate(target);
    match fchmod(&file, target_bits) {
        Ok(()) => Some(Change {
            change_description: format!(
                "Changed permissions on {} from {:04o} to {:04o}",
                directive.permission_path, current_mode, target
            ),
            change_type: ChangeType::Permissions,
            change_success: true,
            change_error: None,
        }),
        Err(e) => Some(Change {
            change_description: format!(
                "Failed to change permissions on {}",
                directive.permission_path
            ),
            change_type: ChangeType::Permissions,
            change_success: false,
            change_error: Some(e.to_string()),
        }),
    }
}

/// Remote permission change via executor (falls back to chmod command).
async fn apply_remote_chmod(
    ctx: &Context,
    directive: &PermissionDirective,
    current_mode: u32,
) -> Option<Change> {
    let mode_str = format!("{:04o}", target_mode(directive, current_mode));
    let result = ctx
        .executor()
        .execute_command("chmod", &[&mode_str, directive.permission_path])
        .await;

    match result {
        Ok(output) if output.success() => {
            // Verify the change took effect — for max-mask directives, verify
            // no disallowed bits remain; for exact directives, verify equality.
            let target = target_mode(directive, current_mode);
            let path = Path::new(directive.permission_path);
            let verified = ctx
                .executor()
                .file_metadata(path)
                .await
                .map(|m| !violates(directive, m.mode & 0o777))
                .unwrap_or(false);

            if verified {
                Some(Change {
                    change_description: format!(
                        "Changed permissions on {} from {:04o} to {:04o}",
                        directive.permission_path, current_mode, target
                    ),
                    change_type: ChangeType::Permissions,
                    change_success: true,
                    change_error: None,
                })
            } else {
                Some(Change {
                    change_description: format!(
                        "Permissions on {} unchanged (filesystem may not support chmod — \
                         e.g. vfat/FAT32 uses mount options fmask/dmask instead)",
                        directive.permission_path
                    ),
                    change_type: ChangeType::Permissions,
                    change_success: false,
                    change_error: None,
                })
            }
        }
        Ok(output) => Some(Change {
            change_description: format!(
                "Failed to change permissions on {}",
                directive.permission_path
            ),
            change_type: ChangeType::Permissions,
            change_success: false,
            change_error: Some(output.stderr),
        }),
        Err(e) => Some(Change {
            change_description: format!(
                "Failed to change permissions on {}",
                directive.permission_path
            ),
            change_type: ChangeType::Permissions,
            change_success: false,
            change_error: Some(e.to_string()),
        }),
    }
}

#[async_trait]
impl HardeningPlugin for PermissionsHardeningPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            plugin_category: FindingCategory::FileSystem,
            plugin_description: "Audits and secures critical file and directory permissions"
                .to_string(),
            plugin_id: PluginId::new("permissions-hardening"),
            plugin_name: "File Permissions Hardening".to_string(),
            plugin_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    fn dependencies(&self) -> Vec<PluginId> {
        vec![]
    }

    async fn scan(&self, ctx: &Context) -> Result<ScanResult> {
        let start_time = Instant::now();
        let mut findings = Vec::new();

        // Check all critical permissions
        for directive in CRITICAL_PERMISSIONS {
            if let Some(finding) = check_path_permissions(ctx, directive).await {
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

    async fn apply(&self, ctx: &mut Context, config: &PluginConfig) -> Result<ApplyResult> {
        let mut changes = Vec::new();

        // Collect paths to checkpoint
        let permission_paths: Vec<&Path> = CRITICAL_PERMISSIONS
            .iter()
            .map(|d| Path::new(d.permission_path))
            .collect();

        let checkpoint_id = crate::create_checkpoint_metadata_only_for_apply(
            ctx,
            "permissions-hardening-pre-apply",
            &permission_paths,
        )
        .await?;

        if checkpoint_id.is_some() {
            changes.push(Change {
                change_description: "Created checkpoint for rollback".to_string(),
                change_type: ChangeType::Permissions,
                change_success: true,
                change_error: None,
            });
        }

        // Apply permissions to all critical paths
        for directive in CRITICAL_PERMISSIONS {
            // Check for a valid exception — skip this path if exempted
            if let Some(exception) = config.has_valid_exception(directive.permission_path) {
                info!(
                    "Skipping {} — exception: {}",
                    directive.permission_path, exception.reason
                );
                changes.push(Change {
                    change_description: format!(
                        "{}: skipped (exception: {})",
                        directive.permission_path, exception.reason
                    ),
                    change_type: ChangeType::Permissions,
                    change_success: true,
                    change_error: None,
                });
                continue;
            }

            // Apply directive mode override if present
            let directive = if let Some(mode_str) = config.directives.get(directive.permission_path)
            {
                let mode = u32::from_str_radix(mode_str, 8).unwrap_or(directive.permission_mode);
                let mut d = directive.clone();
                d.permission_mode = mode;
                d
            } else {
                directive.clone()
            };

            if let Some(change) = apply_path_permissions(ctx, &directive).await {
                changes.push(change);
            }
        }

        let all_successful = changes.iter().all(|c| c.change_success);

        Ok(ApplyResult {
            apply_plugin_id: self.metadata().plugin_id,
            apply_success: all_successful,
            apply_changes: changes,
            apply_checkpoint_id: checkpoint_id,
            apply_error: None,
        })
    }

    async fn rollback(&self, ctx: &mut Context, checkpoint: &Checkpoint) -> Result<()> {
        info!(
            "Rolling back file permissions to checkpoint: {}",
            checkpoint.checkpoint_id.as_str()
        );

        // Restore file permissions from checkpoint
        // The checkpoint system stores file content, permissions, and ownership
        crate::rollback_files_from_checkpoint(ctx, checkpoint)?;

        info!("File permissions restored from checkpoint");

        // No service restart needed - permission changes are immediate

        Ok(())
    }

    async fn validate(&self, ctx: &Context, config: &PluginConfig) -> Result<ValidationReport> {
        let mut issues = Vec::new();
        let mut estimated_changes = Vec::new();

        for directive in CRITICAL_PERMISSIONS {
            // Skip paths with valid exceptions
            if config
                .has_valid_exception(directive.permission_path)
                .is_some()
            {
                continue;
            }

            // Build an effective directive: apply any per-path override to
            // `permission_mode` while preserving `permission_max_mask`, so the
            // dry-run's compliance test matches scan/apply exactly (a stricter
            // mode is compliant for mask directives — no spurious pending change).
            let mut effective = directive.clone();
            if let Some(mode) = config
                .directives
                .get(directive.permission_path)
                .and_then(|s| u32::from_str_radix(s, 8).ok())
            {
                effective.permission_mode = mode;
            }

            let path = Path::new(directive.permission_path);

            // Check if path exists
            if !ctx.executor().path_exists(path).await.unwrap_or(false) {
                // Path doesn't exist - not an error, just skip
                continue;
            }

            // Get current permissions
            match ctx.executor().file_metadata(path).await {
                Ok(metadata) => {
                    let current_mode = metadata.mode & 0o777;

                    // Check if permissions need changing (honours max-mask)
                    if violates(&effective, current_mode) {
                        estimated_changes.push(format!(
                            "{}: {:04o} → {:04o}",
                            directive.permission_path,
                            current_mode,
                            target_mode(&effective, current_mode)
                        ));
                    }
                }
                Err(e) => {
                    // Cannot read metadata - might not have permission
                    issues.push(hardener_core::ValidationIssue {
                        validation_issue_severity: Severity::High,
                        validation_issue_message: format!(
                            "Cannot read {}: {}",
                            directive.permission_path, e
                        ),
                        validation_issue_config_key: Some(directive.permission_path.to_string()),
                    });
                }
            }
        }

        Ok(ValidationReport {
            validation_report_plugin_id: self.metadata().plugin_id,
            validation_report_is_valid: issues
                .iter()
                .all(|i| i.validation_issue_severity != Severity::High),
            validation_report_issues: issues,
            validation_report_estimated_changes: estimated_changes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A representative permissions check (`/etc/shadow`) must now carry
    /// multi-framework mappings: the existing CIS control plus NIST 800-53
    /// and PCI-DSS sourced from SSG `file_permissions_etc_shadow`. STIG is
    /// intentionally absent because that SSG rule declares no `stigid@`.
    #[test]
    fn shadow_has_multi_framework_mappings() {
        let mappings = get_permissions_compliance_mappings("/etc/shadow");

        let has = |fw| mappings.iter().any(|m| m.compliance_framework == fw);
        assert!(
            has(ComplianceFramework::CIS),
            "CIS mapping must be retained"
        );
        assert!(
            has(ComplianceFramework::NIST),
            "NIST mapping must be present"
        );
        assert!(
            has(ComplianceFramework::PCIDSS),
            "PCI-DSS mapping must be present"
        );

        // Verify the exact SSG-sourced identifiers.
        let nist = mappings
            .iter()
            .find(|m| m.compliance_framework == ComplianceFramework::NIST)
            .unwrap();
        assert_eq!(nist.compliance_control_id, "AC-6(1)");
    }

    #[test]
    fn max_mask_treats_stricter_as_compliant_and_never_loosens() {
        let shadow = PermissionDirective {
            permission_description: "t",
            permission_path: "/etc/shadow",
            permission_mode: 0o640, // used as the allowed mask
            _permission_owner: "root",
            _permission_group: "root",
            permission_severity: Severity::Critical,
            permission_max_mask: true,
        };
        // 0000 (RHEL) and 0640 (Debian) both compliant; 0644 (o-r) and 0660 (g-w) violate.
        assert!(!violates(&shadow, 0o000));
        assert!(!violates(&shadow, 0o640));
        assert!(!violates(&shadow, 0o600));
        assert!(violates(&shadow, 0o644));
        assert!(violates(&shadow, 0o660));
        // Apply strips disallowed bits only — never adds any.
        assert_eq!(target_mode(&shadow, 0o644), 0o640);
        assert_eq!(target_mode(&shadow, 0o600), 0o600);

        let passwd = PermissionDirective {
            permission_max_mask: false,
            permission_mode: 0o644,
            ..shadow
        };
        assert!(!violates(&passwd, 0o644));
        assert!(violates(&passwd, 0o646));
        assert_eq!(target_mode(&passwd, 0o646), 0o644);
    }

    /// The `validate` dry-run builds an effective directive (override applied to
    /// `permission_mode`, `permission_max_mask` preserved) and routes it through
    /// the same `violates`/`target_mode` helpers as scan/apply. This mirrors that
    /// path: a mask directive must report NO pending change at a stricter mode
    /// (0000 on RHEL) yet flag a looser one (0644).
    #[test]
    fn validate_effective_directive_honours_max_mask() {
        let shadow = PermissionDirective {
            permission_description: "t",
            permission_path: "/etc/shadow",
            permission_mode: 0o640,
            _permission_owner: "root",
            _permission_group: "root",
            permission_severity: Severity::Critical,
            permission_max_mask: true,
        };

        // Effective directive with a config override to 0o600 keeps mask semantics.
        let mut effective = shadow.clone();
        effective.permission_mode = 0o600;
        assert!(!violates(&effective, 0o000), "stricter mode is compliant");
        assert!(violates(&effective, 0o640), "0640 exceeds the 0600 mask");
        assert_eq!(target_mode(&effective, 0o640), 0o600);

        // No override: baseline 0640 mask — 0000 compliant, 0644 flagged.
        assert!(!violates(&shadow, 0o000));
        assert!(violates(&shadow, 0o644));
    }

    /// Sensitive-file permission checks must also carry HIPAA, GDPR and
    /// ISO/IEC 27001:2022 mappings alongside the existing CIS/NIST/PCI-DSS set.
    #[test]
    fn shadow_has_privacy_and_iso_mappings() {
        let mappings = get_permissions_compliance_mappings("/etc/shadow");

        let has = |fw| mappings.iter().any(|m| m.compliance_framework == fw);
        assert!(has(ComplianceFramework::HIPAA), "HIPAA must be present");
        assert!(has(ComplianceFramework::GDPR), "GDPR must be present");
        assert!(
            has(ComplianceFramework::ISO27001),
            "ISO 27001 must be present"
        );

        // ISO control must be the access-restriction clause for sensitive files.
        let iso = mappings
            .iter()
            .find(|m| m.compliance_framework == ComplianceFramework::ISO27001)
            .unwrap();
        assert_eq!(iso.compliance_control_id, "8.3");

        // HIPAA is the access-control safeguard. The integrity standard
        // 164.312(c)(1) is intentionally absent: SSG carries no HIPAA reference
        // for these file-permission rules, so the access-control citation stands
        // alone (aligned with the SSG preference for 164.312(a)).
        assert!(
            mappings
                .iter()
                .any(|m| m.compliance_framework == ComplianceFramework::HIPAA
                    && m.compliance_control_id == "164.312(a)(1)")
        );
        assert!(
            !mappings
                .iter()
                .any(|m| m.compliance_framework == ComplianceFramework::HIPAA
                    && m.compliance_control_id == "164.312(c)(1)")
        );
    }

    /// Confirms every assessed critical path carries the SOC 2 logical-access
    /// criterion CC6.1, filed under its Trust Services Criteria series.
    #[test]
    fn critical_paths_map_soc2_logical_access() {
        for path in [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/group",
            "/etc/gshadow",
            "/etc/ssh",
        ] {
            let soc2 = get_permissions_compliance_mappings(path)
                .into_iter()
                .find(|m| m.compliance_framework == ComplianceFramework::SOC2)
                .unwrap_or_else(|| panic!("{path} must carry a SOC 2 mapping"));
            assert_eq!(soc2.compliance_control_id, "CC6.1");
            assert_eq!(
                soc2.compliance_section.as_deref(),
                Some("Logical and Physical Access Controls")
            );
        }
    }

    /// Confirms the 800-171r3 crosswalk: the account files translate AC-6(1)
    /// to 3.1.5 and the sshd config directory translates AC-17 to 3.1.12,
    /// both under the Access Control family.
    #[test]
    fn critical_paths_map_nist_800_171_requirements() {
        let nist171_for = |path: &str| {
            get_permissions_compliance_mappings(path)
                .into_iter()
                .find(|m| m.compliance_framework == ComplianceFramework::NIST800171)
                .unwrap_or_else(|| panic!("{path} must carry an 800-171 mapping"))
        };

        for path in ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"] {
            let mapping = nist171_for(path);
            assert_eq!(mapping.compliance_control_id, "3.1.5", "{path}");
            assert_eq!(
                mapping.compliance_section.as_deref(),
                Some("Access Control")
            );
        }

        let sshd = nist171_for("/etc/ssh");
        assert_eq!(sshd.compliance_control_id, "3.1.12");
        assert_eq!(sshd.compliance_section.as_deref(), Some("Access Control"));
    }
}
