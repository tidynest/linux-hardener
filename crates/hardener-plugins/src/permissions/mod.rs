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
    plugin::{Finding, HardeningPlugin, PluginMetadata, ScanResult, UncheckedCheck},
};
use std::os::unix::fs::OpenOptionsExt;
use std::{path::Path, time::Instant};
use tracing::{info, warn};

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
/// mask (`permission_mode`) is set, so a stricter mode is compliant.
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

/// Filesystem-type tokens that cannot store POSIX permission bits. On these a
/// `chmod` exits 0 but the mode is fixed by mount options (fmask/dmask), so a
/// permission finding would be false and a chmod futile. Matched case-insensitively
/// against the token `findmnt`/`stat -f` reports (findmnt yields e.g. `vfat`,
/// `exfat`, `ntfs3`; `stat -f -c %T` reports `msdos` for FAT).
const NON_POSIX_FSTYPES: &[&str] = &["vfat", "msdos", "exfat", "ntfs", "ntfs3", "iso9660", "udf"];

/// Stable id shared by a path's [`Finding`] and its [`UncheckedCheck`], so the
/// CLI/GUI dedupe and compliance keying stay consistent whichever is emitted.
fn permission_check_id(path: &str) -> String {
    format!("perm-{}", path.replace('/', "-"))
}

/// Probes the filesystem type backing `path`. Tries `findmnt -no FSTYPE <path>`
/// (mount-aware, exact); if findmnt cannot run (absent on minimal systems) it
/// falls back to `stat -f -c %T <path>`. Returns the raw reported token, or
/// `None` when neither probe yields a non-empty answer.
async fn probe_fstype(ctx: &Context, path: &str) -> Option<String> {
    if let Ok(output) = ctx
        .executor()
        .execute_command("findmnt", &["-no", "FSTYPE", path])
        .await
        && output.success()
        && !output.stdout.trim().is_empty()
    {
        return Some(output.stdout.trim().to_string());
    }

    if let Ok(output) = ctx
        .executor()
        .execute_command("stat", &["-f", "-c", "%T", path])
        .await
        && output.success()
        && !output.stdout.trim().is_empty()
    {
        return Some(output.stdout.trim().to_string());
    }

    None
}

/// THE shared filesystem gate used by scan, apply and validate so they cannot
/// drift. Returns `Some(fstype)` only when `path` is *positively confirmed* to
/// live on a filesystem that cannot hold POSIX permissions.
///
/// FAIL-SAFE: any probe failure, empty output or unrecognised fstype returns
/// `None`, so the caller keeps today's behaviour (emit the finding, attempt the
/// chmod). A real permissions gap is never hidden by an inconclusive probe.
async fn non_posix_fstype(ctx: &Context, path: &str) -> Option<String> {
    let token = probe_fstype(ctx, path).await?.trim().to_ascii_lowercase();
    NON_POSIX_FSTYPES.contains(&token.as_str()).then_some(token)
}

/// Guidance shared by the scan `UncheckedCheck` and the apply `Skipped` change:
/// a non-POSIX filesystem ignores chmod, so hardening is done through fstab
/// mount options instead of permission bits.
fn non_posix_guidance(path: &str, fstype: &str) -> String {
    format!(
        "{path} is on a {fstype} filesystem; POSIX permissions cannot be set with chmod - \
         harden via fstab mount options (e.g. fmask=0077,dmask=0077)"
    )
}

/// The `UncheckedCheck` emitted for a violating path on a non-POSIX filesystem.
/// Keyed to the same id the finding would have used; compliance mirrors the
/// path's mapping (empty for paths without one, e.g. /boot).
fn non_posix_unchecked(directive: &PermissionDirective, fstype: &str) -> UncheckedCheck {
    UncheckedCheck {
        unchecked_check_id: permission_check_id(directive.permission_path),
        unchecked_title: format!("Permissions on {}", directive.permission_path),
        unchecked_category: FindingCategory::FileSystem,
        unchecked_reason: non_posix_guidance(directive.permission_path, fstype),
        unchecked_compliance: get_permissions_compliance_mappings(directive.permission_path),
    }
}

/// The `Skipped` change emitted when apply meets a violating path on a non-POSIX
/// filesystem: no chmod is attempted (which would silently no-op), the fstab
/// guidance is recorded instead.
fn non_posix_skip_change(path: &str, fstype: &str) -> Change {
    Change {
        change_description: non_posix_guidance(path, fstype),
        change_type: ChangeType::Skipped,
        change_success: true,
        change_error: None,
    }
}

/// Outcome of assessing one critical path during a scan.
enum PermissionCheck {
    /// Compliant, missing or unreadable: nothing to report.
    Clear,
    /// Violates the directive and can be remediated by chmod.
    Insecure(Box<Finding>),
    /// Violates, but sits on a filesystem that cannot hold POSIX permissions,
    /// so chmod cannot fix it: reported as unchecked with fstab guidance.
    NonPosix(Box<UncheckedCheck>),
}

/// Assesses one critical path's permissions.
///
/// A directive override in `config` (an octal string keyed by
/// `permission_path`) replaces the built-in baseline mode before the
/// compliance check runs, so a stricter override can flag an
/// otherwise-compliant path. A valid policy exception for the path annotates
/// a resulting finding via `finding_policy_exception` rather than dropping it.
///
/// Returns [`PermissionCheck::Insecure`] when the path violates its directive on
/// a POSIX filesystem, [`PermissionCheck::NonPosix`] when it violates but sits on
/// a filesystem that cannot hold POSIX permissions (reported as unchecked with
/// fstab guidance, never a false finding), and [`PermissionCheck::Clear`] when
/// the path is compliant, missing or unreadable.
async fn check_path_permissions(
    ctx: &Context,
    directive: &PermissionDirective,
    config: &PluginConfig,
) -> PermissionCheck {
    let path = Path::new(directive.permission_path);

    // Skip if path doesn't exist
    if !ctx.executor().path_exists(path).await.unwrap_or(false) {
        return PermissionCheck::Clear;
    }

    // Get file metadata
    let metadata = match ctx.executor().file_metadata(path).await {
        Ok(metadata) => metadata,
        Err(_) => return PermissionCheck::Clear, // Can't read, skip it
    };

    // Get current permissions (only last 9 bits = rwxrwxrwx)
    let current_mode = metadata.mode & 0o777;

    // Build an effective directive: an octal directive override wins over the
    // built-in baseline (mirrors apply :899-907 / validate :960-964),
    // preserving permission_max_mask so mask semantics (a stricter mode is
    // compliant) still apply to the overridden target. Shadowing `directive`
    // means every downstream use (violates/target_mode/finding fields) picks
    // up the override without further changes.
    let mut effective = directive.clone();
    if let Some(mode) = config
        .directives
        .get(directive.permission_path)
        .and_then(|s| u32::from_str_radix(s, 8).ok())
    {
        effective.permission_mode = mode;
    }
    let directive = &effective;

    // Compliant: nothing to report (and no filesystem probe needed).
    if !violates(directive, current_mode) {
        return PermissionCheck::Clear;
    }

    // A genuine violation. Only now probe the filesystem: if it cannot hold
    // POSIX permissions, chmod would silently no-op, so report the situation as
    // unchecked with fstab guidance instead of a false finding.
    if let Some(fstype) = non_posix_fstype(ctx, directive.permission_path).await {
        return PermissionCheck::NonPosix(Box::new(non_posix_unchecked(directive, &fstype)));
    }

    let target = target_mode(directive, current_mode);
    let policy_exception = config
        .matching_mode_exception(directive.permission_path, current_mode)
        .map(|e| e.to_finding_exception());
    PermissionCheck::Insecure(Box::new(Finding {
        finding_category: FindingCategory::FileSystem,
        finding_current_value: format!("{:04o}", current_mode),
        finding_description: directive.permission_description.to_string(),
        finding_explanation: format!(
            "The path {} has permissions {:04o} but should have {:04o} to prevent unauthorised access",
            directive.permission_path, current_mode, target,
        ),
        finding_id: permission_check_id(directive.permission_path),
        finding_impact: "Low - only affects security posture, no functional impact".to_string(),
        finding_recommended_value: format!("{:04o}", target),
        finding_remediation_steps: vec![format!(
            "chmod {:04o} {}",
            target, directive.permission_path,
        )],
        finding_severity: directive.permission_severity,
        finding_title: format!("Insecure permissions on {}", directive.permission_path),
        finding_compliance: get_permissions_compliance_mappings(directive.permission_path),
        finding_policy_exception: policy_exception,
    }))
}

/// Returns compliance mappings for permission findings.
///
/// Multi-framework mappings are sourced from ComplianceAsCode/SSG rule
/// `references:` blocks (see `// SSG:` comments). NIST IDs are 800-53 Rev 5;
/// PCI-DSS is v4.0. STIG is deliberately omitted for the account files below:
/// the SSG rules `file_permissions_etc_{passwd,shadow,group,gshadow}` declare
/// no `stigid@`: DISA covers them only via the parent SRG
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
/// this plugin's 800-53 entries via the r3 source-control table, never
/// invented.
fn nist171(id: &str, title: &str) -> ComplianceMapping {
    ComplianceMapping {
        compliance_framework: ComplianceFramework::NIST800171,
        compliance_control_id: id.to_string(),
        compliance_control_title: title.to_string(),
        compliance_section: Some("Access Control".to_string()),
    }
}

/// Builds a FedRAMP mapping. FedRAMP's control set is NIST 800-53 at the
/// Moderate (Rev 5) baseline, so `id`/`title` mirror this plugin's 800-53
/// entries verbatim; each id is checked against the GSA rev5 Moderate
/// baseline before it is mapped, never invented. The section is the control's
/// 800-53 family.
fn fedramp(id: &str, title: &str) -> ComplianceMapping {
    ComplianceMapping {
        compliance_framework: ComplianceFramework::FedRAMP,
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
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 AC-6(1).
            fedramp(
                "AC-6(1)",
                "Least Privilege - Authorize Access to Security Functions",
            ),
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
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 AC-6(1).
            fedramp(
                "AC-6(1)",
                "Least Privilege - Authorize Access to Security Functions",
            ),
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
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 AC-6(1).
            fedramp(
                "AC-6(1)",
                "Least Privilege - Authorize Access to Security Functions",
            ),
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
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 AC-6(1).
            fedramp(
                "AC-6(1)",
                "Least Privilege - Authorize Access to Security Functions",
            ),
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
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 AC-17.
            fedramp(
                "AC-17(a)",
                "Remote Access - Usage Restrictions and Configuration",
            ),
        ],
        _ => vec![],
    }
}

/// The "from X to Y" fragment of a chmod change description. When the
/// current mode was verified it names both ends of the transition; when it
/// was not (see [`apply_path_permissions`]), only the target is known, so the
/// description says so explicitly rather than implying a starting mode that
/// was never actually observed.
fn mode_transition_description(current_mode: Option<u32>, target: u32) -> String {
    match current_mode {
        Some(mode) => format!("from {mode:04o} to {target:04o}"),
        None => format!("to {target:04o} (current permissions could not be verified beforehand)"),
    }
}

/// Applies correct permissions to a path and tracks the change.
///
/// `current_mode` is read once by the caller (the apply loop), before the
/// exception check, so it can be compared numerically against a documented
/// exception; this function reuses it rather than reading the metadata
/// again. `None` means the mode could not be verified (the `stat` behind it
/// failed) even though the path may still exist - `path_exists` below is
/// then the sole authority on existence, since it runs `test -e`
/// independently of `stat`. An unverified mode never satisfies a policy
/// exception (the caller already enforces that before reaching here), but
/// hardening still proceeds: an exact directive is chmod'd to its fixed
/// baseline regardless of the current mode, while a max-mask directive's
/// target depends on the current mode and so cannot be safely guessed - it
/// is skipped instead, with a `warn!` and a recorded `Change` so the gap is
/// never silent.
///
/// For local execution: uses `O_NOFOLLOW` open + `fchmod` to operate on
/// the real inode, eliminating the TOCTOU window between check and chmod.
/// For remote execution: falls back to the executor's `execute_command`.
///
/// Returns a Change object if successful, None if path doesn't exist or on error.
async fn apply_path_permissions(
    ctx: &Context,
    directive: &PermissionDirective,
    current_mode: Option<u32>,
) -> Option<Change> {
    let path = Path::new(directive.permission_path);

    // Skip if path doesn't exist. This is the sole existence authority when
    // `current_mode` is unverified: `path_exists` uses `test -e`, independent
    // of the `stat` that failed to yield a mode.
    if !ctx.executor().path_exists(path).await.unwrap_or(false) {
        return None;
    }

    match current_mode {
        Some(mode) if !violates(directive, mode) => return None,
        Some(_) => {}
        None => {
            // The path is confirmed present above, but its mode is unknown.
            // Reproduce pre-branch semantics: an exact directive's target is
            // the fixed baseline regardless of the current mode, so hardening
            // still proceeds; a max-mask directive's target depends on the
            // current mode, which is unknown, so guessing one could loosen an
            // already-stricter host - skip it instead.
            warn!(
                "Permissions on {} could not be verified (stat failed); \
                 hardening proceeds without a known current mode",
                directive.permission_path
            );
            if directive.permission_max_mask {
                return Some(Change {
                    change_description: format!(
                        "{}: skipped (current permissions could not be verified, \
                         so a safe target cannot be computed for this max-mask directive)",
                        directive.permission_path
                    ),
                    change_type: ChangeType::Skipped,
                    change_success: true,
                    change_error: None,
                });
            }
        }
    }

    // A filesystem that cannot hold POSIX permissions ignores chmod (it exits 0
    // but the mode is unchanged). Detect it up front and skip with fstab
    // guidance rather than issue a futile chmod - this also closes the local
    // fchmod path's silent false "success". Fail-safe: an inconclusive probe
    // returns None here, so a genuine POSIX violation still gets chmod'd.
    if let Some(fstype) = non_posix_fstype(ctx, directive.permission_path).await {
        return Some(non_posix_skip_change(directive.permission_path, &fstype));
    }

    // Use TOCTOU-safe fchmod for local targets, executor for remote
    if !ctx.executor().is_remote() {
        apply_local_fchmod(directive, current_mode)
    } else {
        apply_remote_chmod(ctx, directive, current_mode).await
    }
}

/// TOCTOU-safe local permission change via `O_NOFOLLOW` + `fchmod`.
fn apply_local_fchmod(
    directive: &PermissionDirective,
    current_mode: Option<u32>,
) -> Option<Change> {
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

    // `apply_path_permissions` never reaches here with an unverified mode for
    // a max-mask directive (it returns early for that case), so `unwrap_or(0)`
    // only ever substitutes for an exact directive, whose target ignores
    // `current_mode` entirely - the 0 cannot influence the outcome.
    let target = target_mode(directive, current_mode.unwrap_or(0));
    let target_bits = Mode::from_bits_truncate(target);
    match fchmod(&file, target_bits) {
        Ok(()) => Some(Change {
            change_description: format!(
                "Changed permissions on {} {}",
                directive.permission_path,
                mode_transition_description(current_mode, target)
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
    current_mode: Option<u32>,
) -> Option<Change> {
    // See `apply_local_fchmod` re: `unwrap_or(0)` - only ever substitutes for
    // an exact directive's mode-independent target.
    let target = target_mode(directive, current_mode.unwrap_or(0));
    let mode_str = format!("{target:04o}");
    let result = ctx
        .executor()
        .execute_command("chmod", &[&mode_str, directive.permission_path])
        .await;

    match result {
        Ok(output) if output.success() => {
            // Verify the change took effect: for max-mask directives, verify
            // no disallowed bits remain; for exact directives, verify equality.
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
                        "Changed permissions on {} {}",
                        directive.permission_path,
                        mode_transition_description(current_mode, target)
                    ),
                    change_type: ChangeType::Permissions,
                    change_success: true,
                    change_error: None,
                })
            } else {
                Some(Change {
                    change_description: format!(
                        "Permissions on {} unchanged (filesystem may not support chmod, \
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

    async fn scan(&self, ctx: &Context, config: &PluginConfig) -> Result<ScanResult> {
        let start_time = Instant::now();
        let mut findings = Vec::new();
        let mut unchecked = Vec::new();

        // Check all critical permissions
        for directive in CRITICAL_PERMISSIONS {
            match check_path_permissions(ctx, directive, config).await {
                PermissionCheck::Insecure(finding) => findings.push(*finding),
                PermissionCheck::NonPosix(check) => unchecked.push(*check),
                PermissionCheck::Clear => {}
            }
        }

        Ok(ScanResult {
            scan_duration_us: start_time.elapsed().as_micros() as u64,
            scan_error: None,
            scan_findings: findings,
            scan_unchecked: unchecked,
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

        changes.extend(crate::checkpoint_change(&checkpoint_id));

        // Apply permissions to all critical paths
        for directive in CRITICAL_PERMISSIONS {
            let path = Path::new(directive.permission_path);
            // An unverified mode (stat failed) can never confirm an
            // exception, so it is not honoured below. It does not, however,
            // mean there is nothing to harden: `apply_path_permissions`
            // decides how to proceed for that case (see its doc comment),
            // using `path_exists` as the authority on whether the path is
            // even there.
            let current_mode = ctx
                .executor()
                .file_metadata(path)
                .await
                .ok()
                .filter(|m| m.exists)
                .map(|m| m.mode & 0o777);

            // Check for a valid exception whose documented value matches the
            // mode actually observed: skip this path only then.
            if let Some(exception) = current_mode
                .and_then(|mode| config.matching_mode_exception(directive.permission_path, mode))
            {
                info!(
                    "Skipping {} (exception: {})",
                    directive.permission_path, exception.reason
                );
                changes.push(Change {
                    change_description: format!(
                        "{}: skipped (exception: {})",
                        directive.permission_path, exception.reason
                    ),
                    change_type: ChangeType::Skipped,
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

            if let Some(change) = apply_path_permissions(ctx, &directive, current_mode).await {
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
            // Build an effective directive: apply any per-path override to
            // `permission_mode` while preserving `permission_max_mask`, so the
            // dry-run's compliance test matches scan/apply exactly (a stricter
            // mode is compliant for mask directives (no spurious pending change).
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
                Ok(metadata) if !metadata.exists => {
                    // The existence probe above passed, but the metadata read
                    // itself came back empty (the ssh executor's stat sentinel
                    // covers any failed stat, not only a missing path) - the
                    // mode cannot be trusted, so there is nothing to validate.
                }
                Ok(metadata) => {
                    let current_mode = metadata.mode & 0o777;

                    // Skip paths with an exception whose documented value
                    // matches the mode actually observed above (fail closed:
                    // a stale or wrong exception does not suppress a change).
                    if config
                        .matching_mode_exception(directive.permission_path, current_mode)
                        .is_some()
                    {
                        continue;
                    }

                    // A pending change requires both a violation and a filesystem
                    // that chmod can actually change. `&&` short-circuits, so the
                    // filesystem probe only fires for a violating path; a
                    // non-POSIX filesystem (probe positively confirmed) is not a
                    // pending change. Fail-safe: an inconclusive probe returns
                    // None, so a genuine violation is still counted.
                    if violates(&effective, current_mode)
                        && non_posix_fstype(ctx, directive.permission_path)
                            .await
                            .is_none()
                    {
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
            validation_report_compliant_count: 0,
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
        // Apply strips disallowed bits only, never adds any.
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

        // No override: baseline 0640 mask; 0000 compliant, 0644 flagged.
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

    /// Confirms the FedRAMP derivation: AC-6(1) and AC-17 are both GSA rev5
    /// Moderate baseline members, so the account files and the sshd config
    /// directory mirror their existing 800-53 ids verbatim under the Access
    /// Control family.
    #[test]
    fn critical_paths_map_fedramp_moderate_controls() {
        let fedramp_for = |path: &str| {
            get_permissions_compliance_mappings(path)
                .into_iter()
                .find(|m| m.compliance_framework == ComplianceFramework::FedRAMP)
                .unwrap_or_else(|| panic!("{path} must carry a FedRAMP mapping"))
        };

        for path in ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"] {
            let mapping = fedramp_for(path);
            assert_eq!(mapping.compliance_control_id, "AC-6(1)", "{path}");
            assert_eq!(
                mapping.compliance_section.as_deref(),
                Some("Access Control")
            );
        }

        let sshd = fedramp_for("/etc/ssh");
        assert_eq!(sshd.compliance_control_id, "AC-17(a)");
        assert_eq!(sshd.compliance_section.as_deref(), Some("Access Control"));
    }
}
