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
    vendor_config::vendor_path_for,
};
use hardener_core::{
    ApplyResult, Change, ChangeType, PluginConfig, ValidationReport,
    context::Context,
    plugin::{
        Finding, HardeningPlugin, PluginMetadata, ScanResult, UncheckedBlocker, UncheckedCheck,
    },
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

/// `Some(baseline)` when a path whose mode could not be verified should still
/// be hardened to a fixed target: an exact directive's target is
/// `permission_mode` regardless of the current mode, so it never needed one
/// to begin with. `None` when no safe target can be computed without a real
/// current mode: a max-mask directive's target strips bits from a current
/// mode that here is unknown, and guessing one could loosen an
/// already-stricter host.
///
/// This is the single decision both `apply_path_permissions` (which turns it
/// into a `Change`) and `validate_path_permissions` (which turns it into a
/// predicted change or a reported gap) consult, so a dry-run preview and the
/// apply it previews can never again describe different outcomes for the
/// same unverified path.
fn unverified_mode_target(directive: &PermissionDirective) -> Option<u32> {
    (!directive.permission_max_mask).then_some(directive.permission_mode)
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
        // The filesystem cannot express a POSIX mode at all. Root cannot make
        // vfat grow one, which is why the reason names fstab instead.
        unchecked_blocker: UncheckedBlocker::Environment,
        unchecked_compliance: get_permissions_compliance_mappings(directive.permission_path),
    }
}

/// Unchecked entry for a path whose permissions could not be read.
///
/// Shares the id and compliance mappings of the finding this check would
/// otherwise produce, so the compliance report renders ManualReview instead of
/// counting the control as satisfied by an absent finding.
fn unverifiable_unchecked(directive: &PermissionDirective, reason: &str) -> UncheckedCheck {
    UncheckedCheck {
        unchecked_check_id: permission_check_id(directive.permission_path),
        unchecked_title: format!("Permissions on {}", directive.permission_path),
        unchecked_category: FindingCategory::FileSystem,
        unchecked_reason: reason.to_string(),
        // Every caller reaches here from an `Err` out of `path_exists` or
        // `file_metadata`, and neither is classified, so a refusal root would
        // fix is indistinguishable here from one it would not. Saying so is the
        // honest answer; the previous `false` asserted the second.
        unchecked_blocker: UncheckedBlocker::Unknown,
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
    /// Nothing to report: compliant, absent from `/etc` and `/usr/etc` both, or a
    /// path with no vendor counterpart and nothing at `/etc`. A confirmed absence
    /// from `/etc` alone is NOT this variant any more; it delegates to
    /// [`check_vendor_layer_permissions`], because on a layering distribution the
    /// vendor copy is the file in force.
    Clear,
    /// Present, but its permissions could not be read, so nothing can be said
    /// about them. Reported as unchecked rather than folded into `Clear`:
    /// these are paths like /etc/shadow and /etc/sudoers, and silence about
    /// them is indistinguishable from a clean result.
    Unverifiable(Box<UncheckedCheck>),
    /// Violates the directive and can be remediated by chmod.
    Insecure(Box<Finding>),
    /// Absent from `/etc` and violating at the vendor layer (`/usr/etc`), where
    /// this tool never writes. A finding rather than an unchecked entry, because
    /// the mode was read and does violate: what is missing is a remediation this
    /// tool may perform, not the evidence. Its remediation names the copy into
    /// `/etc` that a distribution layering its configuration expects, never a
    /// chmod of the package-owned file.
    VendorOnly(Box<Finding>),
    /// Violates, but sits on a filesystem that cannot hold POSIX permissions,
    /// so chmod cannot fix it: reported as unchecked with fstab guidance.
    NonPosix(Box<UncheckedCheck>),
}

/// The directive as this run should read it.
///
/// An octal directive override keyed by `permission_path` replaces the built-in
/// baseline, preserving `permission_max_mask` so mask semantics still apply to the
/// overridden target.
///
/// It exists because the admin path and the vendor path both need it, and two
/// copies would come to disagree about an override for exactly the paths where
/// only one of the two layers holds the file.
///
/// **Every caller now reaches the rule through here**: `scan`'s admin and vendor
/// assessments, `apply`'s per-directive loop, and `validate`'s. It had three
/// implementations until they were collapsed, and the two that went were
/// behaviour-equivalent rather than divergent, which is the only reason the
/// collapse was a refactor: `apply`'s `unwrap_or(directive.permission_mode)` on
/// an unparseable override and this function's `.ok()` both end at the baseline
/// mode. Family 3 is what the collapse forecloses, not a live defect it fixed.
/// An override reaching the vendor comparison, `validate` naming the override as
/// its target and `apply` chmod'ing to it are each pinned by a test, so a fourth
/// caller cannot quietly grow its own copy without one of them failing.
fn effective_directive(
    directive: &PermissionDirective,
    config: &PluginConfig,
) -> PermissionDirective {
    let mut effective = directive.clone();
    // An operator's override may tighten a target and never relax it, the rule
    // pam, ssh and kernel already hold through `strictness.rs`. It cannot be
    // borrowed from there: `Strictness` scores every value on one `i64` scale,
    // and a mode is a bitmask whose order is partial. 0640 and 0604 are neither
    // stricter nor looser than one another, they are different, and no integer
    // comparison says otherwise. So the rule is stated here as a subset test
    // instead: an override earns its place by setting no bit the baseline does
    // not already set.
    //
    // Applied uniformly to both kinds of directive, which is what closes the
    // quieter half of this. On a max-mask directive `permission_mode` is the
    // allowed-bits mask rather than a mode, and a widened mask does not chmod
    // anything wrong, it makes a world-readable /etc/shadow score compliant and
    // the scan then reports nothing at all. Silence about a Critical path is
    // indistinguishable from a clean host, which is the outcome this plugin
    // exists to prevent.
    //
    // A refused override falls back to the baseline without a finding. That was
    // the maintainer's call, taken with the reporting variant in front of it.
    if let Some(mode) = config
        .directives
        .get(directive.permission_path)
        .and_then(|s| u32::from_str_radix(s, 8).ok())
        .filter(|mode| mode & !directive.permission_mode == 0)
    {
        effective.permission_mode = mode;
    }
    effective
}

/// Assesses the vendor copy of a path `/etc` does not hold.
///
/// openSUSE ships its configuration under `/usr/etc` and reserves `/etc` for
/// administrator overrides, and Fedora is moving the same way, so a confirmed
/// absence from `/etc` is not the same as "there is nothing here". Measured on the
/// openSUSE test container 2026-07-30: `/etc/sudoers` does not exist,
/// `/usr/etc/sudoers` does, at mode 0444 against a directive targeting 0440 at
/// Critical. The file in force is world-readable, and this plugin used to report
/// neither a finding nor an unchecked entry, which is precisely the silence
/// [`PermissionCheck::Unverifiable`] was added to avoid for this path.
///
/// The remediation is a copy into `/etc`, never a chmod of `/usr/etc`. Writing the
/// vendor file is settled policy against: it is package-owned, so a package update
/// would revert the change, and the layering exists so that `/etc` is where an
/// administrator states a deviation. That is why this returns its own variant
/// rather than [`PermissionCheck::Insecure`], whose remediation is a chmod of the
/// path itself and whose findings describe something apply will perform.
///
/// No filesystem-type probe here, unlike the admin path: that probe exists to
/// avoid promising a chmod on a filesystem that cannot hold the mode, and nothing
/// on this path promises a chmod at all.
async fn check_vendor_layer_permissions(
    ctx: &Context,
    directive: &PermissionDirective,
    config: &PluginConfig,
) -> PermissionCheck {
    // /root and /boot have no vendor counterpart, and vendor_path_for says so by
    // requiring the /etc/ prefix. Nothing under /etc is assumed to have one
    // either: the probe below is what decides.
    let Some(vendor_path) = vendor_path_for(directive.permission_path) else {
        return PermissionCheck::Clear;
    };
    let vendor = Path::new(&vendor_path);

    match ctx.executor().path_exists(vendor).await {
        // Absent from both layers. There is no file anywhere, so silence is the
        // whole truth, and this is the branch /etc/gshadow takes on openSUSE.
        Ok(false) => return PermissionCheck::Clear,
        Ok(true) => {}
        Err(e) => {
            return PermissionCheck::Unverifiable(Box::new(unverifiable_unchecked(
                directive,
                &format!(
                    "{} is absent and could not determine whether {vendor_path} exists: {e}",
                    directive.permission_path
                ),
            )));
        }
    }

    let metadata = match ctx.executor().file_metadata(vendor).await {
        Ok(metadata) => metadata,
        Err(e) => {
            return PermissionCheck::Unverifiable(Box::new(unverifiable_unchecked(
                directive,
                &format!(
                    "{} is absent and its vendor copy {vendor_path} could not be read: {e}",
                    directive.permission_path
                ),
            )));
        }
    };
    let current_mode = metadata.mode & 0o777;

    let effective = effective_directive(directive, config);
    let directive = &effective;
    if !violates(directive, current_mode) {
        return PermissionCheck::Clear;
    }

    let target = target_mode(directive, current_mode);
    let policy_exception =
        config.exception_outcome(directive.permission_path, &format!("{current_mode:04o}"));
    PermissionCheck::VendorOnly(Box::new(Finding {
        finding_category: FindingCategory::FileSystem,
        finding_current_value: format!("{:04o}", current_mode),
        finding_description: directive.permission_description.to_string(),
        finding_explanation: format!(
            "{} does not exist, so {vendor_path} is the file in force, and it has permissions {:04o} where {:04o} is required. This tool does not write the vendor layer, so it cannot correct this for you",
            directive.permission_path, current_mode, target,
        ),
        // Keyed on the /etc path, deliberately: the control is about this
        // setting wherever the distribution keeps it, and the compliance
        // mappings, the report and the differential suite all ask by that id.
        finding_id: permission_check_id(directive.permission_path),
        finding_impact: "Low - only affects security posture, no functional impact".to_string(),
        finding_recommended_value: format!("{:04o}", target),
        finding_remediation_steps: vec![
            format!(
                "install -o root -g root -m {:04o} {vendor_path} {}",
                target, directive.permission_path,
            ),
            format!(
                "The copy in {} takes precedence over the vendor file and is where a deviation belongs; editing {vendor_path} in place would be reverted by the next package update",
                directive.permission_path,
            ),
        ],
        finding_severity: directive.permission_severity,
        finding_title: format!("Insecure permissions on {vendor_path}"),
        finding_compliance: get_permissions_compliance_mappings(directive.permission_path),
        finding_exception: policy_exception,
        finding_exception_key: Some(directive.permission_path.to_string()),
    }))
}

/// Assesses one critical path's permissions.
///
/// A directive override in `config` (an octal string keyed by
/// `permission_path`) replaces the built-in baseline mode before the
/// compliance check runs, so a stricter override can flag an
/// otherwise-compliant path. A valid policy exception for the path annotates
/// a resulting finding via `finding_exception` rather than dropping it.
///
/// Returns [`PermissionCheck::Insecure`] when the path violates its directive on
/// a POSIX filesystem, [`PermissionCheck::NonPosix`] when it violates but sits on
/// a filesystem that cannot hold POSIX permissions (reported as unchecked with
/// fstab guidance, never a false finding), [`PermissionCheck::VendorOnly`] when
/// `/etc` holds nothing and the vendor copy under `/usr/etc` violates, and
/// [`PermissionCheck::Clear`] when the path is compliant or absent from both
/// layers.
///
/// A path that exists and cannot be read is [`PermissionCheck::Unverifiable`],
/// never `Clear`. This doc comment claimed otherwise until 2026-07-30, having
/// outlived the variant that fixed it.
async fn check_path_permissions(
    ctx: &Context,
    directive: &PermissionDirective,
    config: &PluginConfig,
) -> PermissionCheck {
    let path = Path::new(directive.permission_path);

    // Only a confirmed absence is nothing to report. An existence probe that
    // errored says nothing either way, and treating it as absence made the
    // scan silent about a path it never managed to look at.
    match ctx.executor().path_exists(path).await {
        Ok(false) => return check_vendor_layer_permissions(ctx, directive, config).await,
        Ok(true) => {}
        Err(e) => {
            return PermissionCheck::Unverifiable(Box::new(unverifiable_unchecked(
                directive,
                &format!(
                    "could not determine whether {} exists: {e}",
                    directive.permission_path
                ),
            )));
        }
    }

    // Get file metadata
    let metadata = match ctx.executor().file_metadata(path).await {
        Ok(metadata) => metadata,
        Err(e) => {
            return PermissionCheck::Unverifiable(Box::new(unverifiable_unchecked(
                directive,
                &format!(
                    "could not read permissions on {}: {e}",
                    directive.permission_path
                ),
            )));
        }
    };

    // Get current permissions (only last 9 bits = rwxrwxrwx)
    let current_mode = metadata.mode & 0o777;

    let effective = effective_directive(directive, config);
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
    let policy_exception =
        config.exception_outcome(directive.permission_path, &format!("{current_mode:04o}"));
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
        finding_exception: policy_exception,
        finding_exception_key: Some(directive.permission_path.to_string()),
    }))
}

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

/// Returns compliance mappings for permission findings.
///
/// Multi-framework mappings are sourced from ComplianceAsCode/SSG rule
/// `references:` blocks (see `// SSG:` comments). NIST IDs are 800-53 Rev 5;
/// PCI-DSS is v4.0. STIG is deliberately omitted for the account files below:
/// the SSG rules `file_permissions_etc_{passwd,shadow,group,gshadow}` declare
/// no `stigid@`: DISA covers them only via the parent SRG
/// (`SRG-OS-000480-GPOS-00227`), so there is no concrete STIG control ID to
/// cite without inventing one.
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
        // Both sudoers paths, and the two frameworks they do NOT carry are the
        // point of this arm rather than an oversight.
        //
        // These seven ids are the ones already sourced in this file whose
        // titles name no file: least privilege and access restriction apply to
        // a Critical path on the same reasoning that puts them on
        // `/etc/shadow`, so transferring them asserts nothing new about the
        // world. That is the whole test for whether an id may move here.
        //
        // CIS is omitted because a CIS control names its file in its own title
        // (`6.1.3 Ensure permissions on /etc/shadow are configured`), so
        // shadow's cannot be transferred, and no sudoers id exists anywhere in
        // this tree to put in its place. PCI-DSS is omitted because its
        // presence is decided per file by the SSG rule: `/etc/gshadow` already
        // drops it for exactly that reason, and there is no SSG rule here to
        // consult. This follows the same rule the doc comment above states for
        // STIG: a framework with no concrete control ID to cite is left out and
        // told about, never filled in by analogy.
        //
        // The consequence of the previous silence, so it is not reintroduced:
        // an empty vector contributes no control id to the catalogue, so
        // sudoers rendered as neither Pass nor Fail nor ManualReview. It was
        // absent, which reads exactly like a clean result.
        "/etc/sudoers" | "/etc/sudoers.d" => vec![
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
            // 800-171r3 3.1.5 <- 800-53 AC-6(1) (SP 800-171r3 source-control table).
            nist171("3.1.5", "Least Privilege"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 AC-6(1).
            fedramp(
                "AC-6(1)",
                "Least Privilege - Authorize Access to Security Functions",
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
/// then the authority on existence. On `SshExecutor` that is a genuinely
/// independent check (a separate `test -e` command against the `stat`
/// command behind `file_metadata`), so the two can disagree for reasons
/// beyond timing. On `LocalExecutor`, `path_exists` is `path.exists()`,
/// which runs the very same `fs::metadata` syscall `file_metadata` reads
/// its mode from, just as a separate, later call; the two can therefore
/// only disagree via a race, which makes this whole branch effectively
/// SSH-only in practice. An unverified mode never satisfies a policy
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

    // The existence authority when `current_mode` is unverified (see the doc
    // comment above: genuinely independent of the failed `stat` on SSH, but only
    // a race locally).
    //
    // An errored probe is not an absence, and reading it as one returned None,
    // which records no `Change` at all. An omitted change cannot be a failed one,
    // so the run reported success and the change list, which is the operator's
    // record of what was hardened, held nothing for the path: indistinguishable
    // from a host that was already correct. It is reported as a failed change
    // rather than as an error, matching the rule that a mode which could not be
    // set is a failed change and not fatal, so the remaining paths are still
    // hardened and the summary still says something went wrong.
    match ctx.executor().path_exists(path).await {
        Ok(true) => {}
        Ok(false) => return None,
        Err(e) => {
            return Some(Change {
                change_description: format!(
                    "{}: could not determine whether the path exists, so it was not examined",
                    directive.permission_path
                ),
                change_type: ChangeType::Permissions,
                change_success: false,
                change_error: Some(e.to_string()),
            });
        }
    }

    match current_mode {
        Some(mode) if !violates(directive, mode) => return None,
        Some(_) => {}
        None => {
            // The path is confirmed present above, but its mode is unknown.
            // This matches pre-branch behaviour only for the metadata
            // sentinel (`Ok(exists: false)`, e.g. a `stat` that reports the
            // path absent while `path_exists` still finds it): pre-branch
            // derived `current_mode = 0` from that same sentinel and
            // hardened an exact directive to its fixed baseline, exactly as
            // this branch now does. It is NOT equivalent for a genuine
            // metadata `Err`: pre-branch's `.ok()?` discarded that silently
            // and recorded no change at all, whereas this branch now hardens
            // an exact directive regardless. In practice `apply` never
            // reaches this function with that kind of `Err`, because
            // `create_checkpoint_metadata_only_for_apply` reads the same
            // metadata for every critical path up front and aborts the
            // whole `apply` via `?` first. A max-mask directive's target
            // depends on the current mode, which is unknown, so guessing
            // one could loosen an already-stricter host - skip it instead.
            warn!(
                "Permissions on {} could not be verified (stat failed); \
                 hardening proceeds without a known current mode",
                directive.permission_path
            );
            if unverified_mode_target(directive).is_none() {
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

/// The mode `apply`'s own loop would see for `path`: `None` when a `stat`
/// failure left the path's mode unestablished even though it may still
/// exist (`path_exists` can genuinely disagree with that on `SshExecutor`;
/// on `LocalExecutor` the two read the same syscall at different times, so
/// they can only disagree via a race - see [`apply_path_permissions`]'s doc
/// comment), `Some` otherwise. Shared by `apply` and `validate` so the two
/// can never again derive "unverified" from the same metadata read in
/// different ways.
async fn current_verified_mode(ctx: &Context, path: &Path) -> Option<u32> {
    ctx.executor()
        .file_metadata(path)
        .await
        .ok()
        .filter(|m| m.exists)
        .map(|m| m.mode & 0o777)
}

/// Validate's counterpart to `apply_path_permissions`: the pending change (if
/// any) a dry-run should report for one critical path. Mirrors that
/// function's shape, including the `current_mode` parameter, so the two can
/// be reasoned about and tested identically and can never again describe a
/// different outcome for the same directive and mode.
///
/// Returns `(estimated_change, issue)`; at most one is ever `Some`.
///
/// `current_mode: None` means the path is confirmed to exist (the caller's
/// `path_exists` check already ran) but its mode could not be established.
/// This consults the same [`unverified_mode_target`] apply does: a max-mask
/// directive has nothing to estimate (apply skips it), so the gap is
/// reported as an issue instead, and that issue is the only place it is
/// surfaced. It does reach the operator: `validation_report_lines` in
/// `hardener-cli/src/output.rs` prints every issue with its severity and
/// marks the report from `validation_report_is_valid`, and the desktop
/// carries them through `PreviewDecision::issues` into the review list.
/// `--format json` carries them too. It is `Severity::High`, so it also
/// fails the dry run, in the fleet path as well as the single-host one:
/// both ask `ValidationReport::has_blocking_issue`, which is Critical and
/// High only. An exact directive is always
/// hardened by apply regardless of the current mode (unless the filesystem
/// cannot hold POSIX permissions at all, in which case there is nothing
/// pending either), so it is reported as a predicted change, worded so the
/// "from" mode is honestly described as unknown rather than invented; a
/// second issue on top would only repeat what the estimate already says.
///
/// `current_mode: Some(mode)` is the pre-existing, unchanged behaviour: a
/// genuine violation on a filesystem that can actually hold POSIX
/// permissions becomes the predicted change.
///
/// A policy exception is deliberately not consulted here. The caller's loop
/// honours it first, exactly where `apply`'s loop honours its own, because an
/// excepted path has to be *recorded* as a documented deviation and a helper
/// returning "nothing to predict" has no way to say that. Suppressing the
/// prediction inside this function is what let the deviation vanish.
async fn validate_path_permissions(
    ctx: &Context,
    directive: &PermissionDirective,
    current_mode: Option<u32>,
) -> (Option<String>, Option<hardener_core::ValidationIssue>) {
    let Some(mode) = current_mode else {
        let Some(target) = unverified_mode_target(directive) else {
            return (
                None,
                Some(hardener_core::ValidationIssue {
                    validation_issue_severity: Severity::High,
                    validation_issue_message: format!(
                        "Current permissions on {} could not be verified; apply will skip \
                         hardening it (no safe target can be computed for this max-mask \
                         directive without the current mode)",
                        directive.permission_path
                    ),
                    validation_issue_config_key: Some(directive.permission_path.to_string()),
                }),
            );
        };

        // Mirrors apply_path_permissions: a non-POSIX filesystem makes chmod
        // futile, so it is not a pending change either. Fail-safe: an
        // inconclusive probe still predicts the chmod, matching apply, which
        // attempts it when the probe cannot positively confirm the
        // filesystem.
        if non_posix_fstype(ctx, directive.permission_path)
            .await
            .is_some()
        {
            return (None, None);
        }

        return (
            Some(format!(
                "{}: current permissions could not be verified → {target:04o} \
                 (apply hardens this exact-mode directive regardless)",
                directive.permission_path
            )),
            None,
        );
    };

    // A pending change requires both a violation and a filesystem that
    // chmod can actually change. `&&` short-circuits, so the filesystem
    // probe only fires for a violating path; a non-POSIX filesystem (probe
    // positively confirmed) is not a pending change. Fail-safe: an
    // inconclusive probe returns None, so a genuine violation is still
    // counted.
    if violates(directive, mode)
        && non_posix_fstype(ctx, directive.permission_path)
            .await
            .is_none()
    {
        return (
            Some(format!(
                "{}: {:04o} → {:04o}",
                directive.permission_path,
                mode,
                target_mode(directive, mode)
            )),
            None,
        );
    }

    (None, None)
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
            //
            // A failed metadata read and a mode that genuinely did not move
            // are different outcomes and must not share a message. Folding
            // them together with `unwrap_or(false)` made every verification
            // failure blame vfat, a cause `scan` has already excluded: a path
            // positively confirmed to be on a non-POSIX filesystem is diverted
            // to `PermissionCheck::NonPosix` long before apply reaches here.
            let path = Path::new(directive.permission_path);
            match ctx.executor().file_metadata(path).await {
                Ok(metadata) if !violates(directive, metadata.mode & 0o777) => Some(Change {
                    change_description: format!(
                        "Changed permissions on {} {}",
                        directive.permission_path,
                        mode_transition_description(current_mode, target)
                    ),
                    change_type: ChangeType::Permissions,
                    change_success: true,
                    change_error: None,
                }),
                // chmod exited 0 and the mode still does not satisfy the
                // directive. State that, rather than guess at a reason.
                Ok(metadata) => Some(Change {
                    change_description: format!(
                        "Permissions on {} are still {:04o} after chmod reported success \
                         (wanted {:04o})",
                        directive.permission_path,
                        metadata.mode & 0o777,
                        target
                    ),
                    change_type: ChangeType::Permissions,
                    change_success: false,
                    change_error: None,
                }),
                // The chmod may well have worked; what failed is the check.
                Err(e) => Some(Change {
                    change_description: format!(
                        "Could not verify permissions on {} after chmod",
                        directive.permission_path
                    ),
                    change_type: ChangeType::Permissions,
                    change_success: false,
                    change_error: Some(e.to_string()),
                }),
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
                PermissionCheck::VendorOnly(finding) => findings.push(*finding),
                PermissionCheck::NonPosix(check) => unchecked.push(*check),
                PermissionCheck::Unverifiable(check) => unchecked.push(*check),
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
            let current_mode = current_verified_mode(ctx, path).await;

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

            let directive = effective_directive(directive, config);

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

    // Neither reload method is implemented: permission and ownership changes
    // are immediate. This plugin's paths also come from operator directives at
    // runtime, so there is no set it could enumerate.

    async fn validate(&self, ctx: &Context, config: &PluginConfig) -> Result<ValidationReport> {
        let mut issues = Vec::new();
        let mut estimated_changes = Vec::new();
        // Excepted paths are recorded rather than dropped: a preview that
        // omits them shows a documented deviation as nothing at all.
        let mut exceptions: Vec<String> = Vec::new();

        for directive in CRITICAL_PERMISSIONS {
            let effective = effective_directive(directive, config);

            let path = Path::new(directive.permission_path);

            // Only a confirmed absence is nothing to preview. This read an
            // errored probe as absence, under a comment calling it "not an
            // error", so a Critical path the run could not examine vanished from
            // the dry run and the operator approved a run whose scope they had
            // not been shown. `scan` was repaired for exactly this and says so at
            // its own site; this caller kept the collapse.
            //
            // High rather than a quieter severity because it is what
            // `validation_report_is_valid` above keys on and what
            // `has_blocking_issue` counts: a preview that could not see a path it
            // manages must not read as a clean one. A confirmed absence still
            // skips silently, which is what keeps openSUSE quiet about
            // /etc/gshadow, absent there from both layers.
            match ctx.executor().path_exists(path).await {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) => {
                    issues.push(hardener_core::ValidationIssue {
                        validation_issue_config_key: None,
                        validation_issue_message: format!(
                            "{}: could not determine whether the path exists ({e}), so this \
                             preview cannot say what apply would do to it",
                            directive.permission_path
                        ),
                        validation_issue_severity: Severity::High,
                    });
                    continue;
                }
            }

            let current_mode = current_verified_mode(ctx, path).await;

            // Honoured here rather than inside the helper, mirroring apply's
            // own loop, and fail closed for the same reason: matching needs a
            // verified mode, so an unverified one matches nothing, and a stale
            // exception documenting a mode the host does not have suppresses
            // no work. An excepted path is not a pending change and must not
            // inflate the count the confirm button is named after; it is not
            // nothing either, so it is recorded as the deviation it is.
            if let Some(mode) = current_mode
                && let Some(exception) =
                    config.matching_mode_exception(directive.permission_path, mode)
            {
                exceptions.push(hardener_common::types::exception_preview_line(
                    directive.permission_path,
                    &format!("{mode:04o}"),
                    &exception.reason,
                ));
                continue;
            }

            // The same current_verified_mode read handed to the same-shaped
            // validate_path_permissions, so a dry-run preview and the apply it
            // previews can never again derive "unverified" differently or act
            // on it differently.
            let (estimate, issue) = validate_path_permissions(ctx, &effective, current_mode).await;
            estimated_changes.extend(estimate);
            issues.extend(issue);
        }

        Ok(ValidationReport {
            validation_report_plugin_id: self.metadata().plugin_id,
            validation_report_is_valid: issues
                .iter()
                .all(|i| i.validation_issue_severity != Severity::High),
            validation_report_issues: issues,
            validation_report_estimated_changes: estimated_changes,
            validation_report_compliant_count: 0,
            validation_report_exceptions: exceptions,
        })
    }
}

#[cfg(test)]
mod tests;
