//! Audit Rules Plugin
//!
//! This plugin configures the Linux audit daemon (auditd) to monitor critical
//! system events for security compliance and intrusion detection.
//!
//! Monitors:
//! - Time changes
//! - User/Group modifications
//! - Network configuration changes
//! - Permission modifications
//! - Privileged command execution
//! - File deletions
//! - Kernel module operations

use async_trait::async_trait;
use hardener_common::{
    error::{HardeningError, Result},
    types::{ComplianceFramework, ComplianceMapping, FindingCategory, PluginId, Severity},
};
use hardener_core::{
    ApplyResult, Change, ChangeType, Checkpoint, PluginConfig, ValidationIssue, ValidationReport,
    context::Context,
    plugin::{Finding, HardeningPlugin, PluginMetadata, ScanResult, UncheckedCheck},
};
use std::{path::Path, time::Instant};
use tracing::{info, warn};

/// Audit Hardening Plugin
///
/// Configures auditd rules for comprehensive system monitoring and compliance.
pub struct AuditHardeningPlugin {}

impl Default for AuditHardeningPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditHardeningPlugin {
    /// Creates a new instance of the Audit Hardening Plugin.
    pub fn new() -> AuditHardeningPlugin {
        AuditHardeningPlugin {}
    }
}

/// Represents a single audit rule directive.
///
/// Each directive defines one audit rule with its category, content, finding_description, and severity.
#[derive(Clone, Debug)]
struct AuditRuleDirective {
    audit_rule_category: &'static str,
    audit_rule_content: &'static str,
    audit_rule_description: &'static str,
    audit_rule_severity: Severity,
}

/// Comprehensive audit rules for system security monitoring.
///
/// These rules monitor critical system events and are based on CIS Benchmark
/// and NIS2 compliance requirements.
const AUDIT_RULES: &[AuditRuleDirective] = &[
    // ============================================================================
    // TIME CHANGES - Monitor system time modifications
    // ============================================================================
    AuditRuleDirective {
        audit_rule_category: "time-change",
        audit_rule_content: "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change",
        audit_rule_description: "Monitor system time modifications (64-bit)",
        audit_rule_severity: Severity::High,
    },
    AuditRuleDirective {
        audit_rule_category: "time-change",
        audit_rule_content: "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -k time-change",
        audit_rule_description: "Monitor system time modifications (32-bit)",
        audit_rule_severity: Severity::High,
    },
    AuditRuleDirective {
        audit_rule_category: "time-change",
        audit_rule_content: "-a always,exit -F arch=b64 -S clock_settime -k time-change",
        audit_rule_description: "Monitor clock_settime syscall (64-bit)",
        audit_rule_severity: Severity::High,
    },
    AuditRuleDirective {
        audit_rule_category: "time-change",
        audit_rule_content: "-w /etc/localtime -p wa -k time-change",
        audit_rule_description: "Monitor timezone configuration changes",
        audit_rule_severity: Severity::Medium,
    },
    // ============================================================================
    // IDENTITY - Monitor user and group modifications
    // ============================================================================
    AuditRuleDirective {
        audit_rule_category: "identity",
        audit_rule_content: "-w /etc/passwd -p wa -k identity",
        audit_rule_description: "Monitor user account file modifications",
        audit_rule_severity: Severity::Critical,
    },
    AuditRuleDirective {
        audit_rule_category: "identity",
        audit_rule_content: "-w /etc/shadow -p wa -k identity",
        audit_rule_description: "Monitor password hash file modifications",
        audit_rule_severity: Severity::Critical,
    },
    AuditRuleDirective {
        audit_rule_category: "identity",
        audit_rule_content: "-w /etc/group -p wa -k identity",
        audit_rule_description: "Monitor group account file modifications",
        audit_rule_severity: Severity::Critical,
    },
    AuditRuleDirective {
        audit_rule_category: "identity",
        audit_rule_content: "-w /etc/gshadow -p wa -k identity",
        audit_rule_description: "Monitor group password file modifications",
        audit_rule_severity: Severity::Critical,
    },
    AuditRuleDirective {
        audit_rule_category: "identity",
        audit_rule_content: "-w /etc/security/opasswd -p wa -k identity",
        audit_rule_description: "Monitor password history file modifications",
        audit_rule_severity: Severity::High,
    },
    // ============================================================================
    // NETWORK CHANGES - Monitor network configuration
    // ============================================================================
    AuditRuleDirective {
        audit_rule_category: "network-change",
        audit_rule_content: "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network-change",
        audit_rule_description: "Monitor hostname and domain name changes (64-bit)",
        audit_rule_severity: Severity::Medium,
    },
    AuditRuleDirective {
        audit_rule_category: "network-change",
        audit_rule_content: "-w /etc/hosts -p wa -k network-change",
        audit_rule_description: "Monitor hosts file modifications",
        audit_rule_severity: Severity::Medium,
    },
    AuditRuleDirective {
        audit_rule_category: "network-change",
        audit_rule_content: "-w /etc/network/ -p wa -k network-change",
        audit_rule_description: "Monitor network configuration directory",
        audit_rule_severity: Severity::Medium,
    },
    // ============================================================================
    // PERMISSION MODIFICATIONS - Monitor file permission and ownership changes
    // ============================================================================
    AuditRuleDirective {
        audit_rule_category: "perm-mod",
        audit_rule_content: "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k perm-mod",
        audit_rule_description: "Monitor file permission changes (64-bit)",
        audit_rule_severity: Severity::Medium,
    },
    AuditRuleDirective {
        audit_rule_category: "perm-mod",
        audit_rule_content: "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -k perm-mod",
        audit_rule_description: "Monitor file permission changes (32-bit)",
        audit_rule_severity: Severity::Medium,
    },
    AuditRuleDirective {
        audit_rule_category: "perm-mod",
        audit_rule_content: "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -k perm-mod",
        audit_rule_description: "Monitor file ownership changes (64-bit)",
        audit_rule_severity: Severity::Medium,
    },
    AuditRuleDirective {
        audit_rule_category: "perm-mod",
        audit_rule_content: "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -k perm-mod",
        audit_rule_description: "Monitor file ownership changes (32-bit)",
        audit_rule_severity: Severity::Medium,
    },
    AuditRuleDirective {
        audit_rule_category: "perm-mod",
        audit_rule_content: "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -k perm-mod",
        audit_rule_description: "Monitor extended attribute changes (64-bit)",
        audit_rule_severity: Severity::Medium,
    },
    // ============================================================================
    // PRIVILEGED COMMANDS - Monitor execution of privileged commands
    // ============================================================================
    AuditRuleDirective {
        audit_rule_category: "privileged",
        audit_rule_content: "-w /usr/bin/sudo -p x -k privileged",
        audit_rule_description: "Monitor sudo command execution",
        audit_rule_severity: Severity::High,
    },
    AuditRuleDirective {
        audit_rule_category: "privileged",
        audit_rule_content: "-w /usr/bin/su -p x -k privileged",
        audit_rule_description: "Monitor su command execution",
        audit_rule_severity: Severity::High,
    },
    AuditRuleDirective {
        audit_rule_category: "privileged",
        audit_rule_content: "-w /usr/bin/passwd -p wa -k privileged",
        audit_rule_description: "Monitor passwd command execution",
        audit_rule_severity: Severity::Medium,
    },
    // ============================================================================
    // FILE DELETION - Monitor file and directory deletion
    // ============================================================================
    AuditRuleDirective {
        audit_rule_category: "delete",
        audit_rule_content: "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete",
        audit_rule_description: "Monitor file deletion operations (64-bit)",
        audit_rule_severity: Severity::Medium,
    },
    AuditRuleDirective {
        audit_rule_category: "delete",
        audit_rule_content: "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -k delete",
        audit_rule_description: "Monitor file deletion operations (32-bit)",
        audit_rule_severity: Severity::Medium,
    },
    // ============================================================================
    // KERNEL MODULES - Monitor kernel module operations
    // ============================================================================
    AuditRuleDirective {
        audit_rule_category: "modules",
        audit_rule_content: "-w /sbin/insmod -p x -k modules",
        audit_rule_description: "Monitor kernel module insertion",
        audit_rule_severity: Severity::High,
    },
    AuditRuleDirective {
        audit_rule_category: "modules",
        audit_rule_content: "-w /sbin/rmmod -p x -k modules",
        audit_rule_description: "Monitor kernel module removal",
        audit_rule_severity: Severity::High,
    },
    AuditRuleDirective {
        audit_rule_category: "modules",
        audit_rule_content: "-w /sbin/modprobe -p x -k modules",
        audit_rule_description: "Monitor modprobe execution",
        audit_rule_severity: Severity::High,
    },
];

/// Path to custom audit rules file for hardening.
const AUDIT_RULES_PATH: &str = "/etc/audit/rules.d/hardening.rules";

/// The directory holding the rules file, which the audit package owns.
const AUDIT_RULES_DIR: &str = "/etc/audit/rules.d";

/// The compiled rule set `augenrules` produces from [`AUDIT_RULES_DIR`], and the
/// file auditd loads at boot. Written by the reload this apply performs rather
/// than by this apply directly, which is why it is easy to miss.
const AUDIT_COMPILED_RULES: &str = "/etc/audit/audit.rules";

/// Where `augenrules` saves whatever [`AUDIT_COMPILED_RULES`] held before it
/// ran. Not every distribution's `augenrules` writes one, so it is the path most
/// likely to be absent when the checkpoint is captured.
const AUDIT_COMPILED_RULES_PREV: &str = "/etc/audit/audit.rules.prev";

/// The mode the rules file is given, as a `chmod` argument.
///
/// 0640, which is what STIG asks of `/etc/audit/rules.d/*.rules` and what the
/// distributions ship. The file is only ever read by `augenrules` and
/// `auditctl`, both of which run as root, so nothing needs the world bit.
const AUDIT_RULES_MODE: &str = "0640";

/// ============================================================================
/// AUDITD HELPER FUNCTIONS
/// ============================================================================
/// Checks if auditd is installed on the system.
async fn is_auditd_installed(ctx: &Context) -> Result<bool> {
    ctx.executor()
        .command_exists("auditd")
        .await
        .map_err(|e| hardener_common::error::HardeningError::Plugin(e.to_string()))
}

/// Checks if auditd service is enabled to start at boot.
///
/// Judged on the word systemd prints and never on its exit status, because the
/// two disagree by design. Measured on a live host rather than read out of the
/// manual: `static` and `indirect` each print their own word and exit **0**,
/// alongside `enabled-runtime`, which systemd documents the same way and which
/// is the one that matters most here. A runtime enablement lives in
/// `/run/systemd/system` and the next boot discards it, so a host in that state
/// has no audit daemon after a reboot while `is-enabled` exits 0 to say it has.
///
/// Reading the status let all three answer "enabled at boot". The consequence
/// ran through every caller in the same direction: scan reported a compliance
/// the host did not have, `validate` previewed no change, and apply skipped the
/// `systemctl enable` that would have repaired it. One boolean stood for
/// "enabled" and for "enabled until the next reboot".
///
/// Only the exact word `enabled` is a permanent enablement. Everything else is
/// read as not enabled, which is the safe direction: the worst it costs is an
/// enable attempt on a unit that cannot be enabled, recorded honestly as a
/// failed change, where the other direction costs an operator their audit trail
/// silently. The firewall plugin needs the fuller answer, because it tells the
/// operator WHICH way the unit fails to start; see `NOT_AT_BOOT_STATES` and
/// `unit_boot_persistence` there. This plugin only decides whether to enable,
/// so it asks the narrower question.
async fn is_auditd_enabled(ctx: &Context) -> Result<bool> {
    let output = ctx
        .executor()
        .execute_command("systemctl", &["is-enabled", "auditd"])
        .await?;
    Ok(output.stdout.trim() == "enabled")
}

/// Checks if auditd service is currently running.
async fn is_auditd_running(ctx: &Context) -> Result<bool> {
    let output = ctx
        .executor()
        .execute_command("systemctl", &["is-active", "auditd"])
        .await?;
    Ok(output.success())
}

/// Result of reading audit rules - distinguishes success from permission error.
enum AuditRulesResult {
    /// Successfully read rules (may be empty if no rules configured).
    Rules(Vec<String>),
    /// Permission denied - cannot determine rule state.
    PermissionDenied,
}

/// Reads current audit rules from the system using auditctl.
///
/// Returns `AuditRulesResult` to distinguish between "no rules" and "permission denied".
async fn read_current_audit_rules(ctx: &Context) -> AuditRulesResult {
    let output = match ctx.executor().execute_command("auditctl", &["-l"]).await {
        Ok(output) => output,
        Err(_) => return AuditRulesResult::PermissionDenied,
    };

    // Check for permission denied in stderr or non-zero exit.
    if !output.success() {
        if output.stderr.contains("root") || output.stderr.contains("permission") {
            return AuditRulesResult::PermissionDenied;
        }
        // Other failure - treat as empty rules (conservative).
        return AuditRulesResult::Rules(Vec::new());
    }

    let rules = output
        .stdout
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.starts_with("No rules"))
        .collect();

    AuditRulesResult::Rules(rules)
}

/// Writes audit rules to the hardening rules file, backing up any existing one
/// first.
///
/// Returns the backup path, or `None` when there was no existing file to back
/// up. A failed backup aborts before the write: overwriting a file this tool
/// could not copy destroys rules with no way back.
///
/// [`AUDIT_RULES_DIR`] must exist before this is called; it no longer creates
/// it. `write_file` cannot make a missing parent, so the apply ensures the
/// directory above its own checkpoint and reports a failure to create it at the
/// call site. Creating it here instead is what made a later rollback of that
/// apply fail: the checkpoint captures the directory, and one that came into
/// existence after the capture is stored with a zero mode, which a rollback
/// reads as "remove this".
async fn write_audit_rules_file(ctx: &Context, content: &str) -> Result<Option<String>> {
    // Create backup with timestamp + random suffix to prevent symlink attacks
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let backup_path = format!("{}.backup.{}.{:08x}", AUDIT_RULES_PATH, timestamp, nonce);

    // Back up whatever is there. Only a confirmed `Ok(false)` means "nothing to
    // copy": an existence probe that errored is not evidence of absence, and
    // treating it as such skipped the backup and then overwrote the file
    // anyway. Ambiguity has to fail towards making a copy.
    let existing = ctx
        .executor()
        .path_exists(Path::new(AUDIT_RULES_PATH))
        .await;
    let backup = if matches!(existing, Ok(false)) {
        None
    } else {
        // `--no-dereference` was here from the start and `-p` was not, the
        // reverse of the ssh plugin's copy; the two flags answer separate
        // questions and a backup needs both. `--no-dereference` copies a
        // symlink as a symlink, so the object about to be overwritten is what
        // gets copied rather than whatever it points at. `-p` preserves mode,
        // ownership and timestamps, which this file needs more than most: the
        // apply insists on 0640 precisely because the rules name every path and
        // syscall the host watches, and a copy restored at the umask's mode
        // hands that map to anyone who can read the directory. `cp -p` exits
        // non-zero when it cannot preserve ownership, as an unprivileged copy
        // of a root-owned file cannot; the check below turns that into an
        // abort, which is the right direction, and apply runs as root so it
        // should not arise.
        //
        // `execute_command` returns Ok for a command that ran and failed, so
        // `?` alone only catches a spawn failure. An unchecked exit code let a
        // failed cp report success and the write proceed over an unsaved file.
        let output = ctx
            .executor()
            .execute_command(
                "cp",
                &["-p", "--no-dereference", AUDIT_RULES_PATH, &backup_path],
            )
            .await?;
        if !output.success() {
            return Err(HardeningError::Plugin(format!(
                "Failed to back up {AUDIT_RULES_PATH} to {backup_path}: cp exited {} ({})",
                output.exit_code,
                output.stderr.trim(),
            )));
        }
        Some(backup_path)
    };

    // Write new rules file
    ctx.executor()
        .write_file(Path::new(AUDIT_RULES_PATH), content)
        .await?;

    Ok(backup)
}

/// Gives the rules file the mode it should have, reporting the failure rather
/// than aborting over it.
///
/// The rules name every path and syscall this host watches, which is a map of
/// the monitoring to anyone who can read it, and STIG asks for these files at
/// 0640 or tighter. Stated here rather than left to whatever a write produces:
/// a local create lands 0644 like any other configuration file and a remote
/// one lands whatever `tee` gives it under the remote umask, so the same apply
/// produced different permissions on different hosts and neither was the one
/// the benchmark asks for.
///
/// A failure is recorded and does not stop the run: the rules are loaded into
/// the kernel either way, and refusing an apply over a permission bit would
/// leave the host less hardened for a lesser problem. Returns the change to
/// record, or `None` when the mode was set.
async fn set_audit_rules_mode(ctx: &Context) -> Option<Change> {
    let failure = match ctx
        .executor()
        .execute_command("chmod", &[AUDIT_RULES_MODE, AUDIT_RULES_PATH])
        .await
    {
        // execute_command returns Ok for a command that ran and failed.
        Ok(output) if output.success() => return None,
        Ok(output) => format!(
            "chmod exited {}: {}",
            output.exit_code,
            output.stderr.trim()
        ),
        Err(e) => e.to_string(),
    };

    Some(Change {
        change_type: ChangeType::ConfigFile,
        change_description: format!(
            "Wrote {AUDIT_RULES_PATH} but could not set its mode to {AUDIT_RULES_MODE}; \
             the rules are in force and the file is readable more widely than intended"
        ),
        change_error: Some(failure),
        change_success: false,
    })
}

/// Reloads audit rules into the running daemon.
///
/// Tries `augenrules --load` first (merges /etc/audit/rules.d/*.rules and
/// loads them without restarting auditd). If that load fails specifically
/// with "Rule exists", kernel-resident rules from a previous load are
/// colliding with the freshly merged set: nothing in a standard setup ever
/// runs a delete-all first, so without intervention every apply after the
/// first on a host would fail here. In that one case the kernel rule set
/// is flushed with a best-effort `auditctl -D` and the load retried once.
/// The flush is deliberately confined to the duplicate-collision retry: a
/// load failing for any other reason (bad rules content, kernel refusal)
/// must leave the previously loaded rules running, and the healthy
/// first-apply path never flushes at all.
///
/// Falls back to `systemctl restart auditd` if augenrules is unavailable
/// or still failing. On many distributions (including Arch), auditd
/// ignores SIGTERM from systemd so a direct restart will fail; augenrules
/// is the supported mechanism. The final error discloses whether a flush
/// happened, because after one the host may be left with no audit rules
/// loaded until they are reloaded manually or the host reboots.
async fn reload_audit_rules(ctx: &Context) -> Result<()> {
    let mut flushed = false;

    // Preferred: augenrules merges /etc/audit/rules.d/*.rules and loads them
    if ctx
        .executor()
        .command_exists("augenrules")
        .await
        .unwrap_or(false)
    {
        let output = ctx
            .executor()
            .execute_command("augenrules", &["--load"])
            .await?;

        if output.success() {
            return Ok(());
        }

        // "Rule exists" means the only obstacle is duplicate kernel-resident
        // rules from a previous load: flush them and retry once. The flush's
        // own exit status is ignored (best-effort): a refusal here means the
        // kernel config is immutable, which the caller's probe already turns
        // into a reboot-required skip after the retry fails too.
        if output.stdout.contains("Rule exists") || output.stderr.contains("Rule exists") {
            flushed = true;
            let _ = ctx.executor().execute_command("auditctl", &["-D"]).await;

            let retry = ctx
                .executor()
                .execute_command("augenrules", &["--load"])
                .await?;

            if retry.success() {
                return Ok(());
            }
        }
    }

    // Fallback: systemctl restart (works on some distros)
    let output = ctx
        .executor()
        .execute_command("systemctl", &["restart", "auditd"])
        .await?;

    if !output.success() {
        let state = if flushed {
            "; the kernel rule set was flushed before the failed retry, so audit \
             rules may currently be unloaded: reload them with \
             `auditctl -R /etc/audit/audit.rules` or reboot"
        } else {
            "; previously loaded audit rules are still active"
        };
        return Err(hardener_common::error::HardeningError::Plugin(format!(
            "Failed to reload audit rules (augenrules --load and systemctl restart both failed){state}"
        )));
    }

    Ok(())
}

/// Probes whether the kernel audit configuration is immutable (`-e 2`),
/// which locks it until the next reboot and makes both reload legs fail by
/// design rather than through a broken audit setup. Detected from
/// `auditctl -s`, whose status report includes an `enabled 2` line under
/// immutable mode. A failed probe (missing binary, no permission, etc.) is
/// treated as "not immutable" so a genuinely broken reload is never
/// silently downgraded to a skip.
///
/// The token match recognises the modern multi-line `auditctl -s` format
/// only; the legacy single-line `AUDIT_STATUS: enabled=2` format will not
/// match and fails safe to the hard-failure path.
async fn is_audit_config_immutable(ctx: &Context) -> bool {
    let Ok(output) = ctx.executor().execute_command("auditctl", &["-s"]).await else {
        return false;
    };
    output.success()
        && output
            .stdout
            .lines()
            .any(|line| line.split_whitespace().eq(["enabled", "2"]))
}

/// Returns compliance mappings for audit findings.
///
/// Multi-framework mappings are sourced from ComplianceAsCode/SSG rule
/// `references:` blocks (see `// SSG:` comments). NIST IDs are 800-53 Rev 5
/// (AU-* audit family); PCI-DSS is v4.0 (Requirement 10, logging); STIG IDs
/// are the SSG-declared RHEL-family `stigid@ol8` values (the Oracle Linux 8
/// STIG mirrors the RHEL 8 STIG content). STIG is omitted for the generic
/// "rules"/"config" bucket because the concrete `stigid@` differs per audit
/// rule, so no single ID applies.
/// Finding types the audit plugin can raise: the keys understood by
/// [`get_audit_compliance_mappings`]. Keep in sync with that match.
const AUDIT_FINDING_TYPES: &[&str] = &[
    "not_installed",
    "not_enabled",
    "not_running",
    "config",
    "rules",
];

/// Every compliance mapping this plugin can emit, across all finding types it
/// raises. Aggregated into the engine's automated-coverage set.
pub fn coverage() -> Vec<ComplianceMapping> {
    AUDIT_FINDING_TYPES
        .iter()
        .flat_map(|&t| get_audit_compliance_mappings(t))
        .collect()
}

/// Builds a SOC 2 mapping. `id` is a 2017 Trust Services Criteria common
/// criterion (e.g. `CC7.2`); `title` tracks the published criterion text. The
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
/// number (e.g. `3.3.1`); `title` the published requirement name; the
/// section is the requirement's official family. Every id is translated from
/// this plugin's 800-53 entries via the r3 source-control table, never
/// invented.
fn nist171(id: &str, title: &str) -> ComplianceMapping {
    ComplianceMapping {
        compliance_framework: ComplianceFramework::NIST800171,
        compliance_control_id: id.to_string(),
        compliance_control_title: title.to_string(),
        compliance_section: Some("Audit and Accountability".to_string()),
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
        compliance_section: Some("Audit and Accountability".to_string()),
    }
}

/// Returns compliance mappings for a given audit finding type.
fn get_audit_compliance_mappings(finding_type: &str) -> Vec<ComplianceMapping> {
    match finding_type {
        // SSG: package_audit_installed
        // (nist: AU-2(a),AU-12(2),AU-14,...; pcidss: Req-10.1; stigid@ol8: OL08-00-030180)
        "not_installed" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "4.1.1.1".to_string(),
                compliance_control_title: "Ensure auditd is installed".to_string(),
                compliance_section: Some("Logging and Auditing".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::NIST,
                compliance_control_id: "AU-2(a)".to_string(),
                compliance_control_title: "Event Logging".to_string(),
                compliance_section: Some("Audit and Accountability".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::STIG,
                compliance_control_id: "OL08-00-030180".to_string(),
                compliance_control_title: "The audit package must be installed".to_string(),
                compliance_section: Some("Audit and Accountability".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::PCIDSS,
                compliance_control_id: "10.1".to_string(),
                compliance_control_title: "Implement audit trails to link access to system \
                                           components"
                    .to_string(),
                compliance_section: Some("Track and Monitor Access".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.312(b)".to_string(),
                compliance_control_title: "Audit Controls".to_string(),
                compliance_section: Some("Technical Safeguards".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.308(a)(1)(ii)(D)".to_string(),
                compliance_control_title: "Information System Activity Review".to_string(),
                compliance_section: Some("Administrative Safeguards".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-AU".to_string(),
                compliance_control_title: "Audit Logging".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.15".to_string(),
                compliance_control_title: "Logging".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            // SOC 2: CC7.2 mirrors the AU-2 event-logging intent (monitoring capability).
            soc2(
                "CC7.2",
                "Monitor system components for anomalies indicative of malicious acts or errors",
            ),
            // 800-171r3 3.3.1 ← 800-53 AU-2 (SP 800-171r3 source-control table).
            nist171("3.3.1", "Event Logging"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 AU-2.
            fedramp("AU-2(a)", "Event Logging"),
        ],
        // SSG: service_auditd_enabled
        // (nist: AU-3,AU-12(c),...; pcidss: Req-10.1; stigid@ol8: OL08-00-030181)
        "not_enabled" | "not_running" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "4.1.1.2".to_string(),
                compliance_control_title: "Ensure auditd service is enabled and running"
                    .to_string(),
                compliance_section: Some("Logging and Auditing".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::NIST,
                compliance_control_id: "AU-12(c)".to_string(),
                compliance_control_title: "Audit Record Generation".to_string(),
                compliance_section: Some("Audit and Accountability".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::STIG,
                compliance_control_id: "OL08-00-030181".to_string(),
                compliance_control_title: "The auditd service must be enabled and running"
                    .to_string(),
                compliance_section: Some("Audit and Accountability".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::PCIDSS,
                compliance_control_id: "10.1".to_string(),
                compliance_control_title: "Implement audit trails to link access to system \
                                           components"
                    .to_string(),
                compliance_section: Some("Track and Monitor Access".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.312(b)".to_string(),
                compliance_control_title: "Audit Controls".to_string(),
                compliance_section: Some("Technical Safeguards".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.308(a)(1)(ii)(D)".to_string(),
                compliance_control_title: "Information System Activity Review".to_string(),
                compliance_section: Some("Administrative Safeguards".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-AU".to_string(),
                compliance_control_title: "Audit Logging".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.15".to_string(),
                compliance_control_title: "Logging".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            // SOC 2: CC7.2 mirrors the AU-12 record-generation intent (monitoring runs).
            soc2(
                "CC7.2",
                "Monitor system components for anomalies indicative of malicious acts or errors",
            ),
            // 800-171r3 3.3.3 ← 800-53 AU-12 (SP 800-171r3 source-control table).
            nist171("3.3.3", "Audit Record Generation"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 AU-12.
            fedramp("AU-12(c)", "Audit Record Generation"),
        ],
        // SSG: audit_rules_* family (e.g. audit_rules_usergroup_modification_*,
        // audit_rules_dac_modification_*, audit_rules_file_deletion_events_*).
        // The whole family shares nist: AU-12(c),AU-2(d),CM-6(a) and maps to
        // PCI-DSS Requirement 10 (audit trail). The CIS id below is retained
        // from the prior implementation.
        "config" | "rules" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "4.1.2.1".to_string(),
                compliance_control_title: "Ensure audit log storage size is configured".to_string(),
                compliance_section: Some("Logging and Auditing".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::NIST,
                compliance_control_id: "AU-12(c)".to_string(),
                compliance_control_title: "Audit Record Generation".to_string(),
                compliance_section: Some("Audit and Accountability".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::PCIDSS,
                compliance_control_id: "10.2.7".to_string(),
                compliance_control_title: "Record audit trail entries for security-relevant events"
                    .to_string(),
                compliance_section: Some("Track and Monitor Access".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.312(b)".to_string(),
                compliance_control_title: "Audit Controls".to_string(),
                compliance_section: Some("Technical Safeguards".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.308(a)(1)(ii)(D)".to_string(),
                compliance_control_title: "Information System Activity Review".to_string(),
                compliance_section: Some("Administrative Safeguards".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-AU".to_string(),
                compliance_control_title: "Audit Logging".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.15".to_string(),
                compliance_control_title: "Logging".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            // Audit rules actively monitor security-relevant events → ISO 8.16.
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.16".to_string(),
                compliance_control_title: "Monitoring activities".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            // SOC 2: CC7.1 mirrors the change-detection intent; the rules watch
            // identity files, DAC changes and deletions for configuration change.
            soc2(
                "CC7.1",
                "Detection and monitoring of configuration changes and new vulnerabilities",
            ),
            // SOC 2: CC7.2 mirrors the AU-12 record-generation intent (anomaly analysis).
            soc2(
                "CC7.2",
                "Monitor system components for anomalies indicative of malicious acts or errors",
            ),
            // 800-171r3 3.3.3 ← 800-53 AU-12 (SP 800-171r3 source-control table).
            nist171("3.3.3", "Audit Record Generation"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 AU-12.
            fedramp("AU-12(c)", "Audit Record Generation"),
        ],
        _ => vec![],
    }
}

/// ============================================================================
/// HARDENING PLUGIN TRAIT IMPLEMENTATION
/// ============================================================================
#[async_trait]
impl HardeningPlugin for AuditHardeningPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            plugin_category: FindingCategory::Audit,
            plugin_description: "Configures Linux audit daemon (auditd) rules for comprehensive system monitoring and compliance".to_string(),
            plugin_id: PluginId::new("audit-hardening"),
            plugin_name: "Audit Rules Hardening".to_string(),
            plugin_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    fn dependencies(&self) -> Vec<PluginId> {
        vec![] // No dependencies
    }

    async fn scan(&self, ctx: &Context, config: &PluginConfig) -> Result<ScanResult> {
        let start = Instant::now();
        let mut findings = Vec::new();
        let mut unchecked = Vec::new();

        // Check if auditd is installed
        if !is_auditd_installed(ctx).await.unwrap_or(false) {
            findings.push(Finding {
                finding_category: FindingCategory::Audit,
                finding_current_value: "not installed".to_string(),
                finding_description: "Audit daemon (auditd) is not installed".to_string(),
                finding_explanation: "The audit daemon is required for comprehensive system monitoring and compliance".to_string(),
                finding_id: "audit_not_installed".to_string(),
                finding_impact: "No system auditing - security events are not logged".to_string(),
                finding_recommended_value: "installed and running".to_string(),
                finding_remediation_steps: vec![
                    "Install auditd package (apt install auditd / dnf install auditd)".to_string(),
                    "Enable auditd service: systemctl enable auditd".to_string(),
                    "Start auditd service: systemctl start auditd".to_string(),
                ],
                finding_severity: Severity::Critical,
                finding_title: "Audit daemon is not installed".to_string(),
                finding_compliance: get_audit_compliance_mappings("not_installed"),
                finding_policy_exception: None,
            });

            // If not installed, no point checking further
            return Ok(ScanResult {
                scan_duration_us: start.elapsed().as_micros() as u64,
                scan_error: None,
                scan_findings: findings,
                scan_unchecked: vec![],
                scan_plugin_id: self.metadata().plugin_id,
                scan_success: true,
            });
        }

        // Check if auditd is enabled
        if !is_auditd_enabled(ctx).await.unwrap_or(false) {
            findings.push(Finding {
                finding_category: FindingCategory::Audit,
                finding_current_value: "disabled".to_string(),
                finding_description: "Audit daemon is not enabled to start at boot".to_string(),
                finding_explanation:
                    "Auditd should be enabled to ensure audit logging starts automatically"
                        .to_string(),
                finding_id: "audit_not_enabled".to_string(),
                finding_impact: "Audit logging may not start after reboot".to_string(),
                finding_recommended_value: "enabled".to_string(),
                finding_remediation_steps: vec!["systemctl enable auditd".to_string()],
                finding_severity: Severity::High,
                finding_title: "Audit daemon not enabled".to_string(),
                finding_compliance: get_audit_compliance_mappings("not_enabled"),
                finding_policy_exception: None,
            });
        }

        // Check if auditd is running
        if !is_auditd_running(ctx).await.unwrap_or(false) {
            findings.push(Finding {
                finding_category: FindingCategory::Audit,
                finding_current_value: "stopped".to_string(),
                finding_description: "Audit daemon is not currently running".to_string(),
                finding_explanation: "Auditd must be running".to_string(),
                finding_id: "auditd_not_running".to_string(),
                finding_impact: "No audit events are being collected".to_string(),
                finding_recommended_value: "running".to_string(),
                finding_remediation_steps: vec!["systemctl start auditd".to_string()],
                finding_severity: Severity::High,
                finding_title: "Audit daemon not running".to_string(),
                finding_compliance: get_audit_compliance_mappings("not_running"),
                finding_policy_exception: None,
            });
        }

        // Check current audit rules.
        // Handle permission denied separately to avoid false positives.
        match read_current_audit_rules(ctx).await {
            AuditRulesResult::Rules(current_rules) => {
                // Successfully read rules - check each required rule.
                for rule in AUDIT_RULES {
                    // Check if this rule category is present in current rules.
                    let rule_exists = current_rules
                        .iter()
                        .any(|current_rule| current_rule.contains(rule.audit_rule_category));

                    if !rule_exists {
                        findings.push(Finding {
                            finding_category: FindingCategory::Audit,
                            finding_current_value: "not configured".to_string(),
                            finding_description: rule.audit_rule_description.to_string(),
                            finding_explanation: format!(
                                "Audit rule for {} is not configured. This rule monitors: {}",
                                rule.audit_rule_category, rule.audit_rule_description
                            ),
                            finding_id: format!(
                                "audit_rule_{}",
                                rule.audit_rule_category.replace('-', "_")
                            ),
                            finding_impact:
                                "Security events in this category are not being audited"
                                    .to_string(),
                            finding_recommended_value: rule.audit_rule_content.to_string(),
                            finding_remediation_steps: vec![
                                format!("Add rule: {}", rule.audit_rule_content),
                                "Restart auditd: systemctl restart auditd".to_string(),
                            ],
                            finding_severity: rule.audit_rule_severity,
                            finding_title: format!(
                                "Missing audit rule: {}",
                                rule.audit_rule_category
                            ),
                            finding_compliance: get_audit_compliance_mappings("rules"),
                            finding_policy_exception: config
                                .has_valid_exception(rule.audit_rule_category)
                                .map(|e| e.to_finding_exception()),
                        });
                    }
                }
            }
            AuditRulesResult::PermissionDenied => {
                // Cannot verify rules without root: report each expected rule
                // as unchecked rather than silently skipping the whole check.
                for rule in AUDIT_RULES {
                    unchecked.push(UncheckedCheck {
                        unchecked_check_id: format!(
                            "audit_rule_{}",
                            rule.audit_rule_category.replace('-', "_")
                        ),
                        unchecked_title: format!("Audit rule: {}", rule.audit_rule_category),
                        unchecked_category: FindingCategory::Audit,
                        unchecked_reason: "listing loaded audit rules (auditctl -l) requires root"
                            .to_string(),
                        unchecked_needs_privilege: true,
                        unchecked_compliance: get_audit_compliance_mappings("rules"),
                    });
                }
            }
        }
        Ok(ScanResult {
            scan_duration_us: start.elapsed().as_micros() as u64,
            scan_error: None,
            scan_findings: findings,
            scan_unchecked: unchecked,
            scan_plugin_id: self.metadata().plugin_id,
            scan_success: true,
        })
    }

    async fn apply(&self, ctx: &mut Context, config: &PluginConfig) -> Result<ApplyResult> {
        let mut changes = Vec::new();

        // Asked ahead of the checkpoint, unlike every other plugin, because the
        // directory created just below belongs to the audit package: a host
        // without that package must be left exactly as it was found, with
        // neither a stray directory nor a checkpoint of a state nothing
        // changed. It is a probe with no side effects, so nothing downstream
        // sees a difference from it running first.
        if !is_auditd_installed(ctx).await.unwrap_or(false) {
            return Ok(ApplyResult {
                apply_changes: vec![Change {
                    change_type: ChangeType::Service,
                    change_description: "Auditd not installed - cannot apply rules".to_string(),
                    change_error: Some("auditd package not found".to_string()),
                    change_success: false,
                }],
                apply_checkpoint_id: None,
                apply_error: Some("Auditd is not installed".to_string()),
                apply_plugin_id: self.metadata().plugin_id,
                apply_success: false,
            });
        }

        // The audit package ships AUDIT_RULES_DIR on most distributions, but
        // not on all of them, and `write_file` cannot create a missing parent:
        // it lands its content through a temporary file in the target
        // directory, so the rules file failed to write there with an error
        // naming only the file.
        //
        // Ahead of the checkpoint rather than next to the write it exists for.
        // The checkpoint captures AUDIT_RULES_DIR, and an absent path is stored
        // with a zero mode, which a rollback reads as "remove this". A
        // directory created after that capture would make a later rollback run
        // `rm -f` on a directory, which `rm` refuses, so the apply's own
        // rollback reported a failure. Created first, the capture records it
        // present and the rollback restores it, leaving behind an empty
        // standard directory. The reason travels to the write site, which is
        // where a failure to create it is reported and where it stops the
        // write.
        let rules_dir_error = crate::ensure_directory(ctx, AUDIT_RULES_DIR).await;

        // Create checkpoint before changes.
        //
        // AUDIT_RULES_PATH is named alongside the directory that holds it, and
        // not left to the recursion. Capturing a directory emits a row for it
        // and one per child that is there at capture time, so on a host that
        // never had the rules file nothing carried it, and a rollback, which
        // walks only the rows the checkpoint holds, left the hardening in place
        // after the operator had asked for it to be undone. Declared, the path
        // is stored absent with a zero mode, which the restore reads as "remove
        // this".
        //
        // Unconditionally, unlike the services plugin, which narrows its mask
        // paths to units the host has installed. That one writes into
        // /etc/systemd/system, an administrator override slot, where declaring
        // a path this tool may never create would put somebody else's file on a
        // rollback's removal list. `hardening.rules` is our own filename that
        // nothing else writes, so it is safe to declare unseen, exactly as the
        // kernel and ssh plugins declare their drop-ins.
        //
        // The two paths below are what `augenrules --load` writes, and they are
        // named for the same reason the rules file is: the reload runs as part
        // of this apply, so the state it leaves is this apply's to undo.
        // `augenrules` compiles every *.rules file in AUDIT_RULES_DIR into
        // AUDIT_COMPILED_RULES and saves the previous compiled copy as
        // AUDIT_COMPILED_RULES_PREV. Both sit in /etc/audit itself rather than
        // in the rules directory, so capturing AUDIT_RULES_DIR recursively
        // never reached either: measured on five distributions, the compiled
        // file went from five or six lines to thirty during the apply and read
        // exactly the same after a rollback that reported success, and the
        // .prev the apply created outlived that rollback everywhere augenrules
        // writes one.
        //
        // The two exercise different halves of the same mechanism, which is why
        // both are named rather than one standing for the pair. The compiled
        // file exists before the apply on every host measured, so it is
        // captured with its content and the restore writes those bytes back;
        // .prev usually does not, so it is stored absent with a zero mode and
        // the restore removes it. Where an administrator's own earlier
        // `augenrules` run left a .prev, it is captured and restored instead,
        // which is the same bargain either way round.
        //
        // Re-running `augenrules` after the restore was the alternative, and it
        // was rejected: it would load rules as a side effect of an undo, it
        // fails in exactly the environments where the apply already fails (a
        // container can start no auditd, and both `augenrules --load` and
        // `systemctl restart` fail there), and it does nothing about .prev.
        //
        // The ceiling, which is worth saying rather than hiding: restoring the
        // file returns the persistent state only. Rules already loaded into the
        // running kernel stay loaded until a reload or a reboot. That is the
        // same shape as the kernel plugin's rollback, which deletes its drop-in
        // without reverting the runtime sysctl values, and it is a known limit
        // of this tool rather than something this declaration introduces.
        //
        // One consequence of declaring rather than recursing: a declared path
        // is captured strictly, so an existing but unreadable
        // AUDIT_COMPILED_RULES now aborts the capture instead of being
        // tolerated as an incidental child would be. The apply runs as root and
        // the file is root-owned, so it should never fire, and it is the bargain
        // every declared path makes: without the content there is nothing to
        // restore, so continuing would leave the operator believing in a
        // recovery that does not exist.
        let audit_paths: Vec<&Path> = vec![
            Path::new("/etc/audit/auditd.conf"),
            Path::new(AUDIT_RULES_DIR),
            Path::new(AUDIT_RULES_PATH),
            Path::new(AUDIT_COMPILED_RULES),
            Path::new(AUDIT_COMPILED_RULES_PREV),
        ];
        let checkpoint_id =
            crate::create_checkpoint_for_apply(ctx, "audit-hardening-pre-apply", &audit_paths)
                .await?;

        changes.extend(crate::checkpoint_change(&checkpoint_id));

        // Enable auditd if not enabled.
        //
        // This writes a `.wants` symlink under /etc/systemd/system, and the
        // checkpoint declared just above covers nothing there, so a rollback
        // leaves auditd wanted at boot. That is the decision rather than an
        // oversight, and it is written here because the question reaches this
        // site by a route that makes it look like one: sweeping the tree for
        // "which apply creates a path its own checkpoint does not declare"
        // found two genuine defects, the `systemctl mask` link and the audit
        // rules file, and then found this, which is not one.
        //
        // Undoing it would mean removing the symlink, which is to say leaving
        // the host with no audit daemon at its next boot, on a host whose
        // operator asked only to undo a hardening run. That contradicts the
        // settled rule that a hardening run never leaves a host less secure
        // than it found it, and the asymmetry it buys is one this plugin
        // already has: it enables auditd and never disables one.
        //
        // The firewall plugin reached the same answer at
        // `ensure_unit_wanted_at_boot`, and its reasoning is NOT identical,
        // which is worth saying because copying it blind would overstate this
        // case. Firewall's rests on two legs: the rule above, plus its own
        // `rollback` re-enabling the firewall unconditionally, so that removing
        // the symlink would leave a rollback which turns the firewall on for
        // this boot and off at the next. This plugin's `rollback` restores
        // files and reloads rules and says nothing about enablement at all, so
        // there is no such incoherence to avoid and the first leg carries the
        // decision on its own.
        //
        // What the operator is left with, said rather than hidden: a host that
        // had auditd disabled before the run has it enabled after the rollback,
        // and one `systemctl disable auditd` undoes that. A rollback removing
        // it for them cannot be undone by anything as cheap.
        if !is_auditd_enabled(ctx).await.unwrap_or(false) {
            let result = ctx
                .executor()
                .execute_command("systemctl", &["enable", "auditd"])
                .await;
            match result {
                Ok(output) if output.success() => {
                    changes.push(Change {
                        change_type: ChangeType::Service,
                        change_description: "Enabled auditd service".to_string(),
                        change_error: None,
                        change_success: true,
                    });
                }
                _ => {
                    changes.push(Change {
                        change_type: ChangeType::Service,
                        change_description: "Failed to enable auditd service".to_string(),
                        change_error: Some("systemctl enable failed".to_string()),
                        change_success: false,
                    });
                }
            }
        }

        // Start auditd if not running
        if !is_auditd_running(ctx).await.unwrap_or(false) {
            let result = ctx
                .executor()
                .execute_command("systemctl", &["start", "auditd"])
                .await;
            match result {
                Ok(output) if output.success() => {
                    changes.push(Change {
                        change_type: ChangeType::Service,
                        change_description: "Started auditd service".to_string(),
                        change_error: None,
                        change_success: true,
                    });
                }
                _ => {
                    changes.push(Change {
                        change_type: ChangeType::Service,
                        change_description: "Failed to start auditd".to_string(),
                        change_error: Some("systemctl start failed".to_string()),
                        change_success: false,
                    });
                }
            }
        }

        // Build rules file content
        let mut rules_content = String::new();
        rules_content.push_str("# Audit rules generated by Linux Hardening Tool\n");
        rules_content.push_str("# DO NOT EDIT - Changes will be overwritten\n\n");

        for category in [
            "time-change",
            "identity",
            "network-change",
            "perm-mod",
            "privileged",
            "delete",
            "modules",
        ] {
            // Check for a valid exception: skip entire category if exempted
            if let Some(exception) = config.has_valid_exception(category) {
                info!(
                    "Skipping audit category '{}' (exception: {})",
                    category, exception.reason
                );
                rules_content.push_str(&format!(
                    "# {}: SKIPPED (exception: {})\n\n",
                    category.to_uppercase(),
                    exception.reason
                ));
                changes.push(Change {
                    change_description: format!(
                        "Audit category {}: skipped (exception: {})",
                        category, exception.reason
                    ),
                    change_type: ChangeType::Skipped,
                    change_success: true,
                    change_error: None,
                });
                continue;
            }

            rules_content.push_str(&format!("# {}\n", category.to_uppercase()));

            for rule in AUDIT_RULES
                .iter()
                .filter(|r| r.audit_rule_category == category)
            {
                rules_content.push_str(&format!("# {}\n", rule.audit_rule_description));
                rules_content.push_str(&format!("{}\n\n", rule.audit_rule_content));
            }
        }

        // Idempotency guard mirroring the kernel plugin's persistent-config
        // drift guard: only back up, rewrite and reload when the rules file we
        // would write differs from what is already on disk. Reading the current
        // file fails safe toward "differs" (write): a needed rule set is never
        // skipped because the current state could not be read.
        let current_rules_file = ctx
            .executor()
            .read_file(Path::new(AUDIT_RULES_PATH))
            .await
            .ok();

        if current_rules_file.as_deref() == Some(rules_content.as_str()) {
            info!(
                "Audit rules file already matches desired content; skipped backup, rewrite and reload"
            );
            changes.push(Change {
                change_type: ChangeType::Skipped,
                change_description: "Audit rules already up to date - unchanged".to_string(),
                change_error: None,
                change_success: true,
            });
        } else {
            // Write rules file. A parent that could not be created is reported
            // with its own reason rather than left to surface as an
            // unexplained write failure, and it stops the write: no content
            // can land in a directory that is not there.
            let write_outcome = match &rules_dir_error {
                Some(reason) => Err(reason.clone()),
                None => write_audit_rules_file(ctx, &rules_content)
                    .await
                    .map_err(|e| e.to_string()),
            };
            match write_outcome {
                Ok(backup) => {
                    changes.push(Change {
                        change_type: ChangeType::ConfigFile,
                        // Naming a backup that was never taken sends an
                        // operator looking for a file that does not exist.
                        change_description: match &backup {
                            Some(path) => format!("Created audit rules file (backup: {path})"),
                            None => {
                                "Created audit rules file (no previous file to back up)".to_string()
                            }
                        },
                        change_error: None,
                        change_success: true,
                    });
                    changes.extend(set_audit_rules_mode(ctx).await);
                }
                Err(reason) => {
                    changes.push(Change {
                        change_type: ChangeType::ConfigFile,
                        change_description: "Failed to write audit rules".to_string(),
                        change_error: Some(reason),
                        change_success: false,
                    });
                }
            }

            // Reload audit rules into running daemon.
            //
            // On Arch the systemd auditd unit ships `RefuseManualStop=yes`, so
            // the `systemctl restart` fallback inside reload_audit_rules can
            // never succeed there and augenrules is the only viable leg. When
            // both legs fail it is not necessarily a broken audit setup: the
            // kernel audit config may be immutable (-e 2) until the next
            // reboot, in which case the rules file is already written and
            // correct, it just cannot be loaded live. Probe for that before
            // deciding whether this is a genuine failure.
            match reload_audit_rules(ctx).await {
                Ok(_) => {
                    changes.push(Change {
                        change_type: ChangeType::Service,
                        change_description: "Loaded audit rules into running daemon".to_string(),
                        change_error: None,
                        change_success: true,
                    });
                }
                Err(e) => {
                    let change = if is_audit_config_immutable(ctx).await {
                        Change {
                            change_type: ChangeType::Skipped,
                            change_description: "Audit rule reload skipped: config is locked \
                                 (-e 2); a reboot is required for rule changes to take effect"
                                .to_string(),
                            change_error: None,
                            change_success: true,
                        }
                    } else {
                        Change {
                            change_type: ChangeType::Service,
                            change_description: "Failed to reload audit rules".to_string(),
                            change_error: Some(e.to_string()),
                            change_success: false,
                        }
                    };
                    changes.push(change);
                }
            }
        }

        // Determine overall success
        let all_successful = changes.iter().all(|c| c.change_success);

        Ok(ApplyResult {
            apply_changes: changes,
            apply_checkpoint_id: checkpoint_id,
            apply_error: if all_successful {
                None
            } else {
                Some("Some changes failed".to_string())
            },
            apply_plugin_id: self.metadata().plugin_id,
            apply_success: all_successful,
        })
    }

    async fn rollback(&self, ctx: &mut Context, checkpoint: &Checkpoint) -> Result<()> {
        info!(
            "Rolling back audit configuration to checkpoint: {}",
            checkpoint.checkpoint_id.as_str()
        );

        // Restore configuration files from checkpoint
        crate::rollback_files_from_checkpoint(ctx, checkpoint)?;

        info!("Audit configuration files restored from checkpoint");

        // Reload audit rules after restoring config
        match reload_audit_rules(ctx).await {
            Ok(_) => info!("Audit rules reloaded successfully"),
            Err(e) => warn!("Failed to reload audit rules: {}", e),
        }

        Ok(())
    }

    async fn validate(&self, ctx: &Context, config: &PluginConfig) -> Result<ValidationReport> {
        let mut estimated_changes = Vec::new();
        // Excepted settings are recorded rather than dropped: a preview that
        // omits them shows a documented deviation as nothing at all.
        let mut exceptions: Vec<String> = Vec::new();
        let mut issues = Vec::new();

        // Check if auditd is installed
        match is_auditd_installed(ctx).await {
            Ok(true) => {
                // Check if auditd is enabled
                if let Ok(false) = is_auditd_enabled(ctx).await {
                    estimated_changes.push("Enable auditd service".to_string());
                }

                // Check if auditd is running
                if let Ok(false) = is_auditd_running(ctx).await {
                    estimated_changes.push("Start auditd service".to_string());
                }

                // Estimate rule changes
                if let AuditRulesResult::Rules(current_rules) = read_current_audit_rules(ctx).await
                {
                    // A category left out because it is excepted is recorded
                    // rather than merely subtracted from the count: a smaller
                    // number with no explanation is how a deliberate deviation
                    // came to look like nothing at all.
                    for rule in AUDIT_RULES {
                        if let Some(exception) =
                            config.has_valid_exception(rule.audit_rule_category)
                            && !exceptions
                                .iter()
                                .any(|e: &String| e.starts_with(rule.audit_rule_category))
                        {
                            exceptions.push(hardener_common::types::exception_preview_line(
                                rule.audit_rule_category,
                                &exception.value,
                                &exception.reason,
                            ));
                        }
                    }

                    let missing_rules = AUDIT_RULES
                        .iter()
                        .filter(|rule| {
                            // Skip rules whose category has a valid exception
                            config
                                .has_valid_exception(rule.audit_rule_category)
                                .is_none()
                                && !current_rules
                                    .iter()
                                    .any(|current| current.contains(rule.audit_rule_category))
                        })
                        .count();

                    if missing_rules > 0 {
                        estimated_changes.push(format!("Add {} audit-rules", missing_rules));
                    }
                }
            }
            Ok(false) => {
                issues.push(ValidationIssue {
                    validation_issue_config_key: None,
                    validation_issue_message:
                        "auditd is not installed - this plugin requires auditd".to_string(),
                    validation_issue_severity: Severity::Critical,
                });
            }
            Err(_) => {
                // Can't determine, add as issue
                issues.push(ValidationIssue {
                    validation_issue_config_key: None,
                    validation_issue_message: "Failed to check auditd installation status"
                        .to_string(),
                    validation_issue_severity: Severity::High,
                });
            }
        }

        Ok(ValidationReport {
            validation_report_estimated_changes: estimated_changes,
            validation_report_compliant_count: 0,
            validation_report_exceptions: exceptions,
            validation_report_is_valid: issues.is_empty(),
            validation_report_issues: issues,
            validation_report_plugin_id: self.metadata().plugin_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hardener_core::{CommandOutput, MockExecutor, SystemExecutor};
    use std::sync::Arc;

    /// A backup that fails must stop the write. Overwriting a rules file this
    /// tool could not copy destroys the operator's audit rules with nothing to
    /// restore from, and `execute_command` returns Ok for a command that ran
    /// and failed, so the exit code is the only signal there is.
    #[tokio::test]
    async fn a_failed_backup_aborts_before_the_rules_file_is_written() {
        let backup_failed = CommandOutput {
            stdout: String::new(),
            stderr: "cp: cannot create regular file: Read-only file system".to_string(),
            exit_code: 1,
        };
        let executor = MockExecutor::new()
            .with_file(AUDIT_RULES_PATH, "-w /etc/passwd -p wa -k identity\n")
            .with_path_exists(AUDIT_RULES_PATH, true)
            // No mkdir is registered because this function no longer runs one:
            // its caller ensures the directory above the checkpoint. Nothing
            // else here can abort the write, so removing the cp check under
            // test would let the write through and fail this test, which is
            // what it is for.
            .with_command_program("cp", backup_failed);
        let executor = Arc::new(executor);
        let ctx = Context::with_executor(executor.clone() as Arc<dyn SystemExecutor>);

        let result = write_audit_rules_file(&ctx, "-w /etc/new -p wa -k new").await;

        assert!(result.is_err(), "a failed cp must surface as an error");
        assert!(
            executor.log().files_written.is_empty(),
            "the rules file must not be written when its backup failed, but these writes happened: {:?}",
            executor.log().files_written
        );
    }

    /// `systemctl is-enabled` is judged on its word and never on its exit
    /// status, because the two disagree by design.
    ///
    /// Measured on a live systemd host rather than taken from the manual:
    /// `static` and `indirect` each print their own word and exit **0**, while
    /// `disabled` and `masked` print theirs and exit 1. `enabled-runtime` is
    /// documented by systemd as exiting 0 and is the case this plugin most
    /// needs to get right, because it is enablement made in
    /// `/run/systemd/system`, which the next boot discards.
    ///
    /// Reading the exit status therefore reports auditd as enabled at boot on
    /// a host where nothing will start it, and the apply skips the enable that
    /// would have repaired it. Both directions are asserted so that a helper
    /// which simply always answered "not enabled" would fail here too.
    #[tokio::test]
    async fn boot_enablement_is_read_from_the_word_and_not_the_exit_status() {
        for (state, exit_code, wanted) in [
            ("enabled", 0, true),
            ("enabled-runtime", 0, false),
            ("static", 0, false),
            ("indirect", 0, false),
            ("disabled", 1, false),
            ("masked", 1, false),
        ] {
            let executor = Arc::new(MockExecutor::new().with_command(
                "systemctl",
                &["is-enabled", "auditd"],
                CommandOutput {
                    stdout: format!("{state}\n"),
                    stderr: String::new(),
                    exit_code,
                },
            ));
            let ctx = Context::with_executor(executor as Arc<dyn SystemExecutor>);

            let enabled = is_auditd_enabled(&ctx)
                .await
                .expect("a registered systemctl answer must not error");

            assert_eq!(
                enabled, wanted,
                "systemctl is-enabled auditd answering '{state}' with exit \
                 {exit_code} must read as enabled={wanted}"
            );
        }
    }

    /// A backup is only worth taking if it is a copy of the thing about to be
    /// replaced, at the mode that thing carries.
    ///
    /// This file is the one the plugin insists on holding at 0640, because the
    /// rules name every path and syscall the host watches; a backup restored
    /// without `-p` lands at whatever the umask gives it and hands that map to
    /// anyone. `--no-dereference` copies a symlink as a symlink, so a rules
    /// file that is a link elsewhere is backed up as the object about to be
    /// overwritten rather than as its target.
    ///
    /// Asserted on the recorded argv rather than on the run succeeding, and
    /// against a mock that answers any `cp` by program name. A test that leaned
    /// on an exact-argument registration missing would fail with "command not
    /// registered", which is a different failure wearing this one's clothes.
    #[tokio::test]
    async fn the_backup_copy_keeps_the_mode_and_does_not_follow_a_symlink() {
        let ok = CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        };
        let executor = Arc::new(
            MockExecutor::new()
                .with_file(AUDIT_RULES_PATH, "-w /etc/passwd -p wa -k identity\n")
                .with_path_exists(AUDIT_RULES_PATH, true)
                .with_command_program("cp", ok),
        );
        let ctx = Context::with_executor(executor.clone() as Arc<dyn SystemExecutor>);

        let backup = write_audit_rules_file(&ctx, "-w /etc/new -p wa -k new")
            .await
            .expect("a mock that answers any cp must let the write through")
            .expect("an existing rules file must be backed up");

        let log = executor.log();
        let (_, args) = log
            .commands_executed
            .iter()
            .find(|(program, _)| program == "cp")
            .expect("the backup must be taken with cp");
        for flag in ["-p", "--no-dereference"] {
            assert!(
                args.iter().any(|argument| argument == flag),
                "the backup cp must pass {flag}, got: {args:?}"
            );
        }
        // Checked separately from the flags because "the flag is present" and
        // "the flag is a flag" are different claims: an argument added after
        // the source would be read by cp as another file to copy.
        assert_eq!(
            &args[args.len() - 2..],
            &[AUDIT_RULES_PATH.to_string(), backup],
            "source and destination must stay the last two arguments, got: {args:?}"
        );
    }

    /// A representative audit check (`not_installed`) must now carry
    /// multi-framework mappings: the existing CIS control plus NIST 800-53,
    /// STIG, and PCI-DSS sourced from SSG `package_audit_installed`.
    #[test]
    fn auditd_install_has_multi_framework_mappings() {
        let mappings = get_audit_compliance_mappings("not_installed");

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
            has(ComplianceFramework::STIG),
            "STIG mapping must be present"
        );
        assert!(
            has(ComplianceFramework::PCIDSS),
            "PCI-DSS mapping must be present"
        );

        // Verify the exact SSG-sourced STIG and NIST identifiers.
        let stig = mappings
            .iter()
            .find(|m| m.compliance_framework == ComplianceFramework::STIG)
            .unwrap();
        assert_eq!(stig.compliance_control_id, "OL08-00-030180");
        let nist = mappings
            .iter()
            .find(|m| m.compliance_framework == ComplianceFramework::NIST)
            .unwrap();
        assert_eq!(nist.compliance_control_id, "AU-2(a)");
    }

    /// Audit findings must also carry HIPAA, GDPR and ISO/IEC 27001:2022
    /// logging mappings alongside the existing CIS/NIST/STIG/PCI-DSS set.
    #[test]
    fn auditd_install_has_privacy_and_iso_mappings() {
        let mappings = get_audit_compliance_mappings("not_installed");

        let has = |fw| mappings.iter().any(|m| m.compliance_framework == fw);
        assert!(has(ComplianceFramework::HIPAA), "HIPAA must be present");
        assert!(has(ComplianceFramework::GDPR), "GDPR must be present");
        assert!(
            has(ComplianceFramework::ISO27001),
            "ISO 27001 must be present"
        );

        // ISO logging clause for audit controls.
        let iso = mappings
            .iter()
            .find(|m| m.compliance_framework == ComplianceFramework::ISO27001)
            .unwrap();
        assert_eq!(iso.compliance_control_id, "8.15");

        // HIPAA must include the Audit Controls safeguard.
        assert!(
            mappings
                .iter()
                .any(|m| m.compliance_framework == ComplianceFramework::HIPAA
                    && m.compliance_control_id == "164.312(b)")
        );
    }

    /// The audit-rules bucket additionally maps to ISO 8.16 (monitoring
    /// activities), since live rules actively monitor security events.
    #[test]
    fn audit_rules_map_to_iso_monitoring() {
        let mappings = get_audit_compliance_mappings("rules");
        assert!(
            mappings
                .iter()
                .any(|m| m.compliance_framework == ComplianceFramework::ISO27001
                    && m.compliance_control_id == "8.16"),
            "audit rules must map to ISO 8.16 monitoring activities"
        );
    }

    /// Confirms the SOC 2 mappings: every auditd service-state finding carries
    /// the anomaly-monitoring criterion CC7.2, and the rules bucket adds the
    /// configuration-change detection criterion CC7.1; both filed under the
    /// "System Operations" TSC series.
    #[test]
    fn audit_findings_map_soc2_monitoring_criteria() {
        for finding_type in ["not_installed", "not_running"] {
            let soc2 = get_audit_compliance_mappings(finding_type)
                .into_iter()
                .find(|m| m.compliance_framework == ComplianceFramework::SOC2)
                .unwrap_or_else(|| panic!("{finding_type} must carry a SOC 2 mapping"));
            assert_eq!(soc2.compliance_control_id, "CC7.2");
            assert_eq!(
                soc2.compliance_section.as_deref(),
                Some("System Operations")
            );
        }

        let rule_ids: Vec<String> = get_audit_compliance_mappings("rules")
            .into_iter()
            .filter(|m| m.compliance_framework == ComplianceFramework::SOC2)
            .map(|m| m.compliance_control_id)
            .collect();
        assert!(rule_ids.contains(&"CC7.1".to_string()));
        assert!(rule_ids.contains(&"CC7.2".to_string()));
    }

    /// Confirms the 800-171r3 crosswalk: AU-2 → 3.3.1 for the install check
    /// and AU-12 → 3.3.3 for the service and rules checks, filed under the
    /// official Audit and Accountability family.
    #[test]
    fn audit_findings_map_nist_800_171_requirements() {
        for (finding_type, id) in [
            ("not_installed", "3.3.1"),
            ("not_running", "3.3.3"),
            ("rules", "3.3.3"),
        ] {
            let mapping = get_audit_compliance_mappings(finding_type)
                .into_iter()
                .find(|m| m.compliance_framework == ComplianceFramework::NIST800171)
                .unwrap_or_else(|| panic!("{finding_type} must carry an 800-171 mapping"));
            assert_eq!(mapping.compliance_control_id, id, "{finding_type}");
            assert_eq!(
                mapping.compliance_section.as_deref(),
                Some("Audit and Accountability")
            );
        }
    }

    /// Confirms the FedRAMP derivation: AU-2 and AU-12 are both GSA rev5
    /// Moderate baseline members, so each finding mirrors its existing 800-53
    /// entry verbatim under the Audit and Accountability family.
    #[test]
    fn audit_findings_map_fedramp_moderate_controls() {
        for (finding_type, id) in [
            ("not_installed", "AU-2(a)"),
            ("not_running", "AU-12(c)"),
            ("rules", "AU-12(c)"),
        ] {
            let mapping = get_audit_compliance_mappings(finding_type)
                .into_iter()
                .find(|m| m.compliance_framework == ComplianceFramework::FedRAMP)
                .unwrap_or_else(|| panic!("{finding_type} must carry a FedRAMP mapping"));
            assert_eq!(mapping.compliance_control_id, id, "{finding_type}");
            assert_eq!(
                mapping.compliance_section.as_deref(),
                Some("Audit and Accountability")
            );
        }
    }

    /// When auditctl requires root to list rules, the scan must report each
    /// expected audit rule as unchecked rather than creating false missing-rule
    /// findings.
    #[tokio::test]
    async fn scan_reports_rules_unchecked_when_auditctl_needs_root() {
        use hardener_core::{CommandOutput, MockExecutor};

        // Mock all commands needed for the scan: auditd is present and running,
        // but auditctl requires root to list rules. The audit_rule_* unchecked
        // entries must appear without false missing-rule findings.
        let mock = MockExecutor::new()
            .with_command_exists("auditd", true)
            .with_command(
                "systemctl",
                &["is-enabled", "auditd"],
                CommandOutput {
                    stdout: "enabled\n".to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            )
            .with_command(
                "systemctl",
                &["is-active", "auditd"],
                CommandOutput {
                    stdout: "active\n".to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            )
            .with_command(
                "auditctl",
                &["-l"],
                CommandOutput {
                    stdout: String::new(),
                    stderr: "You must be root to run this program.".to_string(),
                    exit_code: 4,
                },
            );
        let ctx = Context::with_executor(std::sync::Arc::new(mock));
        let result = AuditHardeningPlugin::new()
            .scan(&ctx, &PluginConfig::default())
            .await
            .unwrap();

        assert!(
            !result
                .scan_findings
                .iter()
                .any(|f| f.finding_id.starts_with("audit_rule_")),
            "no false missing-rule findings"
        );
        assert_eq!(result.scan_unchecked.len(), AUDIT_RULES.len());
        assert!(
            result
                .scan_unchecked
                .iter()
                .all(|u| u.unchecked_check_id.starts_with("audit_rule_"))
        );
    }
}
