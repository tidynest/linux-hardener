//! Mandatory Access Control (MAC) hardening plugin
//!
//! This plugin manages SELinux and AppArmor configurations across different
//! Linux distributions, automatically detecting which MAC system is in use.
//!
//! Supported MAC systems:
//! - SELinux (RHEL, Fedora, CentOS, Rocky Linux, AlmaLinux)
//! - AppArmor (Ubuntu, Debian, openSUSE)

mod divergence;

use async_trait::async_trait;
use hardener_common::types::PluginId;
use hardener_common::{
    error::{HardeningError, Result},
    types::{ComplianceFramework, ComplianceMapping, FindingCategory, Severity},
};
use hardener_core::{
    ApplyResult, Change, ChangeType, PluginConfig, ValidationIssue, ValidationReport,
    context::Context,
    plugin::{
        Finding, HardeningPlugin, PluginMetadata, ScanResult, UncheckedBlocker, UncheckedCheck,
    },
};
use std::path::Path;
use std::time::Instant;
use tracing::{info, warn};

/// Represents the type of MAC system detected on the host.
#[derive(Clone, Debug, PartialEq)]
pub enum MacSystem {
    /// AppArmor
    AppArmor,
    /// SELinux (Security-Enhanced Linux)
    SELinux,
}

/// Outcome of probing the host for a MAC system.
///
/// `Absent` and `Indeterminate` are deliberately distinct. Many distributions
/// ship with neither SELinux nor AppArmor, so absence is a normal, reportable
/// state; a failed probe is not, and reporting it as absence turns "we could
/// not look" into "there is nothing there".
#[derive(Clone, Debug, PartialEq)]
enum MacDetection {
    Found(MacSystem),
    Absent,
    Indeterminate(String),
}

/// Where SELinux records the mode it boots into.
const SELINUX_CONFIG_PATH: &str = "/etc/selinux/config";

/// The exception key for a host an operator has approved to run with no
/// mandatory access control system at all.
///
/// The plugin's other two keys, `selinux-enforcing` and `apparmor-enforce`,
/// are written inline at the findings they excuse. This one is a constant
/// because the state it names has no second reading: a host either has a MAC
/// system or it does not.
const MAC_PRESENT_EXCEPTION: &str = "mac-present";

/// What the restored SELinux configuration asks the running system to be.
///
/// Three outcomes, because a rollback that cannot tell them apart acts on a
/// guess: a mode to set, a target that is not an SELinux host at all, and a
/// question that could not be answered.
enum RestoredMode {
    /// The argument `setenforce` takes: `"1"` enforcing, `"0"` permissive.
    Setenforce(&'static str),
    /// No SELinux configuration on the target.
    NotConfigured,
    /// The configuration could not be read, or names no mode.
    Unknown(String),
}

/// The `setenforce` argument a SELinux configuration file asks for.
///
/// The first `SELINUX=` line wins, as it does for SELinux itself. A commented
/// line is skipped by the prefix match alone, since `#SELINUX=` does not start
/// with `SELINUX=`; the explicit comment test this replaces could never change
/// an answer. Anything that is not `enforcing`, which includes `permissive`
/// and `disabled`, maps to permissive: `setenforce` cannot disable SELinux at
/// runtime, so permissive is the closest the running system can be brought to
/// a disabled configuration until it reboots.
fn selinux_mode_argument(content: &str) -> Option<&'static str> {
    content.lines().find_map(|line| {
        let value = line.trim().strip_prefix("SELINUX=")?;
        Some(if value.trim().eq_ignore_ascii_case("enforcing") {
            "1"
        } else {
            "0"
        })
    })
}

/// Main MAC (Mandatory Access Control) hardening plugin.
///
/// Automatically detects whether the system uses AppArmor or SELinux
/// and applies appropriate hardening configurations.
pub struct MacHardeningPlugin {}

impl Default for MacHardeningPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl MacHardeningPlugin {
    pub fn new() -> MacHardeningPlugin {
        MacHardeningPlugin {}
    }

    /// Detects which MAC system is available on this system.
    ///
    /// Detection Logic:
    /// 1. Check for SELinux (/sys/fs/selinux directory exists)
    /// 2. Check for AppArmor (/sys/kernel/security/apparmor directory exists)
    /// 3. Return None if neither is found
    async fn detect_mac_system(&self, ctx: &Context) -> MacDetection {
        for (path, system) in [
            ("/sys/fs/selinux", MacSystem::SELinux),
            ("/sys/kernel/security/apparmor", MacSystem::AppArmor),
        ] {
            match ctx.executor().path_exists(Path::new(path)).await {
                Ok(true) => {
                    info!("Detected MAC system at {}", path);
                    return MacDetection::Found(system);
                }
                Ok(false) => {}
                // A probe that failed proves nothing. Folding it into "not
                // present" is what let a transient failure read as a
                // deliberate no-op on a host that may have a real, and
                // possibly misconfigured, SELinux or AppArmor.
                Err(e) => {
                    warn!("Could not probe {} for a MAC system: {}", path, e);
                    return MacDetection::Indeterminate(format!("probing {path} failed: {e}"));
                }
            }
        }

        info!("No MAC system detected (checked SELinux and AppArmor)");
        MacDetection::Absent
    }

    /// Brings the running MAC system back in line with the configuration a
    /// rollback has just restored, and reports which leg did it.
    ///
    /// Extracted from `rollback` so it can be exercised: `rollback` itself
    /// needs a checkpoint manager before it reaches this point.
    ///
    /// The three outcomes are kept apart because an operator acts on each
    /// differently. `Some(action)` names the leg that ran. `None` is a
    /// deliberate no-op: nothing was asked of the running system, so there is
    /// nothing to report. `Err` is a reload that was attempted and refused,
    /// which means the restored files are on disk while the running policy is
    /// still the one the apply installed. This used to return `()` and fold
    /// every failure into a `warn!`, so the caller reported "MAC policy
    /// reloaded" on a host where neither leg had done anything at all.
    async fn reload_mac_system(&self, ctx: &Context) -> Result<Option<String>> {
        let mode = match self.restored_selinux_mode(ctx).await {
            RestoredMode::Setenforce(mode) => Some(mode),
            RestoredMode::NotConfigured => None,
            // A mode nobody could read is not a mode to restore. Forcing one
            // would be this rollback deciding the host's security posture on a
            // guess, and the file it just restored already governs the next
            // boot either way. Nothing was run, so nothing is claimed.
            RestoredMode::Unknown(reason) => {
                warn!(
                    "Could not determine the SELinux mode to restore from {}: {}. \
                     Leaving the running mode alone; the restored file governs the next boot",
                    SELINUX_CONFIG_PATH, reason
                );
                return Ok(None);
            }
        };

        // Carried rather than logged and dropped. When the AppArmor leg fails
        // too, the error the caller raises has to say what was tried first,
        // otherwise a SELinux host's diagnosis reads as a missing AppArmor
        // unit and points at the wrong subsystem entirely.
        let mut setenforce_failure = None;
        if let Some(mode) = mode {
            match ctx.executor().execute_command("setenforce", &[mode]).await {
                Ok(output) if output.success() => {
                    info!("SELinux runtime mode restored (setenforce {})", mode);
                    return Ok(Some(format!(
                        "SELinux runtime mode restored (setenforce {mode})"
                    )));
                }
                // execute_command returns Ok for a command that ran and failed,
                // so the status has to be read. `setenforce: SELinux is
                // disabled` used to be logged as a policy reload.
                Ok(output) => {
                    setenforce_failure = Some(format!(
                        "setenforce {mode} exited {}: {}",
                        output.exit_code,
                        output.stderr.trim()
                    ));
                }
                Err(e) => setenforce_failure = Some(format!("could not run setenforce: {e}")),
            }
            if let Some(reason) = &setenforce_failure {
                warn!("{reason}");
            }
        }

        // Reached when the target carries no SELinux configuration, which is
        // what an AppArmor host looks like, and when setenforce did not do what
        // it was asked.
        let apparmor_failure = match ctx
            .executor()
            .execute_command("systemctl", &["reload", "apparmor"])
            .await
        {
            Ok(output) if output.success() => {
                info!("AppArmor profiles reloaded");
                None
            }
            Ok(output) => Some(format!(
                "systemctl reload apparmor exited {}: {}",
                output.exit_code,
                output.stderr.trim()
            )),
            Err(e) => Some(format!("could not run systemctl reload apparmor: {e}")),
        };

        // A setenforce that ran and was refused is not undone by AppArmor
        // reloading cleanly straight after: the restored SELINUX_CONFIG_PATH
        // named a mode, and that mode is still not the one running. Reporting
        // `Ok(Some("AppArmor profiles reloaded"))` here would be the same
        // sentinel conflation this function exists to close, only moved one
        // branch over: one field standing for two legs' outcomes, with the
        // AppArmor success overwriting the SELinux failure instead of a
        // missing SELinux config overwriting an AppArmor one. Both legs'
        // reasons are named, because a SELinux host diagnosed on the
        // AppArmor text alone points at the wrong subsystem, and the AppArmor
        // success (when there was one) is named too so an operator does not
        // read a real reload as if it never happened.
        match (setenforce_failure, apparmor_failure) {
            (None, None) => Ok(Some("AppArmor profiles reloaded".to_string())),
            (None, Some(reason)) => Err(HardeningError::Plugin(format!(
                "Could not reload the MAC system: {reason}"
            ))),
            (Some(reason), None) => Err(HardeningError::Plugin(format!(
                "Could not reload the MAC system: {reason} (AppArmor profiles were reloaded, but \
                 that does not restore SELinux's runtime mode)"
            ))),
            (Some(selinux_reason), Some(apparmor_reason)) => Err(HardeningError::Plugin(format!(
                "Could not reload the MAC system: {selinux_reason}; {apparmor_reason}"
            ))),
        }
    }

    /// The mode the restored [`SELINUX_CONFIG_PATH`] asks for, read from the
    /// host being rolled back.
    ///
    /// Through the executor, like every other file operation in `rollback`. It
    /// used to be a bare `std::fs` read, so rolling a remote host back restored
    /// that host's files and then consulted the **controller's** configuration
    /// to decide what mode to put the target in.
    async fn restored_selinux_mode(&self, ctx: &Context) -> RestoredMode {
        let path = Path::new(SELINUX_CONFIG_PATH);
        let content = match ctx.executor().read_file(path).await {
            Ok(content) => content,
            Err(e) => {
                // Absence confirmed at the target means it is not an SELinux
                // host. Any other failure means the answer is unknown, and the
                // two must not share one outcome.
                return match ctx.executor().path_exists(path).await {
                    Ok(false) => RestoredMode::NotConfigured,
                    _ => RestoredMode::Unknown(e.to_string()),
                };
            }
        };

        match selinux_mode_argument(&content) {
            Some(mode) => RestoredMode::Setenforce(mode),
            // The file exists, so this is an SELinux host, but it names no
            // mode. Unknown rather than absent, for the same reason.
            None => {
                RestoredMode::Unknown(format!("no SELINUX= directive in {SELINUX_CONFIG_PATH}"))
            }
        }
    }

    /// Checks if SELinux is enabled and gets its current mode.
    ///
    /// Returns one of: "Enforcing", "Permissive", or "Disabled"
    async fn get_selinux_mode(&self, ctx: &Context) -> Result<String> {
        let output = ctx
            .executor()
            .execute_command("getenforce", &[])
            .await
            .map_err(|e| HardeningError::Plugin(format!("Failed to execute getenforce: {}", e)))?;

        if !output.success() {
            return Err(HardeningError::Plugin(
                "getenforce command failed".to_string(),
            ));
        }

        let mode = output.stdout.trim().to_string();

        Ok(mode)
    }

    /// Sets SELinux to enforcing mode (requires root).
    async fn set_selinux_enforcing(&self, ctx: &Context) -> Result<Change> {
        let current_mode = self.get_selinux_mode(ctx).await?;

        if current_mode == "Enforcing" {
            return Ok(Change {
                change_description: "SELinux already in enforcing mode".to_string(),
                change_type: ChangeType::Skipped,
                change_success: true,
                change_error: None,
            });
        }

        // Set to enforcing mode
        let output = ctx
            .executor()
            .execute_command("setenforce", &["1"])
            .await
            .map_err(|e| HardeningError::Plugin(format!("Failed to execute setenforce: {}", e)))?;

        if output.success() {
            Ok(Change {
                change_description: format!("Set SELinux mode from {} to Enforcing", current_mode),
                change_type: ChangeType::ConfigFile,
                change_success: true,
                change_error: None,
            })
        } else {
            Ok(Change {
                change_description: "Failed to set SELinux to enforcing mode".to_string(),
                change_type: ChangeType::ConfigFile,
                change_success: false,
                change_error: Some(output.stderr),
            })
        }
    }

    /// Probes AppArmor profile status via `aa-status --verbose` and
    /// classifies the outcome.
    ///
    /// `aa-status` exits non-zero both when AppArmor is not installed and
    /// when it is installed but the caller lacks the privilege to read
    /// profile state, so the raw stderr is classified before either case is
    /// treated as "no MAC in effect" (see [`ApparmorProbe`]).
    async fn probe_apparmor(&self, ctx: &Context) -> ApparmorProbe {
        let output = match ctx
            .executor()
            .execute_command("aa-status", &["--verbose"])
            .await
        {
            Ok(output) => output,
            Err(_) => return ApparmorProbe::Unavailable,
        };

        if !output.success() {
            return if hardener_common::error::message_indicates_permission_denied(&output.stderr) {
                ApparmorProbe::PermissionDenied
            } else {
                ApparmorProbe::Unavailable
            };
        }

        let mut enforce_count = 0;
        let mut complain_count = 0;

        // Parse the aa-status output
        for line in output.stdout.trim().lines() {
            if line.contains("profiles are in enforce mode") {
                // Extract number from line like "   37 profiles are in enforce mode."
                if let Some(num_str) = line.split_whitespace().next() {
                    enforce_count = num_str.parse().unwrap_or(0);
                }
            } else if line.contains("profiles are in complain mode")
                && let Some(num_str) = line.split_whitespace().next()
            {
                complain_count = num_str.parse().unwrap_or(0);
            }
        }

        let total_loaded = enforce_count + complain_count;
        ApparmorProbe::Profiles(enforce_count, complain_count, total_loaded)
    }
}

/// Outcome of [`MacHardeningPlugin::probe_apparmor`].
enum ApparmorProbe {
    /// Profile counts: (enforce_count, complain_count, total_loaded).
    Profiles(usize, usize, usize),
    /// `aa-status` is present but the current privilege level cannot read
    /// profile state. Distinct from [`Self::Unavailable`] so a hardened,
    /// unprivileged scan is never reported as "no AppArmor profiles".
    PermissionDenied,
    /// `aa-status` could not be executed, or failed for a reason other than
    /// privilege (most commonly: AppArmor is not installed).
    Unavailable,
}

/// Returns compliance mappings for MAC findings.
///
/// Multi-framework mappings are sourced from ComplianceAsCode/SSG rule
/// `references:` blocks (see `// SSG:` comments). NIST IDs are 800-53 Rev 5;
/// STIG IDs are the SSG-declared RHEL-family `stigid@ol8` values (the Oracle
/// Linux 8 STIG mirrors the RHEL 8 STIG content). NIST `AC-3` (access
/// enforcement) is the controlling MAC family in `selinux_state` and applies
/// equally to the AppArmor and "no MAC" findings, which are the same control
/// expressed for a different implementation. STIG and PCI-DSS are omitted for
/// the AppArmor and "no-mac-system" findings: the relevant SSG rules
/// (`all_apparmor_profiles_enforced`, `package_apparmor_installed`) declare no
/// `stigid@`/`pcidss`, and `selinux_state` itself declares no `pcidss`.
/// Finding types the MAC plugin can raise: the keys understood by
/// [`get_mac_compliance_mappings`]. Keep in sync with that match.
const MAC_FINDING_TYPES: &[&str] = &[
    "no-mac-system",
    "selinux-not-enforcing",
    "apparmor-complain-mode",
    "apparmor-no-profiles",
];

/// Every compliance mapping this plugin can emit, across all finding types it
/// raises. Aggregated into the engine's automated-coverage set.
pub fn coverage() -> Vec<ComplianceMapping> {
    MAC_FINDING_TYPES
        .iter()
        .flat_map(|&t| get_mac_compliance_mappings(t))
        .collect()
}

/// Builds a SOC 2 mapping. `id` is a 2017 Trust Services Criteria common
/// criterion (e.g. `CC6.8`); `title` tracks the published criterion text. The
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
/// number (e.g. `3.1.2`); `title` the published requirement name; the
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

/// Returns compliance mappings for a given MAC finding type.
fn get_mac_compliance_mappings(finding_type: &str) -> Vec<ComplianceMapping> {
    match finding_type {
        // SSG: package_apparmor_installed / package_selinux (CIS only); MAC absence
        // maps to NIST AC-3 access enforcement (per selinux_state).
        "no-mac-system" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "1.6.1.1".to_string(),
                compliance_control_title: "Ensure SELinux or AppArmor is installed".to_string(),
                compliance_section: Some("Mandatory Access Control".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::NIST,
                compliance_control_id: "AC-3".to_string(),
                compliance_control_title: "Access Enforcement".to_string(),
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
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-SH".to_string(),
                compliance_control_title: "System Hardening".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.3".to_string(),
                compliance_control_title: "Information access restriction".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "5.15".to_string(),
                compliance_control_title: "Access control".to_string(),
                compliance_section: Some("Organizational".to_string()),
            },
            // SOC 2: CC6.8 mirrors the AC-3 enforcement intent expressed as MAC
            // confinement: enforced policy contains unauthorised software activity.
            soc2(
                "CC6.8",
                "Prevent or detect the introduction of unauthorized or malicious software",
            ),
            // 800-171r3 3.1.2 ← 800-53 AC-3 (SP 800-171r3 source-control table).
            nist171("3.1.2", "Access Enforcement"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 AC-3.
            fedramp("AC-3", "Access Enforcement"),
        ],
        // SSG: selinux_state (nist: AC-3,AC-3(3)(a),AU-9,SC-7(21); stigid@ol8: OL08-00-010170)
        "selinux-not-enforcing" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "1.6.1.4".to_string(),
                compliance_control_title:
                    "Ensure the SELinux mode is enforcing or AppArmor is enabled".to_string(),
                compliance_section: Some("Mandatory Access Control".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::NIST,
                compliance_control_id: "AC-3".to_string(),
                compliance_control_title: "Access Enforcement".to_string(),
                compliance_section: Some("Access Control".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::STIG,
                compliance_control_id: "OL08-00-010170".to_string(),
                compliance_control_title: "SELinux must be in enforcing mode".to_string(),
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
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-SH".to_string(),
                compliance_control_title: "System Hardening".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.3".to_string(),
                compliance_control_title: "Information access restriction".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "5.15".to_string(),
                compliance_control_title: "Access control".to_string(),
                compliance_section: Some("Organizational".to_string()),
            },
            // SOC 2: CC6.8 mirrors the AC-3 enforcement intent expressed as MAC
            // confinement: enforced policy contains unauthorised software activity.
            soc2(
                "CC6.8",
                "Prevent or detect the introduction of unauthorized or malicious software",
            ),
            // 800-171r3 3.1.2 ← 800-53 AC-3 (SP 800-171r3 source-control table).
            nist171("3.1.2", "Access Enforcement"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 AC-3.
            fedramp("AC-3", "Access Enforcement"),
        ],
        // SSG: all_apparmor_profiles_enforced (CIS only). NIST AC-3 access
        // enforcement applies; this is the AppArmor expression of the same
        // MAC-not-enforced control as selinux-not-enforcing.
        "apparmor-complain-mode" | "apparmor-no-profiles" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "1.6.1.4".to_string(),
                compliance_control_title:
                    "Ensure the SELinux mode is enforcing or AppArmor is enabled".to_string(),
                compliance_section: Some("Mandatory Access Control".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::NIST,
                compliance_control_id: "AC-3".to_string(),
                compliance_control_title: "Access Enforcement".to_string(),
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
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-SH".to_string(),
                compliance_control_title: "System Hardening".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.3".to_string(),
                compliance_control_title: "Information access restriction".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "5.15".to_string(),
                compliance_control_title: "Access control".to_string(),
                compliance_section: Some("Organizational".to_string()),
            },
            // SOC 2: CC6.8 mirrors the AC-3 enforcement intent expressed as MAC
            // confinement: enforced policy contains unauthorised software activity.
            soc2(
                "CC6.8",
                "Prevent or detect the introduction of unauthorized or malicious software",
            ),
            // 800-171r3 3.1.2 ← 800-53 AC-3 (SP 800-171r3 source-control table).
            nist171("3.1.2", "Access Enforcement"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 AC-3.
            fedramp("AC-3", "Access Enforcement"),
        ],
        _ => vec![],
    }
}

#[async_trait]
impl HardeningPlugin for MacHardeningPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            plugin_category: FindingCategory::Kernel,
            plugin_description: "Manages SELinux and AppArmor MAC system configuration".to_string(),
            plugin_id: PluginId::new("mac-hardening"),
            plugin_name: "MAC System Hardening".to_string(),
            plugin_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    fn dependencies(&self) -> Vec<PluginId> {
        // MAC hardening has no dependencies
        vec![]
    }

    async fn scan(&self, ctx: &Context, config: &PluginConfig) -> Result<ScanResult> {
        let start_time = Instant::now();
        let plugin_id = PluginId::new("mac-hardening");
        let mut findings = Vec::new();
        let mut unchecked = Vec::new();

        // Detect which MAC system is present
        match self.detect_mac_system(ctx).await {
            MacDetection::Found(MacSystem::SELinux) => {
                // Check SELinux mode
                match self.get_selinux_mode(ctx).await {
                    Ok(mode) => {
                        if mode != "Enforcing" {
                            findings.push(Finding {
                                finding_category:          FindingCategory::Kernel,
                                finding_current_value:     mode.clone(),
                                finding_description:       "SELinux is not in enforcing mode".to_string(),
                                finding_explanation:       "SELinux should be in enforcing mode to actively prevent security violations".to_string(),
                                finding_id:                "selinux-not-enforcing".to_string(),
                                finding_impact:            "Security policies are not being enforced".to_string(),
                                finding_recommended_value: "Enforcing".to_string(),
                                finding_remediation_steps: vec![
                                    "Run: setenforce 1".to_string(),
                                    "Edit /etc/selinux/config and set SELINUX=enforcing".to_string(),
                                ],
                                finding_severity: Severity::High,
                                finding_title:    "SELinux Not Enforcing".to_string(),
                                finding_compliance: get_mac_compliance_mappings("selinux-not-enforcing"),
                                finding_exception: config
                                    .exception_outcome_for_presence("selinux-enforcing"),
                                finding_exception_key: Some("selinux-enforcing".to_string()),
                            });
                        }
                    }
                    Err(e) => {
                        warn!("Failed to check SELinux mode: {}", e);
                    }
                }
            }
            MacDetection::Found(MacSystem::AppArmor) => {
                // Check AppArmor profile status
                match self.probe_apparmor(ctx).await {
                    ApparmorProbe::Profiles(_enforce_count, complain_count, total_loaded) => {
                        if complain_count > 0 {
                            findings.push(Finding {
                                finding_category: FindingCategory::Kernel,
                                finding_current_value: format!("{} profiles in complain mode", complain_count),
                                finding_description: "Some AppArmor profiles are in complain mode".to_string(),
                                finding_explanation: "Profiles in complain mode only log violations instead of blocking them".to_string(),
                                finding_id: "apparmor-complain-mode".to_string(),
                                finding_impact: "Security policies are not being enforced for some applications".to_string(),
                                finding_recommended_value: "All profiles in enforce mode".to_string(),
                                finding_remediation_steps: vec![
                                    format!("Review {} profiles in complain mode", complain_count),
                                    "Use aa-enforce to set profiles to enforce mode".to_string(),
                                ],
                                finding_severity: Severity::Medium,
                                finding_title: "AppArmor Profiles in Complain Mode".to_string(),
                                finding_compliance: get_mac_compliance_mappings("apparmor-complain-mode"),
                                finding_exception: config
                                    .exception_outcome_for_presence("apparmor-enforce"),
                                finding_exception_key: Some("apparmor-enforce".to_string()),
                            });
                        }

                        if total_loaded == 0 {
                            findings.push(Finding {
                                finding_category: FindingCategory::Kernel,
                                finding_current_value: "0 profiles loaded".to_string(),
                                finding_description: "No AppArmor profiles are loaded".to_string(),
                                finding_explanation:
                                    "AppArmor is installed but no profiles are active".to_string(),
                                finding_id: "apparmor-no-profiles".to_string(),
                                finding_impact: "No application confinement is in effect"
                                    .to_string(),
                                finding_recommended_value: "Load AppArmor profiles".to_string(),
                                finding_remediation_steps: vec![
                                    "Install apparmor-profiles package".to_string(),
                                    "Enable AppArmor service".to_string(),
                                ],
                                finding_severity: Severity::High,
                                finding_title: "No AppArmor Profiles Loaded".to_string(),
                                finding_compliance: get_mac_compliance_mappings(
                                    "apparmor-no-profiles",
                                ),
                                finding_exception: config
                                    .exception_outcome_for_presence("apparmor-enforce"),
                                finding_exception_key: Some("apparmor-enforce".to_string()),
                            });
                        }
                    }
                    ApparmorProbe::PermissionDenied => {
                        warn!(
                            "aa-status requires elevated privileges to read AppArmor profile state"
                        );
                        // aa-status ran and refused for lack of privilege, so
                        // AppArmor is genuinely installed: a root-only probe
                        // must not read as "no profiles loaded". Its having run
                        // is the whole proof, so nothing is asked a second
                        // time; an existence probe here could only contradict
                        // it, and a contradiction used to delete the gap.
                        let blocker = crate::refusal_blocker(ctx).await;
                        unchecked.push(UncheckedCheck {
                            unchecked_check_id: "apparmor-no-profiles".to_string(),
                            unchecked_title: "AppArmor profile enforcement".to_string(),
                            unchecked_category: FindingCategory::Kernel,
                            unchecked_reason:
                                "reading the AppArmor profile set (aa-status) requires root"
                                    .to_string(),
                            unchecked_blocker: blocker,
                            unchecked_compliance: get_mac_compliance_mappings(
                                "apparmor-no-profiles",
                            ),
                        });
                    }
                    ApparmorProbe::Unavailable => {
                        warn!("Failed to check AppArmor status: aa-status unavailable");
                    }
                }
            }
            // The probe failed, so absence is not a fact this scan can assert.
            // Reported unchecked rather than as a "no MAC system" finding, so
            // the covered controls reach manual review instead of resting on
            // a conclusion nothing supports.
            MacDetection::Indeterminate(reason) => {
                unchecked.push(UncheckedCheck {
                    unchecked_check_id: "no-mac-system".to_string(),
                    unchecked_title: "MAC system presence".to_string(),
                    unchecked_category: FindingCategory::Kernel,
                    unchecked_reason: format!(
                        "could not determine whether a MAC system is present: {reason}"
                    ),
                    // The probe failed and its reason is prose. Whether root
                    // would have got an answer is exactly what is not known.
                    unchecked_blocker: UncheckedBlocker::Unknown,
                    unchecked_compliance: get_mac_compliance_mappings("no-mac-system"),
                });
            }
            MacDetection::Absent => {
                // No MAC system detected
                findings.push(Finding {
                    finding_category: FindingCategory::Kernel,
                    finding_current_value: "None".to_string(),
                    finding_description: "No MAC system detected on this system".to_string(),
                    finding_explanation: "Neither SELinux nor AppArmor is available. Consider enabling one for enhanced security.".to_string(),
                    finding_id: "no-mac-system".to_string(),
                    finding_impact: "Missing kernel-level mandatory access controls".to_string(),
                    finding_recommended_value: "SELinux or AppArmor enabled".to_string(),
                    finding_remediation_steps: vec![
                        "Install and enable AppArmor (Ubuntu/Debian) or SELinux (RHEL/Fedora)".to_string(),
                    ],
                    finding_severity: Severity::Medium,
                    finding_title: "No MAC System Found".to_string(),
                    finding_compliance: get_mac_compliance_mappings("no-mac-system"),
                    // The third subsystem key, beside `selinux-enforcing` and
                    // `apparmor-enforce`: those two accept a MAC system that
                    // is present and not enforcing, and neither can speak for
                    // a host that has no MAC system to enforce anything.
                    finding_exception: config.exception_outcome_for_presence(MAC_PRESENT_EXCEPTION),
                    finding_exception_key: Some(MAC_PRESENT_EXCEPTION.to_string()),
                });
            }
        }

        let duration_us = start_time.elapsed().as_micros() as u64;
        Ok(ScanResult {
            scan_plugin_id: plugin_id,
            scan_success: true,
            scan_findings: findings,
            scan_unchecked: unchecked,
            scan_duration_us: duration_us,
            scan_error: None,
        })
    }

    async fn apply(&self, ctx: &mut Context, config: &PluginConfig) -> Result<ApplyResult> {
        let apply_plugin_id = PluginId::new("mac-hardening");
        let mut apply_changes = Vec::new();

        // Create checkpoint for MAC config files
        let mac_paths: Vec<&Path> = vec![
            Path::new(SELINUX_CONFIG_PATH),
            Path::new("/etc/apparmor"),
            Path::new("/etc/apparmor.d"),
        ];
        let checkpoint_id =
            crate::create_checkpoint_for_apply(ctx, "mac-hardening-pre-apply", &mac_paths).await?;

        apply_changes.extend(crate::checkpoint_change(&checkpoint_id));

        // Detect which MAC system is present
        match self.detect_mac_system(ctx).await {
            MacDetection::Found(MacSystem::SELinux) => {
                // Check for exception before enforcing
                if let Some(exception) = config.has_valid_exception("selinux-enforcing") {
                    info!(
                        "Skipping SELinux enforcement (exception: {})",
                        exception.reason
                    );
                    apply_changes.push(Change {
                        change_description: format!(
                            "SELinux enforcement: skipped (exception: {})",
                            exception.reason
                        ),
                        change_type: ChangeType::Skipped,
                        change_success: true,
                        change_error: None,
                    });
                } else {
                    // Try to set SELinux to enforcing mode
                    match self.set_selinux_enforcing(ctx).await {
                        Ok(change) => {
                            apply_changes.push(change);
                        }
                        Err(e) => {
                            return Ok(ApplyResult {
                                apply_plugin_id,
                                apply_success: false,
                                apply_changes,
                                apply_checkpoint_id: checkpoint_id,
                                apply_error: Some(format!(
                                    "Failed to set SELinux enforcing: {}",
                                    e
                                )),
                            });
                        }
                    }
                }
            }
            MacDetection::Found(MacSystem::AppArmor) => {
                // Check for exception before AppArmor enforcement guidance
                if let Some(exception) = config.has_valid_exception("apparmor-enforce") {
                    info!(
                        "Skipping AppArmor enforcement (exception: {})",
                        exception.reason
                    );
                    apply_changes.push(Change {
                        change_description: format!(
                            "AppArmor enforcement: skipped (exception: {})",
                            exception.reason
                        ),
                        change_type: ChangeType::Skipped,
                        change_success: true,
                        change_error: None,
                    });
                } else {
                    // Advisory only: apply does not touch the host, so this
                    // must not inflate the "N change(s) applied" count (see
                    // ChangeType::Skipped).
                    apply_changes.push(Change {
                        change_description: "AppArmor detected - use aa-enforce to set specific profiles to enforce mode"
                            .to_string(),
                        change_type: ChangeType::Skipped,
                        change_success: true,
                        change_error: None,
                    });
                }
            }
            // A failed probe is not a clean no-op. Recording it as a
            // successful skip told the operator this host needs no MAC
            // configuration, on a host that may have a real and
            // misconfigured SELinux or AppArmor nobody managed to look at.
            MacDetection::Indeterminate(reason) => {
                warn!("Could not determine the MAC system: {}", reason);
                apply_changes.push(Change {
                    change_description:
                        "Could not determine whether a MAC system is present - nothing was changed"
                            .to_string(),
                    change_type: ChangeType::ConfigFile,
                    change_success: false,
                    change_error: Some(reason),
                });
            }
            MacDetection::Absent => {
                // Many distributions ship without SELinux or AppArmor; an
                // absent MAC system is a normal state, not a plugin failure.
                info!("No MAC system detected - nothing to apply");
                apply_changes.push(Change {
                    change_description: "No MAC system detected - nothing to configure (skipped)"
                        .to_string(),
                    change_type: ChangeType::Skipped,
                    change_success: true,
                    change_error: None,
                });
            }
        }

        let apply_success = apply_changes.iter().all(|c| c.change_success);

        Ok(ApplyResult {
            apply_plugin_id,
            apply_success,
            apply_changes,
            apply_checkpoint_id: checkpoint_id,
            apply_error: None,
        })
    }

    fn reloads_for_path(&self, path: &Path) -> bool {
        // `Path::starts_with` compares whole components, so `/etc/apparmor`
        // does not match `/etc/apparmor.d`: both are checkpointed as their
        // own paths (see the `mac_paths` built in `apply`), so both prefixes
        // are named here.
        path.starts_with("/etc/selinux")
            || path.starts_with("/etc/apparmor")
            || path.starts_with("/etc/apparmor.d")
    }

    /// One `Unverifiable` row, always, on every host the suite can build.
    ///
    /// Deliberately not gated on `restored`: the two plugins this probe most
    /// resembles gate themselves because they would otherwise raise a false
    /// alarm, and a row that claims nothing cannot raise one. A rollback that
    /// restored nothing MAC-related still leaves an operator unable to say
    /// what the kernel is enforcing, which is the thing being reported.
    async fn divergences_after_rollback(
        &self,
        ctx: &Context,
        _restored: &[std::path::PathBuf],
    ) -> Vec<hardener_types::RollbackDivergence> {
        divergence::mac_divergences(self, ctx).await
    }

    async fn reload_after_rollback(&self, ctx: &Context) -> Result<Option<String>> {
        // A host that carries neither SELinux nor AppArmor has nothing this
        // rollback could have reloaded; reporting a reload there is claiming
        // an action nobody took. An indeterminate probe is left alone -
        // reload_mac_system already tries setenforce and, failing that, the
        // AppArmor reload, so this still attempts what it always attempted
        // when the answer is merely unknown rather than confirmed absent.
        if matches!(self.detect_mac_system(ctx).await, MacDetection::Absent) {
            return Ok(None);
        }

        // Reported exactly as `reload_mac_system` found it: the leg that ran,
        // no row where nothing was asked of the host, and an error where a
        // reload was attempted and refused.
        self.reload_mac_system(ctx).await
    }

    async fn validate(&self, ctx: &Context, config: &PluginConfig) -> Result<ValidationReport> {
        let validation_plugin_id = PluginId::new("mac-hardening");
        let mut issues = Vec::new();
        let mut estimated_changes = Vec::new();
        // Excepted settings are recorded rather than dropped: a preview that
        // omits them shows a documented deviation as nothing at all.
        let mut exceptions: Vec<String> = Vec::new();

        // Detect which MAC system is present
        match self.detect_mac_system(ctx).await {
            MacDetection::Found(MacSystem::SELinux) => {
                // An excepted enforcement mode is recorded rather than skipped
                // silently, so the preview cannot render a documented
                // deviation as an empty panel.
                if let Some(exception) = config.has_valid_exception("selinux-enforcing") {
                    exceptions.push(hardener_common::types::exception_preview_line(
                        "selinux-enforcing",
                        hardener_common::types::EXCEPTION_OBSERVED_UNCHANGED,
                        &exception.reason,
                    ));
                } else {
                    match self.get_selinux_mode(ctx).await {
                        Ok(mode) => {
                            if mode != "Enforcing" {
                                estimated_changes.push("Set SELinux to enforcing mode".to_string());
                            }
                        }
                        Err(_) => {
                            issues.push(ValidationIssue {
                                validation_issue_severity: Severity::High,
                                validation_issue_message:
                                    "Cannot read SELinux status - getenforce may not be available"
                                        .to_string(),
                                validation_issue_config_key: Some("selinux.mode".to_string()),
                            });
                        }
                    }
                }
            }
            // The suggested collapse into a match guard breaks exhaustiveness
            // here (guarded arms do not count as covering their pattern), so
            // the nested `if` stays.
            #[allow(clippy::collapsible_match)]
            MacDetection::Found(MacSystem::AppArmor) => {
                if let Some(exception) = config.has_valid_exception("apparmor-enforce") {
                    exceptions.push(hardener_common::types::exception_preview_line(
                        "apparmor-enforce",
                        hardener_common::types::EXCEPTION_OBSERVED_UNCHANGED,
                        &exception.reason,
                    ));
                }
                // Skip if AppArmor enforcement is excepted
                if config.has_valid_exception("apparmor-enforce").is_none()
                    && matches!(
                        self.probe_apparmor(ctx).await,
                        ApparmorProbe::Unavailable | ApparmorProbe::PermissionDenied
                    )
                {
                    issues.push(ValidationIssue {
                        validation_issue_severity: Severity::High,
                        validation_issue_message:
                            "Cannot read AppArmor status - aa-status may not be available"
                                .to_string(),
                        validation_issue_config_key: Some("apparmor.status".to_string()),
                    });
                }
            }
            // Apply will refuse to conclude anything here, so the dry run has
            // to say so rather than present an empty, reassuring preview.
            MacDetection::Indeterminate(reason) => {
                issues.push(ValidationIssue {
                    validation_issue_severity: Severity::High,
                    validation_issue_message: format!(
                        "Cannot determine whether a MAC system is present: {reason}"
                    ),
                    validation_issue_config_key: Some("mac.system".to_string()),
                });
            }
            MacDetection::Absent => {
                // No MAC system - this is expected on some distributions.
                // Apply will record a skip, not a change, so the preview
                // must not list it as one either (see ChangeType::Skipped).
            }
        }

        let is_valid = issues.is_empty();

        Ok(ValidationReport {
            validation_report_plugin_id: validation_plugin_id,
            validation_report_is_valid: is_valid,
            validation_report_issues: issues,
            validation_report_estimated_changes: estimated_changes,
            validation_report_compliant_count: 0,
            validation_report_exceptions: exceptions,
        })
    }
}

#[cfg(test)]
mod tests;
