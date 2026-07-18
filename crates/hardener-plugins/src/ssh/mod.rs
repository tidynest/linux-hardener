//! SSH hardening plugin for OpenSSH server configuration management
//!
//! This plugin scans, applies and manages OpenSSH server security settings.
//! It focuses on critical authentication and protocol security including:
//! - Disabling root login
//! - Enforcing key-based authentication
//! - Restricting to strong cryptographic algorithms
//! - Limiting authentication attempts.
//!
//! The plugin reads the sshd_config file, compares against secure baselines,
//! and can apply hardening configurations with automatic backup support.

use async_trait::async_trait;
use chrono::Utc;
use hardener_common::{
    error::Result,
    file_utils::{ConfigFormat, parse_config_value, set_config_directive},
    types::{ComplianceFramework, ComplianceMapping, FindingCategory, PluginId, Severity},
};
use hardener_core::{
    ApplyResult, Change, ChangeType, Checkpoint, PluginConfig, ValidationIssue, ValidationReport,
    context::Context,
    plugin::{Finding, HardeningPlugin, PluginMetadata, ScanResult},
};
use std::{path::Path, time::Instant};
use tracing::{error, info, warn};

/// Represents a single SSH configuration directive to be hardened.
#[derive(Clone, Debug)]
struct SshConfigDirective {
    /// Human-readable finding_description of this directive's security purpose.
    ssh_description: &'static str,
    /// The directive name as it appears in sshd_config (e.g., "PermitRootLogin").
    ssh_directive_name: &'static str,
    /// The secure value for this directive (e.g., "no").
    ssh_secure_value: &'static str,
    /// Severity level if this directive is not set securely.
    ssh_severity: Severity,
}

/// Critical SSH config directives for security hardening.
///
/// These represent the minimum baseline for secure SSH configuration.
const SSH_DIRECTIVES: &[SshConfigDirective] = &[
    SshConfigDirective {
        ssh_directive_name: "PermitRootLogin",
        ssh_secure_value: "no",
        ssh_description: "Disable direct root login via SSH",
        ssh_severity: Severity::Critical,
    },
    SshConfigDirective {
        ssh_directive_name: "PasswordAuthentication",
        ssh_secure_value: "no",
        ssh_description: "Require key-based authentication only",
        ssh_severity: Severity::Critical,
    },
    SshConfigDirective {
        ssh_directive_name: "PermitEmptyPasswords",
        ssh_secure_value: "no",
        ssh_description: "Disallow empty passwords",
        ssh_severity: Severity::Critical,
    },
    SshConfigDirective {
        ssh_directive_name: "MaxAuthTries",
        ssh_secure_value: "3",
        ssh_description: "Limit authentication attempts to prevent brute force",
        ssh_severity: Severity::Medium,
    },
    SshConfigDirective {
        ssh_directive_name: "X11Forwarding",
        ssh_secure_value: "no",
        ssh_description: "Disable X11 forwarding to reduce attack surface",
        ssh_severity: Severity::Medium,
    },
    SshConfigDirective {
        ssh_directive_name: "ClientAliveInterval",
        ssh_secure_value: "300",
        ssh_description: "Disconnect idle SSH sessions after 5 minutes",
        ssh_severity: Severity::Low,
    },
    SshConfigDirective {
        ssh_directive_name: "ClientAliveCountMax",
        ssh_secure_value: "2",
        ssh_description: "Maximum idle connection checks before disconnect",
        ssh_severity: Severity::Low,
    },
];

/// A single cryptographic-algorithm directive (KexAlgorithms / Ciphers / MACs).
///
/// Unlike [`SshConfigDirective`], these have no fixed secure value: the value is
/// computed at apply time as the intersection of [`Self::crypto_desired`] (a
/// hardcoded strong allow-list) with the algorithms the local sshd actually
/// supports (queried via `ssh -Q`). This guarantees we never emit an algorithm
/// the host cannot parse, which would make `sshd` refuse to start (lockout).
#[derive(Clone, Debug)]
struct SshCryptoDirective {
    /// The directive name as it appears in sshd_config.
    crypto_directive_name: &'static str,
    /// The argument passed to `ssh -Q` to enumerate host-supported algorithms.
    crypto_query_arg: &'static str,
    /// Strong, modern allow-list in preference order. The emitted value is
    /// always a subset of this list, so a downgrade can never be produced.
    crypto_desired: &'static [&'static str],
    /// Human-readable purpose for findings/changes.
    crypto_description: &'static str,
    /// Severity if the directive is unset or contains weak algorithms.
    crypto_severity: Severity,
}

/// Strong key-exchange algorithms (post-quantum + curve25519 + large MODP DH).
///
/// Source: OpenSSH 10 defaults and Mozilla "Modern" SSH guidance. PQ hybrids
/// first, then curve25519, then SHA-512 group16/18 as a fallback for hosts that
/// lack the newer KEX. No SHA-1, no group14, no GSSAPI.
const SSH_DESIRED_KEX: &[&str] = &[
    "mlkem768x25519-sha256",
    "sntrup761x25519-sha512",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
];

/// Strong ciphers (AEAD only): ChaCha20-Poly1305 and AES-GCM.
const SSH_DESIRED_CIPHERS: &[&str] = &[
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
];

/// Strong MACs (encrypt-then-MAC only). Only relevant for non-AEAD ciphers,
/// but set explicitly so a weak MAC can never be negotiated.
const SSH_DESIRED_MACS: &[&str] = &[
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "umac-128-etm@openssh.com",
];

/// Cryptographic directives hardened via host-capability intersection.
const SSH_CRYPTO_DIRECTIVES: &[SshCryptoDirective] = &[
    SshCryptoDirective {
        crypto_directive_name: "KexAlgorithms",
        crypto_query_arg: "kex",
        crypto_desired: SSH_DESIRED_KEX,
        crypto_description: "Restrict SSH key exchange to strong (PQ/curve25519) algorithms",
        crypto_severity: Severity::High,
    },
    SshCryptoDirective {
        crypto_directive_name: "Ciphers",
        crypto_query_arg: "cipher",
        crypto_desired: SSH_DESIRED_CIPHERS,
        crypto_description: "Restrict SSH ciphers to AEAD (ChaCha20-Poly1305 / AES-GCM)",
        crypto_severity: Severity::High,
    },
    SshCryptoDirective {
        crypto_directive_name: "MACs",
        crypto_query_arg: "mac",
        crypto_desired: SSH_DESIRED_MACS,
        crypto_description: "Restrict SSH MACs to strong encrypt-then-MAC algorithms",
        crypto_severity: Severity::Medium,
    },
];

/// Queries the local SSH implementation for the algorithms it supports in a
/// given category via `ssh -Q <query_arg>` and returns them as a list.
///
/// One algorithm is printed per line. Returns an empty vector if the command is
/// unavailable or fails; callers treat "no known support" as "set nothing",
/// which keeps the host default rather than risking an unparseable value.
pub async fn supported_algorithms(
    executor: &dyn hardener_core::SystemExecutor,
    query_arg: &str,
) -> Vec<String> {
    match executor.execute_command("ssh", &["-Q", query_arg]).await {
        Ok(output) if output.success() => output
            .stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect(),
        Ok(output) => {
            warn!("`ssh -Q {}` failed: {}", query_arg, output.stderr);
            Vec::new()
        }
        Err(e) => {
            warn!("`ssh -Q {}` could not be executed: {}", query_arg, e);
            Vec::new()
        }
    }
}

/// Returns the intersection of `desired` with `supported`, preserving the
/// preference order of `desired`.
///
/// This is the anti-lockout guarantee: because the result is always a subset of
/// the hardcoded strong `desired` list, no weak algorithm can ever be emitted;
/// because every element is also present in `supported`, we never hand `sshd` an
/// algorithm it cannot parse. An empty result means "host supports none of our
/// strong choices": the caller then skips the directive entirely.
pub fn select_algorithms(desired: &[&str], supported: &[String]) -> Vec<String> {
    desired
        .iter()
        .filter(|algo| supported.iter().any(|s| s == *algo))
        .map(|algo| algo.to_string())
        .collect()
}

/// Validates a candidate sshd_config by writing it to a temporary path and
/// running `sshd -t -f <temp>`.
///
/// This runs before the real config is ever written, so a config that would
/// make the daemon refuse to start is rejected here: no write, no restart, no
/// lockout. The temporary file is always removed, including on the error paths.
pub async fn validate_sshd_config(
    executor: &dyn hardener_core::SystemExecutor,
    candidate: &str,
) -> Result<()> {
    let temp_path = std::env::temp_dir().join(format!(
        "linux-hardener-sshd-validate-{}.conf",
        std::process::id()
    ));

    executor
        .write_file(&temp_path, candidate)
        .await
        .map_err(|e| {
            hardener_common::error::HardeningError::Plugin(format!(
                "Failed to write temp sshd_config for validation: {}",
                e
            ))
        })?;

    let temp_str = temp_path.to_string_lossy().to_string();
    let result = executor
        .execute_command("sshd", &["-t", "-f", &temp_str])
        .await;

    // Best-effort cleanup; never let cleanup failure mask the validation result.
    if let Err(e) = std::fs::remove_file(&temp_path) {
        warn!(
            "Failed to remove temp sshd_config {}: {}",
            temp_path.display(),
            e
        );
    }

    match result {
        Ok(output) if output.success() => Ok(()),
        Ok(output) => Err(hardener_common::error::HardeningError::Plugin(format!(
            "sshd -t rejected candidate config: {}",
            output.stderr.trim()
        ))),
        Err(e) => Err(hardener_common::error::HardeningError::Plugin(format!(
            "Failed to execute `sshd -t`: {}",
            e
        ))),
    }
}

/// Returns true if a crypto directive's current value contains only strong
/// algorithms from the desired allow-list. A missing value, or any token not in
/// the allow-list, is considered insecure (used by `scan`).
fn crypto_value_is_secure(current: Option<&str>, desired: &[&str]) -> bool {
    match current {
        None => false,
        Some(value) => {
            let tokens: Vec<&str> = value
                .split([',', ' '])
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .collect();
            !tokens.is_empty() && tokens.iter().all(|t| desired.contains(t))
        }
    }
}

/// SSH hardening plugin implementing OpenSSH configuration management.
pub struct SshHardeningPlugin;

impl Default for SshHardeningPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl SshHardeningPlugin {
    /// Creates a new instance of the SSH hardening plugin.
    pub fn new() -> SshHardeningPlugin {
        SshHardeningPlugin
    }

    /// Restarts the SSH daemon to apply configuration changes.
    ///
    /// Attempts to restart using systemctl (systemd) first, then falls back
    /// to service command for non-systemd systems.
    ///
    /// # Returns
    /// Ok(()) if restart succeeded, or an error describing the failure.
    async fn restart_ssh_service(ctx: &Context) -> Result<()> {
        // Try systemctl first (most modern distribution).
        let systemctl_result = ctx
            .executor()
            .execute_command("systemctl", &["restart", "sshd"])
            .await;

        match systemctl_result {
            Ok(output) if output.success() => {
                info!("SSH service restarted successfully via systemctl");
                return Ok(());
            }
            Ok(output) => {
                warn!("systemctl restart sshd failed: {}", output.stderr);
            }
            Err(e) => {
                warn!("systemctl command failed: {}", e);
            }
        }

        // Fallback to service command.
        let service_result = ctx
            .executor()
            .execute_command("service", &["ssh", "restart"])
            .await;

        match service_result {
            Ok(output) if output.success() => {
                info!("SSH service restarted successfully via service command");
                Ok(())
            }
            Ok(output) => Err(hardener_common::error::HardeningError::Plugin(format!(
                "Failed to restart SSH service: {}",
                output.stderr
            ))),
            Err(e) => Err(hardener_common::error::HardeningError::Plugin(format!(
                "Failed to execute service restart command: {}",
                e
            ))),
        }
    }
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
/// number (e.g. `3.13.11`); `title` the published requirement name; the
/// section is the requirement's official family. Every id is translated from
/// this plugin's 800-53 entries via the r3 source-control table, never
/// invented.
fn nist171(id: &str, title: &str) -> ComplianceMapping {
    ComplianceMapping {
        compliance_framework: ComplianceFramework::NIST800171,
        compliance_control_id: id.to_string(),
        compliance_control_title: title.to_string(),
        compliance_section: Some("System and Communications Protection".to_string()),
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
        compliance_section: Some("System and Communications Protection".to_string()),
    }
}

/// Returns compliance mappings for a given SSH directive.
/// Every compliance mapping this plugin can emit, across all SSH config and
/// crypto directives it assesses. Aggregated into the engine's coverage set.
pub fn coverage() -> Vec<ComplianceMapping> {
    SSH_DIRECTIVES
        .iter()
        .map(|d| d.ssh_directive_name)
        .chain(
            SSH_CRYPTO_DIRECTIVES
                .iter()
                .map(|d| d.crypto_directive_name),
        )
        .flat_map(get_ssh_compliance_mappings)
        .collect()
}

fn get_ssh_compliance_mappings(directive_name: &str) -> Vec<ComplianceMapping> {
    match directive_name {
        "PermitRootLogin" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "5.2.10".to_string(),
                compliance_control_title: "Ensure SSH root login is disabled".to_string(),
                compliance_section: Some("Access Control".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.312(a)(1)".to_string(),
                compliance_control_title: "Implement technical policies for access to ePHI"
                    .to_string(),
                compliance_section: Some("Access Control".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.312(d)".to_string(),
                compliance_control_title:
                    "Implement procedures to verify person or entity identity".to_string(),
                compliance_section: Some("Authentication".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-AUTH".to_string(),
                compliance_control_title: "Authentication - Verify user identity".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-SH".to_string(),
                compliance_control_title: "System Hardening - Reduce attack surface".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.5".to_string(),
                compliance_control_title: "Secure authentication".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            // SOC 2: CC6.1 mirrors the privileged-access restriction intent (CIS 5.2.10).
            soc2(
                "CC6.1",
                "Logical access security software, infrastructure, and architectures",
            ),
        ],
        "PasswordAuthentication" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "5.2.11".to_string(),
                compliance_control_title: "Ensure SSH PasswordAuthentication is disabled"
                    .to_string(),
                compliance_section: Some("Access Control".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.312(d)".to_string(),
                compliance_control_title:
                    "Implement procedures to verify person or entity identity".to_string(),
                compliance_section: Some("Authentication".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.308(a)(5)(ii)(D)".to_string(),
                compliance_control_title: "Password Management".to_string(),
                compliance_section: Some("Administrative Safeguards".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-AUTH".to_string(),
                compliance_control_title: "Authentication - Verify user identity".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-SH".to_string(),
                compliance_control_title: "System Hardening - Reduce attack surface".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.5".to_string(),
                compliance_control_title: "Secure authentication".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            // SOC 2: CC6.1 mirrors the authentication-strength intent (key-based access).
            soc2(
                "CC6.1",
                "Logical access security software, infrastructure, and architectures",
            ),
        ],
        "PermitEmptyPasswords" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "5.2.11".to_string(),
                compliance_control_title: "Ensure SSH PermitEmptyPasswords is disabled".to_string(),
                compliance_section: Some("Access Control".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.312(d)".to_string(),
                compliance_control_title:
                    "Implement procedures to verify person or entity identity".to_string(),
                compliance_section: Some("Authentication".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.308(a)(5)(ii)(D)".to_string(),
                compliance_control_title: "Password Management".to_string(),
                compliance_section: Some("Administrative Safeguards".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-AUTH".to_string(),
                compliance_control_title: "Authentication - Verify user identity".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-SH".to_string(),
                compliance_control_title: "System Hardening - Reduce attack surface".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.5".to_string(),
                compliance_control_title: "Secure authentication".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            // SOC 2: CC6.1 mirrors the authentication-verification intent (HIPAA 164.312(d)).
            soc2(
                "CC6.1",
                "Logical access security software, infrastructure, and architectures",
            ),
        ],
        "MaxAuthTries" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "5.2.7".to_string(),
                compliance_control_title: "Ensure SSH MaxAuthTries is set to 4 or less".to_string(),
                compliance_section: Some("Access Control".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.312(d)".to_string(),
                compliance_control_title:
                    "Implement procedures to verify person or entity identity".to_string(),
                compliance_section: Some("Authentication".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-AUTH".to_string(),
                compliance_control_title: "Authentication - Verify user identity".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-SH".to_string(),
                compliance_control_title: "System Hardening - Reduce attack surface".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.5".to_string(),
                compliance_control_title: "Secure authentication".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            // SOC 2: CC6.1 mirrors the brute-force limiting intent (CIS 5.2.7).
            soc2(
                "CC6.1",
                "Logical access security software, infrastructure, and architectures",
            ),
        ],
        "X11Forwarding" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "5.2.6".to_string(),
                compliance_control_title: "Ensure SSH X11 forwarding is disabled".to_string(),
                compliance_section: Some("Access Control".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-SH".to_string(),
                compliance_control_title: "System Hardening - Reduce attack surface".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.20".to_string(),
                compliance_control_title: "Networks security".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            // SOC 2: CC6.6 mirrors the tunnelled-exposure reduction intent (ISO 8.20).
            soc2(
                "CC6.6",
                "Protect against threats from sources outside system boundaries",
            ),
        ],
        "ClientAliveInterval" | "ClientAliveCountMax" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "5.2.13".to_string(),
                compliance_control_title: "Ensure SSH Idle Timeout Interval is configured"
                    .to_string(),
                compliance_section: Some("Access Control".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.312(a)(2)(iii)".to_string(),
                compliance_control_title: "Automatic Logoff".to_string(),
                compliance_section: Some("Access Control".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-SH".to_string(),
                compliance_control_title: "System Hardening - Reduce attack surface".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.20".to_string(),
                compliance_control_title: "Networks security".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            // SOC 2: CC6.1 mirrors the idle-session termination intent (HIPAA automatic logoff).
            soc2(
                "CC6.1",
                "Logical access security software, infrastructure, and architectures",
            ),
        ],
        "KexAlgorithms" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "5.2.14".to_string(),
                compliance_control_title: "Ensure only strong Key Exchange algorithms are used"
                    .to_string(),
                compliance_section: Some("Cryptography".to_string()),
            },
            // No STIG mapping: the RHEL 8 STIG's sshd KexAlgorithms rule
            // (RHEL-08-040342 / V-255924) was removed in V2R6 and V2R7 contains
            // none; the RHEL 10 STIG has none either. Source: DISA RHEL 8 STIG
            // V2R7 XCCDF (dl.dod.cyber.mil U_RHEL_8_V2R7_STIG.zip). The mapping
            // formerly here cited "V-230290", which in the real benchmark names
            // an unrelated rule (RHEL-08-010520, known-hosts authentication).
            ComplianceMapping {
                compliance_framework: ComplianceFramework::NIST,
                compliance_control_id: "SC-13".to_string(),
                compliance_control_title: "Cryptographic Protection".to_string(),
                compliance_section: Some("System and Communications Protection".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.312(e)(1)".to_string(),
                compliance_control_title:
                    "Implement technical security measures for ePHI transmission".to_string(),
                compliance_section: Some("Transmission Security".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.312(e)(2)(ii)".to_string(),
                compliance_control_title: "Encryption for transmission".to_string(),
                compliance_section: Some("Transmission Security".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "Art.32(1)(a)".to_string(),
                compliance_control_title: "Pseudonymisation and encryption of personal data"
                    .to_string(),
                compliance_section: Some("Security of Processing".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-NW".to_string(),
                compliance_control_title: "Network Security - Protect data in transit".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.24".to_string(),
                compliance_control_title: "Use of cryptography".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            // SOC 2: CC6.6 mirrors the SC-13 transmission-protection intent (strong Kex).
            soc2(
                "CC6.6",
                "Protect against threats from sources outside system boundaries",
            ),
            // 800-171r3 3.13.11 ← 800-53 SC-13 (SP 800-171r3 source-control table).
            nist171("3.13.11", "Cryptographic Protection"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 SC-13.
            fedramp("SC-13", "Cryptographic Protection"),
        ],
        "Ciphers" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "5.2.15".to_string(),
                compliance_control_title: "Ensure only strong Ciphers are used".to_string(),
                compliance_section: Some("Cryptography".to_string()),
            },
            // DISA RHEL 8 STIG V2R7 XCCDF (dl.dod.cyber.mil U_RHEL_8_V2R7_STIG.zip):
            // the sshd Ciphers rule is RHEL-08-010291 / V-230252 (CAT I). The id
            // formerly here, "V-230291", names an unrelated rule in the real
            // benchmark (RHEL-08-010521, Kerberos authentication).
            ComplianceMapping {
                compliance_framework: ComplianceFramework::STIG,
                compliance_control_id: "RHEL-08-010291".to_string(),
                compliance_control_title:
                    "The RHEL 8 SSH server must be configured to use only DOD-approved encryption ciphers employing FIPS 140-3-validated cryptographic hash algorithms to protect the confidentiality of SSH server connections."
                        .to_string(),
                compliance_section: Some("Cryptography".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::NIST,
                compliance_control_id: "SC-8".to_string(),
                compliance_control_title: "Transmission Confidentiality and Integrity".to_string(),
                compliance_section: Some("System and Communications Protection".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.312(e)(1)".to_string(),
                compliance_control_title:
                    "Implement technical security measures for ePHI transmission".to_string(),
                compliance_section: Some("Transmission Security".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.312(e)(2)(ii)".to_string(),
                compliance_control_title: "Encryption for transmission".to_string(),
                compliance_section: Some("Transmission Security".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "Art.32(1)(a)".to_string(),
                compliance_control_title: "Pseudonymisation and encryption of personal data"
                    .to_string(),
                compliance_section: Some("Security of Processing".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-NW".to_string(),
                compliance_control_title: "Network Security - Protect data in transit".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.24".to_string(),
                compliance_control_title: "Use of cryptography".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            // SOC 2: CC6.6 mirrors the SC-8 transmission-protection intent (strong ciphers).
            soc2(
                "CC6.6",
                "Protect against threats from sources outside system boundaries",
            ),
            // 800-171r3 3.13.8 ← 800-53 SC-8 (SP 800-171r3 source-control table).
            nist171("3.13.8", "Transmission and Storage Confidentiality"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 SC-8.
            fedramp("SC-8", "Transmission Confidentiality and Integrity"),
        ],
        "MACs" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "5.2.16".to_string(),
                compliance_control_title: "Ensure only strong MAC algorithms are used".to_string(),
                compliance_section: Some("Cryptography".to_string()),
            },
            // DISA RHEL 8 STIG V2R7 XCCDF (dl.dod.cyber.mil U_RHEL_8_V2R7_STIG.zip):
            // the sshd MACs rule is RHEL-08-010290 / V-230251 (CAT I). The
            // 010290 = MACs / 010291 = Ciphers pairing is DISA's own numbering,
            // reversed versus intuition, deliberately left as published. The id
            // formerly here, "V-230292", names an unrelated rule in the real
            // benchmark (RHEL-08-010540, separate /var file system, CAT III).
            ComplianceMapping {
                compliance_framework: ComplianceFramework::STIG,
                compliance_control_id: "RHEL-08-010290".to_string(),
                compliance_control_title:
                    "The RHEL 8 SSH server must be configured to use only Message Authentication Codes (MACs) employing FIPS 140-3-validated cryptographic hash algorithms to protect the confidentiality of SSH server connections."
                        .to_string(),
                compliance_section: Some("Cryptography".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::NIST,
                compliance_control_id: "SC-8".to_string(),
                compliance_control_title: "Transmission Confidentiality and Integrity".to_string(),
                compliance_section: Some("System and Communications Protection".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.312(e)(1)".to_string(),
                compliance_control_title:
                    "Implement technical security measures for ePHI transmission".to_string(),
                compliance_section: Some("Transmission Security".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.312(e)(2)(ii)".to_string(),
                compliance_control_title: "Encryption for transmission".to_string(),
                compliance_section: Some("Transmission Security".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "Art.32(1)(a)".to_string(),
                compliance_control_title: "Pseudonymisation and encryption of personal data"
                    .to_string(),
                compliance_section: Some("Security of Processing".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-NW".to_string(),
                compliance_control_title: "Network Security - Protect data in transit".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.24".to_string(),
                compliance_control_title: "Use of cryptography".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            // SOC 2: CC6.6 mirrors the SC-8 transmission-protection intent (strong MACs).
            soc2(
                "CC6.6",
                "Protect against threats from sources outside system boundaries",
            ),
            // 800-171r3 3.13.8 ← 800-53 SC-8 (SP 800-171r3 source-control table).
            nist171("3.13.8", "Transmission and Storage Confidentiality"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 SC-8.
            fedramp("SC-8", "Transmission Confidentiality and Integrity"),
        ],
        _ => vec![],
    }
}

#[async_trait]
impl HardeningPlugin for SshHardeningPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            plugin_category: FindingCategory::Network,
            plugin_description: "Hardens OpenSSH server configuration".to_string(),
            plugin_id: PluginId::new("ssh-hardening"),
            plugin_name: "SSH Hardening".to_string(),
            plugin_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    fn dependencies(&self) -> Vec<PluginId> {
        // SSH hardening has no dependencies on other plugins
        vec![]
    }

    async fn scan(&self, ctx: &Context) -> Result<ScanResult> {
        let start_time = Instant::now();
        let mut findings = Vec::new();
        let plugin_id = PluginId::new("ssh-hardening");

        // Read the SSH configuration file using executor
        let config_content = match ctx
            .executor()
            .read_file(Path::new("/etc/ssh/sshd_config"))
            .await
        {
            Ok(content) => content,
            Err(e) => {
                // If we can't read the config, create a critical finding.
                let duration_us = start_time.elapsed().as_micros() as u64;
                return Ok(ScanResult {
                    scan_plugin_id: plugin_id,
                    scan_success: false,
                    scan_findings: vec![],
                    scan_unchecked: vec![],
                    scan_duration_us: duration_us,
                    scan_error: Some(format!("Failed to read /etc/ssh/sshd_config: {}", e)),
                });
            }
        };

        // Check each SSH directive
        for directive in SSH_DIRECTIVES {
            let current_value = parse_config_value(
                &config_content,
                directive.ssh_directive_name,
                ConfigFormat::SpaceSeparated,
                false,
            );

            let is_insecure = match current_value {
                Some(ref value) => value != directive.ssh_secure_value,
                None => true, // Missing directive is insecure
            };

            if is_insecure {
                findings.push(Finding {
                    finding_category: FindingCategory::Network,
                    finding_current_value: current_value.unwrap_or_else(|| "not set".to_string()),
                    finding_description: directive.ssh_description.to_string(),
                    finding_explanation: format!(
                        "The SSH directive '{}' is not configured securely. {}",
                        directive.ssh_directive_name, directive.ssh_description,
                    ),
                    finding_id: format!("ssh-{}", directive.ssh_directive_name.to_lowercase()),
                    finding_impact: "May allow unauthorised access or weaken SSH security"
                        .to_string(),
                    finding_recommended_value: directive.ssh_secure_value.to_string(),
                    finding_remediation_steps: vec![
                        format!(
                            "Edit /etc/ssh/sshd_config and set: {} {}",
                            directive.ssh_directive_name, directive.ssh_secure_value,
                        ),
                        "Restart SSH service: systemctl restart sshd".to_string(),
                    ],
                    finding_severity: directive.ssh_severity,
                    finding_title: format!(
                        "Insecure SSH setting: {}",
                        directive.ssh_directive_name,
                    ),
                    finding_compliance: get_ssh_compliance_mappings(directive.ssh_directive_name),
                    finding_policy_exception: None,
                });
            }
        }

        // Check cryptographic directives. These are insecure if unset OR if they
        // contain any algorithm outside the strong allow-list (i.e. a weak/legacy
        // cipher, KEX or MAC is enabled).
        for crypto in SSH_CRYPTO_DIRECTIVES {
            let current_value = parse_config_value(
                &config_content,
                crypto.crypto_directive_name,
                ConfigFormat::SpaceSeparated,
                false,
            );

            if !crypto_value_is_secure(current_value.as_deref(), crypto.crypto_desired) {
                findings.push(Finding {
                    finding_category: FindingCategory::Network,
                    finding_current_value: current_value.unwrap_or_else(|| "not set".to_string()),
                    finding_description: crypto.crypto_description.to_string(),
                    finding_explanation: format!(
                        "The SSH directive '{}' is unset or permits weak algorithms. {}",
                        crypto.crypto_directive_name, crypto.crypto_description,
                    ),
                    finding_id: format!("ssh-{}", crypto.crypto_directive_name.to_lowercase()),
                    finding_impact:
                        "Weak SSH cryptography can allow session decryption or downgrade attacks"
                            .to_string(),
                    finding_recommended_value: crypto.crypto_desired.join(","),
                    finding_remediation_steps: vec![
                        format!(
                            "Restrict {} to strong algorithms supported by the host",
                            crypto.crypto_directive_name,
                        ),
                        "Validate with: sshd -t".to_string(),
                        "Restart SSH service: systemctl restart sshd".to_string(),
                    ],
                    finding_severity: crypto.crypto_severity,
                    finding_title: format!(
                        "Weak or unset SSH cryptography: {}",
                        crypto.crypto_directive_name,
                    ),
                    finding_compliance: get_ssh_compliance_mappings(crypto.crypto_directive_name),
                    finding_policy_exception: None,
                });
            }
        }

        let duration_us = start_time.elapsed().as_micros() as u64;
        Ok(ScanResult {
            scan_plugin_id: plugin_id,
            scan_success: true,
            scan_findings: findings,
            scan_unchecked: vec![],
            scan_duration_us: duration_us,
            scan_error: None,
        })
    }

    async fn apply(&self, ctx: &mut Context, config: &PluginConfig) -> Result<ApplyResult> {
        let plugin_id = PluginId::new("ssh-hardening");
        let mut changes = Vec::new();
        let config_path = "/etc/ssh/sshd_config";

        // Step 1: Create checkpoint to capture current state before changes.
        let checkpoint_id = crate::create_checkpoint_for_apply(
            ctx,
            "ssh-hardening-pre-apply",
            &[Path::new(config_path)],
        )
        .await?;

        if checkpoint_id.is_some() {
            changes.push(Change {
                change_description: "Created checkpoint for rollback".to_string(),
                change_type: ChangeType::ConfigFile,
                change_success: true,
                change_error: None,
            });
        }

        // Step 2: Create backup (legacy backup in addition to checkpoint).
        let backup_path = format!(
            "{}.backup.{}",
            config_path,
            Utc::now().format("%Y%m%d_%H%M%S")
        );
        match ctx
            .executor()
            .execute_command("cp", &["-p", config_path, &backup_path])
            .await
        {
            Ok(output) if output.success() => {
                changes.push(Change {
                    change_description: format!("Created backup: {}", backup_path),
                    change_type: ChangeType::ConfigFile,
                    change_success: true,
                    change_error: None,
                });
                info!("SSH config backup created: {}", backup_path);
            }
            Ok(output) => {
                return Ok(ApplyResult {
                    apply_plugin_id: plugin_id,
                    apply_success: false,
                    apply_changes: changes,
                    apply_checkpoint_id: checkpoint_id,
                    apply_error: Some(format!("Failed to create backup: {}", output.stderr)),
                });
            }
            Err(e) => {
                return Ok(ApplyResult {
                    apply_plugin_id: plugin_id,
                    apply_success: false,
                    apply_changes: changes,
                    apply_checkpoint_id: checkpoint_id,
                    apply_error: Some(format!("Failed to create backup: {}", e)),
                });
            }
        }

        // Step 3: Acquire advisory lock on config file to prevent concurrent
        // read-modify-write races with other processes editing sshd_config.
        let lock_file = std::fs::File::open(config_path).map_err(|e| {
            hardener_common::error::HardeningError::Plugin(format!(
                "Failed to open {} for locking: {}",
                config_path, e
            ))
        })?;
        let _lock = nix::fcntl::Flock::lock(lock_file, nix::fcntl::FlockArg::LockExclusive)
            .map_err(|(_file, errno)| {
                hardener_common::error::HardeningError::Plugin(format!(
                    "Failed to lock {}: {}",
                    config_path, errno
                ))
            })?;

        // Step 4: Read current configuration while holding the lock.
        let mut config_content = ctx
            .executor()
            .read_file(Path::new(config_path))
            .await
            .map_err(|e| {
                hardener_common::error::HardeningError::Plugin(format!(
                    "Failed to read {}: {}",
                    config_path, e
                ))
            })?;

        // Step 5: Apply each directive.
        for directive in SSH_DIRECTIVES {
            // Check for a valid exception: skip this directive if exempted
            if let Some(exception) = config.has_valid_exception(directive.ssh_directive_name) {
                info!(
                    "Skipping {} (exception: {})",
                    directive.ssh_directive_name, exception.reason
                );
                changes.push(Change {
                    change_description: format!(
                        "{}: skipped (exception: {})",
                        directive.ssh_directive_name, exception.reason
                    ),
                    change_type: ChangeType::ConfigFile,
                    change_success: true,
                    change_error: None,
                });
                continue;
            }

            // Determine target value: user directive override or hardcoded baseline
            let target_value = config
                .directives
                .get(directive.ssh_directive_name)
                .map(|s| s.as_str())
                .unwrap_or(directive.ssh_secure_value);

            let original_value = parse_config_value(
                &config_content,
                directive.ssh_directive_name,
                ConfigFormat::SpaceSeparated,
                false,
            );

            let needs_change = match &original_value {
                Some(value) => value != target_value,
                None => true,
            };

            if needs_change {
                config_content = set_config_directive(
                    &config_content,
                    directive.ssh_directive_name,
                    target_value,
                    ConfigFormat::SpaceSeparated,
                    false,
                );

                changes.push(Change {
                    change_description: format!(
                        "{}: {} -> {}",
                        directive.ssh_directive_name,
                        original_value.unwrap_or_else(|| "not set".to_string()),
                        target_value
                    ),
                    change_type: ChangeType::ConfigFile,
                    change_success: true,
                    change_error: None,
                });

                info!(
                    "Applied SSH directive: {} = {}",
                    directive.ssh_directive_name, target_value
                );
            }
        }

        // Step 5b: Apply cryptographic directives via host-capability intersection.
        // For each crypto directive, query what the local sshd supports and emit
        // only (desired strong ∩ supported). This can never produce a weak algo
        // (subset of the hardcoded allow-list) nor one the host cannot parse.
        for crypto in SSH_CRYPTO_DIRECTIVES {
            if let Some(exception) = config.has_valid_exception(crypto.crypto_directive_name) {
                info!(
                    "Skipping {} (exception: {})",
                    crypto.crypto_directive_name, exception.reason
                );
                changes.push(Change {
                    change_description: format!(
                        "{}: skipped (exception: {})",
                        crypto.crypto_directive_name, exception.reason
                    ),
                    change_type: ChangeType::ConfigFile,
                    change_success: true,
                    change_error: None,
                });
                continue;
            }

            let supported =
                supported_algorithms(ctx.executor().as_ref(), crypto.crypto_query_arg).await;
            let selected = select_algorithms(crypto.crypto_desired, &supported);

            // Empty intersection: the host supports none of our strong choices.
            // Leave the host default untouched rather than writing an invalid
            // (empty) value that sshd would reject.
            if selected.is_empty() {
                warn!(
                    "No supported strong algorithms for {}; leaving host default",
                    crypto.crypto_directive_name
                );
                changes.push(Change {
                    change_description: format!(
                        "{}: skipped (no strong algorithm supported by host)",
                        crypto.crypto_directive_name
                    ),
                    change_type: ChangeType::ConfigFile,
                    change_success: true,
                    change_error: None,
                });
                continue;
            }

            let target_value = selected.join(",");
            let original_value = parse_config_value(
                &config_content,
                crypto.crypto_directive_name,
                ConfigFormat::SpaceSeparated,
                false,
            );

            if original_value.as_deref() != Some(target_value.as_str()) {
                config_content = set_config_directive(
                    &config_content,
                    crypto.crypto_directive_name,
                    &target_value,
                    ConfigFormat::SpaceSeparated,
                    false,
                );
                changes.push(Change {
                    change_description: format!(
                        "{}: {} -> {}",
                        crypto.crypto_directive_name,
                        original_value.unwrap_or_else(|| "not set".to_string()),
                        target_value
                    ),
                    change_type: ChangeType::ConfigFile,
                    change_success: true,
                    change_error: None,
                });
                info!(
                    "Applied SSH crypto directive: {} = {}",
                    crypto.crypto_directive_name, target_value
                );
            }
        }

        // Step 5c: Validate the candidate config with `sshd -t` BEFORE touching
        // the live file. If sshd would refuse to start, abort here: no write, no
        // restart; the running daemon and its config are left fully intact, so
        // there is no lockout path.
        if let Err(e) = validate_sshd_config(ctx.executor().as_ref(), &config_content).await {
            error!("Candidate sshd_config failed validation, aborting apply: {e}");
            changes.push(Change {
                change_description: "Candidate sshd_config rejected by `sshd -t`; \
                    no changes written, service not restarted"
                    .to_string(),
                change_type: ChangeType::ConfigFile,
                change_success: false,
                change_error: Some(e.to_string()),
            });
            return Ok(ApplyResult {
                apply_plugin_id: plugin_id,
                apply_success: false,
                apply_changes: changes,
                apply_checkpoint_id: checkpoint_id,
                apply_error: Some(format!("sshd config validation failed: {e}")),
            });
        }

        // Step 6: Write modified configuration using executor.
        match ctx
            .executor()
            .write_file(Path::new(config_path), &config_content)
            .await
        {
            Ok(_) => {
                changes.push(Change {
                    change_description: format!("Updated {}", config_path),
                    change_type: ChangeType::ConfigFile,
                    change_success: true,
                    change_error: None,
                });
                info!("SSH configuration updated successfully");
            }
            Err(e) => {
                changes.push(Change {
                    change_description: format!("Failed to write {}", config_path),
                    change_type: ChangeType::ConfigFile,
                    change_success: false,
                    change_error: Some(e.to_string()),
                });
                error!("Failed to write SSH config: {}", e);
            }
        }

        // Step 7: Restart SSH service to apply changes. Only reached after the
        // candidate config passed `sshd -t`, so a restart cannot lock us out.
        match Self::restart_ssh_service(ctx).await {
            Ok(_) => {
                changes.push(Change {
                    change_description: "Restarted SSH service".to_string(),
                    change_type: ChangeType::Service,
                    change_success: true,
                    change_error: None,
                });
                info!("SSH service restarted successfully");
            }
            Err(e) => {
                changes.push(Change {
                    change_description: "Failed to restart SSH service".to_string(),
                    change_type: ChangeType::Service,
                    change_success: false,
                    change_error: Some(e.to_string()),
                });
                error!("Failed to restart SSH service: {}", e);
            }
        }

        let success = changes.iter().all(|c| c.change_success);
        Ok(ApplyResult {
            apply_plugin_id: plugin_id,
            apply_success: success,
            apply_changes: changes,
            apply_checkpoint_id: checkpoint_id,
            apply_error: None,
        })
    }

    async fn rollback(&self, ctx: &mut Context, checkpoint: &Checkpoint) -> Result<()> {
        info!(
            "Rolling back SSH configuration to checkpoint: {}",
            checkpoint.checkpoint_id.as_str()
        );

        // Use the common rollback helper
        crate::rollback_files_from_checkpoint(ctx, checkpoint)?;

        info!("SSH configuration files restored from checkpoint");

        // Restart SSH service to apply the restored configuration
        match Self::restart_ssh_service(ctx).await {
            Ok(_) => {
                info!("SSH service restarted after rollback");
            }
            Err(e) => {
                error!("Failed to restart SSH service after rollback: {}", e);
                return Err(e);
            }
        }

        Ok(())
    }

    async fn validate(&self, ctx: &Context, _config: &PluginConfig) -> Result<ValidationReport> {
        let mut issues = Vec::new();
        let plugin_id = PluginId::new("ssh-hardening");
        let config_path = Path::new("/etc/ssh/sshd_config");

        // Check if SSH config file exists and is readable using executor.
        match ctx.executor().file_metadata(config_path).await {
            Ok(metadata) => {
                // Check if it is a regular file.
                if !metadata.is_file {
                    issues.push(ValidationIssue {
                        validation_issue_severity: Severity::Critical,
                        validation_issue_message: format!(
                            "{} is not a regular file",
                            config_path.display()
                        ),
                        validation_issue_config_key: None,
                    });
                }
            }
            Err(e) => {
                issues.push(ValidationIssue {
                    validation_issue_severity: Severity::Critical,
                    validation_issue_message: format!(
                        "Cannot access {}: {}",
                        config_path.display(),
                        e
                    ),
                    validation_issue_config_key: None,
                });
            }
        }

        // Try to read the configuration and check which directives need changing.
        let mut estimated_changes = Vec::new();

        match ctx.executor().read_file(config_path).await {
            Ok(content) => {
                // Check each directive to see if it needs updating.
                for directive in SSH_DIRECTIVES {
                    // SSHD config is space-separated and case-insensitive.
                    let current_value = parse_config_value(
                        &content,
                        directive.ssh_directive_name,
                        ConfigFormat::SpaceSeparated,
                        false, // case-insensitive
                    );

                    match current_value {
                        Some(val) if val == directive.ssh_secure_value => {
                            // Already set to secure value - no change needed.
                        }
                        Some(val) => {
                            // Value exists but is insecure.
                            estimated_changes.push(format!(
                                "{}: {} → {}",
                                directive.ssh_directive_name, val, directive.ssh_secure_value
                            ));
                        }
                        None => {
                            // Directive not set - will add it.
                            estimated_changes.push(format!(
                                "{}: (not set) → {}",
                                directive.ssh_directive_name, directive.ssh_secure_value
                            ));
                        }
                    }
                }
            }
            Err(e) => {
                issues.push(ValidationIssue {
                    validation_issue_severity: Severity::Critical,
                    validation_issue_message: format!(
                        "Cannot read {}: {}",
                        config_path.display(),
                        e
                    ),
                    validation_issue_config_key: None,
                });
            }
        }

        let valid = issues.is_empty();
        Ok(ValidationReport {
            validation_report_plugin_id: plugin_id,
            validation_report_is_valid: valid,
            validation_report_issues: issues,
            validation_report_estimated_changes: estimated_changes,
        })
    }
}
