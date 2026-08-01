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

mod dropin;
mod include;

/// Where an administrator's sshd_config lives. Not necessarily where the one
/// in force lives: openSUSE ships no `/etc/ssh/sshd_config` and keeps the
/// vendor copy at `/usr/etc/ssh/sshd_config`, so every read goes through
/// `read_layered` and only the write path names this constant directly.
const SSHD_ADMIN_CONFIG_PATH: &str = "/etc/ssh/sshd_config";

/// The drop-in directory sshd reads before the main configuration, and the one
/// openSUSE's own vendor config directs administrators to.
const SSHD_DROPIN_DIR: &str = "/etc/ssh/sshd_config.d";

use crate::strictness::Strictness;
use async_trait::async_trait;
use chrono::Utc;
use hardener_common::{
    error::{HardeningError, Result},
    file_utils::{
        ConfigFormat, Duplicates, global_scope, parse_config_value, set_config_directive,
    },
    types::{ComplianceFramework, ComplianceMapping, FindingCategory, PluginId, Severity},
    vendor_config::{ConfigLayer, LayeredRead, read_layered},
};
use hardener_core::{
    ApplyResult, Change, ChangeType, Checkpoint, PluginConfig, ValidationIssue, ValidationReport,
    context::Context,
    plugin::{
        Finding, HardeningPlugin, PluginMetadata, ScanResult, UncheckedBlocker, UncheckedCheck,
    },
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
    /// Which direction counts as stricter for this directive's values.
    ///
    /// Comparing for equality instead reads a host stricter than the baseline
    /// as violating and then writes the baseline over it: `MaxAuthTries 2`
    /// became `3`, and a five-minute idle timeout replaced a one-minute one.
    ssh_compare: Strictness,
}

/// `PermitRootLogin`, weakest first. `without-password` is sshd's legacy
/// spelling of `prohibit-password` and shares its rank rather than sitting
/// below it; `forced-commands-only` permits strictly less than either, since
/// key-based root login then works only for a forced command.
const PERMIT_ROOT_LOGIN_ORDER: &[&[&str]] = &[
    &["yes"],
    &[REMOTE_ROOT_SAFE_VALUE, "without-password"],
    &["forced-commands-only"],
    &["no"],
];

/// The two values an on/off directive takes, weakest first. `no` is the
/// strict end of every one of them in this table.
const OFF_IS_STRICTER: &[&[&str]] = &[&["yes"], &["no"]];

/// Critical SSH config directives for security hardening.
///
/// These represent the minimum baseline for secure SSH configuration.
const SSH_DIRECTIVES: &[SshConfigDirective] = &[
    SshConfigDirective {
        ssh_directive_name: "PermitRootLogin",
        ssh_secure_value: "no",
        ssh_description: "Disable direct root login via SSH",
        ssh_severity: Severity::Critical,
        ssh_compare: Strictness::Ranked(PERMIT_ROOT_LOGIN_ORDER),
    },
    SshConfigDirective {
        ssh_directive_name: "PasswordAuthentication",
        ssh_secure_value: "no",
        ssh_description: "Require key-based authentication only",
        ssh_severity: Severity::Critical,
        ssh_compare: Strictness::Ranked(OFF_IS_STRICTER),
    },
    SshConfigDirective {
        ssh_directive_name: "PermitEmptyPasswords",
        ssh_secure_value: "no",
        ssh_description: "Disallow empty passwords",
        ssh_severity: Severity::Critical,
        ssh_compare: Strictness::Ranked(OFF_IS_STRICTER),
    },
    SshConfigDirective {
        ssh_directive_name: "MaxAuthTries",
        ssh_secure_value: "3",
        ssh_description: "Limit authentication attempts to prevent brute force",
        ssh_severity: Severity::Medium,
        // Fewer attempts is stricter, and zero is not a disable: it is the
        // strictest setting there is, refusing every attempt.
        ssh_compare: Strictness::AtMost,
    },
    SshConfigDirective {
        ssh_directive_name: "X11Forwarding",
        ssh_secure_value: "no",
        ssh_description: "Disable X11 forwarding to reduce attack surface",
        ssh_severity: Severity::Medium,
        ssh_compare: Strictness::Ranked(OFF_IS_STRICTER),
    },
    SshConfigDirective {
        ssh_directive_name: "ClientAliveInterval",
        ssh_secure_value: "300",
        ssh_description: "Disconnect idle SSH sessions after 5 minutes",
        ssh_severity: Severity::Low,
        // A shorter probe interval drops an idle session sooner, so smaller is
        // stricter, but zero stops sshd probing at all and is therefore the
        // loosest value the setting has.
        ssh_compare: Strictness::NonZeroAtMost,
    },
    SshConfigDirective {
        ssh_directive_name: "ClientAliveCountMax",
        ssh_secure_value: "2",
        ssh_description: "Maximum idle connection checks before disconnect",
        ssh_severity: Severity::Low,
        // Fewer tolerated missed probes is stricter. Zero disconnects on the
        // first one, which is the strict end rather than a disable.
        ssh_compare: Strictness::AtMost,
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

/// Mode the staged candidate is restricted to. It holds the configuration about
/// to be applied, under a predictable name in a world-writable directory, so it
/// states its own mode rather than inheriting the shared writer's default for a
/// created file.
const SCRATCH_MODE: &str = "600";

/// Path the candidate config is staged at while `sshd -t` reads it.
///
/// `/tmp` is named outright rather than taken from `std::env::temp_dir`, which
/// reads the controller's `TMPDIR`. This path is written and read on whichever
/// host the executor targets, so a directory that exists only in the operator's
/// own environment would send a remote apply somewhere the target has never
/// heard of.
///
/// One definition, called by both the implementation and the tests that
/// register the expected `sshd -t -f <path>` invocation: a test mirroring this
/// construction by hand is a second copy that can drift from the first.
pub fn sshd_validate_scratch_path() -> std::path::PathBuf {
    std::path::PathBuf::from("/tmp").join(format!(
        "linux-hardener-sshd-validate-{}.conf",
        std::process::id()
    ))
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
    let temp_path = sshd_validate_scratch_path();

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

    // Narrowed before `sshd -t` is told about it, and not treated as fatal: the
    // same content is about to become the host's own sshd_config, so refusing
    // the apply over the mode of a scratch copy would cost more than it saves.
    // The window between the write and this is the same one every chmod-after-
    // write site here carries.
    match executor
        .execute_command("chmod", &[SCRATCH_MODE, &temp_str])
        .await
    {
        Ok(output) if output.success() => {}
        Ok(output) => warn!(
            "Could not restrict {} to mode {}: {}",
            temp_str,
            SCRATCH_MODE,
            output.stderr.trim()
        ),
        Err(e) => warn!(
            "Could not restrict {} to mode {}: {}",
            temp_str, SCRATCH_MODE, e
        ),
    }

    let result = executor
        .execute_command("sshd", &["-t", "-f", &temp_str])
        .await;

    // Removed on the host it was staged on. Best-effort: cleanup must never
    // mask the validation result, which is the answer the caller acts on. Both
    // failure shapes are reported, because a command that ran and failed comes
    // back as `Ok` carrying a non-zero status.
    match executor.execute_command("rm", &["-f", &temp_str]).await {
        Ok(output) if output.success() => {}
        Ok(output) => warn!(
            "Failed to remove temp sshd_config {}: {}",
            temp_str,
            output.stderr.trim()
        ),
        Err(e) => warn!("Failed to remove temp sshd_config {}: {}", temp_str, e),
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

/// The directive whose strict value can sever the applying session itself.
const PERMIT_ROOT_LOGIN: &str = "PermitRootLogin";

/// The strongest `PermitRootLogin` value that can be applied over a root SSH
/// session without cutting off that session's own future access: password
/// root login stays blocked while key-based access survives. The scanned
/// recommendation stays `no`, so a rescan honestly reports the residual gap;
/// reaching `no` is a deliberate console step.
const REMOTE_ROOT_SAFE_VALUE: &str = "prohibit-password";

/// The target for `directive`: its secure value, tightened by an operator's
/// directive override where the config sets one that tightens it.
///
/// Scan, apply and validate all resolve it here, so a preview cannot judge the
/// host by a rule the apply it previews does not apply, and an override cannot
/// relax a directive below the baseline. Loosening deliberately is what the
/// exceptions mechanism is for, and an exception is labelled in the report
/// where an override would be silent.
fn resolved_target(directive: &SshConfigDirective, config: &PluginConfig) -> String {
    directive.ssh_compare.resolved_target(
        config,
        directive.ssh_directive_name,
        directive.ssh_secure_value,
    )
}

/// True when this apply runs as root over a remote executor, i.e. the very
/// session `PermitRootLogin no` would sever on restart (live-reproduced:
/// a remote root apply locked itself out of the target host).
///
/// Fails safe towards the strict value: any probe error is treated as "not
/// root", leaving the guard inactive; an unprivileged remote session cannot
/// restart sshd, so it cannot sever itself either.
async fn is_remote_root_session(executor: &dyn hardener_core::SystemExecutor) -> bool {
    executor.is_remote() && hardener_core::session_is_root(executor).await
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

/// Returns compliance mappings for a given SSH directive.
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

/// The sshd_config actually in force, with the layer that supplied it.
struct MainConfig {
    path: String,
    layer: ConfigLayer,
    content: String,
}

impl MainConfig {
    /// Where an operator should put a directive so sshd obeys it.
    ///
    /// Never the vendor file: writing `/etc/ssh/sshd_config` on a host whose
    /// configuration lives under `/usr/etc` makes sshd stop reading the vendor
    /// copy, discarding its Include lines and the crypto-policy fragment with
    /// them. sshd takes the first value it obtains and reads the drop-in
    /// directory before the main file, so the drop-in is the mechanism that
    /// works on every distribution and the one openSUSE documents in the
    /// vendor file itself.
    fn edit_target(&self) -> String {
        match self.layer {
            ConfigLayer::Admin => self.path.clone(),
            ConfigLayer::Vendor => format!("{SSHD_DROPIN_DIR}/00-hardener.conf"),
        }
    }
}

/// Takes the advisory lock that makes the read-compute-write cycle atomic
/// against another process editing the same file.
///
/// Only ever called for a local executor: `flock` needs a local file
/// descriptor, so taking it against a remote target locked the controller's
/// file and protected nothing.
///
/// A path that cannot be opened yields no lock rather than an error. This is
/// the openSUSE failure: the lock used to open `/etc/ssh/sshd_config`
/// unconditionally and abort the entire apply when it was not there, on a host
/// whose sshd_config lives under `/usr/etc`. There is nothing to serialise on a
/// file that does not exist, and refusing to harden the host over it is far
/// worse than proceeding, so the reason is logged and the apply continues.
fn lock_config_path(path: &str) -> Option<nix::fcntl::Flock<std::fs::File>> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) => {
            warn!("Proceeding without an advisory lock on {path}: {e}");
            return None;
        }
    };
    match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusive) {
        Ok(lock) => Some(lock),
        Err((_file, errno)) => {
            warn!("Proceeding without an advisory lock on {path}: {errno}");
            None
        }
    }
}

/// Asks the resolver whether the fragment actually won, once it is on disk.
///
/// The whole design rests on `00-hardener.conf` sorting before whatever else
/// the host ships, and that is a claim about filenames this tool does not
/// control. Checking it costs one re-resolve and turns the single assumption
/// underneath the feature into something self-reporting: a directive still
/// answered by another file becomes a failed change naming that file, rather
/// than a success that quietly changed nothing.
async fn verify_dropin_precedence(
    ctx: &Context,
    main_path: &str,
    directives: &[dropin::Directive],
    main_content: &str,
) -> Vec<Change> {
    let resolved = match include::resolve(ctx, main_path, main_content).await {
        Ok(resolved) => resolved,
        Err(e) => {
            return vec![Change {
                change_description: format!(
                    "Wrote {} but could not confirm it takes precedence",
                    dropin::DROPIN_PATH
                ),
                change_type: ChangeType::ConfigFile,
                change_success: false,
                change_error: Some(e.to_string()),
            }];
        }
    };

    directives
        .iter()
        .map(|directive| match resolved.effective(directive.keyword) {
            Some(effective) if effective.source == dropin::DROPIN_PATH => Change {
                change_description: format!(
                    "{}: set to '{}' in {}, which sshd reads before {}{}",
                    directive.keyword,
                    directive.value,
                    dropin::DROPIN_PATH,
                    main_path,
                    directive.note,
                ),
                change_type: ChangeType::ConfigFile,
                change_success: true,
                change_error: None,
            },
            Some(effective) => Change {
                change_description: format!(
                    "{}: written to {} but {} still supplies '{}', and sshd reads it first",
                    directive.keyword,
                    dropin::DROPIN_PATH,
                    effective.source,
                    effective.value,
                ),
                change_type: ChangeType::ConfigFile,
                change_success: false,
                change_error: Some(format!("still overridden by {}", effective.source)),
            },
            None => Change {
                change_description: format!(
                    "{}: written to {} but no file supplies it, so sshd does not read that \
                     fragment",
                    directive.keyword,
                    dropin::DROPIN_PATH,
                ),
                change_type: ChangeType::ConfigFile,
                change_success: false,
                change_error: Some(format!(
                    "{} is not included by {main_path}",
                    dropin::DROPIN_PATH
                )),
            },
        })
        .collect()
}

/// Carries a value the fragment is the only source of into the rewrite that is
/// about to replace it.
///
/// Every branch deciding a directive needs no write ends by rewriting the
/// fragment to whatever accumulated, so a directive left out of that list is
/// removed from the host rather than left alone. Where the value being kept is
/// one the fragment itself supplies, keeping it means writing it again. No note
/// is attached: this is a value being held, not a target being applied, and the
/// change reporting it says why it is not the strict one.
fn keep_value_the_fragment_holds(
    to_dropin: &mut Vec<dropin::Directive>,
    keyword: &'static str,
    held: Option<String>,
) {
    if let Some(value) = held {
        to_dropin.push(dropin::Directive {
            keyword,
            value,
            note: "",
        });
    }
}

/// Unchecked entries for every sshd_config check, when something stopped this
/// scan reading the effective configuration. Ids mirror the finding ids.
///
/// Both the reason and the blocker are the caller's, because the two callers
/// meet different failures and the helper used to speak for both. It said
/// "reading {path} requires root" either way, which is true of the one caller
/// whose read was refused and false of the other, whose read succeeded and
/// whose Include resolution then failed. That second entry named a file it had
/// already read and sent the operator to a remedy for a problem the file did
/// not have.
///
/// The path a caller names is not always `/etc/ssh/sshd_config`: on a host that
/// layers its configuration it may be the vendor copy under `/usr/etc`, and
/// naming the wrong file sends the operator somewhere that is not the problem.
fn unchecked_ssh_checks(reason: &str, blocker: UncheckedBlocker) -> Vec<UncheckedCheck> {
    SSH_DIRECTIVES
        .iter()
        .map(|d| {
            (
                d.ssh_directive_name,
                get_ssh_compliance_mappings(d.ssh_directive_name),
            )
        })
        .chain(SSH_CRYPTO_DIRECTIVES.iter().map(|c| {
            (
                c.crypto_directive_name,
                get_ssh_compliance_mappings(c.crypto_directive_name),
            )
        }))
        .map(|(name, compliance)| UncheckedCheck {
            unchecked_check_id: format!("ssh-{}", name.to_lowercase()),
            unchecked_title: format!("SSH setting: {}", name),
            unchecked_category: FindingCategory::Network,
            unchecked_reason: reason.to_string(),
            unchecked_blocker: blocker,
            unchecked_compliance: compliance,
        })
        .collect()
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

    async fn scan(&self, ctx: &Context, config: &PluginConfig) -> Result<ScanResult> {
        let start_time = Instant::now();
        let mut findings = Vec::new();
        let plugin_id = PluginId::new("ssh-hardening");

        // Read whichever sshd_config is in force, which is not always the one
        // under /etc: openSUSE keeps the vendor copy at /usr/etc and the scan
        // used to report it could not read /etc/ssh/sshd_config and assess
        // nothing at all.
        let main = match read_layered(ctx.executor().as_ref(), SSHD_ADMIN_CONFIG_PATH).await {
            LayeredRead::Found {
                path,
                layer,
                content,
            } => MainConfig {
                path,
                layer,
                content,
            },
            // A root-only sshd_config must not read as "every directive
            // missing": that would falsely flag a hardened host. Surface the
            // privilege failure as unchecked entries instead, naming the file
            // that could not be read rather than assuming it was the /etc one.
            LayeredRead::Unreadable {
                path,
                reason,
                permission_denied,
            } => {
                let duration_us = start_time.elapsed().as_micros() as u64;
                if permission_denied {
                    return Ok(ScanResult {
                        scan_plugin_id: plugin_id,
                        scan_success: true,
                        scan_findings: vec![],
                        scan_unchecked: unchecked_ssh_checks(
                            &format!("reading {path} requires root"),
                            crate::refusal_blocker(ctx).await,
                        ),
                        scan_duration_us: duration_us,
                        scan_error: None,
                    });
                }
                return Ok(ScanResult {
                    scan_plugin_id: plugin_id,
                    scan_success: false,
                    scan_findings: vec![],
                    scan_unchecked: vec![],
                    scan_duration_us: duration_us,
                    scan_error: Some(format!("Failed to read {path}: {reason}")),
                });
            }
            LayeredRead::Absent => {
                let duration_us = start_time.elapsed().as_micros() as u64;
                return Ok(ScanResult {
                    scan_plugin_id: plugin_id,
                    scan_success: false,
                    scan_findings: vec![],
                    scan_unchecked: vec![],
                    scan_duration_us: duration_us,
                    scan_error: Some(format!(
                        "Failed to read {SSHD_ADMIN_CONFIG_PATH}: no sshd_config exists there \
                         or at its /usr/etc counterpart"
                    )),
                });
            }
        };
        let config_content = main.content.clone();

        // sshd uses the first value it obtains, and the shipped config
        // Includes /etc/ssh/sshd_config.d/*.conf above everything this tool
        // writes, so a drop-in silently wins. Reading only the main file
        // reported the value we wrote while sshd enforced the drop-in's.
        let resolved = match include::resolve(ctx, &main.path, &config_content).await {
            Ok(resolved) => resolved,
            Err(e) => {
                // Without the included files the effective configuration is
                // unknown, and guessing from the main file alone is the false
                // pass this replaces.
                let duration_us = start_time.elapsed().as_micros() as u64;
                return Ok(ScanResult {
                    scan_plugin_id: plugin_id,
                    scan_success: false,
                    scan_findings: vec![],
                    scan_unchecked: unchecked_ssh_checks(
                        &format!(
                            "{} was read, but the Include directives it carries \
                             could not be resolved, so the effective configuration \
                             is unknown: {e}",
                            main.path
                        ),
                        // `include::resolve` fails on nesting past its depth
                        // limit, a directory it cannot list, an included file it
                        // cannot read, and a pattern naming no directory. Only
                        // one of those is a refusal root would lift, and nothing
                        // here knows which happened.
                        UncheckedBlocker::Unknown,
                    ),
                    scan_duration_us: duration_us,
                    scan_error: Some(format!(
                        "Cannot resolve sshd_config Include directives: {e}"
                    )),
                });
            }
        };

        // Check each SSH directive
        for directive in SSH_DIRECTIVES {
            let effective = resolved.effective(directive.ssh_directive_name);
            let current_value = effective.as_ref().map(|e| e.value.clone());

            let target = resolved_target(directive, config);

            // Threshold, not equality: a host stricter than the baseline is
            // already compliant. Comparing for equality flagged
            // `MaxAuthTries 2` against a baseline of 3, and apply then wrote
            // the 3 over it. An absent directive violates every direction,
            // since nothing is enforcing it.
            let is_insecure = directive
                .ssh_compare
                .violated_by(&target, current_value.as_deref());

            if is_insecure {
                // An exception is honoured only when it documents the value the
                // host actually has, so a config cannot pass a control by
                // describing a deviation that is not there.
                let current_display = current_value.unwrap_or_else(|| "not set".to_string());
                let policy_exception = config
                    .matching_exception(directive.ssh_directive_name, &current_display)
                    .map(|e| e.to_finding_exception());
                findings.push(Finding {
                    finding_category: FindingCategory::Network,
                    finding_current_value: current_display.clone(),
                    finding_description: directive.ssh_description.to_string(),
                    finding_explanation: match effective.as_ref() {
                        // Naming the file matters when it is not the one this
                        // tool edits: editing sshd_config would not change what
                        // sshd uses, because the drop-in is read first.
                        Some(e) if e.source != main.path => format!(
                            "The SSH directive '{}' is not configured securely. {} \
                             The value in force comes from {}, which sshd reads before \
                             {}, so it overrides anything set there.",
                            directive.ssh_directive_name,
                            directive.ssh_description,
                            e.source,
                            main.path,
                        ),
                        _ => format!(
                            "The SSH directive '{}' is not configured securely. {}",
                            directive.ssh_directive_name, directive.ssh_description,
                        ),
                    },
                    finding_id: format!("ssh-{}", directive.ssh_directive_name.to_lowercase()),
                    finding_impact: "May allow unauthorised access or weaken SSH security"
                        .to_string(),
                    finding_recommended_value: target.to_string(),
                    finding_remediation_steps: vec![
                        format!(
                            "Edit {} and set: {} {}",
                            main.edit_target(),
                            directive.ssh_directive_name,
                            target,
                        ),
                        "Restart SSH service: systemctl restart sshd".to_string(),
                    ],
                    finding_severity: directive.ssh_severity,
                    finding_title: format!(
                        "Insecure SSH setting: {}",
                        directive.ssh_directive_name,
                    ),
                    finding_compliance: get_ssh_compliance_mappings(directive.ssh_directive_name),
                    finding_policy_exception: policy_exception,
                });
            }
        }

        // Check cryptographic directives. These are insecure if unset OR if they
        // contain any algorithm outside the strong allow-list (i.e. a weak/legacy
        // cipher, KEX or MAC is enabled).
        for crypto in SSH_CRYPTO_DIRECTIVES {
            // From the resolved configuration, exactly as the loop above reads
            // its own directives. This read the main file alone until an
            // openSUSE, Fedora or RHEL host made the cost plain: crypto-policies
            // supplies Ciphers, MACs and KexAlgorithms from
            // /etc/ssh/sshd_config.d, the Include sits above everything this
            // tool writes, and sshd takes the first value it obtains. The strong
            // list this tool put in the main file was read back and reported
            // while sshd negotiated the drop-in's, and since these three
            // directives are in `coverage()`, the absent finding rendered their
            // controls as Pass. The mirror was just as wrong: a drop-in already
            // holding a strong list read as "not set" and was reported.
            let effective = resolved.effective(crypto.crypto_directive_name);
            let current_value = effective.as_ref().map(|e| e.value.clone());

            if !crypto_value_is_secure(current_value.as_deref(), crypto.crypto_desired) {
                let current_display = current_value.unwrap_or_else(|| "not set".to_string());
                let policy_exception = config
                    .matching_exception(crypto.crypto_directive_name, &current_display)
                    .map(|e| e.to_finding_exception());
                findings.push(Finding {
                    finding_category: FindingCategory::Network,
                    finding_current_value: current_display.clone(),
                    finding_description: crypto.crypto_description.to_string(),
                    finding_explanation: match effective.as_ref() {
                        // Naming the file matters for the same reason it does
                        // above: editing sshd_config would not change what sshd
                        // negotiates, because the drop-in is read first.
                        Some(e) if e.source != main.path => format!(
                            "The SSH directive '{}' is unset or permits weak algorithms. {} \
                             The value in force comes from {}, which sshd reads before \
                             {}, so it overrides anything set there.",
                            crypto.crypto_directive_name,
                            crypto.crypto_description,
                            e.source,
                            main.path,
                        ),
                        _ => format!(
                            "The SSH directive '{}' is unset or permits weak algorithms. {}",
                            crypto.crypto_directive_name, crypto.crypto_description,
                        ),
                    },
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
                    finding_policy_exception: policy_exception,
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

        // Step 1: Find the config actually in force, then lock it. openSUSE
        // ships no /etc/ssh/sshd_config and keeps the vendor one under
        // /usr/etc, so a lock opening the admin path directly died there
        // before anything else ran. Locking the resolved path serialises
        // concurrent runs just as well, because they resolve the same file.
        let main = match read_layered(ctx.executor().as_ref(), SSHD_ADMIN_CONFIG_PATH).await {
            LayeredRead::Found {
                path,
                layer,
                content,
            } => MainConfig {
                path,
                layer,
                content,
            },
            LayeredRead::Absent => {
                return Err(HardeningError::Plugin(format!(
                    "Failed to read {SSHD_ADMIN_CONFIG_PATH}: no sshd_config exists there or at \
                     its /usr/etc counterpart"
                )));
            }
            LayeredRead::Unreadable { path, reason, .. } => {
                return Err(HardeningError::Plugin(format!(
                    "Failed to read {path}: {reason}"
                )));
            }
        };
        let config_path = main.path.as_str();
        // The vendor file is never written. Where it is the one in force, every
        // managed directive goes to the drop-in instead, because creating
        // /etc/ssh/sshd_config would make sshd stop reading the vendor config
        // and discard its Include lines with it.
        let writing_main = matches!(main.layer, ConfigLayer::Admin);

        // flock needs a local file descriptor and means nothing against a
        // remote target, so it is taken only for a local executor, matching
        // what the permissions plugin does at permissions/mod.rs:845.
        let _lock = (!ctx.executor().is_remote()).then(|| lock_config_path(config_path));

        let original_content = main.content.clone();

        // Step 2: Compute the hardened config from the current content.
        // Directive changes accumulate in `changes`, but nothing is committed
        // to disk until the no-op guard below confirms the config actually
        // differs. Probe the session once up front: on a remote root session
        // the PermitRootLogin target is downgraded so the apply cannot sever
        // its own access.
        let mut config_content = original_content.clone();
        let mut changes = Vec::new();
        // Directives that cannot take effect by editing the main file, either
        // because a drop-in outranks it or because it is the vendor's and must
        // not be touched. These go to the fragment this tool owns.
        let mut to_dropin: Vec<dropin::Directive> = Vec::new();
        let remote_root_session = is_remote_root_session(ctx.executor().as_ref()).await;

        // Which directives a drop-in already answers. sshd reads the Include
        // above everything written here, and uses the first value it obtains,
        // so writing this file cannot change those. Refusing to resolve is
        // fail-closed: without the included files there is no way to tell
        // whether a write would take effect.
        let resolved = include::resolve(ctx, config_path, &original_content).await?;

        for directive in SSH_DIRECTIVES {
            // The exception is honoured only when it documents the value the
            // host actually has, so a stale exception cannot stop hardening.
            // An absent directive reads as "not set", matching scan's rendering
            // and therefore what an operator writes in the config.
            let observed = parse_config_value(
                global_scope(&original_content),
                directive.ssh_directive_name,
                ConfigFormat::SpaceSeparated,
                false,
            )
            .unwrap_or_else(|| "not set".to_string());
            if let Some(exception) =
                config.matching_exception(directive.ssh_directive_name, &observed)
            {
                info!(
                    "Skipping {} (exception: {})",
                    directive.ssh_directive_name, exception.reason
                );
                changes.push(Change {
                    change_description: format!(
                        "{}: skipped (exception: {})",
                        directive.ssh_directive_name, exception.reason
                    ),
                    change_type: ChangeType::Skipped,
                    change_success: true,
                    change_error: None,
                });
                continue;
            }

            let target_value = resolved_target(directive, config);

            // The remote-root lockout guard binds wherever the directive is
            // written. Routing PermitRootLogin to the drop-in with the strict
            // 'no' would sever the very session performing the apply exactly as
            // writing it to the main file would, so the flag is computed before
            // the destination is chosen rather than after.
            let guard_active = remote_root_session
                && directive.ssh_directive_name == PERMIT_ROOT_LOGIN
                && target_value == "no";

            // What the host obeys today, from whichever file supplies it. The
            // lockout guard compares against this rather than the main file's
            // own line, because on a vendor-layer host that line is not the one
            // in force and on an overridden directive it is inert.
            let effective_now = resolved.effective(directive.ssh_directive_name);
            // That value may be in force only because this tool's own fragment
            // supplies it. Wherever the guard below concludes no write is
            // needed, the conclusion rewrites the fragment without this
            // directive, so a value only the fragment holds has to be carried
            // into that rewrite rather than left to a file about to lose it.
            let held_by_our_fragment = effective_now
                .as_ref()
                .filter(|effective| effective.source == dropin::DROPIN_PATH)
                .map(|effective| effective.value.clone());
            let (dropin_target, dropin_note) = if guard_active {
                (
                    REMOTE_ROOT_SAFE_VALUE.to_string(),
                    " (downgraded from 'no': applying 'no' over this root SSH session \
                     would sever access; set 'no' from a console)",
                )
            } else {
                (target_value.clone(), "")
            };
            // The fragment is read before every other file, so whatever it
            // holds is what the host obeys. Writing the bare target into it
            // would therefore overwrite a stricter value elsewhere with a
            // looser one, which is the same defect as writing the main file
            // would be. Clamping rather than skipping keeps the fragment
            // present, which is what holds a vendor-layer host to this target
            // after a package update replaces the file underneath.
            let dropin_target = directive.ssh_compare.clamp_target(
                &dropin_target,
                effective_now
                    .as_ref()
                    .map(|effective| effective.value.as_str()),
            );
            // Never loosen: a value already at least as strict as the safe
            // fallback stays as it is. That includes a case variant of the
            // target and the legacy spelling of the fallback, both of which
            // the directive's own ranking already treats as what they are.
            let already_safe_enough = guard_active
                && effective_now.as_ref().is_some_and(|effective| {
                    !directive
                        .ssh_compare
                        .violated_by(REMOTE_ROOT_SAFE_VALUE, Some(&effective.value))
                });

            // A drop-in read before this file already answers this directive,
            // so writing here cannot change what sshd uses. One that already
            // holds the target leaves the host compliant and is reported as
            // skipped; reporting that as a failure would be a false alarm.
            // Where it holds the wrong value the directive is routed to the
            // fragment this tool owns, which sorts first and therefore wins.
            //
            // A directive our own fragment already answers is not an override
            // to route around: it is this tool's own previous write, and the
            // rewrite below refreshes it. What matters is therefore what would
            // win if the fragment were not there, because that is what decides
            // whether writing the main file can take effect. Discarding the
            // fragment and reading the empty result as "nobody overrides this"
            // instead would hand a second apply the main file as its target
            // while the vendor fragment underneath still outranks it, and prune
            // the fragment that was holding the host.
            let overridden = resolved
                .effective_without(directive.ssh_directive_name, dropin::DROPIN_PATH)
                .filter(|effective| effective.source != config_path);
            if let Some(effective) = overridden {
                // At least as strict as the target, not equal to it: a file
                // underneath holding `MaxAuthTries 2` leaves the host
                // compliant without this tool's fragment just as surely as one
                // holding 3 does, so the fragment is unnecessary either way.
                // Asking for equality here left behind a fragment restating a
                // value the host already had.
                let file_underneath_is_strict_enough = !directive
                    .ssh_compare
                    .violated_by(&target_value, Some(&effective.value));
                if file_underneath_is_strict_enough || already_safe_enough {
                    changes.push(Change {
                        change_description: format!(
                            "{}: already '{}' via {}, which sshd reads before {}",
                            directive.ssh_directive_name,
                            effective.value,
                            effective.source,
                            config_path,
                        ),
                        change_type: ChangeType::Skipped,
                        change_success: true,
                        change_error: None,
                    });
                    // Dropping the directive is right where the file underneath
                    // is already strict enough, because the fragment is then
                    // genuinely unnecessary. It is wrong where the only reason
                    // the host counts as safe is the fragment itself: that file
                    // underneath still says otherwise, so leaving the directive
                    // out of the rewrite hands the host straight back to it.
                    if !file_underneath_is_strict_enough {
                        keep_value_the_fragment_holds(
                            &mut to_dropin,
                            directive.ssh_directive_name,
                            held_by_our_fragment,
                        );
                    }
                    continue;
                }
                to_dropin.push(dropin::Directive {
                    keyword: directive.ssh_directive_name,
                    value: dropin_target,
                    note: dropin_note,
                });
                continue;
            }

            // The vendor file is never edited, so every managed directive goes
            // to the drop-in on a host that keeps its sshd_config under
            // /usr/etc. Being already compliant is not a reason to skip: the
            // vendor value can change under a package update, and the fragment
            // is what holds the host to this tool's target afterwards.
            if !writing_main {
                if already_safe_enough {
                    changes.push(Change {
                        change_description: format!(
                            "PermitRootLogin: kept at '{}' (already the strongest value safely \
                             settable over this root SSH session; set 'no' from a console)",
                            effective_now
                                .map(|effective| effective.value)
                                .unwrap_or_default()
                        ),
                        change_type: ChangeType::Skipped,
                        change_success: true,
                        change_error: None,
                    });
                    // The vendor file is never edited, so the fragment is the
                    // only file this tool may write here. Leaving the directive
                    // out of the rewrite is therefore what removes the value
                    // being reported as kept.
                    keep_value_the_fragment_holds(
                        &mut to_dropin,
                        directive.ssh_directive_name,
                        held_by_our_fragment,
                    );
                    continue;
                }
                to_dropin.push(dropin::Directive {
                    keyword: directive.ssh_directive_name,
                    value: dropin_target,
                    note: dropin_note,
                });
                continue;
            }

            let original_value = parse_config_value(
                global_scope(&config_content),
                directive.ssh_directive_name,
                ConfigFormat::SpaceSeparated,
                false,
            );

            // Compared against the strict target first, so an existing `no`
            // is "already compliant" and the guard below can never loosen it.
            // The comparison is the directive's own, so a value stricter than
            // the target needs no change either, and a case variant of the
            // target is already the target as far as sshd is concerned. That
            // last point used to need a branch of its own here, guarding
            // against the downgrade below "normalising" a `No` into
            // prohibit-password; a ranked comparison cannot reach it.
            let needs_change = directive
                .ssh_compare
                .violated_by(&target_value, original_value.as_deref());

            // Lockout guard: on a remote root session, never write the
            // session-severing `no`. A current value already at least as
            // strict as the safe fallback is left untouched (never loosen);
            // anything weaker gets the fallback with an honest explanation.
            if guard_active
                && needs_change
                && let Some(current) = original_value.as_deref()
                && !directive
                    .ssh_compare
                    .violated_by(REMOTE_ROOT_SAFE_VALUE, Some(current))
            {
                info!(
                    "PermitRootLogin left at '{}' on remote root session (never loosen)",
                    current
                );
                changes.push(Change {
                    change_description: format!(
                        "PermitRootLogin: kept at '{}' (already the strongest value safely \
                         settable over this root SSH session; set 'no' from a console)",
                        current
                    ),
                    change_type: ChangeType::Skipped,
                    change_success: true,
                    change_error: None,
                });
                continue;
            }

            let (target_value, guard_note) = if guard_active && needs_change {
                (
                    REMOTE_ROOT_SAFE_VALUE,
                    " (downgraded from 'no': applying 'no' over this root SSH session \
                     would sever access; set 'no' from a console)",
                )
            } else {
                (target_value.as_str(), "")
            };

            if needs_change {
                config_content = set_config_directive(
                    &config_content,
                    directive.ssh_directive_name,
                    target_value,
                    ConfigFormat::SpaceSeparated,
                    false,
                    Duplicates::Keep,
                );

                changes.push(Change {
                    change_description: format!(
                        "{}: {} -> {}{}",
                        directive.ssh_directive_name,
                        original_value.unwrap_or_else(|| "not set".to_string()),
                        target_value,
                        guard_note
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
            // As above: the crypto allow-list intersection deliberately has no
            // directive override, but the exception itself still only applies
            // when it documents the value actually on the host.
            let observed = parse_config_value(
                global_scope(&original_content),
                crypto.crypto_directive_name,
                ConfigFormat::SpaceSeparated,
                false,
            )
            .unwrap_or_else(|| "not set".to_string());
            if let Some(exception) =
                config.matching_exception(crypto.crypto_directive_name, &observed)
            {
                info!(
                    "Skipping {} (exception: {})",
                    crypto.crypto_directive_name, exception.reason
                );
                changes.push(Change {
                    change_description: format!(
                        "{}: skipped (exception: {})",
                        crypto.crypto_directive_name, exception.reason
                    ),
                    change_type: ChangeType::Skipped,
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
                    change_type: ChangeType::Skipped,
                    change_success: true,
                    change_error: None,
                });
                continue;
            }

            let target_value = selected.join(",");

            // Where this directive belongs, by the same question the directive
            // loop above asks: what would win if this tool's own fragment were
            // not there. Writing the main file cannot change what sshd
            // negotiates when a file it reads first answers the keyword, and on
            // RHEL, Fedora and openSUSE that file is crypto-policies'
            // 50-redhat.conf, which answers all three of these. The apply
            // reported "Ciphers: x -> y" and sshd went on using the drop-in's
            // list. The maintainer's decision is that this tool overrides that
            // fragment rather than deferring to it, so an overridden directive
            // is routed to the fragment this tool owns, which sorts first.
            //
            // Routed rather than written here, deliberately: a directive in
            // `to_dropin` goes through `verify_dropin_precedence`, which reads
            // the configuration back and reports a failed change naming the
            // file still answering the keyword. That 00- sorts before 50- is a
            // claim about filenames nobody controls, and it is checked rather
            // than assumed for these directives exactly as for the others.
            let overridden = resolved
                .effective_without(crypto.crypto_directive_name, dropin::DROPIN_PATH)
                .filter(|effective| effective.source != config_path);
            if let Some(effective) = overridden {
                // Secure rather than equal to the target: a file underneath
                // offering a subset of the allow-list leaves the host with no
                // weak algorithm on offer, which is the same question scan
                // asks, so the two agree about that host and no fragment is
                // needed. Asking for equality would leave a fragment restating
                // a list the host already obeys.
                if crypto_value_is_secure(Some(&effective.value), crypto.crypto_desired) {
                    changes.push(Change {
                        change_description: format!(
                            "{}: already strong via {}, which sshd reads before {}",
                            crypto.crypto_directive_name, effective.source, config_path,
                        ),
                        change_type: ChangeType::Skipped,
                        change_success: true,
                        change_error: None,
                    });
                    continue;
                }
                to_dropin.push(dropin::Directive {
                    keyword: crypto.crypto_directive_name,
                    value: target_value,
                    note: "",
                });
                continue;
            }

            // The vendor file is never edited, so on a host keeping its
            // sshd_config under /usr/etc every managed directive goes to the
            // fragment, crypto included.
            if !writing_main {
                to_dropin.push(dropin::Directive {
                    keyword: crypto.crypto_directive_name,
                    value: target_value,
                    note: "",
                });
                continue;
            }

            let original_value = parse_config_value(
                global_scope(&config_content),
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
                    Duplicates::Keep,
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

        // Step 3: No-op guard. If the hardened config is byte-identical to what
        // was read, the host is already compliant: skip the checkpoint, the
        // backup, the write and - critically - the sshd restart, which is the
        // one operation that can drop the admin's own session. Emit a single
        // Skipped change so the caller still sees the plugin ran.
        //
        // The fragment counts as part of the config here. On a vendor-layer
        // host every directive goes there and the main file is never touched,
        // so comparing the main file alone would report "already compliant" on
        // a host nothing had been written to yet.
        let desired_dropin = (!to_dropin.is_empty()).then(|| dropin::render(&to_dropin));
        // A drop-in that cannot be read counts as changed, which is why the
        // failure is folded into None rather than distinguished: the cost of
        // being wrong is one needless rewrite of a file this tool owns and
        // stamps as managed, and the direction is toward hardening.
        let current_dropin = ctx
            .executor()
            .read_file(Path::new(dropin::DROPIN_PATH))
            .await
            .ok();
        let dropin_changed = desired_dropin.as_deref() != current_dropin.as_deref();

        if config_content == original_content && !dropin_changed {
            changes.push(Change {
                change_description:
                    "sshd_config already compliant - not rewritten, service not restarted"
                        .to_string(),
                change_type: ChangeType::Skipped,
                change_success: true,
                change_error: None,
            });
            info!("sshd_config already compliant; skipped backup, rewrite and restart");
            return Ok(ApplyResult {
                apply_plugin_id: plugin_id,
                apply_success: true,
                apply_changes: changes,
                apply_checkpoint_id: None,
                apply_error: None,
            });
        }

        // Step 4: The config drifts, so commit the change. Create the
        // checkpoint and the legacy backup now (never on a no-op); they lead
        // the committed change list, ahead of the directive changes.
        let mut committed = Vec::new();

        // The fragment joins the checkpoint so a rollback removes it. It is
        // deliberately absent from UNDELETABLE_ROLLBACK_PATHS: a checkpoint
        // taken before this apply records it as truthfully absent, so deleting
        // it is what the operator asked for, and protecting it would leave the
        // hardening in place after a rollback. Same precedent as the kernel
        // plugin's sysctl.d drop-in.
        let checkpoint_id = crate::create_checkpoint_for_apply(
            ctx,
            "ssh-hardening-pre-apply",
            &[Path::new(config_path), Path::new(dropin::DROPIN_PATH)],
        )
        .await?;
        committed.extend(crate::checkpoint_change(&checkpoint_id));

        // The legacy backup sits beside the file it copies, so it is taken only
        // when that file is the administrator's. Copying the vendor config
        // would drop a hardener-named file into /usr/etc, which is the
        // distribution's to own, and there is nothing to back up in any case
        // because the vendor file is never edited.
        let main_write_needed = writing_main && config_content != original_content;
        if main_write_needed {
            let backup_path = format!(
                "{}.backup.{}",
                config_path,
                Utc::now().format("%Y%m%d_%H%M%S")
            );
            // `-p` was here from the start and `--no-dereference` was not, the
            // reverse of the audit plugin's copy; the two flags answer separate
            // questions and a backup needs both. `-p` preserves mode, ownership
            // and timestamps, so a restored copy is the file rather than one
            // wearing the umask's mode. `--no-dereference` copies a symlink as
            // a symlink, which matters here more than at the other two sites: a
            // host whose sshd_config is a link into a configuration-management
            // checkout would otherwise have its managed file copied and the
            // object this apply is about to overwrite left with no backup at
            // all. `cp -p` exits non-zero when it cannot preserve ownership, as
            // an unprivileged copy of a root-owned file cannot; that is caught
            // by the failure arms below, which is the right direction, and
            // apply runs as root so it should not arise.
            match ctx
                .executor()
                .execute_command("cp", &["-p", "--no-dereference", config_path, &backup_path])
                .await
            {
                Ok(output) if output.success() => {
                    committed.push(Change {
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
                        apply_changes: committed,
                        apply_checkpoint_id: checkpoint_id,
                        apply_error: Some(format!("Failed to create backup: {}", output.stderr)),
                    });
                }
                Err(e) => {
                    return Ok(ApplyResult {
                        apply_plugin_id: plugin_id,
                        apply_success: false,
                        apply_changes: committed,
                        apply_checkpoint_id: checkpoint_id,
                        apply_error: Some(format!("Failed to create backup: {}", e)),
                    });
                }
            }
        }

        committed.append(&mut changes);

        // Step 5: Validate the candidate config with `sshd -t` BEFORE touching
        // the live file. If sshd would refuse to start, abort here: no write, no
        // restart; the running daemon and its config are left fully intact, so
        // there is no lockout path.
        //
        // The candidate is the fragment's body ahead of the main file, because
        // that is the order sshd resolves in and the first value wins. On a
        // vendor-layer host the main file is unchanged, so validating it alone
        // would check nothing this apply is about to write.
        let candidate = match &desired_dropin {
            Some(body) => format!("{body}\n{config_content}"),
            None => config_content.clone(),
        };
        if let Err(e) = validate_sshd_config(ctx.executor().as_ref(), &candidate).await {
            error!("Candidate sshd_config failed validation, aborting apply: {e}");
            committed.push(Change {
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
                apply_changes: committed,
                apply_checkpoint_id: checkpoint_id,
                apply_error: Some(format!("sshd config validation failed: {e}")),
            });
        }

        // Step 6: Write modified configuration using executor. The vendor file
        // is never a write target: creating /etc/ssh/sshd_config to hold these
        // directives would make sshd stop reading the vendor config entirely,
        // discarding its Include lines and every setting it makes.
        if main_write_needed {
            match ctx
                .executor()
                .write_file(Path::new(config_path), &config_content)
                .await
            {
                Ok(_) => {
                    committed.push(Change {
                        change_description: format!("Updated {}", config_path),
                        change_type: ChangeType::ConfigFile,
                        change_success: true,
                        change_error: None,
                    });
                    info!("SSH configuration updated successfully");
                }
                Err(e) => {
                    committed.push(Change {
                        change_description: format!("Failed to write {}", config_path),
                        change_type: ChangeType::ConfigFile,
                        change_success: false,
                        change_error: Some(e.to_string()),
                    });
                    error!("Failed to write SSH config: {}", e);
                }
            }
        }

        // Step 6b: Write the fragment, then ask the resolver whether it
        // actually won. That 00- sorts first is a claim about filenames nobody
        // controls, so it is checked rather than trusted: a directive still
        // answered by another file is a failed change naming that file, never a
        // success.
        if dropin_changed {
            match dropin::write_dropin(ctx, &to_dropin).await {
                Ok(()) => committed.extend(
                    verify_dropin_precedence(ctx, config_path, &to_dropin, &config_content).await,
                ),
                Err(e) => {
                    committed.push(Change {
                        change_description: format!("Failed to write {}", dropin::DROPIN_PATH),
                        change_type: ChangeType::ConfigFile,
                        change_success: false,
                        change_error: Some(e.to_string()),
                    });
                    error!("Failed to write the sshd drop-in: {e}");
                }
            }
        }

        // Step 7: Restart SSH service to apply changes. Only reached after the
        // candidate config passed `sshd -t`, so a restart cannot lock us out.
        match Self::restart_ssh_service(ctx).await {
            Ok(_) => {
                committed.push(Change {
                    change_description: "Restarted SSH service".to_string(),
                    change_type: ChangeType::Service,
                    change_success: true,
                    change_error: None,
                });
                info!("SSH service restarted successfully");
            }
            Err(e) => {
                committed.push(Change {
                    change_description: "Failed to restart SSH service".to_string(),
                    change_type: ChangeType::Service,
                    change_success: false,
                    change_error: Some(e.to_string()),
                });
                error!("Failed to restart SSH service: {}", e);
            }
        }

        let success = committed.iter().all(|c| c.change_success);
        Ok(ApplyResult {
            apply_plugin_id: plugin_id,
            apply_success: success,
            apply_changes: committed,
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

    async fn validate(&self, ctx: &Context, config: &PluginConfig) -> Result<ValidationReport> {
        let mut issues = Vec::new();
        let plugin_id = PluginId::new("ssh-hardening");
        // Validate whichever sshd_config is in force. Where neither layer has
        // one, the admin path is the right file to name: it is where an
        // operator would look, and where a working host would keep it.
        let main = read_layered(ctx.executor().as_ref(), SSHD_ADMIN_CONFIG_PATH).await;
        let resolved_path = match &main {
            LayeredRead::Found { path, .. } => path.clone(),
            LayeredRead::Absent | LayeredRead::Unreadable { .. } => {
                SSHD_ADMIN_CONFIG_PATH.to_string()
            }
        };
        let config_path = Path::new(&resolved_path);

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
        // Excepted directives are recorded rather than dropped: the preview
        // must not show "0 changes" over an empty panel on a host where a
        // deviation is deliberate and documented.
        let mut exceptions = Vec::new();

        // The content already came back from the layered read above; reading it
        // a second time would be a second round trip against a remote host.
        // Whether the apply this previews will write the fragment, which is a
        // file appearing in /etc that the preview said nothing about until the
        // kernel plugin was caught doing the same with 99-hardener.conf.
        let mut writes_fragment = false;

        match &main {
            LayeredRead::Found { content, .. } => {
                // Resolved first, because a preview reading a different
                // configuration from the apply it precedes is not a preview.
                // This parsed the main file alone while scan and apply both
                // resolved the Include, so on the layout RHEL, Fedora and
                // openSUSE ship, a main file already holding the target
                // previewed no change while the apply went on to write a
                // fragment beating the drop-in. Failing to resolve is a
                // blocking issue rather than a fallback to the main file: the
                // fallback is precisely the reading that was wrong.
                let resolved = match include::resolve(ctx, &resolved_path, content).await {
                    Ok(resolved) => resolved,
                    Err(e) => {
                        issues.push(ValidationIssue {
                            validation_issue_severity: Severity::Critical,
                            validation_issue_message: format!(
                                "Cannot resolve sshd_config Include directives: {e}"
                            ),
                            validation_issue_config_key: None,
                        });
                        return Ok(ValidationReport {
                            validation_report_plugin_id: plugin_id,
                            validation_report_is_valid: false,
                            validation_report_issues: issues,
                            validation_report_estimated_changes: estimated_changes,
                            validation_report_compliant_count: 0,
                            validation_report_exceptions: exceptions,
                        });
                    }
                };

                // Check each directive to see if it needs updating.
                for directive in SSH_DIRECTIVES {
                    // Resolve the target the way apply and scan do, through the
                    // one function all three call.
                    let target = resolved_target(directive, config);

                    // The value sshd obeys, from whichever file supplies it.
                    let effective = resolved.effective(directive.ssh_directive_name);
                    let current_value = effective.as_ref().map(|e| e.value.clone());
                    // A directive another file answers first is one the apply
                    // routes to the fragment, whatever the main file says.
                    let overridden = effective
                        .as_ref()
                        .is_some_and(|e| e.source != resolved_path);

                    // The exception is honoured only when it documents the
                    // value the host actually has, matching apply's rendering
                    // of an absent directive as "not set".
                    let observed = current_value
                        .clone()
                        .unwrap_or_else(|| "not set".to_string());
                    if let Some(exception) =
                        config.matching_exception(directive.ssh_directive_name, &observed)
                    {
                        exceptions.push(hardener_common::types::exception_preview_line(
                            directive.ssh_directive_name,
                            &observed,
                            &exception.reason,
                        ));
                        continue;
                    }

                    match current_value {
                        Some(value)
                            if !directive.ssh_compare.violated_by(&target, Some(&value)) =>
                        {
                            // Already set to the target value - no change needed.
                        }
                        Some(value) if overridden => {
                            writes_fragment = true;
                            estimated_changes.push(format!(
                                "{}: {} → {}",
                                directive.ssh_directive_name, value, target
                            ));
                        }
                        Some(value) => {
                            // Value exists but does not match the target.
                            estimated_changes.push(format!(
                                "{}: {} → {}",
                                directive.ssh_directive_name, value, target
                            ));
                        }
                        None => {
                            // Directive not set - will add it.
                            estimated_changes.push(format!(
                                "{}: (not set) → {}",
                                directive.ssh_directive_name, target
                            ));
                        }
                    }
                }

                // The crypto directives were previewed by nothing at all
                // until now: an apply writing three cryptographic lists
                // announced none of them. The target is the intersection of
                // this tool's allow-list with what the host supports, so the
                // preview asks `ssh -Q` exactly as the apply does; a host that
                // cannot answer yields an empty intersection, which the apply
                // skips and the preview therefore omits, so the two agree.
                for crypto in SSH_CRYPTO_DIRECTIVES {
                    let effective = resolved.effective(crypto.crypto_directive_name);
                    let current_value = effective.as_ref().map(|e| e.value.clone());
                    let observed = current_value
                        .clone()
                        .unwrap_or_else(|| "not set".to_string());
                    if let Some(exception) =
                        config.matching_exception(crypto.crypto_directive_name, &observed)
                    {
                        exceptions.push(hardener_common::types::exception_preview_line(
                            crypto.crypto_directive_name,
                            &observed,
                            &exception.reason,
                        ));
                        continue;
                    }
                    if crypto_value_is_secure(current_value.as_deref(), crypto.crypto_desired) {
                        continue;
                    }
                    let supported =
                        supported_algorithms(ctx.executor().as_ref(), crypto.crypto_query_arg)
                            .await;
                    let selected = select_algorithms(crypto.crypto_desired, &supported);
                    if selected.is_empty() {
                        continue;
                    }
                    if effective
                        .as_ref()
                        .is_some_and(|e| e.source != resolved_path)
                    {
                        writes_fragment = true;
                    }
                    estimated_changes.push(format!(
                        "{}: {} → {}",
                        crypto.crypto_directive_name,
                        observed,
                        selected.join(",")
                    ));
                }
            }
            LayeredRead::Absent => {
                issues.push(ValidationIssue {
                    validation_issue_severity: Severity::Critical,
                    validation_issue_message: format!(
                        "Cannot read {}: no sshd_config exists there or at its /usr/etc \
                         counterpart",
                        config_path.display()
                    ),
                    validation_issue_config_key: None,
                });
            }
            LayeredRead::Unreadable { path, reason, .. } => {
                issues.push(ValidationIssue {
                    validation_issue_severity: Severity::Critical,
                    validation_issue_message: format!("Cannot read {path}: {reason}"),
                    validation_issue_config_key: None,
                });
            }
        }

        // Named once rather than per directive: the fragment is one file, and
        // an operator approving this run should know a file will appear in /etc
        // that no line above mentions.
        if writes_fragment {
            estimated_changes.push(format!(
                "{} will be written so the settings above are the ones sshd reads first",
                dropin::DROPIN_PATH
            ));
        }

        let valid = issues.is_empty();
        Ok(ValidationReport {
            validation_report_plugin_id: plugin_id,
            validation_report_is_valid: valid,
            validation_report_issues: issues,
            validation_report_estimated_changes: estimated_changes,
            validation_report_compliant_count: 0,
            validation_report_exceptions: exceptions,
        })
    }
}
