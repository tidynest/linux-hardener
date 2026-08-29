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

mod apply;
mod assess;
mod divergence;
mod dropin;
// pub(crate) so the crate's fuzz-seam module can re-export the include
// parsers; every other consumer meets them through scan, apply and validate.
pub(crate) mod include;
mod validate;

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
use hardener_common::{
    error::Result,
    types::{ComplianceFramework, ComplianceMapping, FindingCategory, PluginId, Severity},
    vendor_config::ConfigLayer,
};
use hardener_core::{
    ApplyResult, Change, ChangeType, PluginConfig, ValidationReport,
    context::Context,
    plugin::{HardeningPlugin, PluginMetadata, ScanResult, UncheckedBlocker, UncheckedCheck},
};
use std::path::Path;
use tracing::{info, warn};

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
                "Failed to write temp sshd_config for validation: {:#}",
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
            "Failed to execute `sshd -t`: {:#}",
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

/// How a directive's current value is rendered when it is compared against a
/// policy exception's documented value: what sshd obeys, from whichever file
/// supplies it, or `not set` where nothing supplies it at all.
///
/// Scan, validate and apply all read it here for the same reason they all
/// resolve their target through `resolved_target`: the three have to agree
/// about which host an exception applies to, and the exception is honoured
/// only when it documents the value the host actually has.
///
/// Apply used to read the main file's global scope alone. On the layout RHEL,
/// Fedora and openSUSE ship, where a drop-in answers the keyword before
/// anything this tool writes, that made it compare an exception against
/// `not set` while scan and the preview compared it against the drop-in's
/// value. The operator was told their exception was honoured, and the apply
/// that message described went on to overwrite the value it documented.
fn observed_value(effective: Option<&include::EffectiveValue>) -> String {
    effective.map_or_else(|| "not set".to_string(), |e| e.value.clone())
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

/// Everything a backup of `config_path` carries before its timestamp.
///
/// One source for the copy and for both prunes, so they cannot come to
/// disagree about which files are backups: a prune whose prefix had drifted
/// from the writer's would silently match nothing and the copies would
/// accumulate again with nothing failing.
fn backup_prefix(config_path: &str) -> String {
    format!("{config_path}.backup.")
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

        // Fallback to the service command, under both names the families use.
        //
        // Only reachable once systemctl has already failed, so the host has no
        // working systemd and its init script is what matters: Debian calls it
        // `ssh`, the Red Hat family and openSUSE call it `sshd`. This asked for
        // Debian's name on every distribution, so a non-systemd Rocky or Fedora
        // host was told to restart a service that does not exist there, and the
        // message it got back named that absence rather than the real problem.
        // Trying both costs one extra process on the host where the first name
        // is wrong, which is cheaper and far more predictable than detecting
        // the distribution to choose.
        //
        // `sshd` first, to match the systemctl attempt above; the divergence
        // probe is tied to that same name and says so at `divergence.rs`.
        let mut attempts = Vec::new();
        for unit in ["sshd", "ssh"] {
            match ctx
                .executor()
                .execute_command("service", &[unit, "restart"])
                .await
            {
                Ok(output) if output.success() => {
                    info!("SSH service restarted successfully via `service {unit} restart`");
                    return Ok(());
                }
                Ok(output) => attempts.push(format!("`service {unit} restart`: {}", output.stderr)),
                Err(e) => attempts.push(format!("`service {unit} restart`: {e:#}")),
            }
        }

        // Every attempt, not just the last. Reporting one would send an
        // operator after the wrong init script, and reporting the last would
        // hide that the other name was tried at all.
        Err(hardener_common::error::HardeningError::Plugin(format!(
            "Failed to restart SSH service: {}",
            attempts.join("; ")
        )))
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
            // SSG: sshd_disable_root_login declares
            // `AC-6(2),AC-17(a),IA-2,IA-2(5),CM-7(a),CM-7(b),CM-6(a)`. AC-17(a)
            // is carried here because it was otherwise mapped in exactly one
            // place in the tree, the /etc/ssh arm of the permissions plugin,
            // which asks what mode the directory carries. That check answers
            // its own question honestly on a host with no /etc/ssh and returns
            // Clear, which the generator reads as a Pass for a remote-access
            // control nothing had assessed (#167). The rule that reads the
            // configuration must be able to speak for it.
            ComplianceMapping {
                compliance_framework: ComplianceFramework::NIST,
                compliance_control_id: "AC-17(a)".to_string(),
                compliance_control_title: "Remote Access - Usage Restrictions and Configuration"
                    .to_string(),
                compliance_section: Some("Access Control".to_string()),
            },
            // ISO 27001:2022 8.2 is the successor of A.9.2.3, which the same
            // SSG rule declares. Not an analogy: the correspondence is the
            // standard's own, and the tree numbers ISO by the 2022 revision.
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.2".to_string(),
                compliance_control_title: "Privileged access rights".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            // 800-171r3 3.1.12 ← 800-53 AC-17 (SP 800-171r3 source-control table).
            nist171("3.1.12", "Remote Access"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 AC-17.
            fedramp(
                "AC-17(a)",
                "Remote Access - Usage Restrictions and Configuration",
            ),
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
            // SSG: sshd_set_idle_timeout declares
            // `CM-6(a),AC-17(a),AC-2(5),AC-12,SC-10`. Carried for the same
            // reason as on PermitRootLogin, and not only for the absent-host
            // case: a readable configuration with a compliant PermitRootLogin
            // and no idle timeout would otherwise report AC-17(a) as a Pass
            // that one of its two sourced rules contradicts.
            ComplianceMapping {
                compliance_framework: ComplianceFramework::NIST,
                compliance_control_id: "AC-17(a)".to_string(),
                compliance_control_title: "Remote Access - Usage Restrictions and Configuration"
                    .to_string(),
                compliance_section: Some("Access Control".to_string()),
            },
            // 800-171r3 3.1.12 ← 800-53 AC-17 (SP 800-171r3 source-control table).
            nist171("3.1.12", "Remote Access"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 AC-17.
            fedramp(
                "AC-17(a)",
                "Remote Access - Usage Restrictions and Configuration",
            ),
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
        assess::scan(ctx, config).await
    }

    async fn apply(&self, ctx: &mut Context, config: &PluginConfig) -> Result<ApplyResult> {
        apply::apply(ctx, config).await
    }

    // Known gap: on a host whose /etc has no sshd_config, `apply` checkpoints
    // the vendor copy at /usr/etc/ssh/sshd_config (read_layered's resolution
    // of config_path), which this prefix does not cover. Left uncovered
    // rather than widened to /usr/etc, because on exactly that host every
    // managed directive is written to the drop-in instead, which lives under
    // /etc/ssh and is covered here, so a rollback of that checkpoint still
    // restarts sshd. Widening the prefix would need its own justification -
    // this one is why the gap is safe, not a reason to close it.
    fn reloads_for_path(&self, path: &Path) -> bool {
        path.starts_with("/etc/ssh")
    }

    async fn reload_after_rollback(&self, ctx: &Context) -> Result<Option<String>> {
        Self::restart_ssh_service(ctx).await?;
        info!("SSH service restarted after rollback");
        Ok(Some("sshd restarted".to_string()))
    }

    async fn divergences_after_rollback(
        &self,
        ctx: &Context,
        restored: &[std::path::PathBuf],
    ) -> Vec<hardener_types::RollbackDivergence> {
        // The gate this replaces used to live in the dispatch (#142). Same
        // predicate, one level down, so behaviour is unchanged.
        if !restored.iter().any(|path| self.reloads_for_path(path)) {
            return Vec::new();
        }
        divergence::sshd_divergences(ctx).await
    }

    async fn validate(&self, ctx: &Context, config: &PluginConfig) -> Result<ValidationReport> {
        validate::validate(ctx, config).await
    }
}

#[cfg(test)]
mod tests;
