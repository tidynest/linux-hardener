//! PAM (Pluggable Authentication Modules) hardening plugin
//!
//! This plugin hardens system authentication by configuring:
//! - Password quality requirements (complexity, length)
//! - Account lockout policies (failed login attempts)
//! - Password ageing policies (expiry, reuse prevention)

use async_trait::async_trait;
use hardener_common::file_utils::{ConfigFormat, parse_config_value};
use hardener_common::{
    error::{HardeningError, Result},
    types::{ComplianceFramework, ComplianceMapping, FindingCategory, PluginId, Severity},
};
use hardener_core::{
    Change, ChangeType, Checkpoint, Context, PluginConfig,
    plugin::{
        ApplyResult, Finding, HardeningPlugin, PluginMetadata, ScanResult, UncheckedCheck,
        ValidationIssue, ValidationReport,
    },
};
use std::path::Path;
use std::time::Instant;
use tracing::{debug, info, warn};

/// PAM hardening plugin.
pub struct PamHardeningPlugin {}

impl Default for PamHardeningPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl PamHardeningPlugin {
    /// Creates a new PAM hardening plugin instance.
    pub fn new() -> PamHardeningPlugin {
        PamHardeningPlugin {}
    }
}

/// Builds a single [`ComplianceMapping`] under the shared "Access Control" section.
///
/// Keeps the per-check mapping tables below terse and free of repetition.
fn pam_mapping(framework: ComplianceFramework, control_id: &str, title: &str) -> ComplianceMapping {
    pam_mapping_in(framework, control_id, title, "Access Control")
}

/// Builds a [`ComplianceMapping`] under an explicit section.
///
/// Used for frameworks whose catalogue groups controls differently from the
/// default "Access Control" section, notably ISO/IEC 27001:2022, whose Annex A
/// controls live under the "Technological" theme.
fn pam_mapping_in(
    framework: ComplianceFramework,
    control_id: &str,
    title: &str,
    section: &str,
) -> ComplianceMapping {
    ComplianceMapping {
        compliance_framework: framework,
        compliance_control_id: control_id.to_string(),
        compliance_control_title: title.to_string(),
        compliance_section: Some(section.to_string()),
    }
}

/// HIPAA Security Rule mapping for PAM password-management controls.
///
/// All PAM password quality/ageing/history/lockout checks implement the
/// addressable Password Management specification at 45 CFR §164.308(a)(5)(ii)(D).
fn pam_hipaa_password_mgmt() -> ComplianceMapping {
    pam_mapping(
        ComplianceFramework::HIPAA,
        "164.308(a)(5)(ii)(D)",
        "Password Management",
    )
}

/// GDPR mapping for PAM authentication-strength controls.
///
/// Strong authentication is a technical measure for security of processing
/// under Article 32; "TM-AUTH" is the project's authentication technical-measure tag.
fn pam_gdpr_auth() -> ComplianceMapping {
    pam_mapping(
        ComplianceFramework::GDPR,
        "TM-AUTH",
        "Technical measure: authentication strength",
    )
}

/// ISO/IEC 27001:2022 Annex A mapping for PAM authentication controls.
///
/// Control 8.5 (Secure authentication) covers password policy, account lockout
/// and authentication strength; it sits under the "Technological" theme.
fn pam_iso_secure_auth() -> ComplianceMapping {
    pam_mapping_in(
        ComplianceFramework::ISO27001,
        "8.5",
        "Secure authentication",
        "Technological",
    )
}

/// SOC 2 mapping for PAM authentication controls.
///
/// CC6.1 mirrors the authenticator-management / lockout intent (IA-5(1),
/// AC-7) every PAM check strengthens; the section is the criterion's 2017
/// Trust Services Criteria series.
fn pam_soc2_logical_access() -> ComplianceMapping {
    pam_mapping_in(
        ComplianceFramework::SOC2,
        "CC6.1",
        "Logical access security software, infrastructure, and architectures",
        "Logical and Physical Access Controls",
    )
}

/// NIST SP 800-171 Revision 3 mapping for PAM password-quality and ageing checks.
///
/// Requirement 3.5.7 (Password Management) is sourced from 800-53 IA-5(1) in
/// the r3 source-control table: the control the password arms here already
/// cite as IA-5(1)(a)/(d). Family: Identification and Authentication.
fn pam_nist171_password_mgmt() -> ComplianceMapping {
    pam_mapping_in(
        ComplianceFramework::NIST800171,
        "3.5.7",
        "Password Management",
        "Identification and Authentication",
    )
}

/// NIST SP 800-171 Revision 3 mapping for the PAM faillock lockout check.
///
/// Requirement 3.1.8 (Unsuccessful Logon Attempts) is sourced from 800-53
/// AC-7 in the r3 source-control table; its official family matches the
/// shared "Access Control" section.
fn pam_nist171_unsuccessful_logons() -> ComplianceMapping {
    pam_mapping(
        ComplianceFramework::NIST800171,
        "3.1.8",
        "Unsuccessful Logon Attempts",
    )
}

/// FedRAMP mapping for PAM password-quality checks.
///
/// FedRAMP's control set is NIST 800-53 at the Moderate (Rev 5) baseline;
/// IA-5(1) is a baseline member (GSA rev5 baseline), so the quality arms'
/// existing IA-5(1)(a) entry mirrors across verbatim. Family: Identification
/// and Authentication.
fn pam_fedramp_password_quality() -> ComplianceMapping {
    pam_mapping_in(
        ComplianceFramework::FedRAMP,
        "IA-5(1)(a)",
        "Authenticator Management | Password-Based Authentication",
        "Identification and Authentication",
    )
}

/// FedRAMP mapping for PAM password-ageing checks.
///
/// Same baseline membership as [`pam_fedramp_password_quality`]; the ageing
/// arms cite part (d) of IA-5(1), so the printed id follows suit.
fn pam_fedramp_password_ageing() -> ComplianceMapping {
    pam_mapping_in(
        ComplianceFramework::FedRAMP,
        "IA-5(1)(d)",
        "Authenticator Management | Password-Based Authentication",
        "Identification and Authentication",
    )
}

/// FedRAMP mapping for the PAM faillock lockout check.
///
/// AC-7 is a FedRAMP Moderate (Rev 5) baseline member (GSA rev5 baseline);
/// the lockout arm's AC-7(a) entry mirrors across verbatim under the shared
/// "Access Control" section: the control's official 800-53 family.
fn pam_fedramp_unsuccessful_logons() -> ComplianceMapping {
    pam_mapping(
        ComplianceFramework::FedRAMP,
        "AC-7(a)",
        "Unsuccessful Logon Attempts",
    )
}

/// Returns compliance mappings for PAM findings.
///
/// Multi-framework control IDs are sourced from the ComplianceAsCode/SSG rule
/// `references:` blocks for the matching SSG rule (cited per arm). NIST IDs use
/// 800-53 Rev 5 base controls; STIG IDs are the RHEL 8 DISA STIG group IDs;
/// PCI-DSS uses v4.0 requirement numbers. A framework is omitted where the SSG
/// rule carries no authoritative mapping for it.
///
/// HIPAA, GDPR, ISO/IEC 27001:2022 and SOC 2 apply uniformly to every PAM
/// authentication check, since each one strengthens password management /
/// authentication: HIPAA §164.308(a)(5)(ii)(D) (Password Management), GDPR
/// "TM-AUTH" (Article 32 technical measure), ISO 27001 Annex A 8.5 (Secure
/// authentication, "Technological" theme), and SOC 2 CC6.1 (logical access).
/// NIST SP 800-171 is attached only where an arm carries an 800-53 source
/// control (IA-5(1) → 3.5.7, AC-7 → 3.1.8); arms with no 800-53 reference
/// honestly carry no 800-171 mapping. FedRAMP follows the same rule: IA-5(1)
/// and AC-7 are both FedRAMP Moderate (Rev 5) baseline members, so their
/// arms mirror the 800-53 ids verbatim, and arms with no 800-53 reference
/// carry no FedRAMP mapping either.
/// Every compliance mapping this plugin can emit, across all PAM/login.defs
/// directives it assesses. Aggregated into the engine's coverage set.
pub fn coverage() -> Vec<ComplianceMapping> {
    PAM_DIRECTIVES
        .iter()
        .flat_map(|d| get_pam_compliance_mappings(d.pam_directive_name))
        .collect()
}

fn get_pam_compliance_mappings(check_name: &str) -> Vec<ComplianceMapping> {
    match check_name {
        // SSG: accounts_password_pam_minlen (stigid RHEL-08-020230)
        name if name.contains("minlen") || name.contains("complexity") => vec![
            pam_mapping(
                ComplianceFramework::CIS,
                "5.3.1",
                "Ensure password creation requirements are configured",
            ),
            pam_mapping(
                ComplianceFramework::STIG,
                "RHEL-08-020230",
                "RHEL 8 passwords must have a minimum of 15 characters",
            ),
            pam_mapping(
                ComplianceFramework::NIST,
                "IA-5(1)(a)",
                "Authenticator Management | Password-Based Authentication",
            ),
            // 800-171r3 3.5.7 ← 800-53 IA-5(1) (SP 800-171r3 source-control table).
            pam_nist171_password_mgmt(),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 IA-5(1).
            pam_fedramp_password_quality(),
            pam_mapping(
                ComplianceFramework::PCIDSS,
                "8.2.3",
                "Strong passwords and passphrases",
            ),
            pam_hipaa_password_mgmt(),
            pam_gdpr_auth(),
            pam_iso_secure_auth(),
            pam_soc2_logical_access(),
        ],
        // SSG: accounts_password_pam_dcredit (stigid RHEL-08-020130)
        name if name.contains("dcredit") => vec![
            pam_mapping(
                ComplianceFramework::CIS,
                "5.3.1",
                "Ensure password creation requirements are configured",
            ),
            pam_mapping(
                ComplianceFramework::STIG,
                "RHEL-08-020130",
                "RHEL 8 must enforce password complexity by requiring at least one numeric character",
            ),
            pam_mapping(
                ComplianceFramework::NIST,
                "IA-5(1)(a)",
                "Authenticator Management | Password-Based Authentication",
            ),
            // 800-171r3 3.5.7 ← 800-53 IA-5(1) (SP 800-171r3 source-control table).
            pam_nist171_password_mgmt(),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 IA-5(1).
            pam_fedramp_password_quality(),
            pam_mapping(
                ComplianceFramework::PCIDSS,
                "8.2.3",
                "Strong passwords and passphrases",
            ),
            pam_hipaa_password_mgmt(),
            pam_gdpr_auth(),
            pam_iso_secure_auth(),
            pam_soc2_logical_access(),
        ],
        // SSG: accounts_password_pam_ucredit (stigid RHEL-08-020110)
        name if name.contains("ucredit") => vec![
            pam_mapping(
                ComplianceFramework::CIS,
                "5.3.1",
                "Ensure password creation requirements are configured",
            ),
            pam_mapping(
                ComplianceFramework::STIG,
                "RHEL-08-020110",
                "RHEL 8 must enforce password complexity by requiring at least one uppercase character",
            ),
            pam_mapping(
                ComplianceFramework::NIST,
                "IA-5(1)(a)",
                "Authenticator Management | Password-Based Authentication",
            ),
            // 800-171r3 3.5.7 ← 800-53 IA-5(1) (SP 800-171r3 source-control table).
            pam_nist171_password_mgmt(),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 IA-5(1).
            pam_fedramp_password_quality(),
            pam_mapping(
                ComplianceFramework::PCIDSS,
                "8.2.3",
                "Strong passwords and passphrases",
            ),
            pam_hipaa_password_mgmt(),
            pam_gdpr_auth(),
            pam_iso_secure_auth(),
            pam_soc2_logical_access(),
        ],
        // SSG: accounts_password_pam_lcredit (stigid RHEL-08-020120)
        name if name.contains("lcredit") => vec![
            pam_mapping(
                ComplianceFramework::CIS,
                "5.3.1",
                "Ensure password creation requirements are configured",
            ),
            pam_mapping(
                ComplianceFramework::STIG,
                "RHEL-08-020120",
                "RHEL 8 must enforce password complexity by requiring at least one lowercase character",
            ),
            pam_mapping(
                ComplianceFramework::NIST,
                "IA-5(1)(a)",
                "Authenticator Management | Password-Based Authentication",
            ),
            // 800-171r3 3.5.7 ← 800-53 IA-5(1) (SP 800-171r3 source-control table).
            pam_nist171_password_mgmt(),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 IA-5(1).
            pam_fedramp_password_quality(),
            pam_mapping(
                ComplianceFramework::PCIDSS,
                "8.2.3",
                "Strong passwords and passphrases",
            ),
            pam_hipaa_password_mgmt(),
            pam_gdpr_auth(),
            pam_iso_secure_auth(),
            pam_soc2_logical_access(),
        ],
        // SSG: accounts_password_pam_ocredit (stigid RHEL-08-020280). No PCI-DSS in SSG.
        name if name.contains("ocredit") => vec![
            pam_mapping(
                ComplianceFramework::CIS,
                "5.3.1",
                "Ensure password creation requirements are configured",
            ),
            pam_mapping(
                ComplianceFramework::STIG,
                "RHEL-08-020280",
                "RHEL 8 must enforce password complexity by requiring at least one special character",
            ),
            pam_mapping(
                ComplianceFramework::NIST,
                "IA-5(1)(a)",
                "Authenticator Management | Password-Based Authentication",
            ),
            // 800-171r3 3.5.7 ← 800-53 IA-5(1) (SP 800-171r3 source-control table).
            pam_nist171_password_mgmt(),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 IA-5(1).
            pam_fedramp_password_quality(),
            pam_hipaa_password_mgmt(),
            pam_gdpr_auth(),
            pam_iso_secure_auth(),
            pam_soc2_logical_access(),
        ],
        // SSG: accounts_password_pam_maxrepeat (stigid RHEL-08-020150). No PCI-DSS in SSG.
        name if name.contains("maxrepeat") => vec![
            pam_mapping(
                ComplianceFramework::CIS,
                "5.3.1",
                "Ensure password creation requirements are configured",
            ),
            pam_mapping(
                ComplianceFramework::STIG,
                "RHEL-08-020150",
                "RHEL 8 passwords must not contain more than three consecutive repeating characters",
            ),
            pam_mapping(
                ComplianceFramework::NIST,
                "IA-5(1)(a)",
                "Authenticator Management | Password-Based Authentication",
            ),
            // 800-171r3 3.5.7 ← 800-53 IA-5(1) (SP 800-171r3 source-control table).
            pam_nist171_password_mgmt(),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 IA-5(1).
            pam_fedramp_password_quality(),
            pam_hipaa_password_mgmt(),
            pam_gdpr_auth(),
            pam_iso_secure_auth(),
            pam_soc2_logical_access(),
        ],
        // SSG: accounts_passwords_pam_faillock_deny (stigid RHEL-08-020011)
        name if name.contains("lockout") || name.contains("deny") => vec![
            pam_mapping(
                ComplianceFramework::CIS,
                "5.3.2",
                "Ensure lockout for failed password attempts is configured",
            ),
            pam_mapping(
                ComplianceFramework::STIG,
                "RHEL-08-020011",
                "RHEL 8 must automatically lock an account when three unsuccessful logon attempts occur",
            ),
            pam_mapping(
                ComplianceFramework::NIST,
                "AC-7(a)",
                "Unsuccessful Logon Attempts",
            ),
            // 800-171r3 3.1.8 ← 800-53 AC-7 (SP 800-171r3 source-control table).
            pam_nist171_unsuccessful_logons(),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 AC-7.
            pam_fedramp_unsuccessful_logons(),
            pam_mapping(
                ComplianceFramework::PCIDSS,
                "8.1.6",
                "Limit repeated access attempts by locking out the user ID",
            ),
            pam_hipaa_password_mgmt(),
            pam_gdpr_auth(),
            pam_iso_secure_auth(),
            pam_soc2_logical_access(),
        ],
        // SSG: accounts_password_pam_pwhistory_remember. SSG rule carries no
        // NIST/STIG/PCI-DSS reference, so only CIS is mapped (no guessing).
        name if name.contains("remember") || name.contains("reuse") => vec![
            pam_mapping(
                ComplianceFramework::CIS,
                "5.3.3",
                "Ensure password reuse is limited",
            ),
            pam_hipaa_password_mgmt(),
            pam_gdpr_auth(),
            pam_iso_secure_auth(),
            pam_soc2_logical_access(),
        ],
        // SSG: accounts_maximum_age_login_defs (stigid RHEL-08-020200)
        name if name.contains("PASS_MAX_DAYS") => vec![
            pam_mapping(
                ComplianceFramework::CIS,
                "5.4.1.1",
                "Ensure password expiration is 365 days or less",
            ),
            pam_mapping(
                ComplianceFramework::STIG,
                "RHEL-08-020200",
                "RHEL 8 user account passwords must have a 60-day maximum password lifetime restriction",
            ),
            pam_mapping(
                ComplianceFramework::NIST,
                "IA-5(1)(d)",
                "Authenticator Management | Password-Based Authentication",
            ),
            // 800-171r3 3.5.7 ← 800-53 IA-5(1) (SP 800-171r3 source-control table).
            pam_nist171_password_mgmt(),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 IA-5(1).
            pam_fedramp_password_ageing(),
            pam_mapping(
                ComplianceFramework::PCIDSS,
                "8.2.4",
                "Change user passwords/passphrases at least once every 90 days",
            ),
            pam_hipaa_password_mgmt(),
            pam_gdpr_auth(),
            pam_iso_secure_auth(),
            pam_soc2_logical_access(),
        ],
        // SSG: accounts_minimum_age_login_defs (stigid RHEL-08-020190). No PCI-DSS in SSG.
        name if name.contains("PASS_MIN_DAYS") => vec![
            pam_mapping(
                ComplianceFramework::CIS,
                "5.4.1.2",
                "Ensure minimum days between password changes is configured",
            ),
            pam_mapping(
                ComplianceFramework::STIG,
                "RHEL-08-020190",
                "RHEL 8 passwords for new users must have a minimum of 24 hours between password changes",
            ),
            pam_mapping(
                ComplianceFramework::NIST,
                "IA-5(1)(d)",
                "Authenticator Management | Password-Based Authentication",
            ),
            // 800-171r3 3.5.7 ← 800-53 IA-5(1) (SP 800-171r3 source-control table).
            pam_nist171_password_mgmt(),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 IA-5(1).
            pam_fedramp_password_ageing(),
            pam_hipaa_password_mgmt(),
            pam_gdpr_auth(),
            pam_iso_secure_auth(),
            pam_soc2_logical_access(),
        ],
        // SSG: accounts_password_warn_age_login_defs. SSG rule carries no STIG, so
        // STIG is omitted; NIST and PCI-DSS are mapped from its references block.
        name if name.contains("PASS_WARN_AGE") => vec![
            pam_mapping(
                ComplianceFramework::CIS,
                "5.4.1.3",
                "Ensure password expiration warning days is 7 or more",
            ),
            pam_mapping(
                ComplianceFramework::NIST,
                "IA-5(1)(d)",
                "Authenticator Management | Password-Based Authentication",
            ),
            // 800-171r3 3.5.7 ← 800-53 IA-5(1) (SP 800-171r3 source-control table).
            pam_nist171_password_mgmt(),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 IA-5(1).
            pam_fedramp_password_ageing(),
            pam_mapping(
                ComplianceFramework::PCIDSS,
                "8.2.4",
                "Change user passwords/passphrases at least once every 90 days",
            ),
            pam_hipaa_password_mgmt(),
            pam_gdpr_auth(),
            pam_iso_secure_auth(),
            pam_soc2_logical_access(),
        ],
        _ => vec![
            pam_mapping(
                ComplianceFramework::CIS,
                "5.3.1",
                "Ensure password creation requirements are configured",
            ),
            pam_hipaa_password_mgmt(),
            pam_gdpr_auth(),
            pam_iso_secure_auth(),
            pam_soc2_logical_access(),
        ],
    }
}

#[async_trait]
impl HardeningPlugin for PamHardeningPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            plugin_category: FindingCategory::Authentication,
            plugin_description:
                "Hardens PAM authentication (password policies, account lockout, ageing)"
                    .to_string(),
            plugin_id: PluginId::from("pam-hardening"),
            plugin_name: "PAM Authentication Hardening".to_string(),
            plugin_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    fn dependencies(&self) -> Vec<PluginId> {
        vec![]
    }

    async fn scan(&self, ctx: &Context, config: &PluginConfig) -> Result<ScanResult> {
        let start = Instant::now();
        info!("Starting PAM authentication hardening scan");

        let mut findings = Vec::new();
        let mut unchecked = Vec::new();

        // Read configuration files.
        let pwquality = read_conf_classified(ctx, "/etc/security/pwquality.conf").await;

        let login_defs_content: String = read_login_defs(ctx).await.unwrap_or_else(|e| {
            warn!("Failed to read login.defs: {}", e);
            String::new()
        });

        // Check each PAM directive.
        for directive in PAM_DIRECTIVES {
            if directive.pam_config_file == PamConfigFile::PamAuth {
                debug!(
                    "Skipping PAM module directive: {}",
                    directive.pam_directive_name
                );
                continue;
            }

            let current_value =
                match observed_pam_value(ctx, directive, &pwquality, &login_defs_content).await {
                    PamObserved::Value(v) => Some(v),
                    PamObserved::NotSet => None,
                    PamObserved::PermissionDenied(path) => {
                        unchecked.push(unchecked_pam_directive(directive, path));
                        continue;
                    }
                };

            // Resolve the effective target the same way apply does: a
            // directive override wins over the hardcoded baseline, and for
            // threshold directives (AtMost/AtLeast) it is clamped so an
            // override can only tighten, never loosen (apply ~725-729,
            // ~761-766).
            let target: String = match directive.pam_compare {
                PamCompare::Exact => config
                    .directives
                    .get(directive.pam_directive_name)
                    .map(|s| s.as_str())
                    .unwrap_or(directive.pam_secure_value)
                    .to_string(),
                compare => {
                    let secure: i64 = directive
                        .pam_secure_value
                        .parse()
                        .expect("pam_secure_value must be a valid integer");
                    let over = config
                        .directives
                        .get(directive.pam_directive_name)
                        .and_then(|s| s.parse::<i64>().ok());
                    clamp_target(compare, secure, over).to_string()
                }
            };

            // Check if current value satisfies the directive's comparison
            // against the resolved (overridden + clamped) target.
            let is_secure = !pam_violates(directive, &target, current_value.as_deref());

            if !is_secure {
                let current_display = current_value.unwrap_or_else(|| "not set".to_string());
                let policy_exception = config
                    .matching_exception(directive.pam_directive_name, &current_display)
                    .map(|e| e.to_finding_exception());

                findings.push(Finding {
                    finding_id: format!(
                        "pam-{}",
                        directive.pam_directive_name
                    ),
                    finding_category: FindingCategory::Authentication,
                    finding_current_value: current_display.clone(),
                    finding_description: format!(
                        "PAM directive '{}' is currently '{}' but should be '{}'",
                        directive.pam_directive_name,
                        current_display,
                        target,
                    ),
                    finding_explanation: directive.pam_description.to_string(),
                    finding_impact: "Weak authentication settings can allow easier password guessing and brute-force attacks".to_string(),
                    finding_recommended_value: target.clone(),
                    finding_remediation_steps: vec![
                        format!(
                            "Set {} = {} in the appropriate configuration file",
                            directive.pam_directive_name,
                            target,
                        ),
                    ],
                    finding_severity: directive.pam_severity,
                    finding_title: format!(
                        "Insecure PAM setting: {}",
                        directive.pam_directive_name
                    ),
                    finding_compliance: get_pam_compliance_mappings(directive.pam_directive_name),
                    finding_policy_exception: policy_exception,
                });
            }
        }

        let duration_us = start.elapsed().as_micros() as u64;

        info!(
            "PAM scan completed: {} findings in {}µs",
            findings.len(),
            duration_us,
        );

        Ok(ScanResult {
            scan_plugin_id: self.metadata().plugin_id,
            scan_success: true,
            scan_findings: findings,
            scan_unchecked: unchecked,
            scan_duration_us: duration_us,
            scan_error: None,
        })
    }

    async fn apply(&self, ctx: &mut Context, config: &PluginConfig) -> Result<ApplyResult> {
        let start = Instant::now();
        info!("Starting PAM authentication hardening apply");

        let mut changes = Vec::new();
        let mut all_success = true;

        // Create checkpoint before changes
        let pam_paths: Vec<&Path> = vec![
            Path::new("/etc/security/pwquality.conf"),
            Path::new("/etc/login.defs"),
            Path::new("/etc/pam.d"),
            Path::new("/etc/security/faillock.conf"),
            Path::new("/etc/security/pwhistory.conf"),
        ];
        let checkpoint_id =
            crate::create_checkpoint_for_apply(ctx, "pam-hardening-pre-apply", &pam_paths).await?;

        changes.extend(crate::checkpoint_change(&checkpoint_id));

        // Step 1: Read current configuration files. Backups are created later,
        // and only for a file that will actually be rewritten, so a compliant
        // host accumulates no backup churn in /etc.
        let pwquality_read = read_conf_classified(ctx, "/etc/security/pwquality.conf").await;
        let pwquality_writable = match &pwquality_read {
            ConfRead::Unreadable(e) => {
                warn!("Refusing to rewrite /etc/security/pwquality.conf: {}", e);
                all_success = false;
                changes.push(Change {
                    change_type: ChangeType::ConfigFile,
                    change_description:
                        "Refused to rewrite /etc/security/pwquality.conf: its current contents \
                         could not be read, and rewriting it would discard them"
                            .to_string(),
                    change_success: false,
                    change_error: Some(e.clone()),
                });
                false
            }
            _ => true,
        };
        let mut pwquality_content = match &pwquality_read {
            ConfRead::Content(content) => content.clone(),
            _ => String::new(),
        };
        let mut pwquality_changed = false;

        let login_defs_read = read_conf_classified(ctx, "/etc/login.defs").await;
        let login_defs_writable = match &login_defs_read {
            ConfRead::Unreadable(e) => {
                warn!("Refusing to rewrite /etc/login.defs: {}", e);
                all_success = false;
                changes.push(Change {
                    change_type: ChangeType::ConfigFile,
                    change_description:
                        "Refused to rewrite /etc/login.defs: its current contents could not be \
                         read, and rewriting it would discard them"
                            .to_string(),
                    change_success: false,
                    change_error: Some(e.clone()),
                });
                false
            }
            _ => true,
        };
        let mut login_defs_content = match &login_defs_read {
            ConfRead::Content(content) => content.clone(),
            _ => String::new(),
        };
        let mut login_defs_changed = false;

        // Pre-apply snapshots for the exception check below. Taken once, here,
        // before any directive can mutate `pwquality_content`/`login_defs_content`,
        // or write a `SecurityConf` file: the exception decision must be judged
        // against the host's actual pre-apply state, never against a buffer or
        // file this same loop has already rewritten. Resolving every directive's
        // observed value in this one pass, before any write happens, makes that
        // guarantee hold structurally, so it stays true even if a future
        // directive's `SecurityConf` path happens to collide with an earlier
        // one's, rather than relying on today's `PAM_DIRECTIVES` entries
        // pointing at distinct files.
        let pwquality_observed = pwquality_read;
        let login_defs_observed = login_defs_content.clone();
        let mut observed_values = Vec::with_capacity(PAM_DIRECTIVES.len());
        for directive in PAM_DIRECTIVES {
            observed_values.push(
                observed_pam_value(ctx, directive, &pwquality_observed, &login_defs_observed).await,
            );
        }

        // Step 2: Apply each directive (state-aware: already-correct values
        // record a Skipped no-op and never trigger a rewrite)
        for (directive, observed) in PAM_DIRECTIVES.iter().zip(observed_values.iter()) {
            // Honour an exception only when it documents the value the host
            // actually has. An unset value and an unreadable one both render
            // "not set", matching scan's rendering and what an operator
            // writes in the config, so an exception documenting value =
            // "not set" is honoured even when the file could not be read: a
            // narrow, deliberate gap in the fail-closed rule.

            // Check for a valid exception: skip this directive if exempted
            if let Some(exception) =
                config.matching_exception(directive.pam_directive_name, observed.value_or_not_set())
            {
                info!(
                    "Skipping {} (exception: {})",
                    directive.pam_directive_name, exception.reason
                );
                changes.push(Change {
                    change_type: ChangeType::Skipped,
                    change_description: format!(
                        "{}: skipped (exception: {})",
                        directive.pam_directive_name, exception.reason
                    ),
                    change_success: true,
                    change_error: None,
                });
                continue;
            }

            // Determine target value: user directive override or hardcoded baseline
            let target_value = config
                .directives
                .get(directive.pam_directive_name)
                .map(|s| s.as_str())
                .unwrap_or(directive.pam_secure_value);

            match directive.pam_config_file {
                PamConfigFile::PwQuality => apply_exact_directive(
                    &mut pwquality_content,
                    &mut pwquality_changed,
                    &mut changes,
                    directive.pam_directive_name,
                    target_value,
                    "pwquality.conf",
                ),
                PamConfigFile::LoginDefs => apply_exact_directive(
                    &mut login_defs_content,
                    &mut login_defs_changed,
                    &mut changes,
                    directive.pam_directive_name,
                    target_value,
                    "login.defs",
                ),
                PamConfigFile::PamAuth => {
                    // Skip PAM module for now
                    debug!(
                        "Skipping PAM module directive: {}",
                        directive.pam_directive_name
                    );
                    continue;
                }
                PamConfigFile::SecurityConf(path) => {
                    let secure: i64 = directive
                        .pam_secure_value
                        .parse()
                        .expect("pam_secure_value must be a valid integer");
                    let over = config
                        .directives
                        .get(directive.pam_directive_name)
                        .and_then(|s| s.parse::<i64>().ok());
                    // Clamp so a per-host override can tighten but never loosen.
                    let target = clamp_target(directive.pam_compare, secure, over);

                    // Read directly (rather than reusing `observed`, which already
                    // read this via `read_effective_threshold`) because the refuse-
                    // to-auto-edit message below needs to know specifically whether
                    // the value came from an inline pam.d override, a distinction
                    // `PamObserved` deliberately does not carry.
                    let inline = read_pamd_inline(ctx, directive.pam_directive_name).await;

                    // No-loosen contract: only act when the effective value
                    // breaches the (clamped) target. A stricter value is already
                    // compliant, so touching it could only loosen it. `observed`
                    // (computed above via the shared helper) already resolved
                    // inline-vs-conf-file precedence; "not set" fails to parse as
                    // an integer just like a genuinely missing value, so reusing
                    // it here is equivalent to reading afresh.
                    if !breaches_threshold(
                        directive.pam_compare,
                        target,
                        Some(observed.value_or_not_set()),
                    ) {
                        changes.push(Change {
                            change_type: ChangeType::Skipped,
                            change_description: format!(
                                "{} already meets threshold in {}",
                                directive.pam_directive_name, path,
                            ),
                            change_success: true,
                            change_error: None,
                        });
                        continue;
                    }

                    // An inline pam.d arg overrides the .conf, so writing the
                    // .conf would be a silent no-op. Never auto-edit the auth
                    // stack (a malformed edit can lock users out); report the
                    // manual action and mark the run unsuccessful.
                    if let Some(value) = inline {
                        warn!(
                            "{} is set inline ({}={}) in the PAM stack; refusing to auto-edit it",
                            directive.pam_directive_name, directive.pam_directive_name, value,
                        );
                        all_success = false;
                        changes.push(Change {
                            change_type: ChangeType::ConfigFile,
                            change_description: format!(
                                "{name}={value} is set inline in the PAM stack and overrides {path}; \
                                 edit the PAM stack manually to set {name} to {target}",
                                name = directive.pam_directive_name,
                            ),
                            change_success: false,
                            change_error: Some("inline pam.d override present".to_string()),
                        });
                        continue;
                    }

                    let current = match read_conf_classified(ctx, path).await {
                        ConfRead::Content(content) => content,
                        ConfRead::Absent => String::new(),
                        ConfRead::Unreadable(e) => {
                            warn!("Refusing to rewrite {}: {}", path, e);
                            all_success = false;
                            changes.push(Change {
                                change_type: ChangeType::ConfigFile,
                                change_description: format!(
                                    "Refused to rewrite {path}: its current contents could not be \
                                     read, and rewriting it would discard them",
                                ),
                                change_success: false,
                                change_error: Some(e),
                            });
                            continue;
                        }
                    };

                    let target_str = target.to_string();
                    let updated = apply_directive_to_content(
                        &current,
                        directive.pam_directive_name,
                        &target_str,
                    );

                    if backup_and_write(ctx, path, path, &updated, &mut changes).await {
                        changes.push(Change {
                            change_type: ChangeType::ConfigFile,
                            change_description: format!(
                                "Set {} = {} in {}",
                                directive.pam_directive_name, target_str, path,
                            ),
                            change_success: true,
                            change_error: None,
                        });
                    } else {
                        all_success = false;
                    }
                }
            }
        }

        // Step 3: Back up and rewrite only the files that actually changed.
        // As before, a failed backup blocks the write for that file.
        if pwquality_changed && pwquality_writable {
            if backup_and_write(
                ctx,
                "/etc/security/pwquality.conf",
                "pwquality.conf",
                &pwquality_content,
                &mut changes,
            )
            .await
            {
                changes.push(Change {
                    change_type: ChangeType::ConfigFile,
                    change_description: "Wrote modified pwquality.conf".to_string(),
                    change_success: true,
                    change_error: None,
                });
            } else {
                all_success = false;
            }
        }

        if login_defs_changed && login_defs_writable {
            if backup_and_write(
                ctx,
                "/etc/login.defs",
                "login.defs",
                &login_defs_content,
                &mut changes,
            )
            .await
            {
                changes.push(Change {
                    change_type: ChangeType::ConfigFile,
                    change_description: "Wrote modified login.defs".to_string(),
                    change_success: true,
                    change_error: None,
                });
            } else {
                all_success = false;
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        info!(
            "PAM apply completed: {} changes, success={} in {} ms",
            changes.len(),
            all_success,
            duration_ms
        );

        Ok(ApplyResult {
            apply_plugin_id: self.metadata().plugin_id,
            apply_success: all_success,
            apply_changes: changes,
            apply_checkpoint_id: checkpoint_id,
            apply_error: None,
        })
    }

    async fn rollback(&self, ctx: &mut Context, checkpoint: &Checkpoint) -> Result<()> {
        info!(
            "Rolling back PAM configuration to checkpoint: {}",
            checkpoint.checkpoint_id.as_str()
        );

        // Restore configuration files from checkpoint
        crate::rollback_files_from_checkpoint(ctx, checkpoint)?;

        info!("PAM configuration files restored from checkpoint");

        // PAM doesn't require a service restart - changes take effect immediately
        // for new authentication attempts

        Ok(())
    }

    async fn validate(&self, ctx: &Context, config: &PluginConfig) -> Result<ValidationReport> {
        info!("Validating PAM configuration files");

        let mut issues = Vec::new();

        // Check pwquality.conf
        match ctx
            .executor()
            .file_metadata(Path::new("/etc/security/pwquality.conf"))
            .await
        {
            Ok(metadata) => {
                if !metadata.is_file {
                    issues.push(ValidationIssue {
                        validation_issue_config_key: None,
                        validation_issue_message:
                            "/etc/security/pwquality.conf exists but is not a regular file"
                                .to_string(),
                        validation_issue_severity: Severity::High,
                    });
                }
            }
            Err(_) => {
                issues.push(ValidationIssue {
                    validation_issue_config_key: None,
                    validation_issue_message: "/etc/security/pwquality.conf does not exist or is not readable"
                        .to_string(),
                    validation_issue_severity: Severity::Medium,
                });
            }
        }

        // Check login.defs
        match ctx
            .executor()
            .file_metadata(Path::new("/etc/login.defs"))
            .await
        {
            Ok(metadata) => {
                if !metadata.is_file {
                    issues.push(ValidationIssue {
                        validation_issue_config_key: None,
                        validation_issue_message:
                            "/etc/login.defs exists but is not a regular file".to_string(),
                        validation_issue_severity: Severity::High,
                    });
                }
            }
            Err(_) => {
                issues.push(ValidationIssue {
                    validation_issue_config_key: None,
                    validation_issue_message: "/etc/login.defs does not exist or is not readable"
                        .to_string(),
                    validation_issue_severity: Severity::High,
                });
            }
        }

        // Estimate changes state-aware: read the current file values the same
        // way apply does and list only directives that would actually change;
        // already-compliant directives are tallied in compliant_count, not
        // listed, so estimated_changes holds only real pending changes.
        // Classified reads so a root-only file yields honest requires-root
        // wording, never a false "(currently not set)" claim.
        let pwquality = read_conf_classified(ctx, "/etc/security/pwquality.conf").await;
        let login_defs = read_conf_classified(ctx, "/etc/login.defs").await;

        let mut estimated_changes = Vec::new();
        let mut compliant_count = 0usize;

        // Plain content for the shared helper's login_defs argument: it
        // carries no permission distinction, matching scan's and apply's
        // existing lenient (always-content) read of /etc/login.defs. The
        // classified `login_defs` above is still used, unchanged, by the
        // SecurityConf/PwQuality estimate below.
        let login_defs_str = match &login_defs {
            ConfRead::Content(c) => c.as_str(),
            ConfRead::Absent => "",
            ConfRead::Unreadable(_) => "",
        };

        for d in PAM_DIRECTIVES {
            if d.pam_config_file == PamConfigFile::PamAuth {
                continue;
            }

            // Honour an exception only when it documents the value the host
            // actually has, matching apply's rendering of an absent or
            // unreadable directive as "not set" so neither trusts an
            // exception on faith.
            let observed = observed_pam_value(ctx, d, &pwquality, login_defs_str).await;
            if config
                .matching_exception(d.pam_directive_name, observed.value_or_not_set())
                .is_some()
            {
                continue;
            }

            match &d.pam_config_file {
                PamConfigFile::PwQuality | PamConfigFile::LoginDefs => {
                    let read = if d.pam_config_file == PamConfigFile::PwQuality {
                        &pwquality
                    } else {
                        &login_defs
                    };
                    let target_value = config
                        .directives
                        .get(d.pam_directive_name)
                        .map(|s| s.as_str())
                        .unwrap_or(d.pam_secure_value);
                    // Absent reads as empty content, same as a confirmed-missing
                    // file always has: parsing finds nothing and the directive
                    // is honestly reported "(currently not set)" below. Only an
                    // Unreadable file (existing but blocked by privilege) must
                    // avoid that claim, since it is not a fact this scan can see.
                    let content = match read {
                        ConfRead::Content(c) => c.as_str(),
                        ConfRead::Absent => "",
                        ConfRead::Unreadable(_) => {
                            // Root-only file: never claim "not set" for a value
                            // that cannot be read at this privilege level.
                            estimated_changes.push(format!(
                                "Set {} = {} (current value requires root; applied only if it differs)",
                                d.pam_directive_name, target_value
                            ));
                            continue;
                        }
                    };
                    match parse_config_value(
                        content,
                        d.pam_directive_name,
                        ConfigFormat::Auto,
                        true,
                    ) {
                        Some(current) if current == target_value => compliant_count += 1,
                        Some(current) => estimated_changes.push(format!(
                            "{} will change: {} -> {}",
                            d.pam_directive_name, current, target_value
                        )),
                        None => estimated_changes.push(format!(
                            "Set {} = {} (currently not set)",
                            d.pam_directive_name, target_value
                        )),
                    }
                }
                PamConfigFile::SecurityConf(_) => {
                    // Same clamped target and effective-value resolution as
                    // apply. Reuses `observed` (computed above, the source of
                    // which is this exact `read_effective_threshold` call)
                    // instead of reading again: unlike login.defs, a
                    // `SecurityConf` directive has no lenient/classified
                    // split between the exception check and this estimate,
                    // so there is no wording that reusing it could degrade.
                    let secure: i64 = d
                        .pam_secure_value
                        .parse()
                        .expect("pam_secure_value must be a valid integer");
                    let over = config
                        .directives
                        .get(d.pam_directive_name)
                        .and_then(|s| s.parse::<i64>().ok());
                    let target = clamp_target(d.pam_compare, secure, over);
                    match &observed {
                        PamObserved::Value(v)
                            if !breaches_threshold(d.pam_compare, target, Some(v)) =>
                        {
                            compliant_count += 1
                        }
                        PamObserved::Value(v) => estimated_changes.push(format!(
                            "{} will change: {} -> {}",
                            d.pam_directive_name, v, target
                        )),
                        PamObserved::NotSet => estimated_changes.push(format!(
                            "Set {} = {} (currently not set)",
                            d.pam_directive_name, target
                        )),
                        PamObserved::PermissionDenied(_) => {
                            let op = match d.pam_compare {
                                PamCompare::AtMost => "<=",
                                _ => ">=",
                            };
                            estimated_changes.push(format!(
                                "{} {} {} (current value requires root; applied only if currently looser)",
                                d.pam_directive_name, op, target
                            ));
                        }
                    }
                }
                PamConfigFile::PamAuth => {}
            }
        }

        let is_valid = issues.is_empty();

        Ok(ValidationReport {
            validation_report_plugin_id: self.metadata().plugin_id,
            validation_report_is_valid: is_valid,
            validation_report_issues: issues,
            validation_report_estimated_changes: estimated_changes,
            validation_report_compliant_count: compliant_count,
        })
    }
}

/// Builds the unchecked entry for a PAM directive whose config file cannot be
/// read at the current privilege level. The check id mirrors the finding id.
fn unchecked_pam_directive(directive: &PamDirective, path: &str) -> UncheckedCheck {
    UncheckedCheck {
        unchecked_check_id: format!("pam-{}", directive.pam_directive_name),
        unchecked_title: format!("PAM setting: {}", directive.pam_directive_name),
        unchecked_category: FindingCategory::Authentication,
        unchecked_reason: format!("reading {} requires root", path),
        unchecked_compliance: get_pam_compliance_mappings(directive.pam_directive_name),
    }
}

/// PAM configuration directive with security settings.
#[derive(Clone, Debug)]
struct PamDirective {
    pam_directive_name: &'static str,
    pam_secure_value: &'static str,
    pam_description: &'static str,
    pam_severity: Severity,
    pam_config_file: PamConfigFile,
    pam_compare: PamCompare,
}

/// Represents which PAM configuration file contains the directive.
#[derive(Clone, Debug, Eq, PartialEq)]
enum PamConfigFile {
    /// Password quality settings (/etc/security/pwquality.conf).
    PwQuality,
    /// Password ageing settings (/etc/login.defs).
    LoginDefs,
    /// PAM module configuration (distribution-specific).
    PamAuth,
    /// A `key = value` file under /etc/security (path carried inline).
    SecurityConf(&'static str),
}

/// How a directive's current value is judged against its secure value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PamCompare {
    /// Current must equal the secure value.
    Exact,
    /// Current must be ≤ the secure value (e.g. faillock `deny`, lock no later).
    AtMost,
    /// Current must be ≥ the secure value (e.g. pwhistory `remember`).
    AtLeast,
}

/// Secure PAM configuration directives.
const PAM_DIRECTIVES: &[PamDirective] = &[
    // Password Quality (pwquality.conf)
    PamDirective {
        pam_directive_name: "minlen",
        pam_secure_value: "14",
        pam_description: "Minimum password length of 14 characters",
        pam_severity: Severity::High,
        pam_config_file: PamConfigFile::PwQuality,
        pam_compare: PamCompare::Exact,
    },
    PamDirective {
        pam_directive_name: "dcredit",
        pam_secure_value: "-1",
        pam_description: "Require at least one digit in password",
        pam_severity: Severity::Medium,
        pam_config_file: PamConfigFile::PwQuality,
        pam_compare: PamCompare::Exact,
    },
    PamDirective {
        pam_directive_name: "ucredit",
        pam_secure_value: "-1",
        pam_description: "Require at least one uppercase character in password",
        pam_severity: Severity::Medium,
        pam_config_file: PamConfigFile::PwQuality,
        pam_compare: PamCompare::Exact,
    },
    PamDirective {
        pam_directive_name: "lcredit",
        pam_secure_value: "-1",
        pam_description: "Require at least one lowercase character in password",
        pam_severity: Severity::Medium,
        pam_config_file: PamConfigFile::PwQuality,
        pam_compare: PamCompare::Exact,
    },
    PamDirective {
        pam_directive_name: "ocredit",
        pam_secure_value: "-1",
        pam_description: "Require at least one special character in password",
        pam_severity: Severity::Medium,
        pam_config_file: PamConfigFile::PwQuality,
        pam_compare: PamCompare::Exact,
    },
    PamDirective {
        pam_directive_name: "maxrepeat",
        pam_secure_value: "3",
        pam_description: "Maximum consecutive identical characters in password",
        pam_severity: Severity::Low,
        pam_config_file: PamConfigFile::PwQuality,
        pam_compare: PamCompare::Exact,
    },
    PamDirective {
        pam_directive_name: "PASS_MAX_DAYS",
        pam_secure_value: "90",
        pam_description: "Maximum password age of 90 days",
        pam_severity: Severity::Medium,
        pam_config_file: PamConfigFile::LoginDefs,
        pam_compare: PamCompare::Exact,
    },
    PamDirective {
        pam_directive_name: "PASS_MIN_DAYS",
        pam_secure_value: "1",
        pam_description: "Minimum password age of 1 day (prevents rapid changes)",
        pam_severity: Severity::Low,
        pam_config_file: PamConfigFile::LoginDefs,
        pam_compare: PamCompare::Exact,
    },
    PamDirective {
        pam_directive_name: "PASS_WARN_AGE",
        pam_secure_value: "7",
        pam_description: "Warn users 7 days before password expiry",
        pam_severity: Severity::Low,
        pam_config_file: PamConfigFile::LoginDefs,
        pam_compare: PamCompare::Exact,
    },
    // Account lockout (faillock) and password-reuse (pwhistory). Threshold
    // comparisons: a stricter setting is compliant and apply never loosens it.
    PamDirective {
        pam_directive_name: "deny",
        pam_secure_value: "5",
        pam_description: "Lock the account after at most 5 failed attempts",
        pam_severity: Severity::High,
        pam_config_file: PamConfigFile::SecurityConf("/etc/security/faillock.conf"),
        pam_compare: PamCompare::AtMost,
    },
    PamDirective {
        pam_directive_name: "remember",
        pam_secure_value: "5",
        pam_description: "Remember at least the last 5 passwords to prevent reuse",
        pam_severity: Severity::Medium,
        pam_config_file: PamConfigFile::SecurityConf("/etc/security/pwhistory.conf"),
        pam_compare: PamCompare::AtLeast,
    },
];

/// True when `current` fails the directive's comparison against `target`,
/// the resolved effective target (a directive override clamped so it can
/// only tighten the built-in baseline, or the baseline itself with no
/// override). Unset/unparseable integers fail. Effective value (inline
/// pam.d args or /etc/security/*.conf) is resolved by callers via
/// `read_effective_threshold` before this check.
fn pam_violates(directive: &PamDirective, target: &str, current: Option<&str>) -> bool {
    match directive.pam_compare {
        PamCompare::Exact => current != Some(target),
        compare => breaches_threshold(
            compare,
            target.parse().expect("target must be a valid integer"),
            current,
        ),
    }
}

/// True when integer `current` fails threshold `bound` under `compare`.
/// Unset/unparseable counts as a breach. (Only meaningful for AtMost/AtLeast.)
fn breaches_threshold(compare: PamCompare, bound: i64, current: Option<&str>) -> bool {
    let n = current.and_then(|v| v.parse::<i64>().ok());
    match compare {
        PamCompare::AtMost => n.is_none_or(|n| n > bound),
        PamCompare::AtLeast => n.is_none_or(|n| n < bound),
        PamCompare::Exact => true,
    }
}

/// A per-host override clamped so it can never be looser than the CIS baseline:
/// AtMost keeps the smaller (stricter) of override/secure, AtLeast the larger.
fn clamp_target(compare: PamCompare, secure: i64, over: Option<i64>) -> i64 {
    match (compare, over) {
        (PamCompare::AtMost, Some(o)) => o.min(secure),
        (PamCompare::AtLeast, Some(o)) => o.max(secure),
        _ => secure,
    }
}

/// PAM-stack files that may carry an inline override for a threshold directive's
/// module, plus the module those args attach to. Distro-variant, so a small
/// candidate set is searched and the first match wins.
fn pamd_module_for(arg: &str) -> Option<(&'static str, &'static [&'static str])> {
    match arg {
        "deny" => Some((
            "pam_faillock.so",
            &[
                "/etc/pam.d/system-auth",
                "/etc/pam.d/password-auth",
                "/etc/pam.d/common-auth",
            ],
        )),
        "remember" => Some((
            "pam_pwhistory.so",
            &[
                "/etc/pam.d/system-auth",
                "/etc/pam.d/password-auth",
                "/etc/pam.d/common-password",
            ],
        )),
        _ => None,
    }
}

/// An inline `arg=value` set on the directive's PAM module in the auth stack.
/// Inline args override `/etc/security/*.conf` when present; `None` if not set
/// inline. Only whole-token `arg=` matches (so `even_deny_root` never matches
/// `deny`).
async fn read_pamd_inline(ctx: &Context, arg: &str) -> Option<String> {
    let (module, files) = pamd_module_for(arg)?;
    for file in files {
        // A scan writes nothing, so Absent and Unreadable both simply mean
        // "no inline override here"; only Content is worth scanning.
        let content = match read_conf_classified(ctx, file).await {
            ConfRead::Content(c) => c,
            ConfRead::Absent | ConfRead::Unreadable(_) => continue,
        };
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || !line.contains(module) {
                continue;
            }
            if let Some(value) = line
                .split_whitespace()
                .find_map(|tok| tok.strip_prefix(arg).and_then(|r| r.strip_prefix('=')))
            {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// How a configuration file read turned out.
///
/// `Absent` and `Unreadable` are deliberately distinct: a file that is not
/// there has genuinely unset directives and may be created, whereas a file
/// whose contents could not be read tells us nothing, and merging directives
/// into the empty string would replace the host's file with ours.
enum ConfRead {
    Content(String),
    Absent,
    Unreadable(String),
}

/// Reads a config file, distinguishing absence from a failure to read.
/// Fails closed: any read failure of a path that is not confirmed absent is
/// `Unreadable`, including a failure to determine whether it exists at all.
async fn read_conf_classified(ctx: &Context, path: &str) -> ConfRead {
    match ctx.executor().read_file(Path::new(path)).await {
        Ok(content) => ConfRead::Content(content),
        Err(e) => match ctx.executor().path_exists(Path::new(path)).await {
            Ok(false) => ConfRead::Absent,
            _ => {
                warn!("Failed to read {}: {}", path, e);
                ConfRead::Unreadable(e.to_string())
            }
        },
    }
}

/// Effective value of a threshold directive at the current privilege level.
enum ThresholdRead {
    Value(String),
    NotSet,
    PermissionDenied,
}

/// Effective value of a threshold directive: an inline PAM-stack override wins
/// over the `/etc/security/*.conf` value. A conf file blocked by privileges
/// surfaces as `PermissionDenied` so the caller reports it unchecked.
async fn read_effective_threshold(ctx: &Context, arg: &str, conf: &str) -> ThresholdRead {
    if let Some(inline) = read_pamd_inline(ctx, arg).await {
        return ThresholdRead::Value(inline);
    }
    match read_conf_classified(ctx, conf).await {
        ConfRead::Unreadable(_) => ThresholdRead::PermissionDenied,
        // A missing file has no directives, same as today: empty content.
        ConfRead::Absent => ThresholdRead::NotSet,
        ConfRead::Content(content) => {
            match parse_config_value(&content, arg, ConfigFormat::KeyValue, true) {
                Some(v) => ThresholdRead::Value(v),
                None => ThresholdRead::NotSet,
            }
        }
    }
}

/// The value a PAM directive currently has on the host: a value present in
/// its config file, confirmed absence, or (for `PwQuality`/`SecurityConf`
/// directives only) a config file the current privilege level could not
/// read, carrying the path that was denied so `scan` can still report it
/// unchecked.
///
/// Shared by `scan`, `apply` and `validate` so all three agree on what "the
/// observed value" means. That agreement is load bearing: a policy exception
/// is honoured only when its documented value equals this one, so two
/// callers computing it differently would silently change which exceptions
/// apply.
enum PamObserved {
    Value(String),
    NotSet,
    PermissionDenied(&'static str),
}

impl PamObserved {
    /// Renders as `"not set"` for callers with no `unchecked` concept.
    /// `apply` and `validate` must fail closed on an unreadable value rather
    /// than trust it: this is exactly the string an operator is told to
    /// write in the config for a directive that is genuinely absent, so an
    /// exception only matches when it documents that same fallback.
    fn value_or_not_set(&self) -> &str {
        match self {
            PamObserved::Value(v) => v,
            PamObserved::NotSet | PamObserved::PermissionDenied(_) => "not set",
        }
    }
}

/// Computes [`PamObserved`] for `directive`. `pwquality` and `login_defs` are
/// the file contents the caller has already read, so this performs I/O only
/// for `SecurityConf` directives. `login_defs` carries no permission
/// distinction, matching `scan`'s existing lenient (always-content) read of
/// `/etc/login.defs`.
async fn observed_pam_value(
    ctx: &Context,
    directive: &PamDirective,
    pwquality: &ConfRead,
    login_defs: &str,
) -> PamObserved {
    match &directive.pam_config_file {
        PamConfigFile::PwQuality => match pwquality {
            ConfRead::Content(content) => match parse_config_value(
                content,
                directive.pam_directive_name,
                ConfigFormat::Auto,
                true,
            ) {
                Some(v) => PamObserved::Value(v),
                None => PamObserved::NotSet,
            },
            // A missing file has no directives, same as today: empty content.
            ConfRead::Absent => PamObserved::NotSet,
            ConfRead::Unreadable(_) => {
                PamObserved::PermissionDenied("/etc/security/pwquality.conf")
            }
        },
        PamConfigFile::LoginDefs => match parse_config_value(
            login_defs,
            directive.pam_directive_name,
            ConfigFormat::Auto,
            true,
        ) {
            Some(v) => PamObserved::Value(v),
            None => PamObserved::NotSet,
        },
        PamConfigFile::PamAuth => PamObserved::NotSet,
        PamConfigFile::SecurityConf(path) => {
            match read_effective_threshold(ctx, directive.pam_directive_name, path).await {
                ThresholdRead::Value(v) => PamObserved::Value(v),
                ThresholdRead::NotSet => PamObserved::NotSet,
                ThresholdRead::PermissionDenied => PamObserved::PermissionDenied(path),
            }
        }
    }
}

/// State-aware exact-match apply for a `key = value` config held in memory:
/// mutates `content` and records a real change only when the file's current
/// value differs from the target; an already-correct value records a Skipped
/// no-op instead, leaving the applied count honest.
fn apply_exact_directive(
    content: &mut String,
    changed: &mut bool,
    changes: &mut Vec<Change>,
    name: &str,
    target: &str,
    file_label: &str,
) {
    let current = parse_config_value(content, name, ConfigFormat::Auto, true);
    if current.as_deref() == Some(target) {
        changes.push(Change {
            change_type: ChangeType::Skipped,
            change_description: format!("{} already set to {} in {}", name, target, file_label),
            change_success: true,
            change_error: None,
        });
        return;
    }

    *content = apply_directive_to_content(content, name, target);
    *changed = true;
    changes.push(Change {
        change_type: ChangeType::ConfigFile,
        change_description: format!("Set {} = {} in {}", name, target, file_label),
        change_success: true,
        change_error: None,
    });
}

/// Backs up `path` and writes `content` to it, recording the backup outcome
/// and any failure. A failed backup blocks the write (never modify a file
/// without a backup). Returns true on a successful write; callers push their
/// own success change, since its wording varies by call site.
async fn backup_and_write(
    ctx: &Context,
    path: &str,
    file_label: &str,
    content: &str,
    changes: &mut Vec<Change>,
) -> bool {
    // A file that is not there has nothing to back up, and cp on a missing
    // source fails. Absence is an ordinary case: creating the file is correct.
    // Fail closed, so only a CONFIRMED absence skips the backup. An existence
    // probe that errors, or that says the file is present, still requires one.
    let needs_backup = !matches!(ctx.executor().path_exists(Path::new(path)).await, Ok(false));

    if needs_backup {
        match create_config_backup(ctx, path).await {
            Ok(backup) => changes.push(Change {
                change_type: ChangeType::ConfigFile,
                change_description: format!("Created backup: {}", backup),
                change_success: true,
                change_error: None,
            }),
            Err(e) => {
                warn!("Failed to backup {}: {}", path, e);
                changes.push(Change {
                    change_type: ChangeType::ConfigFile,
                    change_description: format!("Failed to backup {}", file_label),
                    change_success: false,
                    change_error: Some(e.to_string()),
                });
                return false;
            }
        }
    }

    match ctx.executor().write_file(Path::new(path), content).await {
        Ok(_) => {
            info!("Successfully wrote {}", path);
            true
        }
        Err(e) => {
            warn!("Failed to write {}: {}", path, e);
            changes.push(Change {
                change_type: ChangeType::ConfigFile,
                change_description: format!("Failed to write {}", file_label),
                change_success: false,
                change_error: Some(e.to_string()),
            });
            false
        }
    }
}

/// Reads the login.defs configuration file.
async fn read_login_defs(ctx: &Context) -> Result<String> {
    ctx.executor()
        .read_file(Path::new("/etc/login.defs"))
        .await
        .map_err(|e| HardeningError::Plugin(e.to_string()))
}

/// Creates a timestamped backup of a configuration file.
async fn create_config_backup(ctx: &Context, file_path: &str) -> Result<String> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| HardeningError::Plugin(format!("Failed to get system time: {}", e)))?
        .as_secs();

    let backup_path = format!("{}.backup-{}", file_path, timestamp);

    let output = ctx
        .executor()
        .execute_command("cp", &[file_path, &backup_path])
        .await
        .map_err(|e| HardeningError::Plugin(e.to_string()))?;

    if !output.success() {
        return Err(HardeningError::Plugin(format!(
            "Failed to back up {file_path} to {backup_path}: cp exited {} ({})",
            output.exit_code,
            output.stderr.trim(),
        )));
    }

    Ok(backup_path)
}

/// Applies a directive to configuration file content.
///
/// If the directive exists, updates its value.
/// If the directive doesn't exist, appends it to the end.
fn apply_directive_to_content(content: &str, directive_name: &str, secure_value: &str) -> String {
    let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
    let mut found = false;

    // Try to update existing directive.
    for line in &mut lines {
        let trimmed = line.trim();

        // Skip comments.
        if trimmed.starts_with('#') {
            continue;
        }

        // Check if this line contains our directive.
        if let Some(stripped) = trimmed.strip_prefix(directive_name) {
            let remainder = stripped.trim();

            // Check if it is followed by = or whitespace (actual directive, not just prefix match).
            let is_whitespace_separated = if let Some(ch) = remainder.chars().next() {
                ch.is_whitespace()
            } else {
                false
            };

            if remainder.starts_with('=') || is_whitespace_separated {
                // Update the line with new value.
                *line = format!("{} = {}", directive_name, secure_value);
                found = true;
                break;
            }
        }
    }

    // If not found, append to end.
    if !found {
        lines.push(format!("{} = {}", directive_name, secure_value));
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Confirms a representative PAM finding (minimum password length) now
    /// carries multi-framework mappings: CIS (existing) plus STIG, NIST and
    /// PCI-DSS sourced from the SSG `accounts_password_pam_minlen` rule.
    #[test]
    fn pam_minlen_maps_cis_stig_nist_and_pcidss() {
        let frameworks: Vec<ComplianceFramework> = get_pam_compliance_mappings("minlen")
            .iter()
            .map(|m| m.compliance_framework)
            .collect();

        for expected in [
            ComplianceFramework::CIS,
            ComplianceFramework::STIG,
            ComplianceFramework::NIST,
            ComplianceFramework::PCIDSS,
        ] {
            assert!(
                frameworks.contains(&expected),
                "minlen must map framework {expected:?}"
            );
        }
    }

    /// Confirms the same representative PAM finding (minimum password length)
    /// also carries the governance-framework mappings added alongside the
    /// technical ones: ISO/IEC 27001:2022 8.5 (under the "Technological"
    /// theme), HIPAA §164.308(a)(5)(ii)(D) and GDPR "TM-AUTH". Existing CIS /
    /// STIG / NIST / PCI-DSS mappings are left intact (asserted above).
    #[test]
    fn pam_minlen_maps_iso_hipaa_and_gdpr() {
        let mappings = get_pam_compliance_mappings("minlen");
        let frameworks: Vec<ComplianceFramework> =
            mappings.iter().map(|m| m.compliance_framework).collect();

        for expected in [
            ComplianceFramework::ISO27001,
            ComplianceFramework::HIPAA,
            ComplianceFramework::GDPR,
        ] {
            assert!(
                frameworks.contains(&expected),
                "minlen must map framework {expected:?}"
            );
        }

        // The ISO 27001 control must be filed under the "Technological" theme,
        // not the PAM default "Access Control" section.
        let iso = mappings
            .iter()
            .find(|m| m.compliance_framework == ComplianceFramework::ISO27001)
            .expect("minlen must carry an ISO 27001 mapping");
        assert_eq!(iso.compliance_control_id, "8.5");
        assert_eq!(iso.compliance_section.as_deref(), Some("Technological"));
    }

    /// Confirms every PAM authentication check carries the SOC 2 logical-access
    /// criterion CC6.1, filed under its Trust Services Criteria series.
    #[test]
    fn pam_minlen_maps_soc2_logical_access() {
        let soc2 = get_pam_compliance_mappings("minlen")
            .into_iter()
            .find(|m| m.compliance_framework == ComplianceFramework::SOC2)
            .expect("minlen must carry a SOC 2 mapping");
        assert_eq!(soc2.compliance_control_id, "CC6.1");
        assert_eq!(
            soc2.compliance_section.as_deref(),
            Some("Logical and Physical Access Controls")
        );
    }

    /// Confirms the 800-171r3 crosswalk: password-quality checks translate
    /// IA-5(1) to 3.5.7, the faillock check translates AC-7 to 3.1.8, and the
    /// pwhistory check (whose SSG rule carries no 800-53 reference) honestly
    /// carries no 800-171 mapping.
    #[test]
    fn pam_checks_map_nist_800_171_requirements() {
        let nist171_for = |check: &str| {
            get_pam_compliance_mappings(check)
                .into_iter()
                .find(|m| m.compliance_framework == ComplianceFramework::NIST800171)
        };

        let minlen = nist171_for("minlen").expect("minlen must carry an 800-171 mapping");
        assert_eq!(minlen.compliance_control_id, "3.5.7");
        assert_eq!(
            minlen.compliance_section.as_deref(),
            Some("Identification and Authentication")
        );

        let lockout = nist171_for("lockout").expect("lockout must carry an 800-171 mapping");
        assert_eq!(lockout.compliance_control_id, "3.1.8");
        assert_eq!(
            lockout.compliance_section.as_deref(),
            Some("Access Control")
        );

        assert!(
            nist171_for("remember").is_none(),
            "pwhistory has no 800-53 source control and must not claim 800-171"
        );
    }

    /// Confirms the FedRAMP derivation: IA-5(1) and AC-7 are both GSA rev5
    /// Moderate baseline members, so the quality and lockout checks mirror
    /// their 800-53 ids verbatim; the pwhistory check (whose SSG rule
    /// carries no 800-53 reference) honestly carries no FedRAMP mapping.
    #[test]
    fn pam_checks_map_fedramp_moderate_controls() {
        let fedramp_for = |check: &str| {
            get_pam_compliance_mappings(check)
                .into_iter()
                .find(|m| m.compliance_framework == ComplianceFramework::FedRAMP)
        };

        let minlen = fedramp_for("minlen").expect("minlen must carry a FedRAMP mapping");
        assert_eq!(minlen.compliance_control_id, "IA-5(1)(a)");
        assert_eq!(
            minlen.compliance_section.as_deref(),
            Some("Identification and Authentication")
        );

        let max_days =
            fedramp_for("PASS_MAX_DAYS").expect("PASS_MAX_DAYS must carry a FedRAMP mapping");
        assert_eq!(max_days.compliance_control_id, "IA-5(1)(d)");

        let lockout = fedramp_for("lockout").expect("lockout must carry a FedRAMP mapping");
        assert_eq!(lockout.compliance_control_id, "AC-7(a)");
        assert_eq!(
            lockout.compliance_section.as_deref(),
            Some("Access Control")
        );

        assert!(
            fedramp_for("remember").is_none(),
            "pwhistory has no 800-53 source control and must not claim FedRAMP"
        );
    }

    #[tokio::test]
    async fn backup_reports_failure_when_cp_exits_non_zero() {
        use hardener_common::executor::{CommandOutput, MockExecutor};
        use std::sync::Arc;
        use std::time::{SystemTime, UNIX_EPOCH};

        // The backup path embeds a unix timestamp, so register the cp across a
        // small clock window (the idiom used in pam_mock_tests.rs).
        let path = "/etc/security/faillock.conf";
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before the unix epoch")
            .as_secs();
        let mut executor = MockExecutor::new();
        for t in now..now + 3 {
            let backup = format!("{path}.backup-{t}");
            executor = executor.with_command(
                "cp",
                &[path, &backup],
                CommandOutput {
                    stdout: String::new(),
                    stderr: "cp: cannot stat '/etc/security/faillock.conf': Permission denied\n"
                        .to_string(),
                    exit_code: 1,
                },
            );
        }
        let ctx = Context::with_executor(Arc::new(executor));

        let result = create_config_backup(&ctx, path).await;

        let err = result.expect_err("a cp that exits non-zero must not report a backup");
        let message = err.to_string();
        assert!(
            message.contains(path),
            "the error must name the file it failed to back up, got: {message}"
        );
        assert!(
            message.contains("Permission denied"),
            "the error must carry cp's own stderr so an operator can act on it, got: {message}"
        );
    }

    #[tokio::test]
    async fn a_read_error_is_not_reported_as_empty_content() {
        use hardener_common::executor::MockExecutor;
        use std::sync::Arc;

        // A file that exists but cannot be read must never classify as content.
        // Empty content means "the directive is genuinely not set", which is a
        // different fact and drives a rewrite.
        let path = "/etc/security/faillock.conf";
        let executor = MockExecutor::new()
            .with_file(path, "deny = 3\n")
            .with_read_permission_denied(path);
        let ctx = Context::with_executor(Arc::new(executor));

        assert!(
            matches!(
                read_conf_classified(&ctx, path).await,
                ConfRead::Unreadable(_)
            ),
            "an unreadable file must classify as Unreadable"
        );
    }

    #[tokio::test]
    async fn an_absent_file_is_distinguishable_from_an_unreadable_one() {
        use hardener_common::executor::MockExecutor;
        use std::sync::Arc;

        // Nothing registered: the mock reports a confirmed absence.
        let ctx = Context::with_executor(Arc::new(MockExecutor::new()));

        assert!(
            matches!(
                read_conf_classified(&ctx, "/etc/security/faillock.conf").await,
                ConfRead::Absent
            ),
            "a file that is simply not there must classify as Absent, since creating it is correct"
        );
    }

    #[test]
    fn threshold_directives_accept_stricter_and_flag_looser() {
        let deny = PamDirective {
            pam_directive_name: "deny",
            pam_secure_value: "5",
            pam_description: "t",
            pam_severity: Severity::High,
            pam_config_file: PamConfigFile::SecurityConf("/etc/security/faillock.conf"),
            pam_compare: PamCompare::AtMost,
        };
        assert!(pam_violates(&deny, deny.pam_secure_value, Some("10"))); // too loose
        assert!(!pam_violates(&deny, deny.pam_secure_value, Some("3"))); // stricter, compliant
        assert!(!pam_violates(&deny, deny.pam_secure_value, Some("5")));
        assert!(pam_violates(&deny, deny.pam_secure_value, None)); // not configured

        // A clamped override target (not the raw baseline) is what scan()
        // actually compares against: a stricter override on an
        // already-compliant value must now violate.
        assert!(pam_violates(&deny, "2", Some("3"))); // baseline-compliant, override-violating

        let remember = PamDirective {
            pam_directive_name: "remember",
            pam_config_file: PamConfigFile::SecurityConf("/etc/security/pwhistory.conf"),
            pam_compare: PamCompare::AtLeast,
            ..deny
        };
        assert!(pam_violates(
            &remember,
            remember.pam_secure_value,
            Some("2")
        )); // too few
        assert!(!pam_violates(
            &remember,
            remember.pam_secure_value,
            Some("10")
        )); // stricter, compliant
        assert!(!pam_violates(
            &remember,
            remember.pam_secure_value,
            Some("5")
        ));
        assert!(!pam_violates(&remember, "12", Some("15"))); // still compliant against a tighter override

        // Spread from `remember` (not `deny`, already moved above); PamDirective isn't Copy.
        let exact = PamDirective {
            pam_compare: PamCompare::Exact,
            pam_secure_value: "14",
            ..remember
        };
        assert!(!pam_violates(&exact, exact.pam_secure_value, Some("14")));
        assert!(pam_violates(&exact, exact.pam_secure_value, Some("8")));
    }
}
