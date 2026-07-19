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

    async fn scan(&self, ctx: &Context) -> Result<ScanResult> {
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
            let current_value = match directive.pam_config_file {
                PamConfigFile::PwQuality => match &pwquality {
                    ConfRead::Content(content) => parse_config_value(
                        content,
                        directive.pam_directive_name,
                        ConfigFormat::Auto,
                        true,
                    ),
                    ConfRead::PermissionDenied => {
                        unchecked.push(unchecked_pam_directive(
                            directive,
                            "/etc/security/pwquality.conf",
                        ));
                        continue;
                    }
                },
                PamConfigFile::LoginDefs => parse_config_value(
                    &login_defs_content,
                    directive.pam_directive_name,
                    ConfigFormat::Auto,
                    true,
                ),
                PamConfigFile::PamAuth => {
                    debug!(
                        "Skipping PAM module directive: {}",
                        directive.pam_directive_name
                    );
                    continue;
                }
                PamConfigFile::SecurityConf(path) => {
                    match read_effective_threshold(ctx, directive.pam_directive_name, path).await {
                        ThresholdRead::Value(v) => Some(v),
                        ThresholdRead::NotSet => None,
                        ThresholdRead::PermissionDenied => {
                            unchecked.push(unchecked_pam_directive(directive, path));
                            continue;
                        }
                    }
                }
            };

            // Check if current value satisfies the directive's comparison.
            let is_secure = !pam_violates(directive, current_value.as_deref());

            if !is_secure {
                let current_display = current_value.unwrap_or_else(|| "not set".to_string());

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
                        directive.pam_secure_value,
                    ),
                    finding_explanation: directive.pam_description.to_string(),
                    finding_impact: "Weak authentication settings can allow easier password guessing and brute-force attacks".to_string(),
                    finding_recommended_value: directive.pam_secure_value.to_string(),
                    finding_remediation_steps: vec![
                        format!(
                            "Set {} = {} in the appropriate configuration file",
                            directive.pam_directive_name,
                            directive.pam_secure_value,
                        ),
                    ],
                    finding_severity: directive.pam_severity,
                    finding_title: format!(
                        "Insecure PAM setting: {}",
                        directive.pam_directive_name
                    ),
                    finding_compliance: get_pam_compliance_mappings(directive.pam_directive_name),
                    finding_policy_exception: None,
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
        let mut pwquality_content = read_pwquality_config(ctx).await.unwrap_or_else(|e| {
            warn!("Failed to read pwquality.conf, using empty content: {}", e);
            String::new()
        });
        let mut pwquality_changed = false;

        let mut login_defs_content = read_login_defs(ctx).await.unwrap_or_else(|e| {
            warn!("Failed to read login.defs, using empty content: {}", e);
            String::new()
        });
        let mut login_defs_changed = false;

        // Step 2: Apply each directive (state-aware: already-correct values
        // record a Skipped no-op and never trigger a rewrite)
        for directive in PAM_DIRECTIVES {
            // Check for a valid exception: skip this directive if exempted
            if let Some(exception) = config.has_valid_exception(directive.pam_directive_name) {
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

                    let inline = read_pamd_inline(ctx, directive.pam_directive_name).await;
                    let content = read_security_conf(ctx, path).await;
                    let conf_val = parse_config_value(
                        &content,
                        directive.pam_directive_name,
                        ConfigFormat::KeyValue,
                        true,
                    );
                    let effective = inline.clone().or(conf_val);

                    // No-loosen contract: only act when the effective value
                    // breaches the (clamped) target. A stricter value is already
                    // compliant, so touching it could only loosen it.
                    if !breaches_threshold(directive.pam_compare, target, effective.as_deref()) {
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

                    match create_config_backup(ctx, path).await {
                        Ok(backup) => changes.push(Change {
                            change_type: ChangeType::ConfigFile,
                            change_description: format!("Created backup: {}", backup),
                            change_success: true,
                            change_error: None,
                        }),
                        Err(e) => {
                            warn!("Failed to backup {}: {}", path, e);
                            all_success = false;
                            changes.push(Change {
                                change_type: ChangeType::ConfigFile,
                                change_description: format!("Failed to backup {}", path),
                                change_success: false,
                                change_error: Some(e.to_string()),
                            });
                        }
                    }

                    let target_str = target.to_string();
                    let updated = apply_directive_to_content(
                        &content,
                        directive.pam_directive_name,
                        &target_str,
                    );
                    match ctx.executor().write_file(Path::new(path), &updated).await {
                        Ok(_) => changes.push(Change {
                            change_type: ChangeType::ConfigFile,
                            change_description: format!(
                                "Set {} = {} in {}",
                                directive.pam_directive_name, target_str, path,
                            ),
                            change_success: true,
                            change_error: None,
                        }),
                        Err(e) => {
                            warn!("Failed to write {}: {}", path, e);
                            all_success = false;
                            changes.push(Change {
                                change_type: ChangeType::ConfigFile,
                                change_description: format!("Failed to write {}", path),
                                change_success: false,
                                change_error: Some(e.to_string()),
                            });
                        }
                    }
                }
            }
        }

        // Step 3: Back up and rewrite only the files that actually changed.
        // As before, a failed backup blocks the write for that file.
        if pwquality_changed
            && !backup_and_write(
                ctx,
                "/etc/security/pwquality.conf",
                "pwquality.conf",
                &pwquality_content,
                &mut changes,
            )
            .await
        {
            all_success = false;
        }

        if login_defs_changed
            && !backup_and_write(
                ctx,
                "/etc/login.defs",
                "login.defs",
                &login_defs_content,
                &mut changes,
            )
            .await
        {
            all_success = false;
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

        for d in PAM_DIRECTIVES {
            if d.pam_config_file == PamConfigFile::PamAuth
                || config.has_valid_exception(d.pam_directive_name).is_some()
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
                    let ConfRead::Content(content) = read else {
                        // Root-only file: never claim "not set" for a value
                        // that cannot be read at this privilege level.
                        estimated_changes.push(format!(
                            "Set {} = {} (current value requires root; applied only if it differs)",
                            d.pam_directive_name, target_value
                        ));
                        continue;
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
                PamConfigFile::SecurityConf(path) => {
                    // Same clamped target and effective-value resolution as apply.
                    let secure: i64 = d
                        .pam_secure_value
                        .parse()
                        .expect("pam_secure_value must be a valid integer");
                    let over = config
                        .directives
                        .get(d.pam_directive_name)
                        .and_then(|s| s.parse::<i64>().ok());
                    let target = clamp_target(d.pam_compare, secure, over);
                    match read_effective_threshold(ctx, d.pam_directive_name, path).await {
                        ThresholdRead::Value(v)
                            if !breaches_threshold(d.pam_compare, target, Some(&v)) =>
                        {
                            compliant_count += 1
                        }
                        ThresholdRead::Value(v) => estimated_changes.push(format!(
                            "{} will change: {} -> {}",
                            d.pam_directive_name, v, target
                        )),
                        ThresholdRead::NotSet => estimated_changes.push(format!(
                            "Set {} = {} (currently not set)",
                            d.pam_directive_name, target
                        )),
                        ThresholdRead::PermissionDenied => {
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

/// True when `current` fails the directive's comparison. Unset/unparseable
/// integers fail. Effective value (inline pam.d args or /etc/security/*.conf)
/// is resolved by callers via `read_effective_threshold` before this check.
fn pam_violates(directive: &PamDirective, current: Option<&str>) -> bool {
    match directive.pam_compare {
        PamCompare::Exact => current != Some(directive.pam_secure_value),
        compare => breaches_threshold(
            compare,
            directive
                .pam_secure_value
                .parse()
                .expect("pam_secure_value must be a valid integer"),
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
        for line in read_security_conf(ctx, file).await.lines() {
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

/// Outcome of reading a scan-relevant config file at the current privilege level.
enum ConfRead {
    Content(String),
    PermissionDenied,
}

/// Reads a config file, distinguishing privilege failures from absence.
/// A missing file reads as empty content (directives genuinely not set);
/// a permission failure must not masquerade as "not set".
async fn read_conf_classified(ctx: &Context, path: &str) -> ConfRead {
    match ctx.executor().read_file(Path::new(path)).await {
        Ok(content) => ConfRead::Content(content),
        Err(e) if hardener_common::error::is_permission_denied(&e) => ConfRead::PermissionDenied,
        Err(e) => {
            warn!("Failed to read {}: {}", path, e);
            ConfRead::Content(String::new())
        }
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
        ConfRead::PermissionDenied => ThresholdRead::PermissionDenied,
        ConfRead::Content(content) => {
            match parse_config_value(&content, arg, ConfigFormat::KeyValue, true) {
                Some(v) => ThresholdRead::Value(v),
                None => ThresholdRead::NotSet,
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

/// Backs up `path` and writes `content` to it, recording both outcomes.
/// A failed backup blocks the write (never modify a file without a backup).
/// Returns false when either step failed so the caller can mark the run.
async fn backup_and_write(
    ctx: &Context,
    path: &str,
    file_label: &str,
    content: &str,
    changes: &mut Vec<Change>,
) -> bool {
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
                change_description: format!("Failed to create {} backup", file_label),
                change_success: false,
                change_error: Some(e.to_string()),
            });
            return false;
        }
    }

    match ctx.executor().write_file(Path::new(path), content).await {
        Ok(_) => {
            info!("Successfully wrote {}", path);
            changes.push(Change {
                change_type: ChangeType::ConfigFile,
                change_description: format!("Wrote modified {}", file_label),
                change_success: true,
                change_error: None,
            });
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

/// Lenient config read: the file's contents, or an empty string on any
/// failure (absence, privileges, or otherwise). Used where permission
/// classification is not needed: the scan's pam.d inline-override lookups
/// (world-readable files) and apply's /etc/security conf reads (root context).
async fn read_security_conf(ctx: &Context, path: &str) -> String {
    ctx.executor()
        .read_file(Path::new(path))
        .await
        .unwrap_or_default()
}

/// Reads the pwquality configuration file.
async fn read_pwquality_config(ctx: &Context) -> Result<String> {
    ctx.executor()
        .read_file(Path::new("/etc/security/pwquality.conf"))
        .await
        .map_err(|e| HardeningError::Plugin(e.to_string()))
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

    ctx.executor()
        .execute_command("cp", &[file_path, &backup_path])
        .await
        .map_err(|e| HardeningError::Plugin(e.to_string()))?;

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
        assert!(pam_violates(&deny, Some("10"))); // too loose
        assert!(!pam_violates(&deny, Some("3"))); // stricter, compliant
        assert!(!pam_violates(&deny, Some("5")));
        assert!(pam_violates(&deny, None)); // not configured

        let remember = PamDirective {
            pam_directive_name: "remember",
            pam_config_file: PamConfigFile::SecurityConf("/etc/security/pwhistory.conf"),
            pam_compare: PamCompare::AtLeast,
            ..deny
        };
        assert!(pam_violates(&remember, Some("2"))); // too few
        assert!(!pam_violates(&remember, Some("10"))); // stricter, compliant
        assert!(!pam_violates(&remember, Some("5")));

        // Spread from `remember` (not `deny`, already moved above); PamDirective isn't Copy.
        let exact = PamDirective {
            pam_compare: PamCompare::Exact,
            pam_secure_value: "14",
            ..remember
        };
        assert!(!pam_violates(&exact, Some("14")));
        assert!(pam_violates(&exact, Some("8")));
    }
}
