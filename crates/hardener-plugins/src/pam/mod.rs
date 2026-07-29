//! PAM (Pluggable Authentication Modules) hardening plugin
//!
//! This plugin hardens system authentication by configuring:
//! - Password quality requirements (complexity, length)
//! - Account lockout policies (failed login attempts)
//! - Password ageing policies (expiry, reuse prevention)

mod layer_drift;
mod login_defs;

use async_trait::async_trait;
use hardener_common::file_utils::{
    ConfigFormat, Duplicates, parse_config_value, set_config_directive,
};
use hardener_common::{
    error::{HardeningError, Result},
    types::{ComplianceFramework, ComplianceMapping, FindingCategory, PluginId, Severity},
    vendor_config::{ConfigLayer, LayeredRead, read_layered, vendor_path_for},
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

        // Classified, and layered, like every other file this plugin reads. It
        // used to go through a second reader that folded any failure into an
        // empty string, so a root-only /etc/login.defs reported every directive
        // it sets as unset and a hardened host collected findings for settings
        // it already had.
        let login_defs_read = read_conf_classified(ctx, "/etc/login.defs").await;

        // Drift between the layers, for every file the table names rather than
        // for login.defs alone.
        findings.extend(layer_drift_findings(ctx).await);

        // Whether each file's consuming module is loaded, read once per file
        // rather than once per directive: six pwquality keys share one module,
        // and over SSH a per-directive read is six round trips for one answer.
        let presence = module_presence_by_file(ctx).await;

        // Check each PAM directive.
        for directive in PAM_DIRECTIVES {
            if directive.pam_config_file == PamConfigFile::PamAuth {
                debug!(
                    "Skipping PAM module directive: {}",
                    directive.pam_directive_name
                );
                continue;
            }

            // A file no module reads makes its own value irrelevant, so this
            // comes before the value is read at all. Judging the value first
            // and this second would report a directive both compliant and
            // unenforced, which is one host described two ways.
            match presence_for(&presence, directive) {
                ModulePresence::NotInStack { module } => {
                    let conf_path = directive
                        .pam_config_file
                        .conf_path()
                        .expect("a directive with a module has a file");
                    findings.push(module_absent_finding(directive, module, conf_path));
                    continue;
                }
                ModulePresence::Indeterminate {
                    reason,
                    needs_privilege,
                } => {
                    unchecked.push(unchecked_pam_directive(
                        directive,
                        reason.clone(),
                        *needs_privilege,
                    ));
                    continue;
                }
                ModulePresence::InStack | ModulePresence::NoModule => {}
            }

            let current_value =
                match observed_pam_value(ctx, directive, &pwquality, &login_defs_read).await {
                    PamObserved::Value(v) => Some(v),
                    PamObserved::NotSet => None,
                    PamObserved::Unreadable {
                        path,
                        permission_denied,
                    } => {
                        unchecked.push(unchecked_pam_directive(
                            directive,
                            unreadable_reason(path, permission_denied),
                            permission_denied,
                        ));
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
                    .resolve_str(directive.pam_directive_name, directive.pam_secure_value)
                    .to_string(),
                compare => {
                    let secure: i64 = directive
                        .pam_secure_value
                        .parse()
                        .expect("pam_secure_value must be a valid integer");
                    let over = config.resolve_i64(directive.pam_directive_name);
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
        let pwquality_write = conf_is_writable(
            ctx,
            "/etc/security/pwquality.conf",
            &pwquality_read,
            &mut changes,
            &mut all_success,
        )
        .await;
        let mut pwquality_content = match &pwquality_read {
            ConfRead::Content(content, _) => content.clone(),
            _ => String::new(),
        };
        let mut pwquality_changed = false;

        let login_defs_read = read_conf_classified(ctx, "/etc/login.defs").await;
        let login_defs_write = conf_is_writable(
            ctx,
            "/etc/login.defs",
            &login_defs_read,
            &mut changes,
            &mut all_success,
        )
        .await;
        let mut login_defs_content = match &login_defs_read {
            ConfRead::Content(content, _) => content.clone(),
            _ => String::new(),
        };
        let mut login_defs_changed = false;

        // A file no module reads is still written: the value will be right the
        // moment the module is added, and refusing would leave the operator
        // with neither. What must not happen is reporting that as hardening
        // done. Recorded once per file, and it fails the run, because this
        // plugin already refuses to edit /etc/pam.d itself, so the remaining
        // step is the operator's and a run that hardened nothing has not
        // earned a clean result.
        for (path, presence) in module_presence_by_file(ctx).await {
            let ModulePresence::NotInStack { module } = presence else {
                continue;
            };
            warn!(
                "Nothing on this host reads {}: {} is not loaded",
                path, module
            );
            all_success = false;
            changes.push(Change {
                change_type: ChangeType::ConfigFile,
                change_description: module_not_loaded_message(path, module),
                change_success: false,
                change_error: Some(format!("{module} is not loaded by the PAM stack")),
            });
        }

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
        let login_defs_observed = login_defs_read;
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
            let target_value =
                config.resolve_str(directive.pam_directive_name, directive.pam_secure_value);

            // A file whose current contents could not be read is never
            // rewritten, and that refusal was already recorded once, at read
            // time. Skip its directives outright so none of them records a
            // change for a write that cannot happen. "N change(s) applied" is
            // not always N hardening successes: a separator repaired on an
            // already-correct value counts as a change too, because the tool
            // cannot tell a cosmetic repair from a load-bearing one without
            // modelling each consumer's parser, and over-reporting is the
            // safe direction, since under-reporting was the defect this
            // branch fixed. The `SecurityConf` arm classifies its own read
            // and refuses per directive below, which is the same rule applied
            // at its own read site.
            let file_writable = match directive.pam_config_file {
                PamConfigFile::PwQuality => pwquality_write.allowed,
                PamConfigFile::LoginDefs => login_defs_write.allowed,
                _ => true,
            };
            if !file_writable {
                continue;
            }

            match directive.pam_config_file {
                PamConfigFile::PwQuality => apply_exact_directive(
                    &mut pwquality_content,
                    &mut pwquality_changed,
                    &mut changes,
                    directive.pam_directive_name,
                    target_value,
                    directive.pam_config_file.config_format(),
                    "pwquality.conf",
                ),
                PamConfigFile::LoginDefs => apply_exact_directive(
                    &mut login_defs_content,
                    &mut login_defs_changed,
                    &mut changes,
                    directive.pam_directive_name,
                    target_value,
                    directive.pam_config_file.config_format(),
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
                    let over = config.resolve_i64(directive.pam_directive_name);
                    // Clamp so a per-host override can tighten but never loosen.
                    let target = clamp_target(directive.pam_compare, secure, over);

                    // Read directly (rather than reusing `observed`, which already
                    // read this via `read_effective_threshold`) because the refuse-
                    // to-auto-edit message below needs to know specifically whether
                    // the value came from an inline pam.d override, a distinction
                    // `PamObserved` deliberately does not carry.
                    let inline = read_pamd_inline(ctx, path, directive.pam_directive_name).await;

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
                    if let InlineRead::Value(value) = &inline {
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

                    // A stack that could not be read may hold an inline
                    // argument, and one would override this file: writing it
                    // would then succeed, be recorded as applied, and leave the
                    // host enforcing a value the run never saw. Refusing is the
                    // same answer as for an override actually seen, because
                    // both mean this file is not where the value lives.
                    if let InlineRead::Unreadable {
                        path: stack,
                        permission_denied,
                    } = &inline
                    {
                        warn!(
                            "{} may be set inline in {}, which could not be read; refusing to write {}",
                            directive.pam_directive_name, stack, path,
                        );
                        all_success = false;
                        let advice = if *permission_denied {
                            "re-run with sudo, or edit the PAM stack manually"
                        } else {
                            "repair the file, or edit the PAM stack manually"
                        };
                        changes.push(Change {
                            change_type: ChangeType::ConfigFile,
                            change_description: format!(
                                "{stack} could not be read and may set {name} inline, which would \
                                 override {path}; {advice} to set {name} to {target}",
                                name = directive.pam_directive_name,
                            ),
                            change_success: false,
                            change_error: Some(format!("PAM stack {stack} unreadable")),
                        });
                        continue;
                    }

                    let read = read_conf_classified(ctx, path).await;
                    let write =
                        conf_is_writable(ctx, path, &read, &mut changes, &mut all_success).await;
                    if !write.allowed {
                        continue;
                    }
                    // Reachable only for a confirmed absence with no vendor
                    // file behind it, which is the case where creating the
                    // file is correct.
                    let current = match read {
                        ConfRead::Content(content, _) => content,
                        _ => String::new(),
                    };

                    let target_str = target.to_string();
                    let updated = set_config_directive(
                        &current,
                        directive.pam_directive_name,
                        &target_str,
                        directive.pam_config_file.config_format(),
                        true,
                        Duplicates::Remove,
                    );

                    if backup_and_write(ctx, path, path, &updated, write.create_mode, &mut changes)
                        .await
                    {
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
        //
        // The `_writable` half of each guard is deliberate belt and braces, not
        // load bearing: Step 2 skips every directive belonging to a file that
        // could not be read, so nothing can set `_changed` for one. It stays
        // because the write it guards destroys the host's settings if it ever
        // runs on contents that were never read, and a second, local check
        // costs nothing.
        if pwquality_changed
            && pwquality_write.allowed
            && !write_changed_conf(
                ctx,
                "/etc/security/pwquality.conf",
                "pwquality.conf",
                &pwquality_content,
                pwquality_write.create_mode,
                &mut changes,
            )
            .await
        {
            all_success = false;
        }

        if login_defs_changed
            && login_defs_write.allowed
            && !write_changed_conf(
                ctx,
                "/etc/login.defs",
                "login.defs",
                &login_defs_content,
                login_defs_write.create_mode,
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

        // Whether anything reads the files about to be previewed, asked through
        // the same function scan and apply use, so a dry run cannot promise
        // hardening the apply it previews will report as incomplete.
        //
        // High, so the dry run fails. That is the same answer the real apply
        // gives: it records the missing module as a failed change, because the
        // remaining step is a /etc/pam.d edit this plugin refuses to make. A
        // dry run exiting 0 where the apply exits non-zero is the divergence
        // `ValidationReport::has_blocking_issue` exists to prevent.
        for (path, presence) in module_presence_by_file(ctx).await {
            let ModulePresence::NotInStack { module } = presence else {
                continue;
            };
            issues.push(ValidationIssue {
                validation_issue_config_key: None,
                validation_issue_message: module_not_loaded_message(path, module),
                validation_issue_severity: Severity::High,
            });
        }

        // Drift between the layers, asked here through the same function scan
        // uses so the two cannot come to disagree about one host.
        //
        // An issue rather than an estimated change, deliberately. Estimated
        // changes are what apply would do, and their count is read as the real
        // change count; apply does not import keys an existing /etc file omits,
        // because that file is the host's own and this tool cannot tell a key
        // the operator dropped on purpose from one an older release dropped for
        // them. Listing drift there would inflate the count and promise a write
        // that never happens. The message says so outright, so the preview
        // cannot be read as an undertaking to fix it.
        issues.extend(
            layer_drift_findings(ctx)
                .await
                .into_iter()
                .map(|finding| ValidationIssue {
                    validation_issue_config_key: None,
                    validation_issue_message: format!(
                        "{}; apply will not import them, so restoring them is a manual step",
                        finding.finding_description
                    ),
                    validation_issue_severity: finding.finding_severity,
                }),
        );

        // Estimate changes state-aware: read the current file values the same
        // way apply does and list only directives that would actually change;
        // already-compliant directives are tallied in compliant_count, not
        // listed, so estimated_changes holds only real pending changes.
        // Classified reads so a root-only file yields honest requires-root
        // wording, never a false "(currently not set)" claim.
        let pwquality = read_conf_classified(ctx, "/etc/security/pwquality.conf").await;
        let login_defs = read_conf_classified(ctx, "/etc/login.defs").await;

        let mut estimated_changes = Vec::new();
        // Excepted settings are recorded rather than dropped: a preview that
        // omits them shows a documented deviation as nothing at all.
        let mut exceptions: Vec<String> = Vec::new();
        let mut compliant_count = 0usize;

        for d in PAM_DIRECTIVES {
            if d.pam_config_file == PamConfigFile::PamAuth {
                continue;
            }

            // Honour an exception only when it documents the value the host
            // actually has, matching apply's rendering of an absent or
            // unreadable directive as "not set" so neither trusts an
            // exception on faith.
            let observed = observed_pam_value(ctx, d, &pwquality, &login_defs).await;
            if let Some(exception) =
                config.matching_exception(d.pam_directive_name, observed.value_or_not_set())
            {
                exceptions.push(hardener_common::types::exception_preview_line(
                    d.pam_directive_name,
                    observed.value_or_not_set(),
                    &exception.reason,
                ));
                continue;
            }

            match &d.pam_config_file {
                PamConfigFile::PwQuality | PamConfigFile::LoginDefs => {
                    let read = if d.pam_config_file == PamConfigFile::PwQuality {
                        &pwquality
                    } else {
                        &login_defs
                    };
                    let target_value = config.resolve_str(d.pam_directive_name, d.pam_secure_value);
                    // Absent reads as empty content, same as a confirmed-missing
                    // file always has: parsing finds nothing and the directive
                    // is honestly reported "(currently not set)" below. Only an
                    // Unreadable file (existing but blocked by privilege) must
                    // avoid that claim, since it is not a fact this scan can see.
                    let content = match read {
                        ConfRead::Content(c, _) => c.as_str(),
                        ConfRead::Absent => "",
                        ConfRead::Unreadable {
                            path,
                            permission_denied,
                            ..
                        } => {
                            // Never claim "not set" for a value this run could
                            // not see, and never offer the write either:
                            // `conf_is_writable` refuses this whole file and
                            // every directive in it is skipped.
                            estimated_changes.push(unreadable_preview(
                                d.pam_directive_name,
                                target_value,
                                path,
                                *permission_denied,
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
                    let over = config.resolve_i64(d.pam_directive_name);
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
                        // Apply refuses outright here, whether what could not be
                        // read is this directive's own conf or a PAM stack file
                        // that would override it, so the same shared wording as
                        // the arm above applies.
                        PamObserved::Unreadable {
                            path,
                            permission_denied,
                        } => estimated_changes.push(unreadable_preview(
                            d.pam_directive_name,
                            target,
                            path,
                            *permission_denied,
                        )),
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
            validation_report_exceptions: exceptions,
        })
    }
}

/// Builds the unchecked entry for a PAM directive whose config file cannot be
/// read at the current privilege level. The check id mirrors the finding id.
fn unchecked_pam_directive(
    directive: &PamDirective,
    reason: String,
    needs_privilege: bool,
) -> UncheckedCheck {
    UncheckedCheck {
        unchecked_check_id: format!("pam-{}", directive.pam_directive_name),
        unchecked_title: format!("PAM setting: {}", directive.pam_directive_name),
        unchecked_category: FindingCategory::Authentication,
        unchecked_reason: reason,
        unchecked_needs_privilege: needs_privilege,
        unchecked_compliance: get_pam_compliance_mappings(directive.pam_directive_name),
    }
}

/// What apply and validate both say about a file no module reads.
///
/// One sentence, because the two describe the same host and the operator acts
/// on it once. Scan says it per directive instead, since there the compliance
/// mappings have to travel with each control.
fn module_not_loaded_message(conf_path: &str, module: &str) -> String {
    format!(
        "{conf_path} is written but not read: the PAM stack does not load {module}. The \
         settings in it take effect only once that module is added to the stack, which this \
         plugin does not edit"
    )
}

/// The finding for a directive whose configuration file no module reads.
///
/// A separate finding from the ordinary "wrong value" one, and it fires
/// whatever the value is, because the value is not the problem: the file is
/// correct and inert. It keeps the directive's own id, severity and compliance
/// mappings, so every control that rested on the silent pass now rests on this
/// instead rather than on nothing.
fn module_absent_finding(directive: &PamDirective, module: &str, conf_path: &str) -> Finding {
    Finding {
        finding_id: format!("pam-{}", directive.pam_directive_name),
        finding_category: FindingCategory::Authentication,
        finding_current_value: "not enforced".to_string(),
        finding_description: format!(
            "PAM directive '{}' is set in {} but not enforced: the PAM stack does not load \
             {}, which is the only thing that reads that file",
            directive.pam_directive_name, conf_path, module
        ),
        finding_explanation: directive.pam_description.to_string(),
        finding_impact:
            "The setting appears configured and has no effect, so the host enforces nothing \
             while its configuration file says otherwise"
                .to_string(),
        finding_recommended_value: directive.pam_secure_value.to_string(),
        finding_remediation_steps: vec![
            format!("Install the package providing {module} if it is missing"),
            format!(
                "Add {module} to the PAM stack (system-auth, password-auth or the \
                 common-* file this distribution uses), then re-run the scan"
            ),
        ],
        finding_severity: directive.pam_severity,
        finding_title: format!("PAM setting not enforced: {}", directive.pam_directive_name),
        finding_compliance: get_pam_compliance_mappings(directive.pam_directive_name),
        // Deliberately never excepted: an exception documents a value the
        // operator accepts, and this is not about the value.
        finding_policy_exception: None,
    }
}

/// Why a PAM config file could not be read, phrased for an operator.
///
/// Every failure used to render as "requires root". An I/O error or non-UTF-8
/// content does not improve with sudo, so saying it does sends the operator
/// somewhere that cannot help.
fn unreadable_reason(path: &str, permission_denied: bool) -> String {
    if permission_denied {
        format!("reading {path} requires root")
    } else {
        format!("{path} could not be read")
    }
}

/// The parenthetical describing an unknown current value in a dry-run
/// estimate, matching [`unreadable_reason`]'s distinction.
fn current_value_caveat(permission_denied: bool) -> &'static str {
    if permission_denied {
        "current value requires root"
    } else {
        "current value could not be read"
    }
}

/// The dry-run preview line for a directive whose file this run could not read.
///
/// Apply never rewrites a file whose current contents it cannot see, because
/// merging directives into an empty buffer would replace the host's settings
/// with this tool's, so the preview says the directive will not be set and names
/// the file that failed rather than offering a conditional write.
///
/// One definition, because every arm of `validate` asks the same question and
/// two of them came to answer it differently: the `SecurityConf` arm said the
/// directive would not be set while the `PwQuality` and `LoginDefs` arms
/// promised to apply it "only if it differs", so one host was previewed two
/// ways depending on which file was unreadable.
fn unreadable_preview(
    directive_name: &str,
    target: impl std::fmt::Display,
    path: &str,
    permission_denied: bool,
) -> String {
    format!(
        "{directive_name} will not be set to {target}: {path} could not be read ({})",
        current_value_caveat(permission_denied)
    )
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

impl PamConfigFile {
    /// The syntax the file itself accepts. `login.defs(5)` defines
    /// `NAME VALUE`; `=` is not part of it. The `security/*.conf` files take
    /// `key = value`.
    fn config_format(&self) -> ConfigFormat {
        match self {
            PamConfigFile::LoginDefs => ConfigFormat::SpaceSeparated,
            _ => ConfigFormat::KeyValue,
        }
    }

    /// The file the directive lives in, or `None` for a directive that is
    /// itself a line in the PAM stack.
    fn conf_path(&self) -> Option<&'static str> {
        match self {
            PamConfigFile::PwQuality => Some("/etc/security/pwquality.conf"),
            PamConfigFile::LoginDefs => Some("/etc/login.defs"),
            PamConfigFile::SecurityConf(path) => Some(path),
            PamConfigFile::PamAuth => None,
        }
    }
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
fn pam_module_for(conf_path: &str) -> Option<(&'static str, &'static [&'static str])> {
    match conf_path {
        "/etc/security/pwquality.conf" => Some((
            "pam_pwquality.so",
            &[
                "/etc/pam.d/system-auth",
                "/etc/pam.d/password-auth",
                "/etc/pam.d/common-password",
            ],
        )),
        "/etc/security/faillock.conf" => Some((
            "pam_faillock.so",
            &[
                "/etc/pam.d/system-auth",
                "/etc/pam.d/password-auth",
                "/etc/pam.d/common-auth",
            ],
        )),
        "/etc/security/pwhistory.conf" => Some((
            "pam_pwhistory.so",
            &[
                "/etc/pam.d/system-auth",
                "/etc/pam.d/password-auth",
                "/etc/pam.d/common-password",
            ],
        )),
        // /etc/login.defs is deliberately absent: shadow-utils reads it
        // directly, so its settings take effect with no PAM module loaded.
        _ => None,
    }
}

/// Whether the PAM module that reads a configuration file is loaded by the
/// stack.
///
/// Four outcomes, because a file nothing reads, a file whose reader this run
/// could not look for, and a file with no module at all are three different
/// facts that used to be one. The distinction is the same one
/// [`InlineRead`] already draws, applied to the module rather than to its
/// arguments: absence concluded from a file that could not be opened would
/// fail a control on a host that may well be compliant, and absence never
/// concluded at all passes one on evidence nothing consults.
enum ModulePresence {
    /// A stack file was read and loads the module.
    InStack,
    /// At least one stack file was read, none of them loads the module, and
    /// none was left unread. The setting is not in force.
    NotInStack {
        /// The module nothing loads, named so the operator knows what to add.
        module: &'static str,
    },
    /// Nothing could be concluded: a candidate could not be read, or this
    /// distribution keeps its stack somewhere the table does not name.
    Indeterminate {
        /// Phrased for an operator, in the same voice as [`unreadable_reason`].
        reason: String,
        /// Whether a privileged re-run would settle it. A stack file blocked by
        /// permissions would; a distribution whose stack this table does not
        /// name would not, and offering sudo for the second is advice that
        /// changes nothing.
        needs_privilege: bool,
    },
    /// The file has no PAM module, so there is nothing to be in the stack.
    NoModule,
}

/// Every configuration file the directive table names, with whether its
/// consuming module is loaded.
///
/// Built from `PAM_DIRECTIVES` rather than from a second list of files, so a
/// directive added there cannot be the one nobody checked.
async fn module_presence_by_file(ctx: &Context) -> Vec<(&'static str, ModulePresence)> {
    let mut presence: Vec<(&'static str, ModulePresence)> = Vec::new();
    for directive in PAM_DIRECTIVES {
        let Some(path) = directive.pam_config_file.conf_path() else {
            continue;
        };
        if presence.iter().any(|(known, _)| *known == path) {
            continue;
        }
        presence.push((path, read_module_presence(ctx, path).await));
    }
    presence
}

/// The entry [`module_presence_by_file`] holds for a directive's file.
fn presence_for<'a>(
    presence: &'a [(&'static str, ModulePresence)],
    directive: &PamDirective,
) -> &'a ModulePresence {
    directive
        .pam_config_file
        .conf_path()
        .and_then(|path| {
            presence
                .iter()
                .find(|(known, _)| *known == path)
                .map(|(_, found)| found)
        })
        .unwrap_or(&ModulePresence::NoModule)
}

/// Reads whether the module that consumes `conf_path` is loaded.
///
/// Fails closed in both directions. A stack file that could not be read is one
/// more place the module might be, so it makes the answer indeterminate even
/// when another file was read and did not load it. A host where none of the
/// candidates exists is indeterminate too rather than absent, because the
/// candidate list is a set of per-distribution alternatives and a distribution
/// this table does not know is not a distribution without a PAM stack.
async fn read_module_presence(ctx: &Context, conf_path: &str) -> ModulePresence {
    let Some((module, files)) = pam_module_for(conf_path) else {
        return ModulePresence::NoModule;
    };
    let mut read_one = false;
    let mut unread: Option<(&'static str, bool)> = None;
    for file in files {
        match read_conf_classified(ctx, file).await {
            ConfRead::Content(content, _) => {
                read_one = true;
                if content
                    .lines()
                    .map(str::trim)
                    .any(|line| !line.starts_with('#') && line.contains(module))
                {
                    return ModulePresence::InStack;
                }
            }
            // Ordinary: the candidates are per-distribution alternatives, so
            // most hosts have only one or two of them.
            ConfRead::Absent => {}
            ConfRead::Unreadable {
                permission_denied, ..
            } => {
                unread.get_or_insert((file, permission_denied));
            }
        }
    }
    match (read_one, unread) {
        (_, Some((path, permission_denied))) => ModulePresence::Indeterminate {
            reason: unreadable_reason(path, permission_denied),
            needs_privilege: permission_denied,
        },
        (true, None) => ModulePresence::NotInStack { module },
        (false, None) => ModulePresence::Indeterminate {
            reason: format!(
                "no PAM stack file this tool knows of exists, so whether {module} is loaded \
                 could not be determined"
            ),
            // No privilege finds a file that is not there.
            needs_privilege: false,
        },
    }
}

/// An inline `arg=value` set on the directive's PAM module in the auth stack.
/// Inline args override `/etc/security/*.conf` when present; `None` if not set
/// inline. Only whole-token `arg=` matches (so `even_deny_root` never matches
/// `deny`).
async fn read_pamd_inline(ctx: &Context, conf_path: &str, arg: &str) -> InlineRead {
    let Some((module, files)) = pam_module_for(conf_path) else {
        return InlineRead::NotSet;
    };
    let mut unread: Option<(&'static str, bool)> = None;
    for file in files {
        // Absence is ordinary: the candidate list is distro-variant, so most
        // hosts have only one or two of these. Unreadable is not, and is
        // remembered rather than skipped, because an inline argument beats the
        // .conf outright: a file that could not be read may hold the value in
        // force, and reporting the .conf's value instead would be reporting a
        // number nothing on the host consults.
        let content = match read_conf_classified(ctx, file).await {
            ConfRead::Content(c, _) => c,
            ConfRead::Absent => continue,
            ConfRead::Unreadable {
                permission_denied, ..
            } => {
                unread.get_or_insert((file, permission_denied));
                continue;
            }
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
                // A value actually seen is the answer even if another candidate
                // was unreadable: the list is a set of alternatives, not a
                // precedence chain, so finding one settles that an inline
                // override exists and what it says.
                return InlineRead::Value(value.to_string());
            }
        }
    }
    match unread {
        Some((path, permission_denied)) => InlineRead::Unreadable {
            path,
            permission_denied,
        },
        None => InlineRead::NotSet,
    }
}

/// Whether the PAM stack sets a threshold directive inline on its module.
///
/// Three outcomes, because an inline argument overrides `/etc/security/*.conf`
/// entirely. Folding the third into [`Self::NotSet`] made a stack this run
/// could not read indistinguishable from one confirmed to carry no override,
/// and the two lead opposite ways: scan reported the `.conf` value as the
/// host's own, and apply wrote that file believing the write would take
/// effect.
enum InlineRead {
    /// An inline `arg=value` was read off the module.
    Value(String),
    /// Every candidate file was read or confirmed absent, and none sets it.
    NotSet,
    /// A candidate could not be read, so whether one is set is unknown.
    /// `path` names it, and `permission_denied` decides whether telling the
    /// operator to use sudo is honest advice or a dead end.
    Unreadable {
        path: &'static str,
        permission_denied: bool,
    },
}

/// How a configuration file read turned out.
///
/// `Absent` and `Unreadable` are deliberately distinct: a file that is not
/// there has genuinely unset directives and may be created, whereas a file
/// whose contents could not be read tells us nothing, and merging directives
/// into the empty string would replace the host's file with ours.
enum ConfRead {
    /// A file was read, and which layer supplied it. The layer is not
    /// decoration: content from `/usr/etc` is the distribution's, so a write
    /// path that treated it as an ordinary `/etc` file would create an `/etc`
    /// copy and mask the vendor file wholesale, which is the defect this
    /// module's guard exists to refuse.
    Content(String, ConfigLayer),
    /// Absence confirmed at **both** layers, so a directive really is unset.
    Absent,
    /// Present (or of indeterminate existence) but unreadable, at whichever
    /// layer failed. `path` names it, because "your /etc file cannot be read"
    /// and "whether a vendor file exists could not be checked" call for
    /// different advice and the caller cannot tell them apart otherwise.
    /// `permission_denied` separates a privilege failure, which sudo fixes,
    /// from an I/O or encoding failure, which it does not.
    Unreadable {
        path: String,
        reason: String,
        permission_denied: bool,
    },
}

/// Reads whichever copy of a config file the host actually obeys.
///
/// `/etc` first, `/usr/etc` only on absence confirmed there, so an `/etc` file
/// that exists but cannot be read never answers with the vendor copy's values.
/// Fails closed: any read failure of a path that is not confirmed absent is
/// `Unreadable`, including a failure to determine whether it exists at all.
///
/// `Absent` therefore means absent at **both** layers. Every consumer was
/// re-read against that narrowed meaning when this stopped being an `/etc`-only
/// read.
async fn read_conf_classified(ctx: &Context, path: &str) -> ConfRead {
    match read_layered(ctx.executor().as_ref(), path).await {
        LayeredRead::Found { content, layer, .. } => ConfRead::Content(content, layer),
        LayeredRead::Absent => ConfRead::Absent,
        LayeredRead::Unreadable {
            path,
            reason,
            permission_denied,
        } => {
            warn!("Failed to read {}: {}", path, reason);
            let path = path.clone();
            // Only a genuine privilege failure is worth telling the operator to
            // re-run with sudo. An I/O error or non-UTF-8 content will not
            // improve with root, and every failure used to render as "requires
            // root", sending them down a dead end.
            ConfRead::Unreadable {
                path,
                reason,
                permission_denied,
            }
        }
    }
}

/// Whether apply may write `path`, and how, recording the refusal when it may
/// not.
///
/// One decision in one place, called by every site that could write one of this
/// plugin's configuration files. A file whose contents could not be read must
/// not be rewritten, because merging directives into an empty buffer replaces
/// the host's settings with ours; that marks the run unsuccessful, since a run
/// that hardened nothing has not earned a clean result. A file whose content
/// came from the vendor layer is written, carrying that content with it, so the
/// settings this plugin does not manage survive the edit.
/// A finding for every `/etc` file in [`layer_drift::LAYERED_CONFS`] that masks
/// keys its `/usr/etc` counterpart sets.
///
/// One definition, because the question is the same wherever it is asked: it
/// used to be written out inline for `/etc/login.defs` in `scan` and asked
/// nowhere else, so the other three layered files drifted unreported and
/// `validate` could not mention drift at all.
///
/// Only an admin file **in force** can mask anything: if the vendor file is the
/// one being read there is no override, and if there is no vendor file there is
/// nothing to lose. It reports whoever caused the drift, so it catches an
/// operator's hand-rolled file and a vendor that adds a key in a later package
/// as well as a file an older release of this tool wrote.
///
/// The admin files are read here rather than passed in, so a caller cannot
/// cover three files and forget the fourth. `scan` reads two of them a second
/// time as a result; a config file read twice costs less than a check wired to
/// one call site.
async fn layer_drift_findings(ctx: &Context) -> Vec<Finding> {
    let mut findings = Vec::new();

    for conf in layer_drift::LAYERED_CONFS {
        let Some(vendor_path) = vendor_path_for(conf.admin_path) else {
            continue;
        };
        let ConfRead::Content(admin, ConfigLayer::Admin) =
            read_conf_classified(ctx, conf.admin_path).await
        else {
            continue;
        };

        // The layer this read reports is meaningless: read_conf_classified
        // attributes a layer by which probe answered, and this path names the
        // vendor file directly. Its three outcomes are what is wanted.
        match read_conf_classified(ctx, &vendor_path).await {
            ConfRead::Content(vendor, _) => {
                let masked = layer_drift::masked_keys(&admin, &vendor);
                if !masked.is_empty() {
                    findings.push(layer_drift::masked_keys_finding(
                        conf,
                        &vendor_path,
                        &masked,
                    ));
                }
            }
            // No vendor file, so the admin file masks nothing.
            ConfRead::Absent => {}
            // Whether anything is masked cannot be determined. Deliberately not
            // an unchecked entry: those carry a plugin's declared coverage into
            // ManualReview, which would let a housekeeping observation move
            // compliance results.
            ConfRead::Unreadable { path, reason, .. } => {
                warn!("Could not check {} for masked keys: {}", path, reason);
            }
        }
    }

    findings
}

async fn conf_is_writable(
    ctx: &Context,
    path: &str,
    read: &ConfRead,
    changes: &mut Vec<Change>,
    all_success: &mut bool,
) -> ConfWrite {
    match read {
        ConfRead::Content(_, ConfigLayer::Admin) => ConfWrite::allowed(),
        // The content came from `/usr/etc`, so no file exists under `/etc` yet
        // and the buffer the caller holds is the vendor's. Writing that buffer
        // creates the `/etc` copy with every vendor setting intact, and the
        // managed directives are edited into it, so the whole-file override
        // masks nothing. 1.5.1 refused this write instead, which kept the
        // vendor settings by leaving the host unhardened.
        ConfRead::Content(_, ConfigLayer::Vendor) => {
            let vendor = vendor_path_for(path).unwrap_or_else(|| path.to_string());
            info!("Creating {} from {} before editing it", path, vendor);
            changes.push(Change {
                change_type: ChangeType::ConfigFile,
                change_description: format!(
                    "Creating {path} from {vendor} so the settings it makes survive: this \
                     host keeps vendor configuration in {vendor}, and {path} overrides it as \
                     a whole file rather than per directive"
                ),
                change_success: true,
                change_error: None,
            });
            ConfWrite {
                allowed: true,
                create_mode: Some(login_defs::mode_for_copy_of(ctx, &vendor).await),
            }
        }
        ConfRead::Absent => ConfWrite::allowed(),
        // Which layer failed decides the advice. An unreadable `/etc` file is
        // the one in force and rewriting it would discard settings this run
        // cannot see. A vendor layer whose existence could not be determined is
        // a different problem: the `/etc` file is absent, and creating it would
        // silence a vendor file that may well be there.
        ConfRead::Unreadable {
            path: unreadable,
            reason,
            ..
        } if unreadable == path => {
            warn!("Refusing to rewrite {}: {}", path, reason);
            *all_success = false;
            changes.push(Change {
                change_type: ChangeType::ConfigFile,
                change_description: format!(
                    "Refused to rewrite {path}: its current contents could not be read, and \
                     rewriting it would discard them"
                ),
                change_success: false,
                change_error: Some(reason.clone()),
            });
            ConfWrite::refused()
        }
        ConfRead::Unreadable {
            path: vendor,
            reason,
            ..
        } => {
            warn!(
                "Refusing to create {}: whether {} exists could not be checked",
                path, vendor
            );
            *all_success = false;
            changes.push(Change {
                change_type: ChangeType::ConfigFile,
                change_description: format!(
                    "Refused to create {path}: whether this host keeps vendor configuration \
                     in {vendor} could not be checked, and creating {path} would silence it \
                     if it is there"
                ),
                change_success: false,
                change_error: Some(reason.clone()),
            });
            ConfWrite::refused()
        }
    }
}

/// Whether apply may write a file, and the mode to give it if the write creates
/// it.
///
/// `create_mode` exists because
/// [`hardener_common::file_utils::update_file_atomically`] restores an
/// *original* mode, and a file being created has none, so it otherwise keeps
/// whatever mode the temporary file happened to have. A copy of a vendor file
/// that lands 0600 against the vendor's 0644 is unreadable to the ordinary-user
/// tools that consume it, which is a configuration that appears to apply and
/// does not.
struct ConfWrite {
    allowed: bool,
    create_mode: Option<u32>,
}

impl ConfWrite {
    /// Write it as it stands, keeping whatever mode it already has.
    fn allowed() -> Self {
        Self {
            allowed: true,
            create_mode: None,
        }
    }

    /// Do not write it. The reason is already recorded as a failed change.
    fn refused() -> Self {
        Self {
            allowed: false,
            create_mode: None,
        }
    }
}

/// Effective value of a threshold directive at the current privilege level.
enum ThresholdRead {
    Value(String),
    NotSet,
    /// The value could not be determined. `path` names whichever file was
    /// unreadable, which is the `.conf` or a PAM stack file that may override
    /// it, and the operator is owed the one that actually failed.
    /// `permission_denied` decides whether telling them to use sudo is honest
    /// advice or a dead end.
    Unreadable {
        path: &'static str,
        permission_denied: bool,
    },
}

/// Effective value of a threshold directive: an inline PAM-stack override wins
/// over the `/etc/security/*.conf` value. A conf file blocked by privileges
/// surfaces as `PermissionDenied` so the caller reports it unchecked.
async fn read_effective_threshold(ctx: &Context, arg: &str, conf: &'static str) -> ThresholdRead {
    match read_pamd_inline(ctx, conf, arg).await {
        InlineRead::Value(inline) => return ThresholdRead::Value(inline),
        // The stack wins over the conf, so a stack that could not be read
        // leaves the effective value unknown however readable the conf is.
        InlineRead::Unreadable {
            path,
            permission_denied,
        } => {
            return ThresholdRead::Unreadable {
                path,
                permission_denied,
            };
        }
        InlineRead::NotSet => {}
    }
    match read_conf_classified(ctx, conf).await {
        ConfRead::Unreadable {
            permission_denied, ..
        } => ThresholdRead::Unreadable {
            path: conf,
            permission_denied,
        },
        // A missing file has no directives, same as today: empty content.
        ConfRead::Absent => ThresholdRead::NotSet,
        ConfRead::Content(content, _) => {
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
    /// The file holding this directive could not be read, so its value is
    /// unknown. `permission_denied` separates "run with sudo" from a failure
    /// root will not fix.
    Unreadable {
        path: &'static str,
        permission_denied: bool,
    },
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
            PamObserved::NotSet | PamObserved::Unreadable { .. } => "not set",
        }
    }
}

/// Computes [`PamObserved`] for `directive`. `pwquality` and `login_defs` are
/// the classified reads the caller has already performed, so this does I/O only
/// for `SecurityConf` directives.
///
/// `login_defs` is classified rather than plain content because the two states
/// it used to conflate call for opposite answers: a file that is genuinely
/// absent leaves its directives unset, while one that exists and could not be
/// read tells this run nothing at all. Rendering the second as "not set"
/// reported findings against hosts that were already hardened, and it did so
/// wherever an unprivileged scan met a root-only `/etc/login.defs`.
async fn observed_pam_value(
    ctx: &Context,
    directive: &PamDirective,
    pwquality: &ConfRead,
    login_defs: &ConfRead,
) -> PamObserved {
    match &directive.pam_config_file {
        PamConfigFile::PwQuality => match pwquality {
            ConfRead::Content(content, _) => match parse_config_value(
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
            ConfRead::Unreadable {
                permission_denied, ..
            } => PamObserved::Unreadable {
                path: "/etc/security/pwquality.conf",
                permission_denied: *permission_denied,
            },
        },
        PamConfigFile::LoginDefs => match login_defs {
            ConfRead::Content(content, _) => match parse_config_value(
                content,
                directive.pam_directive_name,
                ConfigFormat::Auto,
                true,
            ) {
                Some(v) => PamObserved::Value(v),
                None => PamObserved::NotSet,
            },
            ConfRead::Absent => PamObserved::NotSet,
            ConfRead::Unreadable {
                permission_denied, ..
            } => PamObserved::Unreadable {
                path: "/etc/login.defs",
                permission_denied: *permission_denied,
            },
        },
        PamConfigFile::PamAuth => PamObserved::NotSet,
        PamConfigFile::SecurityConf(path) => {
            match read_effective_threshold(ctx, directive.pam_directive_name, path).await {
                ThresholdRead::Value(v) => PamObserved::Value(v),
                ThresholdRead::NotSet => PamObserved::NotSet,
                // The path carried here, not `path`: what could not be read may
                // be a PAM stack file rather than the conf, and naming the
                // wrong one sends the operator to a file that was fine.
                ThresholdRead::Unreadable {
                    path,
                    permission_denied,
                } => PamObserved::Unreadable {
                    path,
                    permission_denied,
                },
            }
        }
    }
}

/// State-aware exact-match apply for a config held in memory: mutates `content`
/// and records a real change when the file's current value differs from the
/// target, when the file defines the key more than once, or when the line
/// holding an already-correct value needs its separator repaired in place;
/// anything else records a Skipped no-op instead. The third case means the
/// count this produces is not always a count of hardening successes, since a
/// cosmetic repair reports the same as a load-bearing one. `format` is the
/// syntax the file accepts, which is the caller's to know: writing a
/// directive in a syntax its file does not parse leaves the insecure value in
/// force.
fn apply_exact_directive(
    content: &mut String,
    changed: &mut bool,
    changes: &mut Vec<Change>,
    name: &str,
    target: &str,
    format: ConfigFormat,
    file_label: &str,
) {
    let current = parse_config_value(content, name, ConfigFormat::Auto, true);
    let updated = set_config_directive(content, name, target, format, true, Duplicates::Remove);
    // A correct value alone is not enough to leave the file alone: these files
    // take one definition per key, and an earlier release appended a second
    // one in a syntax they do not parse. Skipping on the value would leave that
    // repair undone on every run, so the file never converges. With the value
    // already correct the writer can still rewrite a line where it stands,
    // repair the syntax of that line, or drop a duplicate, and only comparing
    // the lines themselves tells "nothing to do" apart from all three: a
    // repaired line leaves the count of lines exactly as it was, which is how a
    // file whose only definition is the appended one stayed broken and green.
    // Blank lines are excluded because joining the lines drops a trailing
    // blank, which would otherwise read as a change and rewrite a compliant
    // file.
    fn lines_with_text(text: &str) -> Vec<&str> {
        text.lines().filter(|l| !l.trim().is_empty()).collect()
    }
    if current.as_deref() == Some(target) && lines_with_text(&updated) == lines_with_text(content) {
        changes.push(Change {
            change_type: ChangeType::Skipped,
            change_description: format!("{} already set to {} in {}", name, target, file_label),
            change_success: true,
            change_error: None,
        });
        return;
    }

    *content = updated;
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
    create_mode: Option<u32>,
    changes: &mut Vec<Change>,
) -> bool {
    // A file that is not there has nothing to back up, and cp on a missing
    // source fails. Absence is an ordinary case: creating the file is correct.
    // Fail closed, so only a CONFIRMED absence skips the backup. An existence
    // probe that errors, or that says the file is present, still requires one.
    let creating = matches!(ctx.executor().path_exists(Path::new(path)).await, Ok(false));
    let needs_backup = !creating;

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
            // A file that already existed keeps the mode it had, restored by
            // `update_file_atomically`. One being created has no original mode
            // to restore, so it wears the temporary file's until this sets it.
            if let Some(mode) = create_mode.filter(|_| creating) {
                apply_create_mode(ctx, path, mode, changes).await;
            }
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

/// Rewrites a config file whose in-memory buffer the directive loop changed,
/// recording the write. Returns false when no write happened, so the caller can
/// mark the run unsuccessful; `backup_and_write` has already recorded why.
async fn write_changed_conf(
    ctx: &Context,
    path: &str,
    file_label: &str,
    content: &str,
    create_mode: Option<u32>,
    changes: &mut Vec<Change>,
) -> bool {
    if !backup_and_write(ctx, path, file_label, content, create_mode, changes).await {
        return false;
    }
    changes.push(Change {
        change_type: ChangeType::ConfigFile,
        change_description: format!("Wrote modified {}", file_label),
        change_success: true,
        change_error: None,
    });
    true
}

/// Gives a newly created configuration file its intended mode.
///
/// Not fatal when it fails: the settings are in force either way, and refusing
/// the whole apply over a permission bit would leave the host less hardened for
/// a lesser problem. It is recorded rather than only logged, because a file
/// that ordinary-user tools cannot read is a real gap and the operator has to
/// be able to see it.
async fn apply_create_mode(ctx: &Context, path: &str, mode: u32, changes: &mut Vec<Change>) {
    let octal = format!("{mode:o}");
    match ctx
        .executor()
        .execute_command("chmod", &[&octal, path])
        .await
    {
        Ok(output) if output.success() => {}
        Ok(output) => {
            warn!(
                "Could not set mode {} on {}: {}",
                octal, path, output.stderr
            );
            changes.push(Change {
                change_type: ChangeType::ConfigFile,
                change_description: format!("Could not set mode {octal} on {path}"),
                change_success: false,
                change_error: Some(output.stderr.trim().to_string()),
            });
        }
        Err(e) => {
            warn!("Could not set mode {} on {}: {}", octal, path, e);
            changes.push(Change {
                change_type: ChangeType::ConfigFile,
                change_description: format!("Could not set mode {octal} on {path}"),
                change_success: false,
                change_error: Some(e.to_string()),
            });
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every read failure used to render as "requires root", so an I/O error
    /// or non-UTF-8 content told the operator to reach for sudo, which cannot
    /// help. Only a genuine privilege failure earns that wording.
    #[test]
    fn only_a_privilege_failure_tells_the_operator_to_use_root() {
        let denied = unreadable_reason("/etc/security/pwquality.conf", true);
        assert!(
            denied.contains("requires root"),
            "a privilege failure is exactly the sudo case: {denied}"
        );

        let broken = unreadable_reason("/etc/security/pwquality.conf", false);
        assert!(
            !broken.contains("requires root"),
            "an I/O or encoding failure must not be blamed on privilege: {broken}"
        );
        assert!(
            broken.contains("/etc/security/pwquality.conf"),
            "the path must still be named: {broken}"
        );
    }

    /// The dry-run parenthetical carries the same distinction, so a preview
    /// cannot claim a value is root-only when root would not reveal it.
    #[test]
    fn the_dry_run_caveat_matches_the_actual_cause() {
        assert_eq!(current_value_caveat(true), "current value requires root");
        assert!(!current_value_caveat(false).contains("root"));
    }

    /// The unchecked entry a scan emits inherits the same wording, and keeps
    /// its compliance mappings either way so the control still reaches manual
    /// review rather than passing.
    #[test]
    fn an_unchecked_pam_directive_reports_the_real_cause() {
        let directive = PAM_DIRECTIVES
            .iter()
            .find(|d| d.pam_directive_name == "minlen")
            .expect("minlen is a known PAM directive");

        // The privilege-versus-I/O wording moved out to the caller when a
        // second cause of an unchecked directive appeared: a stack file that
        // could not be read is one reason, and a distribution whose stack this
        // table does not name is another, and neither is phrased by this
        // function any more. `unreadable_reason` still owns that distinction
        // and `only_a_privilege_failure_tells_the_operator_to_use_root` still
        // pins it.
        let entry = unchecked_pam_directive(
            directive,
            unreadable_reason("/etc/security/pwquality.conf", true),
            true,
        );
        assert!(entry.unchecked_reason.contains("requires root"));
        assert!(
            entry.unchecked_needs_privilege,
            "a privilege failure must offer the remedy that reaches it"
        );
        assert_eq!(entry.unchecked_check_id, "pam-minlen");
        assert!(
            !entry.unchecked_compliance.is_empty(),
            "the mappings must survive so the control still reaches manual review"
        );

        let carried = unchecked_pam_directive(directive, "any reason at all".to_string(), false);
        assert_eq!(
            carried.unchecked_reason, "any reason at all",
            "the reason is the caller's, reported rather than reinterpreted"
        );
        assert!(
            !carried.unchecked_needs_privilege,
            "a cause privilege cannot reach must not offer sudo, which is what the \
             stack table's own unknown distribution case produces"
        );
    }

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
                ConfRead::Unreadable { .. }
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
