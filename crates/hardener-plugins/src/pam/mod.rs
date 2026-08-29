//! PAM (Pluggable Authentication Modules) hardening plugin
//!
//! This plugin hardens system authentication by configuring:
//! - Password quality requirements (complexity, length)
//! - Account lockout policies (failed login attempts)
//! - Password ageing policies (expiry, reuse prevention)

mod apply;
mod assess;
mod layer_drift;
mod login_defs;
mod validate;

use crate::strictness::Strictness;
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
    Change, ChangeType, Context, PluginConfig,
    plugin::{
        ApplyResult, Finding, HardeningPlugin, PluginMetadata, ScanResult, UncheckedBlocker,
        UncheckedCheck, ValidationIssue, ValidationReport,
    },
};
use hardener_types::ExceptionOutcome;
use std::path::Path;
use tracing::{info, warn};

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

/// Every compliance mapping this plugin can emit, across all PAM/login.defs
/// directives it assesses. Aggregated into the engine's coverage set.
pub fn coverage() -> Vec<ComplianceMapping> {
    PAM_DIRECTIVES
        .iter()
        .flat_map(|d| get_pam_compliance_mappings(d.pam_directive_name))
        .collect()
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
        assess::scan(ctx, config).await
    }

    async fn apply(&self, ctx: &mut Context, config: &PluginConfig) -> Result<ApplyResult> {
        apply::apply(ctx, config).await
    }

    // Neither reload method is implemented: PAM changes take effect
    // immediately for new authentication attempts, so a rollback that
    // restored /etc/pam.d has nothing to reload.

    /// Measured on the same runs as the permissions plugin, on 2026-08-10: a
    /// line naming a probe was appended to `/etc/security/faillock.conf`
    /// after a checkpoint was taken, forced live, then rolled back.
    /// Readback: the appended line was gone after the rollback, and there
    /// was nothing left to report.
    ///
    /// This plugin checkpoints two different classes of file
    /// (`/etc/security/pwquality.conf`, `/etc/login.defs`, `/etc/pam.d`,
    /// `/etc/security/faillock.conf`, `/etc/security/pwhistory.conf`), and
    /// `apply` does not treat them the same: the `SecurityConf` arm above
    /// writes `/etc/security/*.conf` directly via `backup_and_write`, but
    /// `apply` never writes `/etc/pam.d/*` itself, an inline override found
    /// there is only ever reported as a manual action
    /// (`all_success = false`, "edit the PAM stack manually"). What both
    /// classes share, and what actually answers this method, is that
    /// neither has runtime state anywhere but the file: `pam_faillock`,
    /// `pam_pwquality`, `pam_pwhistory` and the stack itself are all read
    /// fresh on every authentication attempt, the same reasoning the
    /// missing reload methods above already give. Restoring the files is
    /// therefore the entire revert for either class.
    ///
    /// **No self-scoping guard.** This plugin takes `reloads_for_path`'s
    /// default, which returns `false` for every path. Gating this method on
    /// `reloads_for_path`, the way SSH's does, would refuse every path and
    /// leave it dead code.
    async fn divergences_after_rollback(
        &self,
        _ctx: &Context,
        _restored: &[std::path::PathBuf],
    ) -> Vec<hardener_types::RollbackDivergence> {
        Vec::new()
    }

    async fn validate(&self, ctx: &Context, config: &PluginConfig) -> Result<ValidationReport> {
        validate::validate(ctx, config).await
    }
}

/// Builds the unchecked entry for a PAM directive whose config file cannot be
/// read at the current privilege level. The check id mirrors the finding id.
fn unchecked_pam_directive(
    directive: &PamDirective,
    reason: String,
    needs_privilege: bool,
) -> UncheckedCheck {
    // `needs_privilege` is derived from the failure rather than asserted, so
    // the two answers this plugin can give map cleanly onto the two the type
    // records. A read DAC or an LSM refused is exactly what root fixes; a
    // file that is simply absent is not, and no privilege will make
    // it appear.
    let blocker = match needs_privilege {
        true => UncheckedBlocker::Privilege,
        false => UncheckedBlocker::Environment,
    };
    UncheckedCheck {
        unchecked_check_id: format!("pam-{}", directive.pam_directive_name),
        unchecked_title: format!("PAM setting: {}", directive.pam_directive_name),
        unchecked_category: FindingCategory::Authentication,
        unchecked_reason: reason,
        unchecked_blocker: blocker,
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
/// whatever the value is, because the value is not the problem: nothing reads
/// the file. It keeps the directive's own id, severity and compliance
/// mappings, so every control that rested on the silent pass now rests on this
/// instead rather than on nothing.
///
/// **It may say nothing about the file's contents**, and this is the whole of
/// the reasoning. It is reached from the `NotInStack` arm, which runs before
/// the directive's value is read, so one sentence has to cover a file that
/// sets the directive, one that could not be read, one absent at both layers
/// and one that is readable and omits it. It used to open "is set in", which
/// is true of the first alone: an unprivileged scan of a host with a
/// root-only `pwquality.conf` logged the failed read and then reported six
/// directives as set in it. Every claim here is now about the stack, which is
/// the thing that was actually read.
/// The one directive whose enforcement depends on how shadow was built.
const MIN_DAYS_DIRECTIVE: &str = "PASS_MIN_DAYS";

/// The two `security/*.conf` files this plugin both compares for layer drift
/// and reads a directive out of.
///
/// Named rather than written out at each use because the two uses have to
/// agree: the hoisted read is matched to the directive's file by string, so a
/// path spelled differently in the two places silently reverts #170 and the
/// file is read, and warned about, twice again.
const FAILLOCK_CONF: &str = "/etc/security/faillock.conf";
const PWHISTORY_CONF: &str = "/etc/security/pwhistory.conf";

/// Whether this host's shadow implements a minimum password age at all.
///
/// Arch builds it without one. `chage` there has no `-m/--mindays`, prints no
/// minimum line, and `useradd` leaves `sp_min` empty while honouring
/// `PASS_MAX_DAYS` and `PASS_WARN_AGE` from the same `/etc/login.defs`. That
/// last part is what rules out a file-reading problem: one `useradd` run took
/// two of the three directives and dropped the third. So writing
/// `PASS_MIN_DAYS` there changes nothing any account will ever see.
///
/// Asked of `chage` through the executor, so a remote scan asks the remote
/// host rather than this one. `chage` is shadow's own reader for these fields
/// and ships with `useradd`, which makes its usage text the closest thing to a
/// direct question about the build.
///
/// Judged on the usage text rather than the exit status, because shadow builds
/// differ on whether `--help` exits zero and several print it to stderr.
/// `None` means the probe could not be run, which callers must not collapse
/// into either answer: a confident "unsupported" derived from a failed probe
/// would report every host as unable to enforce the directive.
async fn min_days_enforceable(ctx: &Context) -> Option<bool> {
    let output = ctx
        .executor()
        .execute_command("chage", &["--help"])
        .await
        .ok()?;
    let usage = format!("{}{}", output.stdout, output.stderr);
    if usage.trim().is_empty() {
        return None;
    }
    Some(usage.contains("--mindays"))
}

/// The finding for a directive the host's shadow cannot act on.
///
/// Shaped like [`module_absent_finding`], because it is the same defect: a
/// value written into a file that nothing on this host will ever read. The
/// remediation cannot be "set it correctly", since it already is set correctly.
fn min_days_unenforceable_finding(directive: &PamDirective) -> Finding {
    Finding {
        finding_id: format!("pam-{}", directive.pam_directive_name),
        finding_category: FindingCategory::Authentication,
        finding_current_value: "not enforced".to_string(),
        finding_description: format!(
            "'{}' is not enforced: this system's shadow provides no minimum \
             password age, so the value in /etc/login.defs reaches no account",
            directive.pam_directive_name
        ),
        finding_explanation: directive.pam_description.to_string(),
        finding_impact:
            "New accounts are created with no minimum password age whatever /etc/login.defs \
             says, so a user can change a password repeatedly to cycle back to an old one"
                .to_string(),
        finding_recommended_value: directive.pam_secure_value.to_string(),
        finding_remediation_steps: vec![
            "This is a property of the distribution's shadow build, not of the configuration: \
             the value in /etc/login.defs is already correct and is left in place"
                .to_string(),
            "Confirm with `chage --help`, which offers no -m/--mindays on an affected host"
                .to_string(),
            "Enforce password-reuse limits through pam_pwhistory instead, which this plugin \
             also manages"
                .to_string(),
        ],
        finding_severity: directive.pam_severity,
        finding_title: format!("PAM setting not enforced: {}", directive.pam_directive_name),
        finding_compliance: get_pam_compliance_mappings(directive.pam_directive_name),
        // Never excepted, for the same reason as the module-absent finding: an
        // exception documents a value the operator accepts, and this is not
        // about the value. The value is already correct.
        finding_exception: ExceptionOutcome::NotConfigured,
        finding_exception_key: None,
    }
}

fn module_absent_finding(directive: &PamDirective, module: &str, conf_path: &str) -> Finding {
    Finding {
        finding_id: format!("pam-{}", directive.pam_directive_name),
        finding_category: FindingCategory::Authentication,
        finding_current_value: "not enforced".to_string(),
        finding_description: format!(
            "PAM directive '{}' is not enforced: the PAM stack does not load {}, which is \
             the only thing that reads {}",
            directive.pam_directive_name, module, conf_path
        ),
        finding_explanation: directive.pam_description.to_string(),
        finding_impact: format!(
            "Nothing on this host reads {conf_path}, so the directive has no effect whatever \
             its value and the host enforces nothing for it"
        ),
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
        finding_exception: ExceptionOutcome::NotConfigured,
        finding_exception_key: None,
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

/// What a dry run reports for a directive whose file this run could not read.
///
/// Apply never rewrites a file whose current contents it cannot see, because
/// merging directives into an empty buffer would replace the host's settings
/// with this tool's, so the report says the directive will not be set and names
/// the file that failed rather than offering a conditional write.
///
/// An issue rather than an estimated change, because estimated changes are
/// documented as genuinely pending ones and their length is read as the real
/// change count: a renderer prints it as "N change(s) to apply" and the fleet
/// path sums it into `would_change`. A line saying no write will happen is the
/// opposite of a pending change, and counting it reported queued writes on a
/// host where apply will attempt none.
///
/// High, so the dry run fails. That is the same answer the real apply gives:
/// `conf_is_writable` refuses the file, records the refusal as a failed change
/// and clears `all_success`. A dry run exiting 0 where the apply exits non-zero
/// is the divergence `ValidationReport::has_blocking_issue` exists to prevent.
///
/// One definition, because every arm of `validate` asks the same question and
/// two of them came to answer it differently: the `SecurityConf` arm said the
/// directive would not be set while the `PwQuality` and `LoginDefs` arms
/// promised to apply it "only if it differs", so one host was previewed two
/// ways depending on which file was unreadable.
fn unreadable_issue(
    directive_name: &str,
    target: impl std::fmt::Display,
    path: &str,
    permission_denied: bool,
) -> ValidationIssue {
    ValidationIssue {
        validation_issue_config_key: None,
        validation_issue_message: format!(
            "{directive_name} will not be set to {target}: {path} could not be read ({})",
            current_value_caveat(permission_denied)
        ),
        validation_issue_severity: Severity::High,
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
    pam_compare: Strictness,
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

/// Secure PAM configuration directives.
const PAM_DIRECTIVES: &[PamDirective] = &[
    // Password Quality (pwquality.conf)
    PamDirective {
        pam_directive_name: "minlen",
        pam_secure_value: "14",
        pam_description: "Minimum password length of 14 characters",
        pam_severity: Severity::High,
        pam_config_file: PamConfigFile::PwQuality,
        pam_compare: Strictness::AtLeast,
    },
    PamDirective {
        pam_directive_name: "dcredit",
        pam_secure_value: "-1",
        pam_description: "Require at least one digit in password",
        pam_severity: Severity::Medium,
        pam_config_file: PamConfigFile::PwQuality,
        pam_compare: Strictness::AtMost,
    },
    PamDirective {
        pam_directive_name: "ucredit",
        pam_secure_value: "-1",
        pam_description: "Require at least one uppercase character in password",
        pam_severity: Severity::Medium,
        pam_config_file: PamConfigFile::PwQuality,
        pam_compare: Strictness::AtMost,
    },
    PamDirective {
        pam_directive_name: "lcredit",
        pam_secure_value: "-1",
        pam_description: "Require at least one lowercase character in password",
        pam_severity: Severity::Medium,
        pam_config_file: PamConfigFile::PwQuality,
        pam_compare: Strictness::AtMost,
    },
    PamDirective {
        pam_directive_name: "ocredit",
        pam_secure_value: "-1",
        pam_description: "Require at least one special character in password",
        pam_severity: Severity::Medium,
        pam_config_file: PamConfigFile::PwQuality,
        pam_compare: Strictness::AtMost,
    },
    PamDirective {
        pam_directive_name: "maxrepeat",
        pam_secure_value: "3",
        pam_description: "Maximum consecutive identical characters in password",
        pam_severity: Severity::Low,
        pam_config_file: PamConfigFile::PwQuality,
        pam_compare: Strictness::NonZeroAtMost,
    },
    PamDirective {
        pam_directive_name: "PASS_MAX_DAYS",
        pam_secure_value: "90",
        pam_description: "Maximum password age of 90 days",
        pam_severity: Severity::Medium,
        pam_config_file: PamConfigFile::LoginDefs,
        pam_compare: Strictness::AtMost,
    },
    PamDirective {
        pam_directive_name: "PASS_MIN_DAYS",
        pam_secure_value: "1",
        pam_description: "Minimum password age of 1 day (prevents rapid changes)",
        pam_severity: Severity::Low,
        pam_config_file: PamConfigFile::LoginDefs,
        pam_compare: Strictness::AtLeast,
    },
    PamDirective {
        pam_directive_name: "PASS_WARN_AGE",
        pam_secure_value: "7",
        pam_description: "Warn users 7 days before password expiry",
        pam_severity: Severity::Low,
        pam_config_file: PamConfigFile::LoginDefs,
        pam_compare: Strictness::AtLeast,
    },
    // Account lockout (faillock) and password-reuse (pwhistory). Threshold
    // comparisons: a stricter setting is compliant and apply never loosens it.
    PamDirective {
        pam_directive_name: "deny",
        pam_secure_value: "5",
        pam_description: "Lock the account after at most 5 failed attempts",
        pam_severity: Severity::High,
        pam_config_file: PamConfigFile::SecurityConf(FAILLOCK_CONF),
        pam_compare: Strictness::AtMost,
    },
    PamDirective {
        pam_directive_name: "remember",
        pam_secure_value: "5",
        pam_description: "Remember at least the last 5 passwords to prevent reuse",
        pam_severity: Severity::Medium,
        pam_config_file: PamConfigFile::SecurityConf(PWHISTORY_CONF),
        pam_compare: Strictness::AtLeast,
    },
];

/// True when `current` fails the directive's comparison against `target`,
/// the resolved effective target (a directive override clamped so it can
/// only tighten the built-in baseline, or the baseline itself with no
/// override). Unset/unparseable integers fail. Effective value (inline
/// pam.d args or /etc/security/*.conf) is resolved by callers via
/// `read_effective_threshold` before this check.
fn pam_violates(directive: &PamDirective, target: &str, current: Option<&str>) -> bool {
    directive.pam_compare.violated_by(target, current)
}

/// The override-clamped target for `directive`: the operator's directive
/// override where the config sets one that tightens the plugin's own secure
/// value, and the secure value itself otherwise.
///
/// Scan, apply and validate each need this, and they must agree, so a preview
/// cannot judge the host by a rule the apply it previews does not apply.
fn clamped_baseline(directive: &PamDirective, config: &PluginConfig) -> String {
    directive.pam_compare.resolved_target(
        config,
        directive.pam_directive_name,
        directive.pam_secure_value,
    )
}

/// Where libpwquality looks for its cracklib dictionary, by distribution
/// family. The path is compiled into libpwquality rather than configured, so
/// this is a candidate set and any one of them being present is enough.
const CRACKLIB_DICTIONARIES: &[&str] = &[
    // Red Hat, Arch and SUSE families.
    "/usr/share/cracklib/pw_dict.pwd",
    // Debian and derivatives, whose cracklib-runtime builds it into a cache.
    "/var/cache/cracklib/cracklib_dict.pwd",
];

/// Whether this host will refuse every password change once `pam_pwquality` is
/// in the stack, because its dictionary check is on and there is no dictionary.
///
/// libpwquality's `dictcheck` defaults on and **fails closed**: with no
/// dictionary to load it rejects every password, strong ones included, and the
/// operator sees a refusal with nothing in it to act on. This tool does not
/// cause that, but it is the thing that ran just before the symptom appears, so
/// an operator who hardens PAM and then cannot change a password will reasonably
/// blame it. Naming the condition and its remedy is the whole job here; the fix
/// is a package operation on a host nobody asked to have packages changed on.
///
/// Three things must all hold, and each is checked rather than assumed:
///
/// - `pam_pwquality.so` is actually loaded, since a module nothing loads reads
///   no dictionary and refuses nothing;
/// - `dictcheck` is not explicitly switched off in `pwquality.conf`;
/// - none of the candidate dictionaries is present.
///
/// Silent when it cannot tell, which is the opposite of this crate's usual
/// fail-closed direction and is deliberate. The other guards refuse to call a
/// host compliant on evidence they lack; this one would be telling an operator
/// their host is broken, and a warning that fires on every host it cannot read
/// is one nobody reads twice.
async fn dictcheck_locks_out_password_changes(
    ctx: &Context,
    presence: &[(&'static str, ModulePresence)],
    pwquality: &ConfRead,
) -> bool {
    let loaded = presence
        .iter()
        .find(|(path, _)| *path == "/etc/security/pwquality.conf")
        .is_some_and(|(_, found)| matches!(found, ModulePresence::InStack));
    if !loaded {
        return false;
    }

    // Only an explicit zero switches it off. An unreadable or absent file
    // leaves the default in force, which is on.
    let content = match pwquality {
        ConfRead::Content(content, _) => content.as_str(),
        ConfRead::Absent => "",
        ConfRead::Unreadable { .. } => return false,
    };
    let disabled = parse_config_value(content, "dictcheck", ConfigFormat::Auto, true)
        .is_some_and(|value| value.trim() == "0");
    if disabled {
        return false;
    }

    // A probe that failed says nothing about whether the file is there, so one
    // `Err` is enough to stay quiet.
    for path in CRACKLIB_DICTIONARIES {
        match ctx.executor().path_exists(Path::new(path)).await {
            Ok(true) => return false,
            Ok(false) => {}
            Err(_) => return false,
        }
    }
    true
}

/// The wording for the lockout above, kept beside the detection so the two
/// cannot drift.
fn dictcheck_lockout_message() -> String {
    format!(
        "pam_pwquality is loaded, its dictcheck is on, and no cracklib \
         dictionary is installed at {}. libpwquality's dictionary check fails \
         closed, so every password change on this host will be refused, strong \
         passwords included, and the refusal names no cause. Install the \
         dictionary (cracklib-dicts on dnf hosts, cracklib-runtime on apt \
         hosts) or set dictcheck = 0 in /etc/security/pwquality.conf. This \
         tool will not install a package on your behalf.",
        CRACKLIB_DICTIONARIES.join(" or ")
    )
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
            // The cause, not just the failure. `permission_denied` is decided
            // here and was left out of the line, so the operator read "failed
            // to read" with nothing telling them whether sudo would help,
            // while audit and firewall say "requires root" plainly in the same
            // scan.
            warn!(
                "Failed to read {}: {} ({})",
                path,
                reason,
                if permission_denied {
                    "permission denied, a privileged re-run would reach it"
                } else {
                    "not a privilege failure, a privileged re-run would not help"
                }
            );
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
/// The table is walked here rather than passed in, so a caller cannot cover
/// three files and forget the fourth. `already_read` is a reuse hint and
/// nothing more: a caller that omits a file it has read costs a second read,
/// never a missed check, which is what kept the safety when the re-reads went.
///
/// Those re-reads were not free. `scan` and `validate` each read two of these
/// four before calling this, and `read_conf_classified` warns on failure, so on
/// a host where `/etc/security/pwquality.conf` is mode 0600 every run printed
/// the identical "Failed to read ... permission denied" line twice, which reads
/// as two separate problems. The second privileged read of an already-read file
/// went with it.
async fn layer_drift_findings(ctx: &Context, already_read: &[(&str, &ConfRead)]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for conf in layer_drift::LAYERED_CONFS {
        let Some(vendor_path) = vendor_path_for(conf.admin_path) else {
            continue;
        };
        let freshly_read;
        let admin_read = match already_read
            .iter()
            .find(|(path, _)| *path == conf.admin_path)
        {
            Some((_, read)) => *read,
            None => {
                freshly_read = read_conf_classified(ctx, conf.admin_path).await;
                &freshly_read
            }
        };
        let ConfRead::Content(admin, ConfigLayer::Admin) = admin_read else {
            continue;
        };

        // The layer this read reports is meaningless: read_conf_classified
        // attributes a layer by which probe answered, and this path names the
        // vendor file directly. Its three outcomes are what is wanted.
        match read_conf_classified(ctx, &vendor_path).await {
            ConfRead::Content(vendor, _) => {
                let masked = layer_drift::masked_keys(admin, &vendor);
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
async fn read_effective_threshold(
    ctx: &Context,
    arg: &str,
    conf: &'static str,
    already_read: &[(&str, &ConfRead)],
) -> ThresholdRead {
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
    // The caller's read where it has one, and only otherwise our own. Same
    // hand-over the drift walk takes, for the same reason: `scan` and
    // `validate` both walk the drift table before reaching this, so without it
    // the conf is read, and warned about, once there and once here (#170).
    let freshly_read;
    let conf_read = match already_read.iter().find(|(path, _)| *path == conf) {
        Some((_, read)) => *read,
        None => {
            freshly_read = read_conf_classified(ctx, conf).await;
            &freshly_read
        }
    };
    match conf_read {
        ConfRead::Unreadable {
            permission_denied, ..
        } => ThresholdRead::Unreadable {
            path: conf,
            permission_denied: *permission_denied,
        },
        // A missing file has no directives, same as today: empty content.
        ConfRead::Absent => ThresholdRead::NotSet,
        ConfRead::Content(content, _) => {
            match parse_config_value(content, arg, ConfigFormat::KeyValue, true) {
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
/// `already_read` covers those: any file in it is taken from there rather than
/// read again, the same hand-over [`layer_drift_findings`] takes. `scan` and
/// `validate` pass all four files the drift table names, because both walk that
/// table before reaching this and would otherwise read the two `SecurityConf`
/// files, and warn about them, twice per run (#170). `apply` passes nothing: it
/// never calls the drift walk, so its read here is the run's first.
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
    already_read: &[(&str, &ConfRead)],
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
            match read_effective_threshold(ctx, directive.pam_directive_name, path, already_read)
                .await
            {
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
    // Blank lines are excluded. The reason they had to be is gone: the writer
    // dropped the file's terminator, so a compliant file came back one byte
    // short, read as a change, and was rewritten on every run. The writer
    // terminates its output now and that hazard is closed. The filter stays
    // because the comparison it serves is about directive lines rather than
    // layout, and a run that only moved a blank line still has nothing to say.
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

    // A file being created needs the directory it goes in to exist, because
    // `write_file` cannot make a missing parent. /etc/security belongs to the
    // pam package, so a host without that package has no such directory, and
    // the write failed there with an error naming only the file. Gated on
    // `creating`: a file that is already there proves its directory is too, so
    // the probe and the mkdir would both be wasted on a rewrite.
    //
    // No ordering treatment is needed, unlike the kernel plugin's identical
    // guard. This apply's checkpoint captures the config files, never the bare
    // directory, so no row is ever written for it and the creation is invisible
    // to a rollback of this apply.
    if creating
        && let Some(dir) = Path::new(path).parent().and_then(Path::to_str)
        && let Some(reason) = crate::ensure_directory(ctx, dir).await
    {
        warn!(
            "Failed to create the directory holding {}: {}",
            path, reason
        );
        changes.push(Change {
            change_type: ChangeType::ConfigFile,
            change_description: format!("Failed to create the directory holding {}", file_label),
            change_success: false,
            change_error: Some(reason),
        });
        return false;
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
///
/// `-p` and `--no-dereference` are both required, and this site passed neither
/// until the three plugins that take such a copy were compared: ssh passed only
/// `-p`, audit only `--no-dereference`, and each was therefore losing whatever
/// the other kept. `-p` preserves mode, ownership and timestamps, without which
/// an operator who copies the backup back gets the file at whatever the umask
/// hands it, and on a `/etc/security/*.conf` that is the difference between a
/// policy file and a world-readable one. `--no-dereference` copies a symlink as
/// a symlink, so a config that is a link elsewhere is backed up as the object
/// about to be overwritten rather than as its target, which is a different file
/// that this apply never touches.
///
/// `cp -p` exits non-zero when it cannot preserve ownership, which an
/// unprivileged copy of a root-owned file cannot. The exit code is checked
/// below and aborts the caller, so on the one path where that could bite, a
/// non-root run, the backup now refuses rather than producing a copy that is
/// not one. Apply runs as root, so it is a refusal that should never be
/// reached.
/// Every file this plugin can leave a timestamped backup beside.
///
/// `/etc/pam.d` is deliberately not here. The apply refuses to edit a stack
/// file and reports the manual action instead, so it never copies one, and the
/// development host bore that out on 2026-08-11: 16 backups across
/// `/etc/security` and none at all in `/etc/pam.d`.
const PAM_BACKED_UP_FILES: [&str; 4] = [
    "/etc/security/pwquality.conf",
    "/etc/security/faillock.conf",
    "/etc/security/pwhistory.conf",
    "/etc/login.defs",
];

/// Everything a backup of `file_path` carries before its timestamp.
///
/// One source for the copy and for both prunes, so they cannot come to
/// disagree about which files are backups: a prune whose prefix had drifted
/// from the writer's would silently match nothing and the copies would
/// accumulate again with nothing failing.
fn pam_backup_prefix(file_path: &str) -> String {
    format!("{file_path}.backup-")
}

async fn create_config_backup(ctx: &Context, file_path: &str) -> Result<String> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| HardeningError::Plugin(format!("Failed to get system time: {}", e)))?
        .as_secs();

    let backup_prefix = pam_backup_prefix(file_path);
    let backup_path = format!("{backup_prefix}{timestamp}");

    let output = ctx
        .executor()
        .execute_command("cp", &["-p", "--no-dereference", file_path, &backup_path])
        .await
        .map_err(|e| HardeningError::Plugin(e.to_string()))?;

    if !output.success() {
        return Err(HardeningError::Plugin(format!(
            "Failed to back up {file_path} to {backup_path}: cp exited {} ({})",
            output.exit_code,
            output.stderr.trim(),
        )));
    }

    // The copy exists, so this file's directory holds one more backup than it
    // did. This function is the only place the plugin makes one, and it is
    // called once per file actually being rewritten, so the retention is per
    // file rather than per directory: /etc/security holds copies of three
    // different configuration files and each keeps its own newest few.
    crate::prune_timestamped_backups(ctx, &backup_prefix, crate::BACKUPS_KEPT).await;

    Ok(backup_path)
}

#[cfg(test)]
mod tests;
