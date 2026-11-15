//! Which password policy the plugin enforces, and what each one asks of the
//! directive table (#190).
//!
//! `PAM_DIRECTIVES` is the benchmark policy, row for row: character-class
//! rules and a 90-day maximum age, the rules every earlier release enforced.
//! The NIST SP 800-63B-4 policy is written below as the rows it changes and
//! nothing else, so a directive added to the table is enforced the same way by
//! both policies until someone decides otherwise, rather than silently going
//! missing from one of them.
//!
//! **What the NIST policy changes, and why.** Section 3.1.1.2 of SP 800-63B-4
//! says verifiers "SHALL require passwords that are used as a single-factor
//! authentication mechanism to be a minimum of 15 characters", "SHALL NOT
//! impose other composition rules (e.g., requiring mixtures of different
//! character types)" and "SHALL NOT require subscribers to change passwords
//! periodically". So `minlen` rises to 15, the four libpwquality credits go to
//! zero, and new accounts get no forced expiry. Everything else stays: the
//! dictionary check (libpwquality's `dictcheck`, on by default and not managed
//! here), `maxrepeat`, the minimum age, lockout and password history.
//!
//! **Honest reporting is the reason this is more than a value table.** Dropping
//! a rule a framework still requires must not turn that framework's control
//! green. Every check carries its controls through `coverage()`, and the report
//! passes an assessed control that has no live finding, so a check that simply
//! stopped looking would pass CIS 5.4.1.1 and DISA STIG RHEL-08-020200 on a host
//! that forces no password change at all. Where the selected policy drops a
//! benchmark rule and the host does not meet that rule, the scan therefore
//! reports a departure finding carrying the frameworks' controls, and those
//! controls fail. The policy's own finding for the same directive carries only
//! the four controls every PAM check maps to (HIPAA, GDPR, ISO/IEC 27001 and
//! SOC 2), which ask that a password policy be followed rather than which one.

use super::{PAM_DIRECTIVES, PamDirective, get_pam_compliance_mappings};
use crate::strictness::Strictness;
use hardener_common::types::{ComplianceFramework, ComplianceMapping, FindingCategory, Severity};
use hardener_core::{PasswordPolicy, PluginConfig, plugin::Finding};

/// The frameworks every PAM check maps to whatever it checks, because each one
/// asks only that the system follows a password policy.
///
/// Kept beside the helpers that build those four mappings in `mod.rs`; a
/// framework added there that applies to every check belongs here too.
const POLICY_AGNOSTIC_FRAMEWORKS: [ComplianceFramework; 4] = [
    ComplianceFramework::HIPAA,
    ComplianceFramework::GDPR,
    ComplianceFramework::ISO27001,
    ComplianceFramework::SOC2,
];

/// One benchmark row as the NIST policy rewrites it.
struct NistRule {
    name: &'static str,
    secure_value: &'static str,
    description: &'static str,
    compare: Strictness,
    /// What the rule drops from the benchmark, in a few words for a change
    /// line, or `None` for a rule that only tightens it.
    drops: Option<&'static str>,
}

/// The rows the NIST SP 800-63B-4 policy changes. Every other row of
/// `PAM_DIRECTIVES` is enforced as the benchmark has it.
const NIST_RULES: &[NistRule] = &[
    NistRule {
        name: "minlen",
        secure_value: "15",
        description: "Minimum password length of 15 characters (NIST SP 800-63B-4 3.1.1.2)",
        compare: Strictness::AtLeast,
        drops: None,
    },
    NistRule {
        name: "dcredit",
        secure_value: "0",
        description: "No digit required and no length credit for one: length replaces \
                      composition rules (NIST SP 800-63B-4 3.1.1.2)",
        compare: Strictness::ClosestToZero,
        drops: Some("no composition rules"),
    },
    NistRule {
        name: "ucredit",
        secure_value: "0",
        description: "No uppercase letter required and no length credit for one: length \
                      replaces composition rules (NIST SP 800-63B-4 3.1.1.2)",
        compare: Strictness::ClosestToZero,
        drops: Some("no composition rules"),
    },
    NistRule {
        name: "lcredit",
        secure_value: "0",
        description: "No lowercase letter required and no length credit for one: length \
                      replaces composition rules (NIST SP 800-63B-4 3.1.1.2)",
        compare: Strictness::ClosestToZero,
        drops: Some("no composition rules"),
    },
    NistRule {
        name: "ocredit",
        secure_value: "0",
        description: "No special character required and no length credit for one: length \
                      replaces composition rules (NIST SP 800-63B-4 3.1.1.2)",
        compare: Strictness::ClosestToZero,
        drops: Some("no composition rules"),
    },
    NistRule {
        name: "PASS_MAX_DAYS",
        secure_value: "99999",
        description: "No forced periodic password change for new accounts; a change is forced \
                      only on evidence of compromise (NIST SP 800-63B-4 3.1.1.2)",
        compare: Strictness::AtLeastOrUnlimited,
        drops: Some("no forced periodic change"),
    },
];

/// One directive as the selected policy enforces it.
pub(super) struct PolicyDirective {
    /// The rule in force: the benchmark row itself, or that row carrying the
    /// selected policy's value, comparison, wording and severity.
    pub(super) rule: PamDirective,
    /// The benchmark row this rule drops a requirement of, and a few words
    /// saying what is dropped. `None` where the rule is the benchmark's own or
    /// only tightens it, so there is nothing the frameworks expect that the
    /// policy deliberately does not deliver.
    pub(super) departure: Option<Departure>,
}

/// What a policy deliberately does not deliver for one directive.
pub(super) struct Departure {
    /// The benchmark row whose requirement is dropped.
    pub(super) benchmark: &'static PamDirective,
    /// What is dropped, phrased to follow a colon in a change line.
    pub(super) drops: &'static str,
}

/// Every directive `policy` enforces, in table order.
pub(super) fn policy_directives(policy: PasswordPolicy) -> Vec<PolicyDirective> {
    PAM_DIRECTIVES
        .iter()
        .map(|benchmark| match policy {
            PasswordPolicy::Benchmark => PolicyDirective {
                rule: benchmark.clone(),
                departure: None,
            },
            PasswordPolicy::Nist80063b => nist_directive(benchmark),
        })
        .collect()
}

fn nist_directive(benchmark: &'static PamDirective) -> PolicyDirective {
    let Some(nist) = NIST_RULES
        .iter()
        .find(|rule| rule.name == benchmark.pam_directive_name)
    else {
        return PolicyDirective {
            rule: benchmark.clone(),
            departure: None,
        };
    };
    PolicyDirective {
        rule: PamDirective {
            pam_secure_value: nist.secure_value,
            pam_description: nist.description,
            pam_compare: nist.compare,
            // A rule that drops a requirement is not a weakness when the host
            // breaks it; it is a host that has not yet adopted the policy.
            pam_severity: match nist.drops {
                Some(_) => Severity::Low,
                None => benchmark.pam_severity,
            },
            ..benchmark.clone()
        },
        departure: nist.drops.map(|drops| Departure { benchmark, drops }),
    }
}

/// The controls a finding against `directive`'s own rule carries.
///
/// A rule that drops a benchmark requirement carries only the four
/// policy-agnostic frameworks. The benchmark's controls for that directive are
/// met by the very value this rule would remove, so failing them for it would
/// report a host as non-compliant with STIG for keeping what STIG asks for.
pub(super) fn rule_mappings(directive: &PolicyDirective) -> Vec<ComplianceMapping> {
    let mappings = get_pam_compliance_mappings(directive.rule.pam_directive_name);
    match directive.departure {
        Some(_) => mappings
            .into_iter()
            .filter(|mapping| POLICY_AGNOSTIC_FRAMEWORKS.contains(&mapping.compliance_framework))
            .collect(),
        None => mappings,
    }
}

/// The controls a departure finding carries: everything the benchmark check
/// maps to except the four policy-agnostic frameworks, which the selected
/// policy does satisfy.
fn departure_mappings(name: &str) -> Vec<ComplianceMapping> {
    get_pam_compliance_mappings(name)
        .into_iter()
        .filter(|mapping| !POLICY_AGNOSTIC_FRAMEWORKS.contains(&mapping.compliance_framework))
        .collect()
}

/// The finding for a benchmark rule the selected policy deliberately drops,
/// on a host that does not meet it.
///
/// Info, because there is nothing wrong with the host by the policy the
/// operator chose, and `apply` will never act on it. It exists so the frameworks
/// that still require the rule fail their controls rather than pass them, and
/// its exception key is the directive's own, so an auditor's accepted deviation
/// can be recorded the usual way.
pub(super) fn departure_finding(
    policy: PasswordPolicy,
    departure: &Departure,
    benchmark_target: &str,
    current_display: &str,
    config: &PluginConfig,
) -> Finding {
    let name = departure.benchmark.pam_directive_name;
    Finding {
        finding_id: format!("pam-{name}-policy-departure"),
        finding_category: FindingCategory::Authentication,
        finding_current_value: current_display.to_string(),
        finding_description: format!(
            "The {} password policy deliberately does not enforce {name} = {benchmark_target}, \
             which the benchmark rules require ({}); this host has '{current_display}'. The \
             CIS, DISA STIG, NIST, PCI DSS and FedRAMP controls mapped to that rule are \
             reported as not met rather than passing",
            policy.id(),
            departure.drops,
        ),
        finding_explanation: departure.benchmark.pam_description.to_string(),
        finding_impact: format!(
            "Compliance only: by the {} policy this is the intended setting, and apply will not \
             change it. Frameworks that still require the rule report its controls as failing for \
             as long as this policy is selected",
            policy.id()
        ),
        finding_recommended_value: benchmark_target.to_string(),
        finding_remediation_steps: vec![
            format!(
                "Nothing to change if your organisation follows NIST SP 800-63B-4. Where an \
                 auditor accepts the deviation, record it as a policy exception for {name} with \
                 value '{current_display}' under [pam.exceptions]"
            ),
            "Where a framework's control for this rule must pass, set password_policy = \
             \"benchmark\" under [pam] instead"
                .to_string(),
        ],
        finding_severity: Severity::Info,
        finding_title: format!(
            "Benchmark rule not enforced by the {} policy: {name}",
            policy.id()
        ),
        finding_compliance: departure_mappings(name),
        finding_exception: config.exception_outcome(name, current_display),
        finding_exception_key: Some(name.to_string()),
    }
}

/// Why an operator's override for a directive the policy relaxes changes
/// nothing, when it does not.
///
/// An override is clamped on the selected policy's own scale, and under the
/// NIST policy the credits have nothing stricter than zero, so an override that
/// asks for a character class loses the clamp. That is the correct answer, and
/// the general rule is that a refused override is silent. These rows are the
/// exception because the refused request is a plausible one: an operator in
/// PCI DSS scope may well try to put a digit requirement back this way, and
/// must hear that it did not take.
pub(super) fn ignored_override(
    policy: PasswordPolicy,
    directive: &PolicyDirective,
    config: &PluginConfig,
) -> Option<String> {
    let departure = directive.departure.as_ref()?;
    let name = directive.rule.pam_directive_name;
    let value = config.directives.get(name)?;
    if super::clamped_baseline(&directive.rule, config) == value.trim() {
        return None;
    }
    Some(format!(
        "[pam.directives] {name} = \"{value}\" has no effect under the {} password policy, \
         which sets {name} to {} ({}). Set password_policy = \"benchmark\" under [pam] to \
         manage {name} through overrides",
        policy.id(),
        directive.rule.pam_secure_value,
        departure.drops,
    ))
}

#[cfg(test)]
mod tests;
