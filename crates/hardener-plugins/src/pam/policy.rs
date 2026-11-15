//! Which password policy the plugin enforces, and what each one asks of the
//! directive table (#190).
//!
//! `PAM_DIRECTIVES` is the benchmark policy, row for row: character-class
//! rules and a 90-day maximum age, the rules every earlier release enforced.
//! The NIST SP 800-63B-4 policy is written below as the rows it changes and
//! the rows it adds, and nothing else, so a directive added to the table is
//! enforced the same way by both policies until someone decides otherwise,
//! rather than silently going missing from one of them.
//!
//! **What the NIST policy changes, and why.** Section 3.1.1.2 of SP 800-63B-4
//! says verifiers "SHALL require passwords that are used as a single-factor
//! authentication mechanism to be a minimum of 15 characters", "SHALL NOT
//! impose other composition rules (e.g., requiring mixtures of different
//! character types)" and "SHALL NOT require subscribers to change passwords
//! periodically". So `minlen` rises to 15, the four libpwquality credits go to
//! zero, and new accounts get no forced expiry. Two libpwquality options the
//! benchmark table never managed impose a composition rule of their own, and
//! the CIS and STIG benchmarks set both: `minclass = 4` and
//! `maxclassrepeat = 4` each refuse every passphrase made of words, so the
//! NIST policy switches them off too. Everything else stays: the dictionary
//! check (libpwquality's `dictcheck`, on by default and not managed here),
//! `maxrepeat`, the minimum age, lockout and password history. `maxsequence`
//! is not managed either: like `maxrepeat` it bans a pattern rather than
//! requiring a mixture, and a passphrase of random words almost never holds a
//! run long enough to trip it.
//!
//! **Honest reporting is the reason this is more than a value table.** Dropping
//! a rule a framework still requires must not turn that framework's control
//! green. Every check carries its controls through `coverage()`, and the report
//! passes an assessed control that has no live finding, so a check that simply
//! stopped looking would pass CIS 5.4.1.1 and DISA STIG RHEL-08-020200 on a host
//! that forces no password change at all. Where the selected policy drops a
//! benchmark rule and the host does not meet that rule, the scan therefore
//! reports a departure finding carrying the controls of the frameworks that
//! still require it (CIS, DISA STIG and PCI DSS), and those controls fail. The
//! policy's own finding for the same directive carries only the four controls
//! every PAM check maps to (HIPAA, GDPR, ISO/IEC 27001 and SOC 2), which ask
//! that a password policy be followed rather than which one. A value that
//! meets neither rule gets one finding carrying every control, rather than two
//! findings that contradict each other about what `apply` will do.

use super::{PAM_DIRECTIVES, PamConfigFile, PamDirective, get_pam_compliance_mappings};
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

/// The frameworks whose current text still requires a rule the NIST policy
/// drops, so the only ones a departure fails, with the name a finding gives
/// each.
///
/// CIS benchmarks still ask for character classes and a maximum age of 365
/// days or less, DISA STIGs for all four classes and a maximum age of 60 or
/// 180 days, and PCI DSS v4.0.1 for a digit and a letter (8.3.6) and, where the
/// password is the only factor, a change every 90 days or dynamic analysis of
/// the account instead (8.3.9).
///
/// The three NIST-derived frameworks are left out on purpose. The plugin's
/// NIST mappings are labelled against SP 800-53 Rev 5, whose IA-5(1) has no
/// password-lifetime item (the base control's IA-5(f) leaves any refresh
/// period to the organisation), leaves composition rules to the organisation
/// in item (h), and says in its guidance that "Enforced composition rules
/// provide marginal security benefits while decreasing usability". SP 800-171 r3
/// requirement 03.05.07 says the same, and FedRAMP's Rev 5 baselines add that
/// password policies "shall not enforce special character or minimum password
/// rotation requirements". Failing those for following SP 800-63B-4 would
/// report a host as breaking NIST for doing what NIST asks.
const DEPARTURE_FRAMEWORKS: [(ComplianceFramework, &str); 3] = [
    (ComplianceFramework::CIS, "CIS"),
    (ComplianceFramework::STIG, "DISA STIG"),
    (ComplianceFramework::PCIDSS, "PCI DSS"),
];

/// What the NIST policy drops when it switches a composition rule off, in a
/// few words to follow a colon in a change line.
const NO_COMPOSITION_RULES: &str = "no composition rules";

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
        drops: Some(NO_COMPOSITION_RULES),
    },
    NistRule {
        name: "ucredit",
        secure_value: "0",
        description: "No uppercase letter required and no length credit for one: length \
                      replaces composition rules (NIST SP 800-63B-4 3.1.1.2)",
        compare: Strictness::ClosestToZero,
        drops: Some(NO_COMPOSITION_RULES),
    },
    NistRule {
        name: "lcredit",
        secure_value: "0",
        description: "No lowercase letter required and no length credit for one: length \
                      replaces composition rules (NIST SP 800-63B-4 3.1.1.2)",
        compare: Strictness::ClosestToZero,
        drops: Some(NO_COMPOSITION_RULES),
    },
    NistRule {
        name: "ocredit",
        secure_value: "0",
        description: "No special character required and no length credit for one: length \
                      replaces composition rules (NIST SP 800-63B-4 3.1.1.2)",
        compare: Strictness::ClosestToZero,
        drops: Some(NO_COMPOSITION_RULES),
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

/// libpwquality options the benchmark table never managed that impose a
/// composition rule of their own, which the NIST policy therefore switches
/// off.
///
/// Both are off at zero (pwquality.conf(5): "The check is disabled if the
/// value is 0" for `maxclassrepeat`; `minclass` defaults to 0) and both are set
/// by the benchmarks: CIS RHEL 9 v2.0.0 asks for `minclass = 4` and the RHEL 9
/// STIG for `minclass = 4` and `maxclassrepeat = 4`. Measured on 2026-11-15
/// with libpwquality 1.4.5, either one at 4 refused all 1,000 random
/// passphrases of five or seven EFF words that the rest of this policy
/// accepts, so a host hardened to those benchmarks would otherwise report the
/// NIST policy as met while still refusing every passphrase.
///
/// Low, like the credits: a host that has them has not adopted the policy
/// yet, which is not a weakness.
const NIST_ONLY_ROWS: &[PamDirective] = &[
    PamDirective {
        pam_directive_name: "minclass",
        pam_secure_value: "0",
        pam_description: "No minimum number of character classes: length replaces composition \
                          rules (NIST SP 800-63B-4 3.1.1.2)",
        pam_severity: Severity::Low,
        pam_config_file: PamConfigFile::PwQuality,
        pam_compare: Strictness::ClosestToZero,
    },
    PamDirective {
        pam_directive_name: "maxclassrepeat",
        pam_secure_value: "0",
        pam_description: "No limit on consecutive characters of one class, which would refuse \
                          every passphrase made of words (NIST SP 800-63B-4 3.1.1.2)",
        pam_severity: Severity::Low,
        pam_config_file: PamConfigFile::PwQuality,
        pam_compare: Strictness::ClosestToZero,
    },
];

/// One directive as the selected policy enforces it.
pub(super) struct PolicyDirective {
    /// The rule in force: the benchmark row itself, that row carrying the
    /// selected policy's value, comparison, wording and severity, or a row the
    /// policy adds.
    pub(super) rule: PamDirective,
    /// What the rule relaxes, or `None` where the rule is the benchmark's own
    /// or only tightens it, so there is nothing the frameworks expect that the
    /// policy deliberately does not deliver.
    pub(super) relaxation: Option<Relaxation>,
}

/// What a policy deliberately relaxes for one directive.
pub(super) struct Relaxation {
    /// What is dropped, phrased to follow a colon in a change line.
    pub(super) drops: &'static str,
    /// The benchmark row whose requirement is dropped, or `None` for a row
    /// the benchmark never managed, which only switches a check off.
    pub(super) benchmark: Option<&'static PamDirective>,
}

impl PolicyDirective {
    fn benchmark(row: &'static PamDirective) -> Self {
        Self {
            rule: row.clone(),
            relaxation: None,
        }
    }

    /// True for a row the selected policy adds to the benchmark table only to
    /// switch a libpwquality check off.
    ///
    /// Such a row is met by a module that is not loaded at all, since nothing
    /// then imposes the check, so a missing `pam_pwquality` is not reported
    /// against it: the length row reports that, and carries the controls.
    pub(super) fn only_switches_off(&self) -> bool {
        self.relaxation
            .as_ref()
            .is_some_and(|relaxation| relaxation.benchmark.is_none())
    }
}

/// Every directive `policy` enforces, in table order, with any rows the
/// policy adds placed after the last row of the file they live in.
pub(super) fn policy_directives(policy: PasswordPolicy) -> Vec<PolicyDirective> {
    let mut directives: Vec<PolicyDirective> = PAM_DIRECTIVES
        .iter()
        .map(|benchmark| match policy {
            PasswordPolicy::Benchmark => PolicyDirective::benchmark(benchmark),
            PasswordPolicy::Nist80063b => nist_directive(benchmark),
        })
        .collect();
    if policy == PasswordPolicy::Nist80063b {
        // Beside the other pwquality rows, so a preview lists one file's
        // changes together.
        let at = directives
            .iter()
            .rposition(|d| d.rule.pam_config_file == PamConfigFile::PwQuality)
            .map_or(directives.len(), |last| last + 1);
        directives.splice(
            at..at,
            NIST_ONLY_ROWS.iter().map(|row| PolicyDirective {
                rule: row.clone(),
                relaxation: Some(Relaxation {
                    drops: NO_COMPOSITION_RULES,
                    benchmark: None,
                }),
            }),
        );
    }
    directives
}

fn nist_directive(benchmark: &'static PamDirective) -> PolicyDirective {
    let Some(nist) = NIST_RULES
        .iter()
        .find(|rule| rule.name == benchmark.pam_directive_name)
    else {
        return PolicyDirective::benchmark(benchmark);
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
        relaxation: nist.drops.map(|drops| Relaxation {
            drops,
            benchmark: Some(benchmark),
        }),
    }
}

/// The controls a finding against `directive`'s own rule carries.
///
/// A rule that relaxes anything carries only the four policy-agnostic
/// frameworks. The benchmark's controls for that directive are met by the very
/// value this rule would remove, so failing them for it would report a host as
/// non-compliant with STIG for keeping what STIG asks for.
pub(super) fn rule_mappings(directive: &PolicyDirective) -> Vec<ComplianceMapping> {
    let mappings = get_pam_compliance_mappings(directive.rule.pam_directive_name);
    match directive.relaxation {
        Some(_) => mappings
            .into_iter()
            .filter(|mapping| POLICY_AGNOSTIC_FRAMEWORKS.contains(&mapping.compliance_framework))
            .collect(),
        None => mappings,
    }
}

/// The controls a departure finding carries: those of the benchmark check
/// that belong to a framework still requiring the dropped rule.
fn departure_mappings(name: &str) -> Vec<ComplianceMapping> {
    get_pam_compliance_mappings(name)
        .into_iter()
        .filter(|mapping| {
            DEPARTURE_FRAMEWORKS
                .iter()
                .any(|(framework, _)| *framework == mapping.compliance_framework)
        })
        .collect()
}

/// "CIS, DISA STIG and PCI DSS", naming only the departure frameworks that
/// `mappings` contains, in the order the constant lists them.
fn departure_framework_names(mappings: &[ComplianceMapping]) -> String {
    let names: Vec<&str> = DEPARTURE_FRAMEWORKS
        .iter()
        .filter(|(framework, _)| {
            mappings
                .iter()
                .any(|mapping| mapping.compliance_framework == *framework)
        })
        .map(|(_, name)| *name)
        .collect();
    match names.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} and {last}", rest.join(", ")),
        Some((only, _)) => (*only).to_string(),
        None => "no".to_string(),
    }
}

/// The finding for a benchmark rule the selected policy deliberately drops,
/// on a host that meets the policy's own rule and not the benchmark's.
///
/// Info, because there is nothing wrong with the host by the policy the
/// operator chose, and `apply` will never act on it. It exists so the frameworks
/// that still require the rule fail their controls rather than pass them, and
/// its exception key is the directive's own, so an auditor's accepted deviation
/// can be recorded the usual way.
pub(super) fn departure_finding(
    policy: PasswordPolicy,
    drops: &str,
    benchmark: &PamDirective,
    benchmark_target: &str,
    current_display: &str,
    config: &PluginConfig,
) -> Finding {
    let name = benchmark.pam_directive_name;
    let compliance = departure_mappings(name);
    Finding {
        finding_id: format!("pam-{name}-policy-departure"),
        finding_category: FindingCategory::Authentication,
        finding_current_value: current_display.to_string(),
        finding_description: format!(
            "The {} password policy deliberately does not enforce {name} = {benchmark_target}, \
             which the benchmark rules require ({drops}); this host has '{current_display}'. The \
             {} controls mapped to that rule are reported as not met rather than passing. NIST \
             SP 800-53, NIST SP 800-171 and FedRAMP are not failed by it: their current texts \
             leave password lifetime and composition rules to the organisation",
            policy.id(),
            departure_framework_names(&compliance),
        ),
        finding_explanation: benchmark.pam_description.to_string(),
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
        finding_compliance: compliance,
        finding_exception: config.exception_outcome(name, current_display),
        finding_exception_key: Some(name.to_string()),
    }
}

/// The finding for a value that meets neither the selected policy's rule nor
/// the benchmark rule that policy drops: `PASS_MAX_DAYS 0`, which expires every
/// password at once, `PASS_MAX_DAYS 120`, a positive credit that lets a
/// password be shorter than the minimum, or a value that is not set.
///
/// One finding rather than a policy finding beside a departure, because a
/// departure says the value is the intended one and `apply` leaves it alone,
/// and here `apply` rewrites it. It carries every control the check maps to,
/// since the value meets neither side. A value that is set is as weak as the
/// benchmark judges it, so it keeps the benchmark's severity. An unset one is
/// what the selected policy wants in effect (libpwquality's credits default to
/// 0, and login.defs(5) assumes `-1`, no expiry, for an unset
/// `PASS_MAX_DAYS`), so it keeps the policy's lower severity: it is reported
/// only so the value is written down, where a drop-in or a vendor layer cannot
/// quietly supply another.
pub(super) fn unmet_by_either_finding(
    policy: PasswordPolicy,
    directive: &PolicyDirective,
    benchmark: &PamDirective,
    target: &str,
    benchmark_target: &str,
    current: Option<&str>,
    config: &PluginConfig,
) -> Finding {
    let name = directive.rule.pam_directive_name;
    let current_display = current.unwrap_or("not set");
    Finding {
        finding_id: format!("pam-{name}"),
        finding_category: FindingCategory::Authentication,
        finding_current_value: current_display.to_string(),
        finding_description: format!(
            "PAM directive '{name}' is currently '{current_display}' but should be '{target}' \
             under the {} password policy. It does not meet the benchmark rule that policy \
             replaces either ({name} = {benchmark_target}), so every control the check maps to \
             is reported as not met",
            policy.id(),
        ),
        finding_explanation: directive.rule.pam_description.to_string(),
        finding_impact: format!(
            "The value meets neither the {} policy nor the benchmark rules. apply writes \
             {target}, after which only the benchmark rule stays unmet, reported as an Info \
             policy departure",
            policy.id(),
        ),
        finding_recommended_value: target.to_string(),
        finding_remediation_steps: vec![format!(
            "Set {name} = {target} in the appropriate configuration file"
        )],
        finding_severity: match current {
            Some(_) => benchmark.pam_severity,
            None => directive.rule.pam_severity,
        },
        finding_title: format!(
            "PAM setting meets neither the {} policy nor the benchmark: {name}",
            policy.id()
        ),
        finding_compliance: get_pam_compliance_mappings(name),
        finding_exception: config.exception_outcome(name, current_display),
        finding_exception_key: Some(name.to_string()),
    }
}

/// The note a change line carries when writing `written` over the host's
/// `current` value relaxes a rule, so a relaxation never appears as an
/// anonymous edit; `None` when the write relaxes nothing.
///
/// A write relaxes a dropped benchmark rule only when the host's value is
/// stricter than what is written by that rule's own measure: a `-1` credit
/// replaced by `0`, or a 90-day maximum age replaced by 99999. Writing over an
/// unset value, a broken one such as `PASS_MAX_DAYS 0`, or a positive credit
/// that shortened the minimum is a repair, and labelling it a relaxation would
/// misdescribe it. A row the benchmark never managed relaxes whatever positive
/// value it replaces, since both of its checks are off at zero and below.
pub(super) fn relaxation_note(
    policy: PasswordPolicy,
    directive: &PolicyDirective,
    current: Option<&str>,
    written: &str,
) -> Option<String> {
    let relaxation = directive.relaxation.as_ref()?;
    let current = current?;
    let relaxes = match relaxation.benchmark {
        Some(benchmark) => benchmark.pam_compare.is_stricter(current, written),
        None => current.trim().parse::<i64>().is_ok_and(|n| n > 0),
    };
    relaxes.then(|| format!(" ({} password policy: {})", policy.id(), relaxation.drops))
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
    let relaxation = directive.relaxation.as_ref()?;
    let name = directive.rule.pam_directive_name;
    let value = config.directives.get(name)?;
    if super::clamped_baseline(&directive.rule, config) == value.trim() {
        return None;
    }
    let instead = match relaxation.benchmark {
        Some(_) => format!(
            "Set password_policy = \"benchmark\" under [pam] to manage {name} through overrides"
        ),
        None => format!(
            "The benchmark policy does not manage {name}, so set password_policy = \
             \"benchmark\" under [pam] to keep the value the host has"
        ),
    };
    Some(format!(
        "[pam.directives] {name} = \"{value}\" has no effect under the {} password policy, \
         which sets {name} to {} ({}). {instead}",
        policy.id(),
        directive.rule.pam_secure_value,
        relaxation.drops,
    ))
}

#[cfg(test)]
mod tests;
