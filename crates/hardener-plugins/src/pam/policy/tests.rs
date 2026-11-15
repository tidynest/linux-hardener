#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`policy`](super).
//!
//! This file sits in the `policy/` directory beside `policy.rs`, so `super`
//! resolves to `crate::pam::policy` and its private items are in reach.

use super::*;
use crate::pam::coverage;
use std::collections::HashSet;

fn find<'a>(directives: &'a [PolicyDirective], name: &str) -> &'a PolicyDirective {
    directives
        .iter()
        .find(|d| d.rule.pam_directive_name == name)
        .unwrap_or_else(|| panic!("{name} is a known directive"))
}

/// The benchmark policy is the table itself, so selecting it, or selecting
/// nothing, changes nothing any earlier release did.
#[test]
fn the_benchmark_policy_is_the_directive_table_unchanged() {
    let directives = policy_directives(PasswordPolicy::Benchmark);
    assert_eq!(directives.len(), PAM_DIRECTIVES.len());
    for (policy_directive, row) in directives.iter().zip(PAM_DIRECTIVES) {
        assert_eq!(
            policy_directive.rule.pam_directive_name,
            row.pam_directive_name
        );
        assert_eq!(policy_directive.rule.pam_secure_value, row.pam_secure_value);
        assert_eq!(policy_directive.rule.pam_compare, row.pam_compare);
        assert_eq!(policy_directive.rule.pam_severity, row.pam_severity);
        assert!(
            policy_directive.departure.is_none(),
            "{} departs from nothing under the benchmark policy",
            row.pam_directive_name
        );
    }
}

/// The NIST policy raises the minimum to 15, drops the four credits and the
/// maximum age, and keeps every other row exactly as the benchmark has it:
/// lockout, history, the minimum age and the warning period all stay.
#[test]
fn the_nist_policy_changes_six_rows_and_keeps_the_rest() {
    let directives = policy_directives(PasswordPolicy::Nist80063b);
    assert_eq!(directives.len(), PAM_DIRECTIVES.len());

    let minlen = find(&directives, "minlen");
    assert_eq!(minlen.rule.pam_secure_value, "15");
    assert_eq!(minlen.rule.pam_compare, Strictness::AtLeast);
    assert!(
        minlen.departure.is_none(),
        "15 tightens the benchmark's 14, so the frameworks lose nothing"
    );

    for credit in ["dcredit", "ucredit", "lcredit", "ocredit"] {
        let directive = find(&directives, credit);
        assert_eq!(directive.rule.pam_secure_value, "0");
        assert_eq!(directive.rule.pam_compare, Strictness::ClosestToZero);
        assert_eq!(directive.rule.pam_severity, Severity::Low);
        let departure = directive
            .departure
            .as_ref()
            .unwrap_or_else(|| panic!("{credit} drops a benchmark rule"));
        assert_eq!(departure.benchmark.pam_secure_value, "-1");
    }

    let max_days = find(&directives, "PASS_MAX_DAYS");
    assert_eq!(max_days.rule.pam_secure_value, "99999");
    assert_eq!(max_days.rule.pam_compare, Strictness::AtLeastOrUnlimited);
    assert!(max_days.departure.is_some());

    for kept in [
        "maxrepeat",
        "PASS_MIN_DAYS",
        "PASS_WARN_AGE",
        "deny",
        "remember",
    ] {
        let directive = find(&directives, kept);
        let row = PAM_DIRECTIVES
            .iter()
            .find(|d| d.pam_directive_name == kept)
            .expect("a known directive");
        assert_eq!(directive.rule.pam_secure_value, row.pam_secure_value);
        assert_eq!(directive.rule.pam_compare, row.pam_compare);
        assert!(
            directive.departure.is_none(),
            "{kept} is enforced as the benchmark has it"
        );
    }
}

/// A rule naming a directive the table does not have would be dropped without
/// a word, and the policy would quietly enforce the benchmark's value for it.
#[test]
fn every_nist_rule_names_a_directive_the_table_has() {
    assert!(!NIST_RULES.is_empty(), "the loop below would check nothing");
    for rule in NIST_RULES {
        assert!(
            PAM_DIRECTIVES
                .iter()
                .any(|row| row.pam_directive_name == rule.name),
            "{} is not in PAM_DIRECTIVES, so the NIST policy would never apply it",
            rule.name
        );
        // The rule's own target must be placeable on its own scale, or the
        // clamp that resolves it would panic at run time.
        assert!(
            !rule
                .compare
                .violated_by(rule.secure_value, Some(rule.secure_value))
        );
    }
}

/// The honesty property in one place: a dropped rule's own finding carries
/// only the four policy-agnostic frameworks, and its departure finding carries
/// every other framework the benchmark check maps to. Together they cover the
/// check's controls exactly, so nothing is lost and nothing is double-counted.
#[test]
fn a_dropped_rule_splits_its_controls_between_the_two_findings() {
    let directives = policy_directives(PasswordPolicy::Nist80063b);
    for name in ["dcredit", "ucredit", "lcredit", "ocredit", "PASS_MAX_DAYS"] {
        let directive = find(&directives, name);
        let own = rule_mappings(directive);
        let departure = departure_mappings(name);

        assert!(!own.is_empty() && !departure.is_empty());
        assert!(
            own.iter()
                .all(|m| POLICY_AGNOSTIC_FRAMEWORKS.contains(&m.compliance_framework)),
            "{name}'s own finding must not fail a framework that wants the rule kept"
        );
        assert!(
            departure
                .iter()
                .all(|m| !POLICY_AGNOSTIC_FRAMEWORKS.contains(&m.compliance_framework)),
            "{name}'s departure must not fail a framework the policy satisfies"
        );

        let mut together: Vec<_> = own
            .iter()
            .chain(&departure)
            .map(|m| (m.compliance_framework, m.compliance_control_id.clone()))
            .collect();
        together.sort_by(|a, b| a.1.cmp(&b.1));
        let mut all: Vec<_> = get_pam_compliance_mappings(name)
            .iter()
            .map(|m| (m.compliance_framework, m.compliance_control_id.clone()))
            .collect();
        all.sort_by(|a, b| a.1.cmp(&b.1));
        assert_eq!(
            together, all,
            "{name}: the two findings must cover the check exactly"
        );
    }

    // A rule that only tightens keeps every mapping it had.
    let minlen = find(&directives, "minlen");
    assert_eq!(
        rule_mappings(minlen).len(),
        get_pam_compliance_mappings("minlen").len()
    );
}

/// The STIG and PCI DSS controls for expiry are the ones the issue is about,
/// so they are named outright rather than left to the general rule above.
#[test]
fn the_expiry_departure_fails_the_stig_and_pci_controls() {
    let ids: HashSet<String> = departure_mappings("PASS_MAX_DAYS")
        .into_iter()
        .map(|m| m.compliance_control_id)
        .collect();
    for control in ["5.4.1.1", "RHEL-08-020200", "8.2.4"] {
        assert!(
            ids.contains(control),
            "{control} must fail under the NIST policy"
        );
    }
}

/// Every control either finding can carry is one the plugin already declares,
/// so the report renders the failure against a control it lists rather than
/// through the safety net for unknown ids.
#[test]
fn every_control_the_nist_policy_can_fail_is_already_declared() {
    let declared: HashSet<String> = coverage()
        .into_iter()
        .map(|m| m.compliance_control_id)
        .collect();
    assert!(
        !declared.is_empty(),
        "the plugin declares no coverage at all"
    );
    for directive in policy_directives(PasswordPolicy::Nist80063b) {
        let name = directive.rule.pam_directive_name;
        for mapping in rule_mappings(&directive)
            .into_iter()
            .chain(departure_mappings(name))
        {
            assert!(
                declared.contains(&mapping.compliance_control_id),
                "{name} can emit {} which coverage() does not declare",
                mapping.compliance_control_id
            );
        }
    }
}

#[test]
fn a_departure_finding_is_informational_and_excepted_by_the_directive_name() {
    let directives = policy_directives(PasswordPolicy::Nist80063b);
    let departure = find(&directives, "dcredit")
        .departure
        .as_ref()
        .expect("dcredit drops a benchmark rule");

    let finding = departure_finding(
        PasswordPolicy::Nist80063b,
        departure,
        "-1",
        "0",
        &PluginConfig::default(),
    );
    assert_eq!(finding.finding_id, "pam-dcredit-policy-departure");
    assert_eq!(finding.finding_severity, Severity::Info);
    assert_eq!(finding.finding_exception_key.as_deref(), Some("dcredit"));
    assert_eq!(finding.finding_recommended_value, "-1");
    assert!(
        finding.finding_title.contains("nist-800-63b"),
        "the report must say which policy was applied: {}",
        finding.finding_title
    );
}

/// Under the NIST policy an override cannot put a character class back, and
/// says so; an override that does take effect, and every override under the
/// benchmark policy, stays silent as overrides always have.
#[test]
fn only_a_refused_override_on_a_dropped_rule_is_called_out() {
    let mut config = PluginConfig::default();
    config
        .directives
        .insert("dcredit".to_string(), "-1".to_string());
    config
        .directives
        .insert("PASS_MAX_DAYS".to_string(), "-1".to_string());
    config
        .directives
        .insert("minlen".to_string(), "8".to_string());

    let nist = policy_directives(PasswordPolicy::Nist80063b);
    let note = ignored_override(PasswordPolicy::Nist80063b, find(&nist, "dcredit"), &config)
        .expect("a refused character-class override is called out");
    assert!(
        note.contains("has no effect") && note.contains("benchmark"),
        "{note}"
    );

    assert!(
        ignored_override(
            PasswordPolicy::Nist80063b,
            find(&nist, "PASS_MAX_DAYS"),
            &config
        )
        .is_none(),
        "-1 means no expiry at all, which wins the clamp on this policy's scale"
    );
    assert!(
        ignored_override(PasswordPolicy::Nist80063b, find(&nist, "minlen"), &config).is_none(),
        "a loosening override on a kept rule is refused silently, as it always was"
    );

    let benchmark = policy_directives(PasswordPolicy::Benchmark);
    assert!(
        ignored_override(
            PasswordPolicy::Benchmark,
            find(&benchmark, "dcredit"),
            &config
        )
        .is_none()
    );
}
