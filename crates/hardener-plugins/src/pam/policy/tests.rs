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

/// The three frameworks derived from NIST SP 800-53, which a departure must
/// never fail (#190, control round 1).
const NIST_DERIVED: [ComplianceFramework; 3] = [
    ComplianceFramework::NIST,
    ComplianceFramework::NIST800171,
    ComplianceFramework::FedRAMP,
];

fn find<'a>(directives: &'a [PolicyDirective], name: &str) -> &'a PolicyDirective {
    directives
        .iter()
        .find(|d| d.rule.pam_directive_name == name)
        .unwrap_or_else(|| panic!("{name} is a known directive"))
}

fn benchmark_row(name: &str) -> &'static PamDirective {
    PAM_DIRECTIVES
        .iter()
        .find(|d| d.pam_directive_name == name)
        .unwrap_or_else(|| panic!("{name} is in PAM_DIRECTIVES"))
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
            policy_directive.relaxation.is_none(),
            "{} relaxes nothing under the benchmark policy",
            row.pam_directive_name
        );
    }
}

/// The NIST policy raises the minimum to 15, drops the four credits and the
/// maximum age, switches `minclass` and `maxclassrepeat` off, and keeps every
/// other row exactly as the benchmark has it: lockout, history, the minimum
/// age and the warning period all stay.
#[test]
fn the_nist_policy_changes_six_rows_adds_two_and_keeps_the_rest() {
    let directives = policy_directives(PasswordPolicy::Nist80063b);
    assert_eq!(
        directives.len(),
        PAM_DIRECTIVES.len() + NIST_ONLY_ROWS.len()
    );

    let minlen = find(&directives, "minlen");
    assert_eq!(minlen.rule.pam_secure_value, "15");
    assert_eq!(minlen.rule.pam_compare, Strictness::AtLeast);
    assert!(
        minlen.relaxation.is_none(),
        "15 tightens the benchmark's 14, so the frameworks lose nothing"
    );

    for credit in ["dcredit", "ucredit", "lcredit", "ocredit"] {
        let directive = find(&directives, credit);
        assert_eq!(directive.rule.pam_secure_value, "0");
        assert_eq!(directive.rule.pam_compare, Strictness::ClosestToZero);
        assert_eq!(directive.rule.pam_severity, Severity::Low);
        let relaxation = directive
            .relaxation
            .as_ref()
            .unwrap_or_else(|| panic!("{credit} drops a benchmark rule"));
        let benchmark = relaxation
            .benchmark
            .unwrap_or_else(|| panic!("{credit} replaces a benchmark row"));
        assert_eq!(benchmark.pam_secure_value, "-1");
        assert!(!directive.only_switches_off());
    }

    let max_days = find(&directives, "PASS_MAX_DAYS");
    assert_eq!(max_days.rule.pam_secure_value, "99999");
    assert_eq!(max_days.rule.pam_compare, Strictness::AtLeastOrUnlimited);
    assert!(
        max_days
            .relaxation
            .as_ref()
            .is_some_and(|r| r.benchmark.is_some())
    );

    for added in ["minclass", "maxclassrepeat"] {
        let directive = find(&directives, added);
        assert_eq!(directive.rule.pam_secure_value, "0");
        assert_eq!(directive.rule.pam_compare, Strictness::ClosestToZero);
        assert_eq!(directive.rule.pam_config_file, PamConfigFile::PwQuality);
        assert_eq!(directive.rule.pam_severity, Severity::Low);
        assert!(
            directive.only_switches_off(),
            "{added} has no benchmark row behind it"
        );
    }

    for kept in [
        "maxrepeat",
        "PASS_MIN_DAYS",
        "PASS_WARN_AGE",
        "deny",
        "remember",
    ] {
        let directive = find(&directives, kept);
        let row = benchmark_row(kept);
        assert_eq!(directive.rule.pam_secure_value, row.pam_secure_value);
        assert_eq!(directive.rule.pam_compare, row.pam_compare);
        assert!(
            directive.relaxation.is_none(),
            "{kept} is enforced as the benchmark has it"
        );
    }
}

/// The added rows sit right after the last pwquality row, so a dry run lists
/// one file's pending changes together.
#[test]
fn the_added_rows_follow_the_other_pwquality_rows() {
    let names: Vec<&str> = policy_directives(PasswordPolicy::Nist80063b)
        .iter()
        .map(|d| d.rule.pam_directive_name)
        .collect();
    let maxrepeat = names
        .iter()
        .position(|n| *n == "maxrepeat")
        .expect("maxrepeat is a pwquality row");
    assert_eq!(
        &names[maxrepeat + 1..maxrepeat + 3],
        &["minclass", "maxclassrepeat"],
        "{names:?}"
    );
}

/// A rule naming a directive the table does not have would be dropped without
/// a word, and the policy would quietly enforce the benchmark's value for it.
/// An added row naming one the table does have would be enforced twice.
#[test]
fn every_nist_rule_names_a_directive_the_table_has_and_no_added_row_does() {
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
    assert!(!NIST_ONLY_ROWS.is_empty());
    for row in NIST_ONLY_ROWS {
        assert!(
            PAM_DIRECTIVES
                .iter()
                .all(|benchmark| benchmark.pam_directive_name != row.pam_directive_name),
            "{} is already a benchmark row",
            row.pam_directive_name
        );
        assert!(
            !row.pam_compare
                .violated_by(row.pam_secure_value, Some(row.pam_secure_value))
        );
    }
}

/// The honesty property in one place. A dropped rule's own finding carries
/// only the four policy-agnostic frameworks; its departure carries the CIS,
/// STIG and PCI DSS controls, whose texts still require the rule; and the
/// NIST-derived controls are in neither, because SP 800-53 Rev 5, SP 800-171
/// r3 and FedRAMP Rev 5 do not require it. Those three groups are the check's
/// whole mapping, so nothing is lost by accident.
#[test]
fn a_dropped_rule_splits_its_controls_three_ways() {
    let directives = policy_directives(PasswordPolicy::Nist80063b);
    for name in ["dcredit", "ucredit", "lcredit", "ocredit", "PASS_MAX_DAYS"] {
        let directive = find(&directives, name);
        let own = rule_mappings(directive);
        let departure = departure_mappings(name);
        let all = get_pam_compliance_mappings(name);

        assert!(!own.is_empty() && !departure.is_empty());
        assert!(
            own.iter()
                .all(|m| POLICY_AGNOSTIC_FRAMEWORKS.contains(&m.compliance_framework)),
            "{name}'s own finding must not fail a framework that wants the rule kept"
        );
        assert!(
            departure.iter().all(|m| DEPARTURE_FRAMEWORKS
                .iter()
                .any(|(f, _)| *f == m.compliance_framework)),
            "{name}'s departure fails only frameworks that still require the rule"
        );
        assert!(
            departure
                .iter()
                .any(|m| m.compliance_framework == ComplianceFramework::STIG),
            "{name}: every dropped rule has a STIG control behind it"
        );

        let key = |m: &ComplianceMapping| (m.compliance_framework, m.compliance_control_id.clone());
        let split: HashSet<_> = own.iter().chain(&departure).map(key).collect();
        let rest: HashSet<_> = all.iter().map(key).filter(|k| !split.contains(k)).collect();
        assert!(
            rest.iter().all(|(f, _)| NIST_DERIVED.contains(f)),
            "{name}: only NIST-derived controls may be left out of both findings: {rest:?}"
        );
        assert_eq!(
            own.len() + departure.len() + rest.len(),
            all.len(),
            "{name}: the three groups must not overlap"
        );
    }

    // A rule that only tightens keeps every mapping it had.
    let minlen = find(&directives, "minlen");
    assert_eq!(
        rule_mappings(minlen).len(),
        get_pam_compliance_mappings("minlen").len()
    );
}

/// The assertion control round 1 asked for outright: following SP 800-63B-4
/// never fails NIST SP 800-53, NIST SP 800-171 or FedRAMP through a departure.
#[test]
fn no_departure_fails_a_nist_derived_framework() {
    for directive in policy_directives(PasswordPolicy::Nist80063b) {
        let name = directive.rule.pam_directive_name;
        for mapping in departure_mappings(name) {
            assert!(
                !NIST_DERIVED.contains(&mapping.compliance_framework),
                "{name}'s departure would fail {:?} {}",
                mapping.compliance_framework,
                mapping.compliance_control_id
            );
        }
    }
}

/// The STIG and PCI DSS controls for expiry are the ones the issue is about,
/// so they are named outright rather than left to the general rule above, and
/// so is the NIST control that must not fail.
#[test]
fn the_expiry_departure_fails_the_stig_and_pci_controls_but_not_nist() {
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
    assert!(
        !ids.contains("IA-5(1)(d)"),
        "SP 800-53 Rev 5 IA-5(1)(d) is password storage, not lifetime"
    );
}

/// Every control any finding can carry is one the plugin already declares,
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
            .chain(get_pam_compliance_mappings(name))
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
fn a_departure_finding_is_informational_and_names_only_the_frameworks_it_fails() {
    let finding = departure_finding(
        PasswordPolicy::Nist80063b,
        NO_COMPOSITION_RULES,
        benchmark_row("dcredit"),
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
    assert!(
        finding
            .finding_description
            .contains("The CIS, DISA STIG and PCI DSS controls"),
        "{}",
        finding.finding_description
    );

    // ocredit has no PCI DSS mapping, so its departure does not claim one.
    let ocredit = departure_finding(
        PasswordPolicy::Nist80063b,
        NO_COMPOSITION_RULES,
        benchmark_row("ocredit"),
        "-1",
        "0",
        &PluginConfig::default(),
    );
    assert!(
        ocredit
            .finding_description
            .contains("The CIS and DISA STIG controls"),
        "{}",
        ocredit.finding_description
    );
}

/// A value that meets neither rule gets one finding, carrying every control,
/// at the benchmark's severity when a value is set and the policy's when it is
/// not.
#[test]
fn a_value_that_meets_neither_rule_fails_every_control_once() {
    let directives = policy_directives(PasswordPolicy::Nist80063b);
    let max_days = find(&directives, "PASS_MAX_DAYS");
    let benchmark = benchmark_row("PASS_MAX_DAYS");
    let config = PluginConfig::default();

    let broken = unmet_by_either_finding(
        PasswordPolicy::Nist80063b,
        max_days,
        benchmark,
        "99999",
        "90",
        Some("0"),
        &config,
    );
    assert_eq!(broken.finding_id, "pam-PASS_MAX_DAYS");
    assert_eq!(broken.finding_severity, Severity::Medium);
    assert_eq!(broken.finding_recommended_value, "99999");
    assert_eq!(
        broken.finding_compliance.len(),
        get_pam_compliance_mappings("PASS_MAX_DAYS").len()
    );
    assert!(
        !broken.finding_impact.contains("will not change"),
        "apply rewrites this value, so the finding must not say otherwise: {}",
        broken.finding_impact
    );

    let unset = unmet_by_either_finding(
        PasswordPolicy::Nist80063b,
        max_days,
        benchmark,
        "99999",
        "90",
        None,
        &config,
    );
    assert_eq!(unset.finding_severity, Severity::Low);
    assert_eq!(unset.finding_current_value, "not set");
}

/// Only a write that leaves the host looser than it was by the dropped rule's
/// own measure is labelled a relaxation.
#[test]
fn a_relaxation_note_marks_only_a_write_that_relaxes() {
    let nist = policy_directives(PasswordPolicy::Nist80063b);
    let note = |name: &str, current: Option<&str>, written: &str| {
        relaxation_note(
            PasswordPolicy::Nist80063b,
            find(&nist, name),
            current,
            written,
        )
    };

    assert_eq!(
        note("dcredit", Some("-1"), "0").as_deref(),
        Some(" (nist-800-63b password policy: no composition rules)")
    );
    assert_eq!(
        note("PASS_MAX_DAYS", Some("90"), "99999").as_deref(),
        Some(" (nist-800-63b password policy: no forced periodic change)")
    );
    assert!(
        note("PASS_MAX_DAYS", Some("120"), "99999").is_some(),
        "120 days is still a forced change, which 99999 drops"
    );
    assert!(
        note("minclass", Some("4"), "0").is_some(),
        "minclass 4 demanded every class"
    );

    for (name, current, why) in [
        (
            "dcredit",
            Some("2"),
            "a positive credit shortened the minimum",
        ),
        (
            "PASS_MAX_DAYS",
            Some("0"),
            "0 expired every password at once",
        ),
        ("dcredit", None, "an unset credit is already 0"),
        (
            "PASS_MAX_DAYS",
            None,
            "an unset maximum is already no expiry",
        ),
        ("minclass", Some("-1"), "minclass -1 imposes nothing"),
        ("minclass", None, "an unset minclass is already 0"),
        ("minlen", Some("14"), "raising the minimum relaxes nothing"),
    ] {
        let written = find(&nist, name).rule.pam_secure_value;
        assert!(
            note(name, current, written).is_none(),
            "{name} {current:?} -> {written}: {why}"
        );
    }

    let benchmark = policy_directives(PasswordPolicy::Benchmark);
    assert!(
        relaxation_note(
            PasswordPolicy::Benchmark,
            find(&benchmark, "dcredit"),
            Some("0"),
            "-1"
        )
        .is_none(),
        "the benchmark policy relaxes nothing"
    );
}

/// Under the NIST policy an override cannot put a character class back, and
/// says so; an override that does take effect, and every override under the
/// benchmark policy, stays silent as overrides always have.
#[test]
fn only_a_refused_override_on_a_relaxed_rule_is_called_out() {
    let mut config = PluginConfig::default();
    for (key, value) in [
        ("dcredit", "-1"),
        ("PASS_MAX_DAYS", "-1"),
        ("minlen", "8"),
        ("minclass", "4"),
    ] {
        config.directives.insert(key.to_string(), value.to_string());
    }

    let nist = policy_directives(PasswordPolicy::Nist80063b);
    let note = ignored_override(PasswordPolicy::Nist80063b, find(&nist, "dcredit"), &config)
        .expect("a refused character-class override is called out");
    assert!(
        note.contains("has no effect") && note.contains("manage dcredit through overrides"),
        "{note}"
    );

    let minclass = ignored_override(PasswordPolicy::Nist80063b, find(&nist, "minclass"), &config)
        .expect("a refused minclass override is called out");
    assert!(
        minclass.contains("does not manage minclass"),
        "the benchmark policy has no minclass rule to manage it with: {minclass}"
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
