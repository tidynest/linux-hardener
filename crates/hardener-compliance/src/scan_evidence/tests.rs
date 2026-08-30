#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading.

//! Unit tests for [`scan_evidence`](super).
//!
//! Ported from `hardener-plugins/src/scan_outcome/tests.rs` when the flatten
//! moved behind `ReportGenerator::generate`. They build their inventory by
//! hand rather than from the registry, which the compliance crate cannot
//! reach: the rule under test is "a plugin that contributed nothing has its
//! declared coverage routed to manual review", and that holds for any plugin
//! set. Testing it against the real eight tied the assertions to whichever
//! controls those eight happen to declare today.

use super::*;
use hardener_common::types::{ComplianceFramework, ComplianceMapping, FindingCategory};
use hardener_types::PluginMetadata;

fn mapping(control: &str) -> ComplianceMapping {
    ComplianceMapping {
        compliance_framework: ComplianceFramework::CIS,
        compliance_control_id: control.to_string(),
        compliance_control_title: format!("control {control}"),
        compliance_section: None,
    }
}

fn plugin(id: &str, controls: &[&str]) -> PluginCoverage {
    PluginCoverage {
        metadata: PluginMetadata {
            plugin_category: FindingCategory::Authentication,
            plugin_description: String::new(),
            plugin_id: PluginId::new(id),
            plugin_name: format!("{id} plugin"),
            plugin_version: "0.1.0".to_string(),
        },
        coverage: controls.iter().map(|c| mapping(c)).collect(),
    }
}

/// Two plugins declaring different controls, which is what makes "the entry
/// carries *this* plugin's coverage" a claim that can fail.
fn inventory() -> PluginInventory {
    PluginInventory::Known(vec![
        plugin("ssh-hardening", &["1.1", "1.2"]),
        plugin("kernel-hardening", &["2.1"]),
    ])
}

fn scan_of(plugin_id: &str, success: bool) -> ScanResult {
    ScanResult {
        scan_plugin_id: PluginId::new(plugin_id),
        scan_success: success,
        scan_findings: vec![],
        scan_unchecked: vec![],
        scan_duration_us: 0,
        scan_error: (!success).then(|| "permission denied".to_string()),
        scan_skipped: None,
    }
}

fn ids(unchecked: &[UncheckedCheck]) -> Vec<&str> {
    unchecked
        .iter()
        .map(|c| c.unchecked_check_id.as_str())
        .collect()
}

/// The whole point of the entry: it has to carry the coverage, or the scoring
/// pass has nothing to route to manual review and passes the controls anyway.
#[test]
fn an_incomplete_scan_carries_the_plugins_whole_coverage() {
    let check = unassessed_check(
        &plugin("ssh-hardening", &["1.1", "1.2"]),
        Unassessed::ScanIncomplete(Some("denied")),
    );

    assert_eq!(check.unchecked_compliance.len(), 2);
    assert!(check.unchecked_reason.contains("denied"));
}

/// A plugin the config disabled did not fail; it never ran. The two states
/// reach the same place in a report but must not read as the same event, or an
/// operator debugging a manual-review entry goes looking for a failure that
/// never happened.
#[test]
fn a_disabled_plugin_is_not_reported_as_a_failed_scan() {
    let check = unassessed_check(
        &plugin("ssh-hardening", &["1.1"]),
        Unassessed::DisabledByConfig,
    );

    assert!(!check.unchecked_compliance.is_empty());
    assert!(check.unchecked_reason.contains("disabled by configuration"));
    assert!(
        !check.unchecked_title.contains("did not complete"),
        "a plugin that never ran did not fail: {}",
        check.unchecked_title
    );
}

/// Every plugin reported, all clean: nothing to stand in for.
#[test]
fn a_scan_covering_every_plugin_contributes_no_unassessed_entry() {
    let results = vec![
        scan_of("ssh-hardening", true),
        scan_of("kernel-hardening", true),
    ];

    let (_, unchecked) = flatten(&inventory(), &results, &[]);

    assert!(unchecked.is_empty(), "{:?}", ids(&unchecked));
}

/// **The fleet defect, at the level the rule lives.** A scan that covered one
/// plugin says nothing about the other, and silence must not read as a pass.
#[test]
fn a_plugin_absent_from_the_results_is_reported_unassessed() {
    let (_, unchecked) = flatten(&inventory(), &[scan_of("ssh-hardening", true)], &[]);

    assert_eq!(ids(&unchecked), vec!["kernel-hardening-not-assessed"]);
    assert_eq!(
        unchecked[0].unchecked_compliance.len(),
        1,
        "the absent plugin's own control has to be carried, or it still passes"
    );
}

#[test]
fn a_failed_scan_and_a_disabled_plugin_both_contribute_one() {
    let (_, unchecked) = flatten(
        &inventory(),
        &[scan_of("ssh-hardening", false)],
        &[PluginId::new("kernel-hardening")],
    );

    assert_eq!(unchecked.len(), 2, "{:?}", ids(&unchecked));
}

/// A plugin named in `skipped` reads as disabled rather than merely uncovered.
///
/// Both route to manual review, so no score distinguishes them. The reason an
/// auditor reads does, and it is the only place the difference survives.
#[test]
fn a_skipped_plugin_says_it_was_disabled_rather_than_uncovered() {
    let (_, disabled) = flatten(
        &inventory(),
        &[scan_of("ssh-hardening", true)],
        &[PluginId::new("kernel-hardening")],
    );
    let (_, uncovered) = flatten(&inventory(), &[scan_of("ssh-hardening", true)], &[]);

    assert!(
        disabled[0]
            .unchecked_reason
            .contains("disabled by configuration")
    );
    assert!(uncovered[0].unchecked_reason.contains("did not cover it"));
}

/// The three `Unassessed` variants do not share a blocker, and the difference
/// costs an operator a run if it is got wrong.
///
/// A plugin the config disabled and one this run did not select are the
/// operator's own doing, and no privilege overrules either. A plugin whose scan
/// reported its own failure is a different thing entirely: the reason is that
/// plugin's prose, nothing here reads it, and it may well be a refusal root
/// would lift. Claiming `Environment` for that one would be asserting sudo is
/// useless on the strength of a string nobody looked at.
#[test]
fn an_incomplete_scan_claims_nothing_where_a_disabled_plugin_claims_environment() {
    let (_, unchecked) = flatten(
        &inventory(),
        &[scan_of("ssh-hardening", false)],
        &[PluginId::new("kernel-hardening")],
    );

    let blocker_of = |id_starts: &str| {
        unchecked
            .iter()
            .find(|check| check.unchecked_check_id.starts_with(id_starts))
            .map(|check| check.unchecked_blocker)
            .unwrap_or_else(|| panic!("no entry for {id_starts}: {:?}", ids(&unchecked)))
    };

    assert_eq!(
        blocker_of("ssh-hardening"),
        UncheckedBlocker::Unknown,
        "a plugin whose own scan failed may not have its cause guessed at"
    );
    assert_eq!(
        blocker_of("kernel-hardening"),
        UncheckedBlocker::Environment,
        "a plugin the operator disabled is not waiting for a privileged re-run"
    );
}

/// A result whose plugin the inventory does not know keeps its findings and
/// gets no stand-in: it declares no coverage either, so its controls already
/// sit outside the assessed set.
#[test]
fn a_result_from_an_unknown_plugin_gets_no_stand_in() {
    let (_, unchecked) = flatten(
        &inventory(),
        &[
            scan_of("ssh-hardening", true),
            scan_of("kernel-hardening", true),
            scan_of("retired-plugin", false),
        ],
        &[],
    );

    assert!(unchecked.is_empty(), "{:?}", ids(&unchecked));
}

/// A run that cannot enumerate its plugins cannot say any control was
/// assessed.
///
/// This used to be carried by a stand-in entry listing the engine's whole
/// coverage, because the assessed set arrived as its own parameter and stayed
/// populated. It is now structural: `Unavailable` makes
/// [`PluginInventory::assessed_controls`] empty, so no control is assessable at
/// all and the stand-in only has to say why.
#[test]
fn a_registry_that_cannot_be_enumerated_leaves_no_control_assessable() {
    let unavailable = PluginInventory::Unavailable("read lock poisoned".to_string());

    assert!(
        unavailable.assessed_controls().is_empty(),
        "nothing may be assessed by a run that cannot list its plugins"
    );

    let (_, unchecked) = flatten(&unavailable, &[scan_of("ssh-hardening", true)], &[]);

    assert_eq!(ids(&unchecked), vec!["plugin-registry-unavailable"]);
    assert!(
        unchecked[0].unchecked_reason.contains("poisoned"),
        "the reason must carry what went wrong: {}",
        unchecked[0].unchecked_reason
    );
}

/// The stand-in must not fire on the ordinary path. An engine-wide manual
/// review entry on every report is the same defect pointing the other way: it
/// would bury a real assessment under controls that were in fact made.
#[test]
fn an_enumerable_registry_contributes_no_stand_in() {
    let (_, unchecked) = flatten(
        &inventory(),
        &[
            scan_of("ssh-hardening", true),
            scan_of("kernel-hardening", true),
        ],
        &[],
    );

    assert!(
        !ids(&unchecked).contains(&"plugin-registry-unavailable"),
        "{:?}",
        ids(&unchecked)
    );
}

/// The assessed set is the union of what the plugins declare, deduplicated.
///
/// It used to be injected beside the per-plugin table, which let a caller pass
/// a union that did not match the plugins it also passed.
#[test]
fn the_assessed_set_is_the_union_of_what_the_plugins_declare() {
    let overlapping = PluginInventory::Known(vec![
        plugin("ssh-hardening", &["1.1", "1.2"]),
        plugin("kernel-hardening", &["1.2", "2.1"]),
    ]);

    let assessed = overlapping.assessed_controls();

    let mut ids: Vec<&str> = assessed
        .iter()
        .map(|m| m.compliance_control_id.as_str())
        .collect();
    ids.sort_unstable();
    assert_eq!(
        ids,
        vec!["1.1", "1.2", "2.1"],
        "a shared control counts once"
    );
}

// --- skip-marker entries -----------------------------------------------------
//
// A marker entry is the reason travelling inside `results`: the same fact the
// `skipped` parameter states, but one a wire consumer or a persisted session
// can also receive. These pin the routing: by reason, never through the
// failure arm, and never doubled by the absent-plugin arm.

/// The marker's whole payload is the reason. It must arrive as
/// DisabledByConfig, not as a scan that did not complete, and its controls
/// route to manual review exactly as the `skipped` parameter's would.
#[test]
fn a_skip_marker_is_routed_by_its_reason_not_as_a_failure() {
    let mut marker = scan_of("ssh-hardening", false);
    marker.scan_skipped = Some(SkipReason::DisabledByConfig);
    let results = vec![marker, scan_of("kernel-hardening", true)];

    let (_, unchecked) = flatten(&inventory(), &results, &[]);

    assert_eq!(ids(&unchecked), vec!["ssh-hardening-not-assessed"]);
    assert!(
        unchecked[0]
            .unchecked_reason
            .contains("disabled by configuration")
    );
    assert!(
        !unchecked[0].unchecked_title.contains("did not complete"),
        "a plugin that never ran did not fail: {}",
        unchecked[0].unchecked_title
    );
}

/// A marker for a plugin this build no longer registers declares no coverage,
/// so it stands in for nothing, exactly as an absent unregistered plugin
/// would.
#[test]
fn a_skip_marker_for_an_unregistered_plugin_stands_in_for_nothing() {
    let mut marker = scan_of("retired-plugin", false);
    marker.scan_skipped = Some(SkipReason::DisabledByConfig);
    let results = vec![
        marker,
        scan_of("ssh-hardening", true),
        scan_of("kernel-hardening", true),
    ];

    let (_, unchecked) = flatten(&inventory(), &results, &[]);

    assert!(unchecked.is_empty(), "{:?}", ids(&unchecked));
}

/// The CLI resolves configuration in-process and passes `skipped`, while its
/// own results now also carry markers. One stand-in must come out of that
/// redundancy, not two: presence consumed the marker, and the absent arm must
/// not fire again for a plugin the results already name.
#[test]
fn a_plugin_both_marked_and_passed_as_skipped_yields_one_entry() {
    let mut marker = scan_of("ssh-hardening", false);
    marker.scan_skipped = Some(SkipReason::DisabledByConfig);
    let skipped = vec![PluginId::new("ssh-hardening")];
    let results = vec![marker, scan_of("kernel-hardening", true)];

    let (_, unchecked) = flatten(&inventory(), &results, &skipped);

    assert_eq!(ids(&unchecked), vec!["ssh-hardening-not-assessed"]);
}
