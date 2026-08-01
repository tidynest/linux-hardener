#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`scan_outcome`].
//!
//! Split out of `scan_outcome.rs`. This file sits in the `scan_outcome/` directory
//! beside it, so `super` still resolves to `crate::scan_outcome` and every
//! import carried across unchanged, private items included.

use super::*;

fn metadata_for(plugin_id: &str) -> PluginMetadata {
    create_plugin_registry_metadata()
        .into_iter()
        .find(|m| m.plugin_id.as_str() == plugin_id)
        .expect("plugin must be registered")
}

fn create_plugin_registry_metadata() -> Vec<PluginMetadata> {
    crate::create_plugin_registry()
        .list()
        .expect("registry must enumerate")
}

fn scan_of(plugin_id: &str, success: bool) -> ScanResult {
    ScanResult {
        scan_plugin_id: PluginId::new(plugin_id),
        scan_success: success,
        scan_findings: vec![],
        scan_unchecked: vec![],
        scan_duration_us: 0,
        scan_error: (!success).then(|| "permission denied".to_string()),
    }
}

/// The whole point of the entry: it has to carry the coverage, or the
/// generator has nothing to route to manual review and passes the controls
/// anyway.
#[test]
fn an_incomplete_scan_carries_the_plugins_whole_coverage() {
    let metadata = metadata_for("ssh-hardening");
    let declared = crate::coverage_for("ssh-hardening").unwrap();

    let check = unassessed_check(&metadata, Unassessed::ScanIncomplete(Some("denied")));

    assert_eq!(check.unchecked_compliance.len(), declared.len());
    assert!(check.unchecked_reason.contains("denied"));
}

/// A plugin the config disabled did not fail; it never ran. The two states
/// reach the same place in a report but must not read as the same event,
/// or an operator debugging a manual-review entry goes looking for a
/// failure that never happened.
#[test]
fn a_disabled_plugin_is_not_reported_as_a_failed_scan() {
    let metadata = metadata_for("ssh-hardening");

    let check = unassessed_check(&metadata, Unassessed::DisabledByConfig);

    assert!(!check.unchecked_compliance.is_empty());
    assert!(check.unchecked_reason.contains("disabled by configuration"));
    assert!(
        !check.unchecked_title.contains("did not complete"),
        "a plugin that never ran did not fail: {}",
        check.unchecked_title
    );
}

#[test]
fn a_successful_scan_contributes_no_unassessed_entry() {
    let metadata = metadata_for("ssh-hardening");

    let (_, unchecked) = flatten_scans(&[(metadata, scan_of("ssh-hardening", true))], &[]);

    assert!(unchecked.is_empty());
}

/// A run that cannot enumerate the plugins cannot say any control was
/// assessed. Folding that failure into an empty list silences both the
/// incomplete-scan branch and the not-covered loop beneath it, so every
/// control the engine covers reports `Pass` on evidence nobody collected.
#[test]
fn a_registry_that_cannot_be_enumerated_leaves_no_control_assessable() {
    let listed = Err(hardener_common::error::HardeningError::Plugin(
        "Failed to acquire read lock: poisoned".to_string(),
    ));

    let (registered, unavailable) = registered_or_unavailable(listed);

    assert!(registered.is_empty());
    let check = unavailable.expect("a registry that could not be listed must be recorded");
    assert!(
        check.unchecked_reason.contains("poisoned"),
        "the reason must carry what went wrong: {}",
        check.unchecked_reason
    );

    // Engine-wide rather than any one plugin's: a control only ssh
    // declares and a control only the kernel plugin declares must both be
    // carried, or whichever is missing still passes on silence.
    for plugin_id in ["ssh-hardening", "kernel-hardening"] {
        let declared = crate::coverage_for(plugin_id).expect("plugin declares coverage");
        assert!(
            !declared.is_empty(),
            "{plugin_id} declares nothing to carry"
        );
        for mapping in declared {
            // Framework and id are the whole invariant: the generator
            // matches an unchecked entry to a control on that pair alone
            // and takes the title from its catalogue, which is why the
            // payload may deduplicate a control two plugins both declare.
            assert!(
                check.unchecked_compliance.iter().any(|carried| {
                    carried.compliance_framework == mapping.compliance_framework
                        && carried.compliance_control_id == mapping.compliance_control_id
                }),
                "{plugin_id} control {} is not carried, so it can still pass",
                mapping.compliance_control_id
            );
        }
    }
}

/// The stand-in must not fire on the ordinary path. An engine-wide manual
/// review entry on every report is the same defect pointing the other way:
/// it would bury a real assessment under controls that were in fact made.
#[test]
fn an_enumerable_registry_contributes_no_stand_in() {
    let (registered, unavailable) =
        registered_or_unavailable(crate::create_plugin_registry().list());

    assert!(!registered.is_empty());
    assert!(unavailable.is_none());
}

#[test]
fn a_failed_scan_and_a_disabled_plugin_both_contribute_one() {
    let ssh = metadata_for("ssh-hardening");
    let kernel = metadata_for("kernel-hardening");

    let (_, unchecked) = flatten_scans(
        &[(ssh, scan_of("ssh-hardening", false))],
        std::slice::from_ref(&kernel),
    );

    assert_eq!(unchecked.len(), 2);
}
