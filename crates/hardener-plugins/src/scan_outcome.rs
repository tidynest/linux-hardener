//! Turning per-plugin scan results into the flat lists a compliance report
//! consumes.
//!
//! The report generator decides a control's status from statically declared
//! plugin coverage plus the findings it is handed. A plugin that produced no
//! evidence this run therefore passes every control it covers, on the strength
//! of the silence its own absence caused, unless something says otherwise.
//! That something is an `UncheckedCheck` carrying the plugin's whole declared
//! coverage, which routes those controls to `ManualReview` through the path
//! already built for checks that could not run at the current privilege level.
//!
//! This lives beside `coverage_for` rather than in either front end because the
//! CLI and the desktop both need it, and each keeping its own copy is precisely
//! how the rule came to be applied in one and not the other.

use hardener_common::types::{FindingCategory, PluginId};
use hardener_core::{Finding, PluginMetadata, ScanResult, UncheckedCheck};

/// Why a plugin contributed no evidence to this run.
#[derive(Clone, Copy, Debug)]
pub enum Unassessed<'a> {
    /// Its scan ran and did not complete.
    ScanIncomplete(Option<&'a str>),
    /// The config disabled it, so it never ran at all.
    DisabledByConfig,
    /// The scan simply did not cover it. Inferred from a plugin's absence from
    /// a result set, which is all a persisted session records: a filtered scan
    /// and a config-disabled plugin are indistinguishable after the fact, and
    /// both mean the same thing to a compliance report.
    NotCovered,
}

/// Flattens per-plugin scan results into the findings and unchecked lists the
/// compliance generator consumes.
///
/// `skipped` names plugins the config disabled. Those never ran, so they appear
/// nowhere in `grouped`, and without an entry of their own, disabling a plugin
/// would quietly pass every control it covers.
pub fn flatten_scans(
    grouped: &[(PluginMetadata, ScanResult)],
    skipped: &[PluginMetadata],
) -> (Vec<Finding>, Vec<UncheckedCheck>) {
    let mut findings = Vec::new();
    let mut unchecked = Vec::new();

    for (metadata, result) in grouped {
        if !result.scan_success {
            unchecked.push(unassessed_check(
                metadata,
                Unassessed::ScanIncomplete(result.scan_error.as_deref()),
            ));
        }
        findings.extend(result.scan_findings.iter().cloned());
        unchecked.extend(result.scan_unchecked.iter().cloned());
    }

    for metadata in skipped {
        unchecked.push(unassessed_check(metadata, Unassessed::DisabledByConfig));
    }

    (findings, unchecked)
}

/// The `ScanResult` standing in for a plugin whose `scan` call itself errored,
/// so the failure travels the same path as a plugin that returned `Ok` while
/// reporting `scan_success: false`.
///
/// Both front ends need this. Dropping the plugin instead is what let a failed
/// scan read as a clean one, and a caller that persists results needs the
/// failure recorded rather than merely logged, because the report is built from
/// what was stored.
pub fn failed_scan(plugin_id: &PluginId, error: &str) -> ScanResult {
    ScanResult {
        scan_plugin_id: plugin_id.clone(),
        scan_success: false,
        scan_findings: Vec::new(),
        scan_unchecked: Vec::new(),
        scan_duration_us: 0,
        scan_error: Some(error.to_string()),
    }
}

/// Flattens results that arrive without their plugin metadata, as a persisted
/// scan session's do, resolving metadata from the registry.
///
/// Any registered plugin with no result at all contributes an unassessed entry.
/// A stored session records only what ran, so absence is the only signal there
/// is, and every reason for it (the config disabled the plugin, the operator
/// scanned a subset, the plugin was added after the session was stored) means
/// the same thing to a compliance report: nobody assessed those controls this
/// run, so none of them may report `Pass`.
///
/// When the registry itself cannot be enumerated there is no plugin left to
/// name, so one entry carrying the engine's whole coverage stands in for all
/// of them. See [`registered_or_unavailable`].
pub fn flatten_persisted_scans(results: &[ScanResult]) -> (Vec<Finding>, Vec<UncheckedCheck>) {
    let (registered, unavailable) =
        registered_or_unavailable(crate::create_plugin_registry().list());

    let mut findings = Vec::new();
    let mut unchecked: Vec<UncheckedCheck> = unavailable.into_iter().collect();

    for result in results {
        findings.extend(result.scan_findings.iter().cloned());
        unchecked.extend(result.scan_unchecked.iter().cloned());

        // A result whose plugin this build no longer registers keeps its
        // findings above, but gets no stand-in entry: it declares no coverage
        // either, so the controls it would have assessed already sit outside
        // the generator's assessed set and report ManualReview anyway.
        if !result.scan_success
            && let Some(metadata) = registered
                .iter()
                .find(|m| m.plugin_id == result.scan_plugin_id)
        {
            unchecked.push(unassessed_check(
                metadata,
                Unassessed::ScanIncomplete(result.scan_error.as_deref()),
            ));
        }
    }

    for metadata in &registered {
        if !results
            .iter()
            .any(|r| r.scan_plugin_id == metadata.plugin_id)
        {
            unchecked.push(unassessed_check(metadata, Unassessed::NotCovered));
        }
    }

    (findings, unchecked)
}

/// The plugin list a persisted flatten works from, together with whatever has
/// to stand in for it when the registry cannot be enumerated at all.
///
/// Discarding the error left an empty list, which reads exactly like a build
/// registering no plugins: the loops below find nothing to stand in for, and
/// the report passes every control on the resulting silence. The list has
/// nowhere to record why it is empty, so the stand-in travels beside it.
fn registered_or_unavailable(
    listed: hardener_common::error::Result<Vec<PluginMetadata>>,
) -> (Vec<PluginMetadata>, Option<UncheckedCheck>) {
    match listed {
        Ok(registered) => (registered, None),
        Err(error) => (
            Vec::new(),
            Some(registry_unavailable_check(&error.to_string())),
        ),
    }
}

/// The entry standing in for a run that could not enumerate its plugins.
///
/// It carries the engine's whole declared coverage, because a run that cannot
/// say which plugins exist cannot say that any control was assessed, and the
/// generator passes a control it finds neither failed nor unchecked. This is
/// the same rule `unassessed_check` applies per plugin, widened to the only
/// scope left when no plugin can be named.
///
/// The category is the one field with no honest answer: no variant describes
/// an engine-level failure. Nothing branches on it, and no renderer prints it
/// (`output.rs` shows the title and the reason), so it reaches only the JSON
/// output and the reason carries the meaning instead.
fn registry_unavailable_check(reason: &str) -> UncheckedCheck {
    UncheckedCheck {
        unchecked_check_id: "plugin-registry-unavailable".to_string(),
        unchecked_title: "Plugin registry could not be enumerated".to_string(),
        unchecked_category: FindingCategory::Audit,
        unchecked_reason: format!(
            "the plugins this run would have assessed could not be listed ({reason}), \
             so no control may be reported as satisfied"
        ),
        unchecked_needs_privilege: false,
        unchecked_compliance: crate::compliance_coverage(),
    }
}

/// The unchecked entry standing in for a plugin that produced no evidence.
///
/// It carries the plugin's whole declared coverage, so a reader of the report
/// sees those controls as awaiting manual review rather than satisfied. A
/// plugin absent from the coverage table declares nothing, and its controls
/// already sit outside the generator's assessed set;
/// `every_registered_plugin_declares_its_coverage` is what keeps that true as
/// plugins are added.
pub fn unassessed_check(metadata: &PluginMetadata, why: Unassessed<'_>) -> UncheckedCheck {
    let id = metadata.plugin_id.as_str();
    let (suffix, title, reason) = match why {
        Unassessed::ScanIncomplete(error) => (
            "scan-incomplete",
            format!("{} scan did not complete", metadata.plugin_name),
            error.unwrap_or("reason not reported").to_string(),
        ),
        Unassessed::DisabledByConfig => (
            "not-assessed",
            format!("{} did not run", metadata.plugin_name),
            "disabled by configuration, so the controls it covers were not assessed".to_string(),
        ),
        Unassessed::NotCovered => (
            "not-assessed",
            format!("{} did not run", metadata.plugin_name),
            "this scan did not cover it, so the controls it covers were not assessed".to_string(),
        ),
    };

    UncheckedCheck {
        unchecked_check_id: format!("{id}-{suffix}"),
        unchecked_title: title,
        unchecked_category: metadata.plugin_category,
        unchecked_reason: reason,
        unchecked_needs_privilege: false,
        unchecked_compliance: crate::coverage_for(id).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
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
}
