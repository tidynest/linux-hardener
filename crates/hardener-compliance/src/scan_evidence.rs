//! Turning per-plugin scan results into the flat lists a report is scored
//! from, inside the generator rather than in front of it.
//!
//! **Why this is here and not in the front ends.** A control's status comes
//! from statically declared plugin coverage plus the findings the generator is
//! handed. A plugin that produced no evidence this run therefore passes every
//! control it covers, on the strength of the silence its own absence caused,
//! unless something says otherwise. That something is an [`UncheckedCheck`]
//! carrying the plugin's whole declared coverage, which routes those controls
//! to `ManualReview` through the path already built for checks that could not
//! run at the current privilege level.
//!
//! This rule used to live in `hardener_plugins::scan_outcome`, in front of the
//! generator, and every caller had to remember to go through it. On 2026-08-22
//! the desktop's fleet path did not, and a row scanned with one plugin reported
//! the same 38 passing CIS controls as a row scanned with all eight. Six call
//! sites were then traced by hand and each fixed. **Nothing stopped a seventh**,
//! which is why the flatten moved behind [`ReportGenerator::generate`]: its
//! parameter is now raw scan results, so there is no hand-flattened pair for a
//! new caller to pass.
//!
//! **Why the plugin set is injected rather than read.** The compliance crate
//! does not reach out for its inputs, and `hardener-plugins` is where the
//! registry and the coverage table live. Depending on that crate to seal this
//! would have traded one coupling for a worse one, so the inventory arrives as
//! a parameter exactly as `coverage` used to.
//!
//! [`ReportGenerator::generate`]: crate::ReportGenerator::generate

use hardener_common::types::FindingCategory;
use hardener_types::{
    Finding, PluginCoverage, PluginId, PluginInventory, ScanResult, UncheckedBlocker,
    UncheckedCheck,
};

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

/// Flattens scan results into a findings and unchecked pair.
///
/// **Public, and that does not weaken the seal.** What the fleet defect turned
/// on was a caller flattening by hand and handing the wrong pair to the
/// generator, so controls nobody assessed scored as passes.
/// [`ReportGenerator::generate`] takes raw results now and `score` beside it is
/// private, so there is no way to feed a flattened pair into scoring at all.
/// This exists for callers that need the list itself rather than a score:
/// `batch scan` publishes it as JSON and never builds a report.
///
/// `skipped` names plugins the config disabled, which never ran and so appear
/// nowhere in `results`. Without an entry of their own, disabling a plugin
/// would quietly pass every control it covers. A caller reading a persisted
/// session has no such list, because a stored session records only what ran:
/// there, absence alone is the signal, and every reason for it means the same
/// thing to a report.
pub fn flatten(
    inventory: &PluginInventory,
    results: &[ScanResult],
    skipped: &[PluginId],
) -> (Vec<Finding>, Vec<UncheckedCheck>) {
    let plugins = inventory.plugins();
    let mut findings = Vec::new();
    let mut unchecked: Vec<UncheckedCheck> = match inventory {
        PluginInventory::Known(_) => Vec::new(),
        PluginInventory::Unavailable(reason) => vec![registry_unavailable_check(reason)],
    };

    for result in results {
        findings.extend(result.scan_findings.iter().cloned());
        unchecked.extend(result.scan_unchecked.iter().cloned());

        // A result whose plugin this build no longer registers keeps its
        // findings above, but gets no stand-in entry: it declares no coverage
        // either, so the controls it would have assessed already sit outside
        // the assessed set and report ManualReview anyway.
        if !result.scan_success
            && let Some(plugin) = plugins
                .iter()
                .find(|p| p.metadata.plugin_id == result.scan_plugin_id)
        {
            unchecked.push(unassessed_check(
                plugin,
                Unassessed::ScanIncomplete(result.scan_error.as_deref()),
            ));
        }
    }

    for plugin in plugins {
        if results
            .iter()
            .any(|r| r.scan_plugin_id == plugin.metadata.plugin_id)
        {
            continue;
        }
        // Disabled by the operator and merely not covered are the same silence
        // to a score, and are reported apart only so the reason an auditor
        // reads is the true one.
        let why = if skipped.contains(&plugin.metadata.plugin_id) {
            Unassessed::DisabledByConfig
        } else {
            Unassessed::NotCovered
        };
        unchecked.push(unassessed_check(plugin, why));
    }

    (findings, unchecked)
}

/// The entry standing in for a run that could not enumerate its plugins.
///
/// It carries no coverage, because a run that cannot say which plugins exist
/// cannot say that any control was assessed: [`PluginInventory::Unavailable`]
/// makes the assessed set empty, so every control reaches `ManualReview`
/// through the unassessed arm rather than needing to be named here.
///
/// The category is the one field with no honest answer: no variant describes an
/// engine-level failure. Nothing branches on it, and no renderer prints it, so
/// it reaches only the JSON output and the reason carries the meaning instead.
fn registry_unavailable_check(reason: &str) -> UncheckedCheck {
    UncheckedCheck {
        unchecked_check_id: "plugin-registry-unavailable".to_string(),
        unchecked_title: "Plugin registry could not be enumerated".to_string(),
        unchecked_category: FindingCategory::Audit,
        unchecked_reason: format!(
            "the plugins this run would have assessed could not be listed ({reason}), \
             so no control may be reported as satisfied"
        ),
        // The registry is enumerated in the calling process. Nothing about
        // privilege reaches it, so a privileged re-run reports exactly this
        // again.
        unchecked_blocker: UncheckedBlocker::Environment,
        unchecked_compliance: Vec::new(),
    }
}

/// The unchecked entry standing in for a plugin that produced no evidence.
///
/// It carries the plugin's whole declared coverage, so a reader of the report
/// sees those controls as awaiting manual review rather than satisfied.
fn unassessed_check(plugin: &PluginCoverage, why: Unassessed<'_>) -> UncheckedCheck {
    let metadata = &plugin.metadata;
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
        // Two of the three are the operator's own doing, and root overrules
        // neither: a plugin the config disabled, and one this run did not
        // select. The third is a plugin whose scan reported its own failure,
        // and that reason is the plugin's prose rather than anything this
        // function classified, so it may well be a refusal root would lift.
        // Claiming Environment for it would be asserting the remedy is useless
        // on the strength of a string nobody read.
        unchecked_blocker: match why {
            Unassessed::ScanIncomplete(_) => UncheckedBlocker::Unknown,
            Unassessed::DisabledByConfig | Unassessed::NotCovered => UncheckedBlocker::Environment,
        },
        unchecked_compliance: plugin.coverage.clone(),
    }
}

#[cfg(test)]
mod tests;
