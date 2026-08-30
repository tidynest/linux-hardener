//! What this crate hands a compliance report: the plugin set it is scored
//! against, and the stand-in result for a plugin whose scan errored.
//!
//! **The flatten used to be here and is not any more.** It turned per-plugin
//! results into the flat lists a report consumes, contributing an unassessed
//! entry for any plugin that produced no evidence so its controls could not
//! pass on silence. Being in front of the generator, it was something every
//! caller had to remember, and on 2026-08-22 the desktop's fleet path did not:
//! a row scanned with one plugin reported the same 38 passing CIS controls as a
//! row scanned with all eight. Six call sites were traced and fixed, and
//! nothing stopped a seventh.
//!
//! It now lives in `hardener_compliance::scan_evidence`, behind
//! `ReportGenerator::generate`, whose parameter is raw scan results. There is
//! no flattened pair for a new caller to get wrong. What stays here is
//! [`plugin_inventory`], because the registry and the coverage table are in
//! this crate, and the compliance crate takes it as a parameter rather than
//! depending on this one.

use hardener_common::types::PluginId;
use hardener_core::ScanResult;
use hardener_types::{PluginCoverage, PluginInventory};

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
        scan_skipped: None,
    }
}

/// Every plugin this build registers, paired with the coverage it declares.
///
/// This is what a compliance report is scored against, and it is built here
/// because the registry and the coverage table both live in this crate. It is
/// consumed by `hardener_compliance::ReportGenerator::new`, which takes it as a
/// parameter rather than reaching for it: the compliance crate does not depend
/// on this one, deliberately.
///
/// A registry that cannot be enumerated becomes
/// [`PluginInventory::Unavailable`] rather than an empty list. Discarding the
/// error would leave a list that reads exactly like a build registering no
/// plugins, and a report scored against no plugins passes every control on the
/// resulting silence.
pub fn plugin_inventory() -> PluginInventory {
    match crate::create_plugin_registry().list() {
        Ok(registered) => PluginInventory::Known(
            registered
                .into_iter()
                .map(|metadata| PluginCoverage {
                    coverage: crate::coverage_for(metadata.plugin_id.as_str()).unwrap_or_default(),
                    metadata,
                })
                .collect(),
        ),
        Err(error) => PluginInventory::Unavailable(error.to_string()),
    }
}
