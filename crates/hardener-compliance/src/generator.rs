//! Report generation from scan findings.
//!
//! The ReportGenerator takes scan findings and the engine's automated-coverage
//! set and produces compliance reports by mapping findings to framework controls.

use crate::config::ReportConfig;
use crate::frameworks;
use crate::profiles;
use crate::report::{ComplianceReport, ComplianceSummary, ControlResult};
use crate::scan_evidence;
use chrono::Utc;
use hardener_common::types::{ComplianceFramework, ComplianceMapping, ControlStatus};
use hardener_core::config::scope::{ComplianceConfig, ScopeExclusion};
use hardener_core::plugin::{Finding, UncheckedCheck};
use hardener_types::{ExceptionOutcome, PluginId, PluginInventory, ScanResult};
use std::collections::{HashMap, HashSet};

/// Generates compliance reports from scan findings.
pub struct ReportGenerator {
    config: ReportConfig,
    /// Every `(framework, control)` the engine actually assesses. A control
    /// present here can report `Pass`/`Fail`; one absent is `ManualReview`.
    ///
    /// Derived from `inventory` at construction rather than injected beside it.
    /// The two used to arrive as separate parameters, which let a caller pass a
    /// union that did not match the plugins it also passed.
    coverage: Vec<ComplianceMapping>,
    /// The plugins this report is scored against, kept so [`Self::generate`]
    /// can tell which of them produced no evidence.
    inventory: PluginInventory,
    /// The operator's declared-not-applicable set, from the controller's
    /// `[compliance]` config section.
    exclusions: ComplianceConfig,
    /// The host this report is about, as `(target, hostname, name)`: the
    /// canonical `RemoteHostProfile::target()`, the bare hostname and the
    /// inventory display name, which are the spellings
    /// [`ScopeExclusion::covers_host`] matches against.
    ///
    /// `None` is the local host. It matches an untargeted exclusion and never
    /// matches a targeted one, so naming hosts cannot change the controller's
    /// own report by accident.
    host: Option<(String, String, String)>,
}

impl ReportGenerator {
    /// Creates a new ReportGenerator.
    ///
    /// `inventory` is every plugin this build registers, with the coverage each
    /// declares. Callers obtain it from `hardener_plugins::plugin_inventory()`;
    /// the compliance crate stays independent of the plugins crate by taking it
    /// as a parameter.
    ///
    /// It replaced a plain `coverage: Vec<ComplianceMapping>` union, because
    /// [`Self::generate`] needs to name the plugins that produced no evidence
    /// and a union cannot say who is missing. The union is still what the
    /// assessed set is built from, derived here so the two cannot disagree.
    ///
    /// `exclusions` is the operator's declared-not-applicable set, from the
    /// controller's `[compliance]` config section. Taken as a parameter for the
    /// same reason `coverage` is: the compliance crate does not reach out for
    /// its inputs.
    ///
    /// An exclusion is inert for the eight frameworks with no curated
    /// catalogue. Their catalogue *is* `coverage`, so every control they list
    /// is one the engine assesses, and the assessed arm decides it one arm
    /// above the exclusion arm. Only CIS and ISO 27001, the two curated
    /// catalogues, list controls no plugin covers, and so only those two have
    /// anything for a declaration to convert.
    pub fn new(
        config: ReportConfig,
        inventory: PluginInventory,
        exclusions: ComplianceConfig,
    ) -> Self {
        Self {
            config,
            coverage: inventory.assessed_controls(),
            inventory,
            exclusions,
            host: None,
        }
    }

    /// Names the host this report is about, so host-targeted exclusions
    /// resolve. `target` is the canonical `RemoteHostProfile::target()`,
    /// `hostname` the bare hostname and `name` the inventory display name.
    ///
    /// A setter rather than a fourth `new` parameter because every caller
    /// outside the fleet path reports on the local host and would pass the
    /// same three empty strings. Leaving it unset is the local host, so those
    /// call sites stay unchanged and the fleet path says what it is doing.
    pub fn for_host(mut self, target: String, hostname: String, name: String) -> Self {
        self.host = Some((target, hostname, name));
        self
    }

    /// Generates compliance reports for all frameworks in the configured scenario.
    ///
    /// `results` are the per-plugin scan results as they came back, not a
    /// flattened pair. **That is the point of the signature.** A control with
    /// no finding against it and no unchecked entry beside it passes, so a
    /// plugin that contributed nothing passes every control it covers unless
    /// something stands in for it. That standing-in used to happen in front of
    /// this call, in `hardener_plugins::scan_outcome`, and every caller had to
    /// remember to go through it; on 2026-08-22 the desktop's fleet path did
    /// not, and a row scanned with one plugin reported the same 38 passing CIS
    /// controls as a row scanned with all eight. Taking raw results leaves a
    /// new caller nothing to hand-flatten.
    ///
    /// `skipped` names plugins the operator's config disabled. A caller
    /// reading a persisted session passes none: a stored session records only
    /// what ran, so absence is the only signal there is, and every reason for
    /// it means the same thing to a report.
    ///
    /// Returns one report per framework.
    pub fn generate(&self, results: &[ScanResult], skipped: &[PluginId]) -> Vec<ComplianceReport> {
        let (findings, unchecked) = scan_evidence::flatten(&self.inventory, results, skipped);
        self.score(&findings, &unchecked)
    }

    /// Scores one already-flattened pair.
    ///
    /// Private, so the flatten above is the only way in. It is separate from
    /// [`Self::generate`] because the scoring is what the framework tests
    /// exercise and they have no plugins to build results from.
    fn score(&self, findings: &[Finding], unchecked: &[UncheckedCheck]) -> Vec<ComplianceReport> {
        // Rewrite every mapping list once for the active profile so findings,
        // coverage, and catalogue all match on one identifier scheme. These
        // are report-internal copies; the caller's findings stay canonical.
        let profile = self.config.profile;
        let findings: Vec<Finding> = findings
            .iter()
            .map(|finding| Finding {
                finding_compliance: profiles::translate_all(profile, &finding.finding_compliance),
                ..finding.clone()
            })
            .collect();
        let unchecked: Vec<UncheckedCheck> = unchecked
            .iter()
            .map(|check| UncheckedCheck {
                unchecked_compliance: profiles::translate_all(profile, &check.unchecked_compliance),
                ..check.clone()
            })
            .collect();
        let coverage = profiles::translate_all(profile, &self.coverage);

        self.config
            .scenario
            .frameworks()
            .iter()
            .map(|framework| {
                self.generate_for_framework(framework, &findings, &unchecked, &coverage)
            })
            .collect()
    }

    /// Whether `exclusion` covers the host this report is about.
    ///
    /// With no host named the report is about the local system, and only an
    /// untargeted exclusion covers it: a declaration made about named remote
    /// hosts must never raise the controller's own score.
    fn covers_this_host(&self, exclusion: &ScopeExclusion) -> bool {
        match &self.host {
            Some((target, hostname, name)) => exclusion.covers_host(target, hostname, name),
            None => exclusion.hosts.is_empty(),
        }
    }

    /// Generates a compliance report for a single framework from
    /// profile-translated findings, unchecked checks, and coverage.
    fn generate_for_framework(
        &self,
        framework: &ComplianceFramework,
        findings: &[Finding],
        unchecked: &[UncheckedCheck],
        coverage: &[ComplianceMapping],
    ) -> ComplianceReport {
        // Controls the engine assesses for this framework, from plugin coverage.
        let assessed: HashSet<&str> = coverage
            .iter()
            .filter(|m| m.compliance_framework == *framework)
            .map(|m| m.compliance_control_id.as_str())
            .collect();

        // Controls whose covering check could not run at the current privilege
        // level: the absence of a finding proves nothing for these, so they
        // must never auto-pass.
        let unchecked_ids: HashSet<&str> = unchecked
            .iter()
            .flat_map(|u| &u.unchecked_compliance)
            .filter(|m| m.compliance_framework == *framework)
            .map(|m| m.compliance_control_id.as_str())
            .collect();

        // Build the control catalogue: the curated standard (CIS / ISO 27001),
        // if any (itself profile-translated), merged with the derived coverage
        // set and deduplicated by id. For frameworks without a curated catalogue
        // the result *is* the coverage set, so every listed control is assessed
        // and reports `Pass`/`Fail`.
        let curated = frameworks::curated_controls(framework).unwrap_or_default();
        let mut catalogue: Vec<ComplianceMapping> = Vec::new();
        let mut catalogue_ids: HashSet<String> = HashSet::new();
        for mapping in profiles::translate_all(self.config.profile, &curated)
            .into_iter()
            .chain(
                coverage
                    .iter()
                    .filter(|m| m.compliance_framework == *framework)
                    .cloned(),
            )
        {
            if catalogue_ids.insert(mapping.compliance_control_id.clone()) {
                catalogue.push(mapping);
            }
        }

        // The operator's declared-not-applicable set for this framework, and the
        // day each exclusion's review deadline is measured against. Resolved
        // once rather than per control.
        //
        // Config keys are normalised through `ComplianceFramework::from_id`,
        // which is what every other parser in this tool accepts, so a
        // hand-written `[compliance.not_applicable.CIS]` or `.nist-800-171`
        // resolves rather than being silently inert. A key naming no known
        // framework resolves to nothing and stays inert, which is the existing
        // fail-closed behaviour: there is no interval to measure its review
        // deadline against, and this mechanism only ever raises a score.
        //
        // Every key that resolves to this framework contributes, rather than an
        // arbitrary first match, so two spellings of one framework in the same
        // file do not make the result depend on hash order.
        let today = Utc::now().date_naive();
        let framework_id = framework.id();
        let excluded: HashMap<&str, &ScopeExclusion> = self
            .exclusions
            .not_applicable
            .iter()
            .filter(|(key, _)| ComplianceFramework::from_id(key) == Some(*framework))
            .flat_map(|(_, controls)| controls.iter().map(|(id, e)| (id.as_str(), e)))
            .collect();

        // Map each control to a result. A mapped finding always fails the control,
        // even one the check could not evaluate this run: Fail still wins over
        // unchecked. With no finding, an unchecked control cannot auto-pass
        // either; only a control the engine both assesses and could actually
        // evaluate this run passes on the mere absence of a finding.
        //
        // Arm order is load-bearing and is the feature's security property.
        // `assessed` sits above the exclusion arm, so a plugin gaining coverage
        // for an excluded control supersedes the declaration on the next scan
        // rather than at its review date. Six of the ten frameworks state a
        // change trigger and no interval, so this is the mechanism they name;
        // the review date is the backstop for changes the tool cannot see.
        let mut controls: Vec<ControlResult> = catalogue
            .iter()
            .map(|control| {
                let related = related_findings(findings, framework, &control.compliance_control_id);
                let status = if has_live_finding(&related) {
                    ControlStatus::Fail
                } else if unchecked_ids.contains(control.compliance_control_id.as_str()) {
                    ControlStatus::ManualReview
                } else if assessed.contains(control.compliance_control_id.as_str()) {
                    ControlStatus::Pass
                } else if let Some(exclusion) = excluded.get(control.compliance_control_id.as_str())
                    && exclusion.is_valid_on(framework_id, today)
                    && self.covers_this_host(exclusion)
                {
                    // Last arm on purpose. A live finding, an unchecked control
                    // and an assessed control are all decided above, so this can
                    // only ever convert a ManualReview. An exclusion is never a
                    // way to mute a failure. The host gate is one more condition
                    // on this arm, never a way around the three above it.
                    //
                    // The unchecked arm sitting above this one means a control
                    // whose check could not run this session stays ManualReview
                    // even when excluded. That is deliberate and conservative:
                    // privilege is a property of the run, not of applicability.
                    ControlStatus::NotApplicable
                } else {
                    ControlStatus::ManualReview
                };
                ControlResult {
                    control_id: control.compliance_control_id.clone(),
                    control_title: control.compliance_control_title.clone(),
                    control_section: control
                        .compliance_section
                        .clone()
                        .unwrap_or_else(|| "General".to_string()),
                    control_status: status,
                    control_findings: related,
                }
            })
            .collect();

        // Safe-failure net: a finding referencing a control absent from the
        // catalogue is still a real failure and must appear in the report rather
        // than be silently dropped. (With derived catalogues this is rarely hit,
        // but it guarantees a wrong mapping can only ever over-report a failure.)
        // If every finding mapped to this control turns out to be excepted,
        // there is no live violation left to surface, so the control is skipped
        // entirely rather than manufactured as a Fail backed only by documented
        // deviations.
        let mut seen: HashSet<String> = controls.iter().map(|c| c.control_id.clone()).collect();
        for mapping in findings.iter().flat_map(|f| &f.finding_compliance) {
            if mapping.compliance_framework != *framework
                || !seen.insert(mapping.compliance_control_id.clone())
            {
                continue;
            }
            let related = related_findings(findings, framework, &mapping.compliance_control_id);
            if !has_live_finding(&related) {
                continue;
            }
            controls.push(ControlResult {
                control_id: mapping.compliance_control_id.clone(),
                control_title: mapping.compliance_control_title.clone(),
                control_section: mapping
                    .compliance_section
                    .clone()
                    .unwrap_or_else(|| "General".to_string()),
                control_status: ControlStatus::Fail,
                control_findings: related,
            });
        }

        let summary = ComplianceSummary::from_controls(&controls);

        ComplianceReport {
            report_framework: *framework,
            report_profile: self.config.profile,
            report_generated_at: Utc::now(),
            report_controls: controls,
            report_summary: summary,
            // Every unchecked entry, not only those mapping a control in this
            // framework: the sentence describes the scan, and the scan is the
            // same one whichever framework is being rendered from it. Narrowing
            // it per framework would make the same run report different
            // coverage depending on which report you asked for.
            report_coverage_note: hardener_types::unchecked_summary(unchecked),
        }
    }
}

/// Collects every finding mapping to a given `(framework, control_id)`,
/// excepted ones included. Status is decided from the live subset via
/// [`has_live_finding`], but an excepted finding stays in the list so the
/// report shows the documented deviation instead of an unexplained clean pass.
fn related_findings(
    findings: &[Finding],
    framework: &ComplianceFramework,
    control_id: &str,
) -> Vec<Finding> {
    findings
        .iter()
        .filter(|f| {
            f.finding_compliance.iter().any(|c| {
                c.compliance_framework == *framework && c.compliance_control_id == control_id
            })
        })
        .cloned()
        .collect()
}

/// Whether any of these findings is still a live violation. Only a finding
/// whose exception outcome is `Applied` (validated by `Plugin::scan` against
/// the config) is a documented deviation, not a failure; `NotConfigured` and
/// `Declined` are both live and drive a control to Fail.
fn has_live_finding(findings: &[Finding]) -> bool {
    findings
        .iter()
        .any(|f| !matches!(f.finding_exception, ExceptionOutcome::Applied(_)))
}

#[cfg(test)]
mod tests;
