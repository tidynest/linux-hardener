//! Report generation from scan findings.
//!
//! The ReportGenerator takes scan findings and the engine's automated-coverage
//! set and produces compliance reports by mapping findings to framework controls.

use crate::config::ReportConfig;
use crate::frameworks;
use crate::profiles;
use crate::report::{ComplianceReport, ComplianceSummary, ControlResult};
use chrono::Utc;
use hardener_common::types::{ComplianceFramework, ComplianceMapping, ControlStatus};
use hardener_core::plugin::{Finding, UncheckedCheck};
use std::collections::HashSet;

/// Generates compliance reports from scan findings.
pub struct ReportGenerator {
    config: ReportConfig,
    /// Every `(framework, control)` the engine actually assesses, supplied by the
    /// caller (the plugins crate's `compliance_coverage()`). A control present
    /// here can report `Pass`/`Fail`; one absent is `ManualReview`.
    coverage: Vec<ComplianceMapping>,
}

impl ReportGenerator {
    /// Creates a new ReportGenerator.
    ///
    /// `coverage` is the engine's automated-coverage set: the union of every
    /// control any plugin can assess. Callers obtain it from
    /// `hardener_plugins::compliance_coverage()`; the compliance crate stays
    /// independent of the plugins crate by taking it as a parameter.
    pub fn new(config: ReportConfig, coverage: Vec<ComplianceMapping>) -> Self {
        Self { config, coverage }
    }

    /// Generates compliance reports for all frameworks in the configured scenario.
    ///
    /// `unchecked` lists checks the scan could not evaluate at its current
    /// privilege level; the controls they cover must never auto-pass on the
    /// mere absence of a finding.
    ///
    /// Returns one report per framework.
    pub fn generate(
        &self,
        findings: &[Finding],
        unchecked: &[UncheckedCheck],
    ) -> Vec<ComplianceReport> {
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

        // Map each control to a result. A mapped finding always fails the control,
        // even one the check could not evaluate this run: Fail still wins over
        // unchecked. With no finding, an unchecked control cannot auto-pass
        // either; only a control the engine both assesses and could actually
        // evaluate this run passes on the mere absence of a finding.
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

/// Whether any of these findings is still a live violation. A finding carrying
/// a policy exception (validated by `Plugin::scan` against the config) is a
/// documented deviation, not a failure, so it never drives a control to Fail.
fn has_live_finding(findings: &[Finding]) -> bool {
    findings
        .iter()
        .any(|f| f.finding_policy_exception.is_none())
}

#[cfg(test)]
mod tests;
