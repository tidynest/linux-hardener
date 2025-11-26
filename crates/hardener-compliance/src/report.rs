//! Compliance report data structures.
//!
//! Defines the report structure, control results, and summary statistics.

use chrono::{DateTime, Utc};
use hardener_common::types::{ComplianceFramework, ControlStatus};
use hardener_core::plugin::Finding;
use serde::{Deserialize, Serialize};

/// A complete compliance report for a single framework.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ComplianceReport {
    /// The compliance framework this report covers.
    pub report_framework: ComplianceFramework,
    /// When this report was generated.
    pub report_generated_at: DateTime<Utc>,
    /// Individual control check results.
    pub report_controls: Vec<ControlResult>,
    /// Summary statistics for the report.
    pub report_summary: ComplianceSummary,
}

/// Result of checking a single compliance control.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ControlResult {
    /// The control identifier (e.g., "1.5.1" for CIS).
    pub control_id: String,
    /// Human-readable title of the control.
    pub control_title: String,
    /// Section/category within the framework.
    pub control_section: String,
    /// Whether the control passed or failed.
    pub control_status: ControlStatus,
    /// Findings that caused this control to fail (empty if passed).
    pub control_findings: Vec<Finding>,
}

/// Summary statistics for a compliance report.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ComplianceSummary {
    /// Total number of controls checked.
    pub summary_total_controls: usize,
    /// Number of controls that passed.
    pub summary_passing: usize,
    /// Number of controls that failed.
    pub summary_failing: usize,
    /// Number of controls requiring manual review.
    pub summary_manual_review: usize,
    /// Number of controls not applicable to this system.
    pub summary_not_applicable: usize,
    /// Overall compliance score as s percentage.
    pub summary_score_percentage: f64,
}

impl ComplianceSummary {
    /// Creates a new summary by calculating statistics from control results.
    pub fn from_controls(controls: &[ControlResult]) -> ComplianceSummary {
        let total = controls.len();
        let passing = controls
            .iter()
            .filter(|c| c.control_status == ControlStatus::Pass)
            .count();
        let failing = controls
            .iter()
            .filter(|c| c.control_status == ControlStatus::Fail)
            .count();
        let not_applicable = controls
            .iter()
            .filter(|c| c.control_status == ControlStatus::NotApplicable)
            .count();
        let manual_review = controls
            .iter()
            .filter(|c| c.control_status == ControlStatus::ManualReview)
            .count();

        let applicable = total.saturating_sub(not_applicable);
        let score = if applicable > 0 {
            (passing as f64 / applicable as f64) * 100.0
        } else {
            100.0
        };

        Self {
            summary_total_controls: total,
            summary_passing: passing,
            summary_failing: failing,
            summary_manual_review: manual_review,
            summary_not_applicable: not_applicable,
            summary_score_percentage: score,
        }
    }
}
