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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_control(id: &str, status: ControlStatus) -> ControlResult {
        ControlResult {
            control_id: id.to_string(),
            control_title: format!("Test control {}", id),
            control_section: "Test Section".to_string(),
            control_status: status,
            control_findings: vec![],
        }
    }

    #[test]
    fn test_summary_from_controls_all_passing() {
        let controls = vec![
            make_control("1.1", ControlStatus::Pass),
            make_control("1.2", ControlStatus::Pass),
            make_control("1.3", ControlStatus::Pass),
        ];

        let summary = ComplianceSummary::from_controls(&controls);

        assert_eq!(summary.summary_total_controls, 3);
        assert_eq!(summary.summary_passing, 3);
        assert_eq!(summary.summary_failing, 0);
        assert_eq!(summary.summary_not_applicable, 0);
        assert_eq!(summary.summary_manual_review, 0);
        assert!((summary.summary_score_percentage - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_summary_from_controls_all_failing() {
        let controls = vec![
            make_control("1.1", ControlStatus::Fail),
            make_control("1.2", ControlStatus::Fail),
        ];

        let summary = ComplianceSummary::from_controls(&controls);

        assert_eq!(summary.summary_total_controls, 2);
        assert_eq!(summary.summary_passing, 0);
        assert_eq!(summary.summary_failing, 2);
        assert!((summary.summary_score_percentage - 0.0).abs() < 0.01);
    }

    #[test]
    fn test_summary_from_controls_mixed() {
        let controls = vec![
            make_control("1.1", ControlStatus::Pass),
            make_control("1.2", ControlStatus::Fail),
            make_control("1.3", ControlStatus::Pass),
            make_control("1.4", ControlStatus::Fail),
        ];

        let summary = ComplianceSummary::from_controls(&controls);

        assert_eq!(summary.summary_total_controls, 4);
        assert_eq!(summary.summary_passing, 2);
        assert_eq!(summary.summary_failing, 2);
        assert!((summary.summary_score_percentage - 50.0).abs() < 0.01);
    }

    #[test]
    fn test_summary_from_controls_with_na() {
        let controls = vec![
            make_control("1.1", ControlStatus::Pass),
            make_control("1.2", ControlStatus::NotApplicable),
            make_control("1.3", ControlStatus::NotApplicable),
        ];

        let summary = ComplianceSummary::from_controls(&controls);

        assert_eq!(summary.summary_total_controls, 3);
        assert_eq!(summary.summary_passing, 1);
        assert_eq!(summary.summary_not_applicable, 2);
        // Score based on applicable controls only (1 passing out of 1 applicable = 100%)
        assert!((summary.summary_score_percentage - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_summary_from_controls_with_manual_review() {
        let controls = vec![
            make_control("1.1", ControlStatus::Pass),
            make_control("1.2", ControlStatus::ManualReview),
        ];

        let summary = ComplianceSummary::from_controls(&controls);

        assert_eq!(summary.summary_total_controls, 2);
        assert_eq!(summary.summary_passing, 1);
        assert_eq!(summary.summary_manual_review, 1);
    }

    #[test]
    fn test_summary_from_controls_empty() {
        let controls: Vec<ControlResult> = vec![];

        let summary = ComplianceSummary::from_controls(&controls);

        assert_eq!(summary.summary_total_controls, 0);
        assert_eq!(summary.summary_passing, 0);
        assert_eq!(summary.summary_failing, 0);
        // Empty controls should return 100% (no failures)
        assert!((summary.summary_score_percentage - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_summary_from_controls_all_na() {
        let controls = vec![
            make_control("1.1", ControlStatus::NotApplicable),
            make_control("1.2", ControlStatus::NotApplicable),
        ];

        let summary = ComplianceSummary::from_controls(&controls);

        assert_eq!(summary.summary_total_controls, 2);
        assert_eq!(summary.summary_not_applicable, 2);
        // All N/A should return 100% (no applicable controls to fail)
        assert!((summary.summary_score_percentage - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_compliance_report_serialization() {
        let report = ComplianceReport {
            report_framework: ComplianceFramework::CIS,
            report_generated_at: Utc::now(),
            report_controls: vec![make_control("1.1", ControlStatus::Pass)],
            report_summary: ComplianceSummary {
                summary_total_controls: 1,
                summary_passing: 1,
                summary_failing: 0,
                summary_not_applicable: 0,
                summary_manual_review: 0,
                summary_score_percentage: 100.0,
            },
        };

        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("CIS"));
        assert!(json.contains("1.1"));

        // Verify round-trip
        let deserialized: ComplianceReport = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.report_framework, ComplianceFramework::CIS);
        assert_eq!(deserialized.report_controls.len(), 1);
    }

    #[test]
    fn test_control_result_serialization() {
        let control = make_control("1.5.1", ControlStatus::Fail);

        let json = serde_json::to_string(&control).unwrap();
        assert!(json.contains("1.5.1"));
        assert!(json.contains("Fail"));

        let deserialized: ControlResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.control_id, "1.5.1");
        assert_eq!(deserialized.control_status, ControlStatus::Fail);
    }
}
