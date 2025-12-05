//! Compliance report data structures.
//!
//! Re-exports report types from `hardener-types` and provides helper implementations.

// Re-export all report types from hardener-types
pub use hardener_types::{ComplianceReport, ComplianceSummary, ControlResult};

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use super::*;
    use hardener_types::{ComplianceFramework, ControlStatus};

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
