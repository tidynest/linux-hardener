//! Notification system for scan results.
//!
//! Provides email and webhook notifications after scheduled scans complete.
//! Notifications are filtered by severity threshold before dispatch.

pub mod dispatcher;
pub mod email;
pub mod webhook;

use crate::config::NotifyMode;
use crate::db::{ScanSession, above_floor, is_worse};
use crate::runner::{RegressionInfo, ScanSummary};
use async_trait::async_trait;
use hardener_common::types::Severity;

/// Result of a notification attempt.
#[derive(Clone, Debug)]
pub struct NotificationResult {
    /// Channel identifier (e.g., "email", "webhook:slack").
    pub channel: String,
    /// Whether the notification was sent successfully.
    pub success: bool,
    /// Error message if failed.
    pub error: Option<String>,
}

impl NotificationResult {
    /// Creates a successful result.
    pub fn ok(channel: impl Into<String>) -> Self {
        Self {
            channel: channel.into(),
            success: true,
            error: None,
        }
    }

    /// Creates a failed result.
    pub fn failed(channel: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            channel: channel.into(),
            success: false,
            error: Some(error.into()),
        }
    }
}

/// Trait for notification channels.
///
/// Implemented by `EmailNotifier` and `WebhookNotifier` to provide
/// a uniform interface for sending scan result notifications.
#[async_trait]
pub trait Notifier: Send + Sync {
    /// Sends a notification with the scan summary.
    ///
    /// Returns a result indicating success or failure for logging purposes.
    /// Implementations should not panic; errors are captured in the result.
    async fn send(&self, summary: &ScanSummary) -> NotificationResult;

    /// Returns the channel identifier for logging.
    fn channel(&self) -> &str;
}

/// Parses a severity string to the enum, defaulting to Medium.
pub fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        "info" => Severity::Info,
        _ => Severity::Medium,
    }
}

/// Checks if a scan summary meets the minimum severity threshold.
///
/// Returns `true` if any findings severity is >= the threshold.
pub fn meets_severity_threshold(summary: &ScanSummary, min_severity: Severity) -> bool {
    match min_severity {
        Severity::Critical => summary.critical_count > 0,
        Severity::High => summary.critical_count > 0 || summary.high_count > 0,
        Severity::Medium => {
            summary.critical_count > 0 || summary.high_count > 0 || summary.medium_count > 0
        }
        Severity::Low => {
            summary.critical_count > 0
                || summary.high_count > 0
                || summary.medium_count > 0
                || summary.low_count > 0
        }
        Severity::Info => summary.total_findings > 0,
    }
}

/// Decides whether a completed scan should notify, and whether it is a regression.
///
/// Pure: no IO. `floor` is the already-resolved severity floor (the dispatcher's
/// `min_severity`). `previous` is the host's prior completed scan, if any.
///
/// Returns `(should_send, regression_context)`. A regression at the floor always
/// also satisfies the absolute threshold, so `Both` never double-sends.
pub fn alert_decision(
    mode: NotifyMode,
    floor: Severity,
    previous: Option<&ScanSession>,
    current: &ScanSummary,
) -> (bool, Option<RegressionInfo>) {
    let absolute = matches!(mode, NotifyMode::Findings | NotifyMode::Both)
        && meets_severity_threshold(current, floor);

    let regressed = matches!(mode, NotifyMode::Regression | NotifyMode::Both)
        && previous.is_some_and(|p| {
            is_worse(
                above_floor(p.severity_tuple(), floor),
                above_floor(current.severity_tuple(), floor),
            )
        });

    let info = if regressed {
        previous.map(|p| RegressionInfo::new(p, current))
    } else {
        None
    };

    (absolute || regressed, info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::ScanSummary;

    /// Creates a test summary with specified severity counts.
    fn make_summary(critical: usize, high: usize, medium: usize, low: usize) -> ScanSummary {
        ScanSummary {
            session_id: "test-session".to_string(),
            host: "testhost".to_string(),
            plugins_scanned: vec!["kernel".to_string()],
            total_findings: critical + high + medium + low,
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            low_count: low,
            info_count: 0,
            json_path: None,
            json_hash: None,
            had_errors: false,
            regression: None,
        }
    }

    #[test]
    fn notification_result_ok() {
        let result = NotificationResult::ok("email");
        assert!(result.success);
        assert_eq!(result.channel, "email");
        assert!(result.error.is_none());
    }

    #[test]
    fn notification_result_failed() {
        let result = NotificationResult::failed("webhook:slack", "Connection timeout");
        assert!(!result.success);
        assert_eq!(result.channel, "webhook:slack");
        assert_eq!(result.error, Some("Connection timeout".to_string()));
    }

    #[test]
    fn parse_severity_all_levels() {
        assert_eq!(parse_severity("critical"), Severity::Critical);
        assert_eq!(parse_severity("CRITICAL"), Severity::Critical);
        assert_eq!(parse_severity("high"), Severity::High);
        assert_eq!(parse_severity("HIGH"), Severity::High);
        assert_eq!(parse_severity("medium"), Severity::Medium);
        assert_eq!(parse_severity("MEDIUM"), Severity::Medium);
        assert_eq!(parse_severity("low"), Severity::Low);
        assert_eq!(parse_severity("LOW"), Severity::Low);
        assert_eq!(parse_severity("info"), Severity::Info);
        assert_eq!(parse_severity("INFO"), Severity::Info);
    }

    #[test]
    fn parse_severity_unknown_defaults_medium() {
        assert_eq!(parse_severity("unknown"), Severity::Medium);
        assert_eq!(parse_severity(""), Severity::Medium);
        assert_eq!(parse_severity("invalid"), Severity::Medium);
    }

    #[test]
    fn threshold_critical_requires_critical() {
        assert!(meets_severity_threshold(
            &make_summary(1, 0, 0, 0),
            Severity::Critical
        ));
        assert!(!meets_severity_threshold(
            &make_summary(0, 5, 0, 0),
            Severity::Critical
        ));
        assert!(!meets_severity_threshold(
            &make_summary(0, 0, 10, 0),
            Severity::Critical
        ));
    }

    #[test]
    fn threshold_high_accepts_critical_or_high() {
        assert!(meets_severity_threshold(
            &make_summary(1, 0, 0, 0),
            Severity::High
        ));
        assert!(meets_severity_threshold(
            &make_summary(0, 1, 0, 0),
            Severity::High
        ));
        assert!(!meets_severity_threshold(
            &make_summary(0, 0, 10, 0),
            Severity::High
        ));
    }

    #[test]
    fn threshold_medium_accepts_critical_high_medium() {
        assert!(meets_severity_threshold(
            &make_summary(1, 0, 0, 0),
            Severity::Medium
        ));
        assert!(meets_severity_threshold(
            &make_summary(0, 1, 0, 0),
            Severity::Medium
        ));
        assert!(meets_severity_threshold(
            &make_summary(0, 0, 1, 0),
            Severity::Medium
        ));
        assert!(!meets_severity_threshold(
            &make_summary(0, 0, 0, 5),
            Severity::Medium
        ));
    }

    #[test]
    fn threshold_low_accepts_all_except_info() {
        assert!(meets_severity_threshold(
            &make_summary(1, 0, 0, 0),
            Severity::Low
        ));
        assert!(meets_severity_threshold(
            &make_summary(0, 1, 0, 0),
            Severity::Low
        ));
        assert!(meets_severity_threshold(
            &make_summary(0, 0, 1, 0),
            Severity::Low
        ));
        assert!(meets_severity_threshold(
            &make_summary(0, 0, 0, 1),
            Severity::Low
        ));
    }

    #[test]
    fn threshold_info_accepts_any_findings() {
        let mut summary = make_summary(0, 0, 0, 0);
        summary.info_count = 1;
        summary.total_findings = 1;
        assert!(meets_severity_threshold(&summary, Severity::Info));
    }

    #[test]
    fn threshold_no_findings_never_triggers() {
        let empty = make_summary(0, 0, 0, 0);
        assert!(!meets_severity_threshold(&empty, Severity::Critical));
        assert!(!meets_severity_threshold(&empty, Severity::High));
        assert!(!meets_severity_threshold(&empty, Severity::Medium));
        assert!(!meets_severity_threshold(&empty, Severity::Low));
        assert!(!meets_severity_threshold(&empty, Severity::Info));
    }

    use crate::config::NotifyMode;
    use crate::db::ScanSession;

    fn prev_session(critical: i32, high: i32, medium: i32, low: i32) -> ScanSession {
        ScanSession {
            id: "prev".into(),
            started_at: 100,
            completed_at: Some(100),
            status: "completed".into(),
            trigger_type: "schedule".into(),
            host_identifier: "h".into(),
            plugins_scanned: String::new(),
            total_findings: critical + high + medium + low,
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            low_count: low,
            info_count: 0,
            error_message: None,
            json_file_path: None,
            hash: None,
        }
    }

    #[test]
    fn findings_mode_matches_threshold_no_annotation() {
        // Findings mode ignores history: sends iff threshold met, never annotates.
        let prev = prev_session(0, 0, 0, 0);
        let cur = make_summary(1, 0, 0, 0); // 1 critical
        let (send, info) =
            alert_decision(NotifyMode::Findings, Severity::Critical, Some(&prev), &cur);
        assert!(send);
        assert!(info.is_none());

        let clean = make_summary(0, 0, 0, 0);
        let (send, _) = alert_decision(
            NotifyMode::Findings,
            Severity::Critical,
            Some(&prev),
            &clean,
        );
        assert!(!send);
    }

    #[test]
    fn regression_mode_quiet_until_worse() {
        let prev = prev_session(1, 0, 0, 0); // already 1 critical
        // Same posture: no alert even though threshold is met.
        let same = make_summary(1, 0, 0, 0);
        let (send, _) = alert_decision(
            NotifyMode::Regression,
            Severity::Critical,
            Some(&prev),
            &same,
        );
        assert!(!send);

        // Worse: a new critical -> alert + annotation.
        let worse = make_summary(2, 0, 0, 0);
        let (send, info) = alert_decision(
            NotifyMode::Regression,
            Severity::Critical,
            Some(&prev),
            &worse,
        );
        assert!(send);
        let info = info.expect("regression annotated");
        assert_eq!(info.delta_critical, 1);
    }

    #[test]
    fn regression_first_scan_never_alerts() {
        let cur = make_summary(5, 0, 0, 0);
        let (send, _) = alert_decision(NotifyMode::Regression, Severity::Critical, None, &cur);
        assert!(!send);
    }

    #[test]
    fn regression_respects_floor() {
        let prev = prev_session(0, 0, 0, 3); // 3 low
        let cur = make_summary(0, 0, 0, 5); // 5 low, worse only at Low level
        // Floor High: low changes are below the floor -> not a regression.
        let (send, _) = alert_decision(NotifyMode::Regression, Severity::High, Some(&prev), &cur);
        assert!(!send);
        // Floor Low: counts -> regression.
        let (send, info) = alert_decision(NotifyMode::Regression, Severity::Low, Some(&prev), &cur);
        assert!(send);
        assert_eq!(info.unwrap().delta_low, 2);
    }

    #[test]
    fn both_mode_alerts_and_annotates_on_regression() {
        let prev = prev_session(1, 0, 0, 0);
        let worse = make_summary(2, 0, 0, 0);
        let (send, info) =
            alert_decision(NotifyMode::Both, Severity::Critical, Some(&prev), &worse);
        assert!(send);
        assert!(info.is_some());
    }

    #[test]
    fn both_mode_absolute_without_previous() {
        // Both mode, first scan with findings at/above the floor: sends, not annotated.
        let cur = make_summary(1, 0, 0, 0);
        let (send, info) = alert_decision(NotifyMode::Both, Severity::Critical, None, &cur);
        assert!(send);
        assert!(info.is_none());
    }
}
