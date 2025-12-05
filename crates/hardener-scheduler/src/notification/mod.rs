//! Notification system for scan results.
//!
//! Provides email and webhook notifications after scheduled scans complete.
//! Notifications are filtered by severity threshold before dispatch.

pub mod dispatcher;
pub mod email;
pub mod webhook;

use crate::runner::ScanSummary;
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
            summary.critical_count > 0
                || summary.high_count > 0
                || summary.medium_count > 0
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::ScanSummary;

    /// Creates a test summary with specified severity counts.
    fn make_summary(critical: usize, high: usize, medium: usize, low: usize)
                    -> ScanSummary {
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
        assert!(meets_severity_threshold(&make_summary(1, 0, 0, 0), Severity::Critical));
        assert!(!meets_severity_threshold(&make_summary(0, 5, 0, 0), Severity::Critical));
        assert!(!meets_severity_threshold(&make_summary(0, 0, 10, 0), Severity::Critical));
    }

    #[test]
    fn threshold_high_accepts_critical_or_high() {
        assert!(meets_severity_threshold(&make_summary(1, 0, 0, 0), Severity::High));
        assert!(meets_severity_threshold(&make_summary(0, 1, 0, 0), Severity::High));
        assert!(!meets_severity_threshold(&make_summary(0, 0, 10, 0), Severity::High));
    }

    #[test]
    fn threshold_medium_accepts_critical_high_medium() {
        assert!(meets_severity_threshold(&make_summary(1, 0, 0, 0), Severity::Medium));
        assert!(meets_severity_threshold(&make_summary(0, 1, 0, 0), Severity::Medium));
        assert!(meets_severity_threshold(&make_summary(0, 0, 1, 0), Severity::Medium));
        assert!(!meets_severity_threshold(&make_summary(0, 0, 0, 5), Severity::Medium));
    }

    #[test]
    fn threshold_low_accepts_all_except_info() {
        assert!(meets_severity_threshold(&make_summary(1, 0, 0, 0), Severity::Low));
        assert!(meets_severity_threshold(&make_summary(0, 1, 0, 0), Severity::Low));
        assert!(meets_severity_threshold(&make_summary(0, 0, 1, 0), Severity::Low));
        assert!(meets_severity_threshold(&make_summary(0, 0, 0, 1), Severity::Low));
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
}
