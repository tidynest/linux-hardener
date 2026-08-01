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
mod tests;
