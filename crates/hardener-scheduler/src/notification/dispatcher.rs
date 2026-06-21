//! Notification dispatcher for coordinating all channels
//!
//! Manages email and webhook notifiers, applies severity filtering,
//! and logs all notification attempts to the database.

use super::{
    NotificationResult, Notifier, email::EmailNotifier, parse_severity, webhook::WebhookNotifier,
};
use crate::config::NotificationConfig;
use crate::db::ScanHistoryManager;
use crate::runner::ScanSummary;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Dispatches notifications to all configured channels.
pub struct NotificationDispatcher {
    /// All active notifiers.
    notifiers: Vec<Box<dyn Notifier>>,
    /// Minimum severity to trigger notifications.
    min_severity: hardener_common::types::Severity,
    /// Database for logging attempts.
    db: Arc<ScanHistoryManager>,
    /// Active notification trigger mode.
    mode: crate::config::NotifyMode,
}

impl NotificationDispatcher {
    /// Creates a dispatcher from notification configuration.
    ///
    /// Initialises all enabled channels (email, webhooks).
    /// Channels that fail to initialise are skipped with a warning.
    pub fn new(config: &NotificationConfig, db: Arc<ScanHistoryManager>) -> Self {
        let mut notifiers: Vec<Box<dyn Notifier>> = Vec::new();

        // Add email notifier if configured
        if let Some(email) = EmailNotifier::new(&config.email) {
            debug!("Email notifier enabled");
            notifiers.push(Box::new(email));
        }

        // Add webhook notifiers for each endpoint
        if config.webhooks.enabled {
            for endpoint in &config.webhooks.endpoints {
                if let Some(webhook) = WebhookNotifier::new(endpoint.clone()) {
                    debug!("Webhook '{}' notifier enabled", endpoint.name);
                    notifiers.push(Box::new(webhook));
                }
            }
        }

        let min_severity = if config.notify_min_severity.is_empty() {
            hardener_common::types::Severity::Critical
        } else {
            parse_severity(&config.notify_min_severity)
        };

        info!(
            "Notification dispatcher initialised with {} channel(s), min_severity = {}",
            notifiers.len(),
            min_severity
        );

        Self {
            notifiers,
            min_severity,
            db,
            mode: config.notify_mode,
        }
    }

    /// Dispatches notifications for a completed scan.
    ///
    /// Calls `alert_decision` to decide whether to send and whether the scan
    /// regressed. When a regression is detected, the summary is annotated with
    /// the regression context before being forwarded to each channel.
    ///
    /// `previous` is the host's most recent prior completed session (if any).
    /// Pass `None` when the history lookup was skipped or failed.
    ///
    /// Returns results from all notification attempts (empty when no-send).
    pub async fn dispatch(
        &self,
        summary: &ScanSummary,
        previous: Option<&crate::db::ScanSession>,
    ) -> Vec<NotificationResult> {
        let (send, regression) =
            crate::notification::alert_decision(self.mode, self.min_severity, previous, summary);

        if !send {
            debug!("Skipping notifications: alert_decision returned no-send");
            return Vec::new();
        }

        if self.notifiers.is_empty() {
            debug!("No notifiers configured, skipping dispatch");
            return Vec::new();
        }

        // Rebind summary to an annotated clone only when a regression is present; the non-regression path sends the original with no allocation.
        let annotated;
        let summary = if regression.is_some() {
            annotated = ScanSummary {
                regression,
                ..summary.clone()
            };
            &annotated
        } else {
            summary
        };

        info!(
            "Dispatching notifications for session {} ({} findings, regression={})",
            summary.session_id,
            summary.total_findings,
            summary.regression.is_some()
        );

        let mut results = Vec::with_capacity(self.notifiers.len());
        for notifier in &self.notifiers {
            let result = notifier.send(summary).await;
            let status = if result.success { "sent" } else { "failed" };
            if let Err(e) = self
                .db
                .log_notification(
                    &summary.session_id,
                    &result.channel,
                    status,
                    result.error.as_deref(),
                )
                .await
            {
                warn!("Failed to log notification attempt: {}", e);
            }
            if result.success {
                info!("Notification sent via {}", result.channel);
            } else {
                warn!(
                    "Notification failed via {}: {}",
                    result.channel,
                    result.error.as_deref().unwrap_or("unknown error")
                );
            }
            results.push(result);
        }
        results
    }

    /// Returns the number of configured notifiers.
    pub fn notifier_count(&self) -> usize {
        self.notifiers.len()
    }

    /// Returns true if any notifiers are configured.
    pub fn has_notifiers(&self) -> bool {
        !self.notifiers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{NotificationConfig, NotifyMode};
    use crate::db::ScanHistoryManager;
    use crate::notification::Notifier;
    use crate::runner::ScanSummary;
    use std::sync::Arc;
    use tempfile::tempdir;

    struct MockNotifier;
    #[async_trait::async_trait]
    impl Notifier for MockNotifier {
        async fn send(&self, _summary: &ScanSummary) -> NotificationResult {
            NotificationResult::ok("mock")
        }
        fn channel(&self) -> &str {
            "mock"
        }
    }

    fn summary(critical: usize) -> ScanSummary {
        ScanSummary {
            session_id: "s".into(),
            host: "h".into(),
            plugins_scanned: vec![],
            total_findings: critical,
            critical_count: critical,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            info_count: 0,
            json_path: None,
            json_hash: None,
            had_errors: false,
            regression: None,
        }
    }

    async fn dispatcher_with(mode: NotifyMode) -> NotificationDispatcher {
        let dir = tempdir().unwrap();
        let db = Arc::new(
            ScanHistoryManager::new(&dir.path().join("t.db"))
                .await
                .unwrap(),
        );
        let config = NotificationConfig {
            notify_min_severity: "critical".into(),
            notify_mode: mode,
            ..Default::default()
        };
        let mut d = NotificationDispatcher::new(&config, db);
        d.notifiers.push(Box::new(MockNotifier));
        d
    }

    #[tokio::test]
    async fn regression_mode_silent_without_previous() {
        let d = dispatcher_with(NotifyMode::Regression).await;
        // First scan (no previous): even with criticals, regression mode is quiet.
        let results = d.dispatch(&summary(3), None).await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn findings_mode_sends_on_threshold() {
        let d = dispatcher_with(NotifyMode::Findings).await;
        let results = d.dispatch(&summary(1), None).await;
        assert_eq!(results.len(), 1);
    }
}
