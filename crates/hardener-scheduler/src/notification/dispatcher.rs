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

        self.send_to_notifiers(summary).await
    }

    /// Sends `summary` to every configured channel unconditionally, bypassing the
    /// mode/severity decision in `dispatch`. Used by the "test notification"
    /// feature, which must verify the channels regardless of notify_mode/threshold.
    /// Returns an empty vec only when no channels are configured.
    pub async fn send_test(&self, summary: &ScanSummary) -> Vec<NotificationResult> {
        if self.notifiers.is_empty() {
            return Vec::new();
        }
        self.send_to_notifiers(summary).await
    }

    /// Sends `summary` to every notifier and logs each attempt. This is the
    /// shared inner loop used by both `dispatch` and `send_test`.
    async fn send_to_notifiers(&self, summary: &ScanSummary) -> Vec<NotificationResult> {
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
mod tests;
