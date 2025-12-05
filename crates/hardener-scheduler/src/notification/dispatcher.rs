//! Notification dispatcher for coordinating all channels
//!
//! Manages email and webhook notifiers, applies severity filtering,
//! and logs all notification attempts to the database.

use super::{
    email::EmailNotifier, meets_severity_threshold, parse_severity, webhook::WebhookNotifier,
    NotificationResult, Notifier,
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
        }
    }

    /// Dispatches notifications for a completed scan.
    ///
    /// - Checks severity before sending
    /// - Sends to all configured channels in parallel
    /// - Logs each attempt to the database
    ///
    /// Returns results from all notification attempts.
    pub async fn dispatch(&self, summary: &ScanSummary) -> Vec<NotificationResult> {
        // Check severity threshold
        if !meets_severity_threshold(summary, self.min_severity) {
            debug!(
                "Skipping notifications: no findings at or above {:?}",
                self.min_severity
            );
            return Vec::new();
        }

        if self.notifiers.is_empty() {
            debug!("No notifiers configured, skipping dispatch");
            return Vec::new();
        }

        info!(
            "Dispatching notifications for session {} ({} findings)",
            summary.session_id, summary.total_findings
        );

        let mut results = Vec::with_capacity(self.notifiers.len());

        // Send to each channel and log results
        for notifier in &self.notifiers {
            let result = notifier.send(summary).await;

            // Log to database
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
