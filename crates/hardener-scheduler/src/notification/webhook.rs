//! Webhook notifications (Discord, Slack, Generic)
//!
//! Sends HTTP POST requests to configured endpoints with scan summaries.
//! Supports environment variable expansion in headers using `${VAR}` syntax.

use super::{NotificationResult, Notifier};
use crate::config::{WebhookEndpoint, WebhookFormat};
use crate::runner::ScanSummary;
use async_trait::async_trait;
use reqwest::Client;
use std::env;
use std::time::Duration;
use tracing::{debug, error, warn};

/// HTTP request timeout for webhook endpoint.
const WEBHOOK_TIMEOUT_SECS: u64 = 30;

/// Sends notification to a single webhook endpoint.
pub struct WebhookNotifier {
    endpoint: WebhookEndpoint,
    client: Client,
}

impl WebhookNotifier {
    /// Creates a new WebhookNotifier for an endpoint.
    ///
    /// Returns `None` if the endpoint URL is empty.
    pub fn new(endpoint: WebhookEndpoint) -> Option<Self> {
        if endpoint.url.is_empty() {
            warn!("Webhook '{}' has empty URL, skipping", endpoint.name);
            return None;
        }

        let client = Client::builder()
            .timeout(Duration::from_secs(WEBHOOK_TIMEOUT_SECS))
            .build()
            .ok()?;

        Some(Self { endpoint, client })
    }

    /// Expands environment variables in header values.
    ///
    /// Replaces `${VAR_NAME}` with the value of the environment variable.
    /// Unset variables are replaced with empty strings.
    fn expand_env_vars(value: &str) -> String {
        let mut result = value.to_string();
        let mut start = 0;

        while let Some(var_start) = result[start..].find("${") {
            let var_start = start + var_start;
            if let Some(var_end) = result[var_start..].find('}') {
                let var_end = var_start + var_end;
                let var_name = &result[var_start + 2..var_end];
                let var_value = env::var(var_name).unwrap_or_default();
                result.replace_range(var_start..=var_end, &var_value);
                start = var_start + var_value.len();
            } else {
                break;
            }
        }

        result
    }

    /// Builds the JSON payload based on the endpoint format.
    fn build_payload(&self, summary: &ScanSummary) -> serde_json::Value {
        match self.endpoint.format {
            WebhookFormat::Slack => self.build_slack_payload(summary),
            WebhookFormat::Discord => self.build_discord_payload(summary),
            WebhookFormat::Generic => self.build_generic_payload(summary),
        }
    }

    /// Determines colour based on highest severity.
    fn severity_colour(summary: &ScanSummary) -> &'static str {
        if summary.critical_count > 0 {
            "#dc3545" // Red
        } else if summary.high_count > 0 {
            "#fd7e14" // Orange
        } else if summary.medium_count > 0 {
            "#ffc107" // Yellow
        } else {
            "#28a745" // Green
        }
    }

    /// Determines colour code for Discord (integer format).
    fn discord_colour(summary: &ScanSummary) -> u32 {
        if summary.critical_count > 0 {
            0xdc3545 // Red
        } else if summary.high_count > 0 {
            0xfd7e14 // Orange
        } else if summary.medium_count > 0 {
            0xffc107 // Yellow
        } else {
            0x28a745 // Green
        }
    }

    /// Builds Slack-formatted payload with attachment.
    fn build_slack_payload(&self, summary: &ScanSummary) -> serde_json::Value {
        serde_json::json!({
            "attachments": [{
                "color": Self::severity_colour(summary),
                "title": format!(
                    "Security Scan: {} findings on {}",
                    summary.total_findings, summary.host
                ),
                "fields": [
                    {
                        "title": "Critical",
                        "value": summary.critical_count.to_string(),
                        "short": true
                    },
                    {
                        "title": "High",
                        "value": summary.high_count.to_string(),
                        "short": true
                    },
                    {
                        "title": "Medium",
                        "value": summary.medium_count.to_string(),
                        "short": true
                    },
                    {
                        "title": "Low",
                        "value": summary.low_count.to_string(),
                        "short": true
                    },
                ],
                "footer": format!("Session: {}", summary.session_id),
            }]
        })
    }

    /// Builds Discord-formatted payload with embed.
    fn build_discord_payload(&self, summary: &ScanSummary) -> serde_json::Value {
        serde_json::json!({
            "embeds": [{
                "title": format!(
                    "Security Scan: {} findings on {}",
                    summary.total_findings, summary.host
                ),
                "color": Self::discord_colour(summary),
                "fields": [
                    {
                        "name": "Critical",
                        "value": summary.critical_count.to_string(),
                        "inline": true
                    },
                    {
                        "name": "High",
                        "value": summary.high_count.to_string(),
                        "inline": true
                    },
                    {
                        "name": "Medium",
                        "value": summary.medium_count.to_string(),
                        "inline": true
                    },
                    {
                        "name": "Low",
                        "value": summary.low_count.to_string(),
                        "inline": true
                    },
                ],
                "footer": { "text": format!("Session: {}", summary.session_id) },
            }]
        })
    }

    /// Builds generic JSON payload with full details.
    fn build_generic_payload(&self, summary: &ScanSummary) -> serde_json::Value {
        serde_json::json!({
            "event": "security_scan_completed",
            "host": summary.host,
            "session_id": summary.session_id,
            "plugins_scanned": summary.plugins_scanned,
            "findings": {
                "total": summary.total_findings,
                "critical": summary.critical_count,
                "high": summary.high_count,
                "medium": summary.medium_count,
                "low": summary.low_count,
                "info": summary.info_count,
            },
            "json_path": summary.json_path,
            "had_errors": summary.had_errors,
        })
    }
}

#[async_trait]
impl Notifier for WebhookNotifier {
    async fn send(&self, summary: &ScanSummary) -> NotificationResult {
        let payload = self.build_payload(summary);

        let mut request = self
            .client
            .post(&self.endpoint.url)
            .header("Content-Type", "application/json");

        // Add custom headers with env var expansion
        for (key, value) in &self.endpoint.headers {
            let expanded = Self::expand_env_vars(value);
            request = request.header(key, expanded);
        }

        match request.json(&payload).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    debug!("Webhook '{}' sent successfully", self.endpoint.name);
                    NotificationResult::ok(self.channel())
                } else {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    error!(
                        "Webhook '{}' returned {}: {}",
                        self.endpoint.name, status, body
                    );
                    NotificationResult::failed(self.channel(), format!("HTTP {}: {}", status, body))
                }
            }
            Err(e) => {
                error!("Webhook '{}' request failed: {}", self.endpoint.name, e);
                NotificationResult::failed(self.channel(), e.to_string())
            }
        }
    }

    fn channel(&self) -> &str {
        &self.endpoint.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_env_vars_no_vars() {
        let result = WebhookNotifier::expand_env_vars("plain text");
        assert_eq!(result, "plain text");
    }

    #[test]
    fn expand_env_vars_single_var() {
        // SAFETY: Test runs single-threaded; no concurrent env access
        unsafe { std::env::set_var("TEST_WEBHOOK_VAR", "secret123") };
        let result = WebhookNotifier::expand_env_vars("Bearer ${TEST_WEBHOOK_VAR}");
        assert_eq!(result, "Bearer secret123");
        // SAFETY: Test runs single-threaded; no concurrent env access
        unsafe { std::env::remove_var("TEST_WEBHOOK_VAR") };
    }

    #[test]
    fn expand_env_vars_multiple_vars() {
        // SAFETY: Test runs single-threaded; no concurrent env access
        unsafe {
            std::env::set_var("TEST_VAR_A", "alpha");
            std::env::set_var("TEST_VAR_B", "beta");
        }
        let result = WebhookNotifier::expand_env_vars("${TEST_VAR_A}-${TEST_VAR_B}");
        assert_eq!(result, "alpha-beta");
        // SAFETY: Test runs single-threaded; no concurrent env access
        unsafe {
            std::env::remove_var("TEST_VAR_A");
            std::env::remove_var("TEST_VAR_B");
        }
    }

    #[test]
    fn expand_env_vars_missing_var_becomes_empty() {
        let result = WebhookNotifier::expand_env_vars("prefix-${NONEXISTENT_VAR_XYZ}-suffix");
        assert_eq!(result, "prefix--suffix");
    }

    #[test]
    fn expand_env_vars_unclosed_brace_unchanged() {
        let result = WebhookNotifier::expand_env_vars("${UNCLOSED");
        assert_eq!(result, "${UNCLOSED");
    }

    #[test]
    fn expand_env_vars_empty_string() {
        let result = WebhookNotifier::expand_env_vars("");
        assert_eq!(result, "");
    }

    #[test]
    fn severity_colour_critical_is_red() {
        let summary = make_test_summary(1, 0, 0, 0);
        assert_eq!(WebhookNotifier::severity_colour(&summary), "#dc3545");
    }

    #[test]
    fn severity_colour_high_is_orange() {
        let summary = make_test_summary(0, 1, 0, 0);
        assert_eq!(WebhookNotifier::severity_colour(&summary), "#fd7e14");
    }

    #[test]
    fn severity_colour_medium_is_yellow() {
        let summary = make_test_summary(0, 0, 1, 0);
        assert_eq!(WebhookNotifier::severity_colour(&summary), "#ffc107");
    }

    #[test]
    fn severity_colour_low_is_green() {
        let summary = make_test_summary(0, 0, 0, 1);
        assert_eq!(WebhookNotifier::severity_colour(&summary), "#28a745");
    }

    #[test]
    fn discord_colour_critical_is_red() {
        let summary = make_test_summary(1, 0, 0, 0);
        assert_eq!(WebhookNotifier::discord_colour(&summary), 0xdc3545);
    }

    #[test]
    fn webhook_new_rejects_empty_url() {
        let endpoint = WebhookEndpoint {
            name: "test".to_string(),
            url: String::new(),
            format: WebhookFormat::Generic,
            headers: std::collections::HashMap::new(),
        };
        assert!(WebhookNotifier::new(endpoint).is_none());
    }

    #[test]
    fn webhook_new_accepts_valid_endpoint() {
        let endpoint = WebhookEndpoint {
            name: "test".to_string(),
            url: "https://example.com/webhook".to_string(),
            format: WebhookFormat::Slack,
            headers: std::collections::HashMap::new(),
        };
        assert!(WebhookNotifier::new(endpoint).is_some());
    }

    /// Helper to create a test summary.
    fn make_test_summary(critical: usize, high: usize, medium: usize, low: usize) -> ScanSummary {
        ScanSummary {
            session_id: "test".to_string(),
            host: "testhost".to_string(),
            plugins_scanned: vec![],
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
}
