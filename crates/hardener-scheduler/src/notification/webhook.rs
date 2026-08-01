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

/// Returns the regression label prefix when the scan regressed, or `""` otherwise.
fn regression_marker(summary: &ScanSummary) -> &'static str {
    if summary.regression.is_some() {
        "[REGRESSION] "
    } else {
        ""
    }
}

/// Returns `true` if the address is loopback, private, link-local, or unspecified.
fn is_blocked_addr(addr: std::net::IpAddr) -> bool {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    match addr {
        IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip == Ipv4Addr::new(0, 0, 0, 0)
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
            || ip.is_unspecified()
            || ip == Ipv6Addr::LOCALHOST
            // fe80::/10 link-local
            || (ip.segments()[0] & 0xffc0) == 0xfe80
            // fc00::/7 unique local (private equivalent)
            || (ip.segments()[0] & 0xfe00) == 0xfc00
            // ::ffff:0:0/96 mapped IPv4 - check the inner v4
            || ip.to_ipv4_mapped().is_some_and(|v4| {
                v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
            })
        }
    }
}

/// Validates a webhook URL against SSRF risks.
///
/// Rejects non-HTTP schemes, loopback, private, and link-local addresses.
fn validate_webhook_url(url: &str) -> Result<url::Url, String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("Invalid URL: {e}"))?;

    // Require HTTP(S) scheme
    match parsed.scheme() {
        "https" | "http" => {}
        scheme => return Err(format!("scheme '{scheme}' not allowed, use https or http")),
    }

    // If the host is an IP literal, check it immediately
    if let Some(host) = parsed.host() {
        match host {
            url::Host::Ipv4(ip) if is_blocked_addr(ip.into()) => {
                return Err(format!("blocked address: {ip}"));
            }
            url::Host::Ipv6(ip) if is_blocked_addr(ip.into()) => {
                return Err(format!("blocked address: {ip}"));
            }
            url::Host::Domain("") => return Err("empty hostname".to_string()),
            _ => {}
        }
    } else {
        return Err("URL has no host".to_string());
    }

    Ok(parsed)
}

/// Resolves a hostname and rejects it if any resolved IP is blocked.
///
/// Must be called in an async context before making the HTTP request.
async fn validate_resolved_url(url: &url::Url) -> Result<(), String> {
    let Some(host) = url.host_str() else {
        return Err("URL has no host".to_string());
    };
    let port = url.port_or_known_default().unwrap_or(443);
    let addr_str = format!("{host}:{port}");

    let addrs = tokio::net::lookup_host(&addr_str)
        .await
        .map_err(|e| format!("DNS resolution failed for '{host}': {e}"))?;

    for sock_addr in addrs {
        if is_blocked_addr(sock_addr.ip()) {
            return Err(format!(
                "'{host}' resolves to blocked address {}",
                sock_addr.ip()
            ));
        }
    }

    Ok(())
}

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

        if let Err(reason) = validate_webhook_url(&endpoint.url) {
            warn!("Webhook '{}' rejected: {reason}", endpoint.name);
            return None;
        }

        let client = Client::builder()
            .timeout(Duration::from_secs(WEBHOOK_TIMEOUT_SECS))
            .build()
            .ok()?;

        Some(Self { endpoint, client })
    }

    /// Allowed environment variable prefixes for header expansion.
    const ENV_ALLOWLIST: &[&str] = &["HARDENER_WEBHOOK_", "HARDENER_AUTH_"];

    /// Expands environment variables in header values.
    ///
    /// Only variables matching the allowlist prefixes are expanded.
    /// Unset or disallowed variables are replaced with empty strings.
    fn expand_env_vars(value: &str) -> String {
        let mut result = value.to_string();
        let mut start = 0;

        while let Some(var_start) = result[start..].find("${") {
            let var_start = start + var_start;
            if let Some(var_end) = result[var_start..].find('}') {
                let var_end = var_start + var_end;
                let var_name = &result[var_start + 2..var_end];
                let var_value = if Self::ENV_ALLOWLIST.iter().any(|p| var_name.starts_with(p)) {
                    env::var(var_name).unwrap_or_default()
                } else {
                    warn!("Blocked env var expansion for '{var_name}': not in allowlist");
                    String::new()
                };
                result.replace_range(var_start..=var_end, &var_value);
                start = var_start + var_value.len();
            } else {
                break;
            }
        }

        result
    }

    /// Validates a custom header key and value.
    ///
    /// Rejects keys with non-token characters and values containing
    /// control characters (CR, LF, NUL) to prevent header injection.
    fn validate_header(key: &str, value: &str) -> Result<(), String> {
        if !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(format!("invalid header key: {key}"));
        }
        if value
            .bytes()
            .any(|b| b == b'\r' || b == b'\n' || b == b'\0')
        {
            return Err(format!(
                "header value for '{key}' contains control characters"
            ));
        }
        Ok(())
    }

    /// Builds the JSON payload based on the endpoint format.
    fn build_payload(&self, summary: &ScanSummary) -> serde_json::Value {
        match self.endpoint.format {
            WebhookFormat::Slack => Self::build_slack_payload(summary),
            WebhookFormat::Discord => Self::build_discord_payload(summary),
            WebhookFormat::Generic => Self::build_generic_payload(summary),
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
    fn build_slack_payload(summary: &ScanSummary) -> serde_json::Value {
        let marker = regression_marker(summary);
        serde_json::json!({
            "attachments": [{
                "color": Self::severity_colour(summary),
                "title": format!(
                    "{}Security Scan: {} findings on {}",
                    marker, summary.total_findings, summary.host
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
    fn build_discord_payload(summary: &ScanSummary) -> serde_json::Value {
        let marker = regression_marker(summary);
        serde_json::json!({
            "embeds": [{
                "title": format!(
                    "{}Security Scan: {} findings on {}",
                    marker, summary.total_findings, summary.host
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
    pub(crate) fn build_generic_payload(summary: &ScanSummary) -> serde_json::Value {
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
            "regression": summary.regression.as_ref().map(|r| serde_json::json!({
                "previous_started_at": r.previous_started_at,
                "previous_total": r.previous_total,
                "delta_critical": r.delta_critical,
                "delta_high": r.delta_high,
                "delta_medium": r.delta_medium,
                "delta_low": r.delta_low,
            })),
        })
    }
}

#[async_trait]
impl Notifier for WebhookNotifier {
    async fn send(&self, summary: &ScanSummary) -> NotificationResult {
        // Strict SSRF: re-validate with DNS resolution before every request
        if let Ok(parsed) = url::Url::parse(&self.endpoint.url)
            && let Err(reason) = validate_resolved_url(&parsed).await
        {
            error!("Webhook '{}' SSRF blocked: {reason}", self.endpoint.name);
            return NotificationResult::failed(self.channel(), format!("SSRF blocked: {reason}"));
        }

        let payload = self.build_payload(summary);

        let mut request = self
            .client
            .post(&self.endpoint.url)
            .header("Content-Type", "application/json");

        // Add custom headers with env var expansion and injection validation
        for (key, value) in &self.endpoint.headers {
            let expanded = Self::expand_env_vars(value);
            if let Err(reason) = Self::validate_header(key, &expanded) {
                error!("Webhook '{}' header rejected: {reason}", self.endpoint.name);
                return NotificationResult::failed(self.channel(), reason);
            }
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
mod tests;
