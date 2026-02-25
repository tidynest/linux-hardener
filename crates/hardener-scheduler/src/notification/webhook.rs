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
        unsafe { env::set_var("HARDENER_WEBHOOK_TOKEN", "secret123") };
        let result = WebhookNotifier::expand_env_vars("Bearer ${HARDENER_WEBHOOK_TOKEN}");
        assert_eq!(result, "Bearer secret123");
        // SAFETY: Test runs single-threaded; no concurrent env access
        unsafe { env::remove_var("HARDENER_WEBHOOK_TOKEN") };
    }

    #[test]
    fn expand_env_vars_multiple_vars() {
        // SAFETY: Test runs single-threaded; no concurrent env access
        unsafe {
            env::set_var("HARDENER_WEBHOOK_A", "alpha");
            env::set_var("HARDENER_AUTH_B", "beta");
        }
        let result = WebhookNotifier::expand_env_vars("${HARDENER_WEBHOOK_A}-${HARDENER_AUTH_B}");
        assert_eq!(result, "alpha-beta");
        // SAFETY: Test runs single-threaded; no concurrent env access
        unsafe {
            env::remove_var("HARDENER_WEBHOOK_A");
            env::remove_var("HARDENER_AUTH_B");
        }
    }

    #[test]
    fn expand_env_vars_blocked_var_becomes_empty() {
        // SAFETY: Test runs single-threaded; no concurrent env access
        unsafe { env::set_var("SECRET_KEY", "should_not_leak") };
        let result = WebhookNotifier::expand_env_vars("${SECRET_KEY}");
        assert_eq!(result, "");
        unsafe { env::remove_var("SECRET_KEY") };
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

    // --- SSRF validation tests ---

    #[test]
    fn blocked_addr_loopback_v4() {
        assert!(is_blocked_addr("127.0.0.1".parse().unwrap()));
        assert!(is_blocked_addr("127.255.255.254".parse().unwrap()));
    }

    #[test]
    fn blocked_addr_private_ranges() {
        assert!(is_blocked_addr("10.0.0.1".parse().unwrap()));
        assert!(is_blocked_addr("172.16.0.1".parse().unwrap()));
        assert!(is_blocked_addr("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn blocked_addr_link_local_and_unspecified() {
        assert!(is_blocked_addr("169.254.1.1".parse().unwrap()));
        assert!(is_blocked_addr("0.0.0.0".parse().unwrap()));
    }

    #[test]
    fn blocked_addr_v6_loopback_and_private() {
        assert!(is_blocked_addr("::1".parse().unwrap()));
        assert!(is_blocked_addr("fe80::1".parse().unwrap()));
        assert!(is_blocked_addr("fc00::1".parse().unwrap()));
        assert!(is_blocked_addr("fd12::1".parse().unwrap()));
    }

    #[test]
    fn blocked_addr_v4_mapped_v6() {
        // ::ffff:127.0.0.1 — mapped loopback must be caught
        assert!(is_blocked_addr("::ffff:127.0.0.1".parse().unwrap()));
        assert!(is_blocked_addr("::ffff:10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn allowed_addr_public() {
        assert!(!is_blocked_addr("8.8.8.8".parse().unwrap()));
        assert!(!is_blocked_addr("93.184.216.34".parse().unwrap()));
        assert!(!is_blocked_addr("2606:4700::1".parse().unwrap()));
    }

    #[test]
    fn validate_url_accepts_https() {
        assert!(validate_webhook_url("https://example.com/hook").is_ok());
    }

    #[test]
    fn validate_url_accepts_http() {
        assert!(validate_webhook_url("http://example.com/hook").is_ok());
    }

    #[test]
    fn validate_url_rejects_ftp_scheme() {
        let err = validate_webhook_url("ftp://example.com").unwrap_err();
        assert!(err.contains("ftp"));
    }

    #[test]
    fn validate_url_rejects_file_scheme() {
        let err = validate_webhook_url("file:///etc/passwd").unwrap_err();
        assert!(err.contains("file"));
    }

    #[test]
    fn validate_url_rejects_loopback_literal() {
        assert!(validate_webhook_url("http://127.0.0.1/hook").is_err());
    }

    #[test]
    fn validate_url_rejects_private_literal() {
        assert!(validate_webhook_url("http://192.168.1.1/hook").is_err());
        assert!(validate_webhook_url("http://10.0.0.1/hook").is_err());
    }

    #[test]
    fn validate_url_rejects_v6_loopback_literal() {
        assert!(validate_webhook_url("http://[::1]/hook").is_err());
    }

    #[test]
    fn validate_url_rejects_invalid_url() {
        assert!(validate_webhook_url("not a url at all").is_err());
    }

    #[test]
    fn validate_url_rejects_nonsense_input() {
        assert!(validate_webhook_url("://missing-scheme").is_err());
        assert!(validate_webhook_url("").is_err());
    }

    #[test]
    fn webhook_new_rejects_loopback_url() {
        let endpoint = WebhookEndpoint {
            name: "test".to_string(),
            url: "http://127.0.0.1/hook".to_string(),
            format: WebhookFormat::Generic,
            headers: std::collections::HashMap::new(),
        };
        assert!(WebhookNotifier::new(endpoint).is_none());
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
