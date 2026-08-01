#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`webhook`](super).
//!
//! Split out of `notification/webhook.rs`. This file sits in the `webhook/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`,
//! so `super` still resolves to `crate::notification::webhook` and every import carried
//! across unchanged, private items included.
//!
//! 33 tests, the largest block in this crate.

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
    // ::ffff:127.0.0.1: mapped loopback must be caught
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

#[test]
fn generic_payload_includes_regression_when_present() {
    let mut s = make_test_summary(1, 0, 0, 0);
    // No regression -> the key is present but JSON null.
    assert!(WebhookNotifier::build_generic_payload(&s)["regression"].is_null());

    s.regression = Some(crate::runner::RegressionInfo {
        previous_started_at: 1_700_000_000,
        previous_total: 0,
        delta_critical: 1,
        delta_high: 0,
        delta_medium: 0,
        delta_low: 0,
    });
    let payload = WebhookNotifier::build_generic_payload(&s);
    assert_eq!(payload["regression"]["delta_critical"], 1);
}

#[test]
fn slack_title_marks_regression() {
    let mut s = make_test_summary(1, 0, 0, 0);
    s.regression = Some(crate::runner::RegressionInfo {
        previous_started_at: 1_700_000_000,
        previous_total: 0,
        delta_critical: 1,
        delta_high: 0,
        delta_medium: 0,
        delta_low: 0,
    });
    let v = WebhookNotifier::build_slack_payload(&s);
    assert!(
        v["attachments"][0]["title"]
            .as_str()
            .unwrap_or("")
            .starts_with("[REGRESSION] "),
        "Slack attachment title must start with '[REGRESSION] '"
    );
}

#[test]
fn discord_title_marks_regression() {
    let mut s = make_test_summary(1, 0, 0, 0);
    s.regression = Some(crate::runner::RegressionInfo {
        previous_started_at: 1_700_000_000,
        previous_total: 0,
        delta_critical: 1,
        delta_high: 0,
        delta_medium: 0,
        delta_low: 0,
    });
    let v = WebhookNotifier::build_discord_payload(&s);
    assert!(
        v["embeds"][0]["title"]
            .as_str()
            .unwrap_or("")
            .starts_with("[REGRESSION] "),
        "Discord embed title must start with '[REGRESSION] '"
    );
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
        regression: None,
    }
}
