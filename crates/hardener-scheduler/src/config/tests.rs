#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`config`](super).
//!
//! Split out of `config.rs`. This file sits in the `config/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`,
//! so `super` still resolves to `crate::config` and every import carried
//! across unchanged, private items included.

use super::*;

#[test]
fn default_config_has_sensible_values() {
    let config = SchedulerConfig::default();
    assert!(!config.enabled);
    assert_eq!(config.schedule, "0 0 2 * * *");
    assert!(config.plugins.is_empty());
    assert_eq!(config.min_severity, "medium");
}

#[test]
fn storage_defaults_to_appropriate_dir() {
    let storage = StorageConfig::default();
    // Path depends on whether running as root or user
    // Just verify the filename is correct and retention is set
    assert!(
        storage
            .database_path
            .file_name()
            .is_some_and(|n| n == "scheduler.db")
    );
    assert!(
        storage
            .json_output_dir
            .file_name()
            .is_some_and(|n| n == "scans")
    );
    assert_eq!(storage.retention_count, 90);
}

#[test]
fn default_data_dir_returns_valid_path() {
    let dir = default_data_dir();
    // Should end with "linux-hardener"
    assert!(dir.file_name().is_some_and(|n| n == "linux-hardener"));
}

#[test]
fn email_defaults_to_tls_port_587() {
    let email = EmailConfig::default();
    assert!(!email.enabled);
    assert_eq!(email.smtp_port, 587);
    assert!(email.smtp_tls);
}

#[test]
fn webhook_format_deserialises_lowercase() {
    let json = r#""slack""#;
    let format: WebhookFormat = serde_json::from_str(json).unwrap();
    assert_eq!(format, WebhookFormat::Slack);
}

#[test]
fn notify_mode_defaults_to_findings_and_round_trips() {
    // Omitted field deserialises to the default (Findings).
    let cfg: NotificationConfig = toml::from_str("").unwrap();
    assert_eq!(cfg.notify_mode, NotifyMode::Findings);

    let cfg: NotificationConfig = toml::from_str(r#"notify_mode = "regression""#).unwrap();
    assert_eq!(cfg.notify_mode, NotifyMode::Regression);

    let cfg: NotificationConfig = toml::from_str(r#"notify_mode = "both""#).unwrap();
    assert_eq!(cfg.notify_mode, NotifyMode::Both);
}

#[test]
fn full_config_deserialises_from_toml() {
    let toml_str = r#"
          enabled = true
          schedule = "0 30 3 * * *"
          plugins = ["kernel", "ssh"]
          min_severity = "high"

          [storage]
          database_path = "/custom/path/db.sqlite"
          retention_days = 30

          [notifications]
          notify_min_severity = "critical"

          [notifications.email]
          enabled = true
          smtp_host = "mail.example.com"
          recipients = ["admin@example.com"]

          [notifications.webhooks]
          enabled = true

          [[notifications.webhooks.endpoints]]
          name = "slack"
          url = "https://hooks.slack.com/test"
          format = "slack"
      "#;

    let config: SchedulerConfig = toml::from_str(toml_str).unwrap();
    assert!(config.enabled);
    assert_eq!(config.schedule, "0 30 3 * * *");
    assert_eq!(config.plugins, vec!["kernel", "ssh"]);
    assert_eq!(config.storage.retention_days, 30);
    assert!(config.notifications.email.enabled);
    assert_eq!(config.notifications.webhooks.endpoints.len(), 1);
    assert_eq!(
        config.notifications.webhooks.endpoints[0].format,
        WebhookFormat::Slack
    );
}
