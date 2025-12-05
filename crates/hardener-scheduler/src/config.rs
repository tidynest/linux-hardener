//! Scheduler configuration structures.
//!
//! Defines the `[scheduler]` section of the hardener config file,
//! supporting scan scheduling, storage options, and notifications.

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf};

/// Root scheduler configuration.
///
/// Loaded from `[scheduler]` section in config.toml
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SchedulerConfig {
    /// Enable scheduled scanning daemon.
    pub enabled: bool,
    /// Cron expression for scan schedule (6-field: sec min hour dom mon dow)
    pub schedule: String,
    /// Plugins to scan (empty = all plugins).
    pub plugins: Vec<String>,
    /// Minimum severity to include in results.
    pub min_severity: String,
    /// Storage configuration.
    pub storage: StorageConfig,
    /// Notification configuration.
    pub notifications: NotificationConfig,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            schedule: "0 0 2 * * *".into(), // Daily at 02:00
            plugins: Vec::new(),
            min_severity: "medium".into(),
            storage: StorageConfig::default(),
            notifications: NotificationConfig::default(),
        }
    }
}

/// Storage paths and retention settings.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct StorageConfig {
    /// SQLite database path for scan history.
    pub database_path: PathBuf,
    /// Directory for JSON scan exports.
    pub json_output_dir: PathBuf,
    /// Maximum scan sessions to retain (0 = unlimited).
    pub retention_count: u32,
    /// Retention period in days (0 = use retention_count)
    pub retention_days: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            database_path: PathBuf::from("/var/lib/linux-hardener/scheduler.db"),
            json_output_dir: PathBuf::from("/var/lib/linux-hardener/scans"),
            retention_count: 90,
            retention_days: 0,
        }
    }
}

/// Notification channel settings.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct NotificationConfig {
    /// Minimum severity to trigger notifications.
    pub notify_min_severity: String,
    /// Email notification settings.
    pub email: EmailConfig,
    /// Webhook notification settings.
    pub webhooks: WebhookConfig,
}

/// SMTP email configuration.
///
/// Password is read from `HARDENER_SMTP_PASSWORD` environment variable.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct EmailConfig {
    pub enabled: bool,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_tls: bool,
    pub smtp_username: String,
    pub recipients: Vec<String>,
    pub from_address: String,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            smtp_host: String::new(),
            smtp_port: 587,
            smtp_tls: true,
            smtp_username: String::new(),
            recipients: Vec::new(),
            from_address: String::new(),
        }
    }
}

/// Webhook endpoints configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct WebhookConfig {
    pub enabled: bool,
    pub endpoints: Vec<WebhookEndpoint>,
}

/// Individual webhook endpoint.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct WebhookEndpoint {
    /// Identifier for logging/status.
    pub name: String,
    /// Webhook URL.
    pub url: String,
    /// Payload format (slack, discord, generic).
    pub format: WebhookFormat,
    /// Additional HTTP headers (supports `${ENV_VAR}` expansion).
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

/// Webhook payload format.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WebhookFormat {
    #[default]
    Generic,
    Slack,
    Discord,
}

#[cfg(test)]
mod tests {
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
    fn storage_defaults_to_var_lib() {
        let storage = StorageConfig::default();
        assert_eq!(
            storage.database_path,
            PathBuf::from("/var/lib/linux-hardener/scheduler.db")
        );
        assert_eq!(storage.retention_count, 90);
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
}
