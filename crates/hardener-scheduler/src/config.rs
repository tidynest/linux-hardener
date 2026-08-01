//! Scheduler configuration structures.
//!
//! Defines the `[scheduler]` section of the hardener config file,
//! supporting scan scheduling, storage options, and notifications.

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf};

/// Returns the appropriate base directory for scheduler data.
///
/// - Root user (uid 0): `/var/lib/linux-hardener/`
/// - Regular user: `~/.local/share/linux-hardener/`
fn default_data_dir() -> PathBuf {
    // Check if running as root
    #[cfg(unix)]
    {
        if unsafe { libc::geteuid() } == 0 {
            return PathBuf::from("/var/lib/linux-hardener");
        }
    }

    // For non-root users, use XDG data directory
    dirs::data_local_dir()
        .map(|p| p.join("linux-hardener"))
        .unwrap_or_else(|| {
            // Fallback if home directory cannot be determined
            PathBuf::from("/var/lib/linux-hardener")
        })
}

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
    #[serde(default)]
    pub storage: StorageConfig,
    /// Notification configuration.
    #[serde(default)]
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
        let base = default_data_dir();
        Self {
            database_path: base.join("scheduler.db"),
            json_output_dir: base.join("scans"),
            retention_count: 90,
            retention_days: 0,
        }
    }
}

/// Which notification triggers are active.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NotifyMode {
    /// Alert when this scan has findings at or above `notify_min_severity` (current behaviour).
    #[default]
    Findings,
    /// Alert only when this scan is worse than the host's previous scan (quiet until change).
    Regression,
    /// Alert on either of the above; a regression scan is annotated as such.
    Both,
}

/// Notification channel settings.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct NotificationConfig {
    /// Minimum severity to trigger notifications.
    pub notify_min_severity: String,
    /// Which notification triggers are active.
    pub notify_mode: NotifyMode,
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
mod tests;
