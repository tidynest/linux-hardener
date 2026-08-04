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
        // SAFETY: geteuid() is a pure read of the calling process's effective
        // uid. It takes no arguments, touches no memory the caller owns, and
        // POSIX requires it to always succeed, so there is no failure mode and
        // no thread-safety condition to observe.
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
///
/// `#[serde(default)]` on the struct, as on every table below it except
/// [`WebhookEndpoint`], whose `name` and `url` stay required. This is the table
/// an operator writes by hand, and without it the four scalar fields were all
/// mandatory together: `[scheduler]` with `enabled = true` and nothing else
/// failed the file with ``missing field `schedule` ``. The section is read from
/// whichever file in the search order carries it, and a parse error there is
/// fatal, so one partial section stopped `daemon` and `history` outright rather
/// than the section falling back to these defaults.
///
/// The price, stated because nothing else catches it: the mandatory group was
/// an accidental typo detector, and a misspelled key is now accepted in silence
/// where it used to be a hard error. `deny_unknown_fields` would restore that,
/// and is deliberately not used here: no configuration struct in this workspace
/// sets it, and making this one table reject an unknown key would refuse a file
/// written for a newer version on an older binary.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
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
    ///
    /// Defaulted, unlike `name` and `url` beside it: `WebhookFormat` already
    /// declares `Generic` as its default and the reference documents it, so an
    /// endpoint that omitted the key failed the whole file rather than taking
    /// the format it had been promised. The other two stay required because
    /// neither has an answer worth guessing.
    #[serde(default)]
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
