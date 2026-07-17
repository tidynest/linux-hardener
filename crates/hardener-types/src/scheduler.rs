//! Scheduler configuration types shared between backend and WASM frontend.

use serde::{Deserialize, Serialize};

/// Schedule configuration for the GUI.
///
/// Mirrors the fields from `hardener-scheduler::SchedulerConfig` that
/// the frontend needs, without native-only dependencies like PathBuf.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct SchedulerUiConfig {
    pub enabled: bool,
    pub schedule: String,
    pub plugins: Vec<String>,
    pub min_severity: String,
    pub notifications: NotificationUiConfig,
}

/// Notification settings for the GUI.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct NotificationUiConfig {
    pub notify_min_severity: String,
    pub email: EmailUiConfig,
    pub webhooks: WebhookUiConfig,
}

/// Email notification settings (GUI subset: no SMTP internals).
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct EmailUiConfig {
    pub enabled: bool,
    pub recipients: Vec<String>,
    pub from_address: String,
}

/// Webhook notification settings (single endpoint for GUI).
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct WebhookUiConfig {
    pub enabled: bool,
    pub url: String,
    pub format: String,
}

/// Result of a test notification attempt.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TestNotificationResult {
    pub success: bool,
    pub message: String,
}
