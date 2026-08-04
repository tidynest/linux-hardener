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
///
/// The desktop offers one webhook; `[scheduler.notifications.webhooks]` on disk
/// is `{ enabled, endpoints }`. These three fields are the form's shape and the
/// wire type below is the file's, so the two are converted rather than confused:
/// this struct used to serialise itself, writing `url` and `format` into a table
/// whose backend struct has neither, and since nothing rejects an unknown key
/// the save succeeded, the endpoint list stayed empty and no notification was
/// ever dispatched.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(from = "WebhookWire", into = "WebhookWire")]
pub struct WebhookUiConfig {
    pub enabled: bool,
    pub url: String,
    pub format: String,
}

/// The format written when the form has not chosen one.
///
/// `WebhookUiConfig::default()` leaves `format` empty and the scheduler page
/// sets the form straight from it, so a fresh form saved unchanged carries an
/// empty format through. As a flat key the backend never read it; inside an
/// endpoint `""` is not one of its three variants and the file stops parsing,
/// so this guard is what makes writing the list safe.
const DEFAULT_WEBHOOK_FORMAT: &str = "generic";

/// The name given to the endpoint the desktop writes.
///
/// The backend uses it for logging and status only, and the form has no field
/// for it, so it is a constant rather than something invented per save.
const DESKTOP_ENDPOINT_NAME: &str = "desktop";

/// The on-disk shape of `[scheduler.notifications.webhooks]`.
///
/// `url` and `format` are the flat pair earlier desktop builds wrote. They are
/// read so an existing installation's setting still reaches the form, and never
/// written, so the dead keys leave the file on the first save.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct WebhookWire {
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    endpoints: Vec<WebhookEndpointWire>,
}

/// One entry of the endpoint list, matching `hardener-scheduler`'s own.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct WebhookEndpointWire {
    name: String,
    url: String,
    format: String,
}

impl From<WebhookWire> for WebhookUiConfig {
    fn from(wire: WebhookWire) -> Self {
        // The list wins when it has an entry, because that is what the daemon
        // reads; the flat pair answers only for a file written before it.
        let (url, format) = match wire.endpoints.into_iter().next() {
            Some(endpoint) => (endpoint.url, endpoint.format),
            None => (
                wire.url.unwrap_or_default(),
                wire.format.unwrap_or_default(),
            ),
        };
        Self {
            enabled: wire.enabled,
            url,
            format,
        }
    }
}

impl From<WebhookUiConfig> for WebhookWire {
    fn from(config: WebhookUiConfig) -> Self {
        // An endpoint with no URL is not a webhook, and the dispatcher would
        // post to it. `enabled` still round-trips on its own.
        let endpoints = if config.url.is_empty() {
            Vec::new()
        } else {
            let format = if config.format.is_empty() {
                DEFAULT_WEBHOOK_FORMAT.to_string()
            } else {
                config.format
            };
            vec![WebhookEndpointWire {
                name: DESKTOP_ENDPOINT_NAME.to_string(),
                url: config.url,
                format,
            }]
        };
        Self {
            enabled: config.enabled,
            url: None,
            format: None,
            endpoints,
        }
    }
}

/// Result of a test notification attempt.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TestNotificationResult {
    pub success: bool,
    pub message: String,
}

#[cfg(test)]
mod tests;
