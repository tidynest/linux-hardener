//! Types for the config file picker UI.

use serde::{Deserialize, Serialize};

/// Summary of a validated configuration file.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ConfigSummary {
    /// Path to the config file that was validated.
    pub config_path: String,
    /// Whether the file parsed successfully.
    pub config_is_valid: bool,
    /// Parse error message (None if valid).
    pub config_error: Option<String>,
    /// Names of plugins that are enabled in this config.
    pub config_enabled_plugins: Vec<String>,
    /// Total directive count across all plugin sections.
    pub config_directive_count: u32,
    /// Total exception count across all plugin sections.
    pub config_exception_count: u32,
}
