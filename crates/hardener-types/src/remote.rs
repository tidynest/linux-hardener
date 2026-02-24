//! Types for remote SSH scanning.

use serde::{Deserialize, Serialize};

/// A saved SSH host profile for remote scanning.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RemoteHostProfile {
    /// Display name (e.g., "web-01").
    pub name: String,
    /// Hostname or IP address.
    pub hostname: String,
    /// SSH username. None uses current system user.
    pub user: Option<String>,
    /// SSH port (default 22).
    #[serde(default = "default_port")]
    pub port: u16,
    /// Path to SSH private key. None uses SSH agent.
    pub key_file: Option<String>,
    /// Whether to verify remote host key (default true).
    #[serde(default = "default_true")]
    pub host_key_checking: bool,
}

fn default_port() -> u16 {
    22
}

fn default_true() -> bool {
    true
}

/// TOML file structure for saved host profiles.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HostsConfig {
    #[serde(default)]
    pub hosts: Vec<RemoteHostProfile>,
}

/// Result of an SSH connection attempt.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RemoteConnectionStatus {
    /// Successfully connected.
    Connected { host: String, user: String },
    /// Connection failed.
    Failed { error: String },
}

/// Active connection info for the UI.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemoteConnectionInfo {
    pub profile_name: String,
    pub host: String,
    pub user: String,
}
