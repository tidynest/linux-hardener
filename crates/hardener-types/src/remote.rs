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

impl RemoteHostProfile {
    /// Parses an ad-hoc `user@host[:port]` target into a profile. A `:port`
    /// suffix overrides `port` (the caller's default); `name` is the bare
    /// hostname, matching the CLI's inline-host convention. Shared by the CLI's
    /// `--ssh` flag and the desktop's ad-hoc fleet hosts: one parser, no
    /// drift. ponytail: unbracketed IPv6 keeps its default port (no unambiguous
    /// `host:port` form); add bracketed `[addr]` support only if a user needs it.
    pub fn from_target(
        target: &str,
        port: u16,
        key_file: Option<String>,
        host_key_checking: bool,
    ) -> Self {
        let (user, rest) = match target.split_once('@') {
            Some((u, h)) => (Some(u.to_string()), h),
            None => (None, target),
        };
        let (hostname, port) = match rest.rsplit_once(':') {
            Some((host, p)) if !host.contains(':') => match p.parse::<u16>() {
                Ok(parsed) => (host.to_string(), parsed),
                Err(_) => (rest.to_string(), port),
            },
            _ => (rest.to_string(), port),
        };
        Self {
            name: hostname.clone(),
            hostname,
            user,
            port,
            key_file,
            host_key_checking,
        }
    }

    /// True when `host` is a plausible hostname or IP for an ad-hoc target:
    /// non-empty, no leading `-` (which ssh would read as an option), and every
    /// character drawn from a conservative host set: ASCII letters and digits,
    /// `.`, `-`, plus `:` `[` `]` for IPv6 literals. Rejects the space, comma
    /// and other punctuation that a mistyped `user@host, note:port` slips past
    /// [`from_target`](Self::from_target). Run this on the already-parsed
    /// hostname (post user/port split), never the raw target. Shared by the
    /// desktop client and the Tauri backend so both guards stay mirrored; std
    /// only, so it also compiles for the WASM frontend.
    pub fn is_valid_hostname(host: &str) -> bool {
        !host.is_empty()
            && !host.starts_with('-')
            && host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
    }

    /// Canonical `user@host:port` (or `host:port`) target string. This is the
    /// batch history key for ad-hoc hosts, so the GUI and CLI agree on it.
    pub fn target(&self) -> String {
        match &self.user {
            Some(user) => format!("{}@{}:{}", user, self.hostname, self.port),
            None => format!("{}:{}", self.hostname, self.port),
        }
    }
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

/// One persisted scan session for a host's history expander. `started` is a
/// display-ready local datetime; `direction` compares against the next-older
/// scan by severity priority (`"better"` / `"worse"` / `"same"`), absent for
/// the oldest known scan.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostSessionInfo {
    pub started: String,
    pub status: String,
    pub total_findings: i32,
    pub critical: i32,
    pub high: i32,
    pub medium: i32,
    pub low: i32,
    pub info: i32,
    pub direction: Option<String>,
}

/// Tauri event name carrying [`FleetProgress`] payloads during a fleet scan.
/// One definition for backend emit and frontend listen.
pub const FLEET_PROGRESS_EVENT: &str = "fleet-progress";

/// One host finished during a fleet scan. `done`/`total` count completed
/// hosts so far, in completion (not input) order.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FleetProgress {
    /// Display name of the finished host (inventory name or ad-hoc target).
    pub host: String,
    /// Hosts completed so far, including this one.
    pub done: usize,
    /// Total hosts in this scan.
    pub total: usize,
    /// Whether this host ended in a failed status.
    pub failed: bool,
}

#[cfg(test)]
mod tests;
