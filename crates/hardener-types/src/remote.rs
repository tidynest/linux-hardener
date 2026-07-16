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
    /// `--ssh` flag and the desktop's ad-hoc fleet hosts — one parser, no
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_target_parses_user_host_port() {
        let p = RemoteHostProfile::from_target("admin@web-01:2222", 22, None, true);
        assert_eq!(p.user.as_deref(), Some("admin"));
        assert_eq!(p.hostname, "web-01");
        assert_eq!(p.port, 2222, ":port suffix overrides the default");
        assert_eq!(p.name, "web-01", "name is the bare hostname");
    }

    #[test]
    fn from_target_applies_caller_defaults() {
        let p = RemoteHostProfile::from_target("web-01", 2200, Some("/k".into()), false);
        assert_eq!(p.user, None, "no user part means current user");
        assert_eq!(p.port, 2200, "caller default port applies without :suffix");
        assert_eq!(p.key_file.as_deref(), Some("/k"));
        assert!(!p.host_key_checking);
    }

    #[test]
    fn from_target_leaves_ipv6_and_bad_ports_alone() {
        let v6 = RemoteHostProfile::from_target("root@fe80::1", 22, None, true);
        assert_eq!(v6.hostname, "fe80::1", "unbracketed IPv6 keeps its colons");
        assert_eq!(v6.port, 22, "IPv6 target keeps the default port");
        let bad = RemoteHostProfile::from_target("host:notaport", 22, None, true);
        assert_eq!(
            bad.hostname, "host:notaport",
            "unparsable port is not split"
        );
        assert_eq!(bad.port, 22);
    }
}
