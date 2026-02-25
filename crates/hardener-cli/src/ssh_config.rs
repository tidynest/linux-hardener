//! SSH configuration parsing and validation.

use std::{path::PathBuf, time::Duration};

/// Parsed SSH connection configuration.
#[derive(Clone, Debug)]
pub struct SshConnectionConfig {
    pub user: Option<String>,
    pub host: String,
    pub port: u16,
    pub identity_file: Option<PathBuf>,
    pub timeout: Duration,
    pub strict_host_key_checking: bool,
}

impl SshConnectionConfig {
    /// Parses SSH connection string (user@host or host) and CLI options.
    pub fn from_cli(
        ssh_target: &str,
        port: u16,
        identity_file: Option<PathBuf>,
        timeout_secs: u64,
        no_verify: bool,
    ) -> SshConnectionConfig {
        let (user, host) = if let Some(at_pos) = ssh_target.find('@') {
            let user = &ssh_target[..at_pos];
            let host = &ssh_target[at_pos + 1..];
            (Some(user.to_string()), host.to_string())
        } else {
            (None, ssh_target.to_string())
        };

        SshConnectionConfig {
            user,
            host,
            port,
            identity_file,
            timeout: Duration::from_secs(timeout_secs),
            strict_host_key_checking: !no_verify,
        }
    }

    /// Returns the connection string for display (user@host:port)
    pub fn display(&self) -> String {
        match &self.user {
            Some(user) => format!("{}@{}:{}", user, self.host, self.port),
            None => format!("{}:{}", self.host, self.port),
        }
    }

    /// Converts to hardener_core::SshConfig for the executor.
    pub fn to_core_config(&self) -> hardener_core::SshConfig {
        use openssh::KnownHosts;

        hardener_core::SshConfig {
            host: self.host.clone(),
            port: self.port,
            user: self.user.clone(),
            identity_file: self
                .identity_file
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            known_hosts: if self.strict_host_key_checking {
                KnownHosts::Strict
            } else {
                eprintln!(
                    "WARNING: SSH host key verification disabled - connection is vulnerable to MITM attacks"
                );
                KnownHosts::Accept
            },
            connect_timeout: self.timeout,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_user_at_host() {
        let config = SshConnectionConfig::from_cli("root@server.com", 22, None, 30, false);
        assert_eq!(config.user, Some("root".to_string()));
        assert_eq!(config.host, "server.com");
        assert_eq!(config.port, 22);
        assert!(config.strict_host_key_checking);
    }

    #[test]
    fn test_parse_host_only() {
        let config = SshConnectionConfig::from_cli("server.com", 2222, None, 60, true);
        assert_eq!(config.user, None);
        assert_eq!(config.host, "server.com");
        assert_eq!(config.port, 2222);
        assert!(!config.strict_host_key_checking);
    }

    #[test]
    fn test_display_with_user() {
        let config = SshConnectionConfig::from_cli("admin@host", 22, None, 30, false);
        assert_eq!(config.display(), "admin@host:22");
    }

    #[test]
    fn test_display_without_user() {
        let config = SshConnectionConfig::from_cli("host", 22, None, 30, false);
        assert_eq!(config.display(), "host:22");
    }
}
