//! SSH-based system executor for remote hosts.

use super::{CommandOutput, FileMetadata, SystemExecutor};
use anyhow::{Context, Result};
use async_trait::async_trait;
use openssh::{KnownHosts, Session, SessionBuilder};
use std::{path::Path, time::Duration};

/// SSH executor configuration.
#[derive(Clone, Debug)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub identity_file: Option<String>,
    pub known_hosts: KnownHosts,
    pub connect_timeout: Duration,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 22,
            user: None,
            identity_file: None,
            known_hosts: KnownHosts::Strict,
            connect_timeout: Duration::from_secs(30),
        }
    }
}

/// Escapes a string for safe inclusion in a single-quoted shell argument.
///
/// Replaces each single quote with the sequence `'\''` which ends the
/// current single-quoted string, adds an escaped quote, and reopens.
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Generate a heredoc delimiter guaranteed absent from `content`.
fn unique_delimiter(content: &str) -> String {
    let mut delim = String::from("HARDENER_EOF");
    while content.contains(&delim) {
        delim.push('X');
    }
    delim
}

/// SSH-based system executor for remote hosts.
pub struct SshExecutor {
    session: Session,
    host: String,
    user: Option<String>,
    port: u16,
}

impl SshExecutor {
    /// Creates a new SSH executor by connecting to the remote host.
    pub async fn connect(config: SshConfig) -> Result<Self> {
        let mut builder = SessionBuilder::default();

        if let Some(ref user) = config.user {
            builder.user(user.clone());
        }

        builder.port(config.port);
        builder.known_hosts_check(config.known_hosts.clone());

        if let Some(ref identity) = config.identity_file {
            builder.keyfile(identity);
        }

        builder.connect_timeout(config.connect_timeout);

        let session = builder
            .connect(&config.host)
            .await
            .with_context(|| format!("Failed to connect to {}", config.host))?;

        Ok(Self {
            session,
            host: config.host,
            user: config.user,
            port: config.port,
        })
    }

    /// Helper to execute a remote command and get output.
    async fn run_command(&self, cmd: &str) -> Result<CommandOutput> {
        let output = self
            .session
            .raw_command(cmd)
            .output()
            .await
            .with_context(|| format!("SSH command failed: {}", cmd))?;

        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or(-1),
        })
    }
}

#[async_trait]
impl SystemExecutor for SshExecutor {
    fn description(&self) -> String {
        format!(
            "ssh://{}@{}:{}",
            self.user.as_deref().unwrap_or("root"),
            self.host,
            self.port,
        )
    }

    fn is_remote(&self) -> bool {
        true
    }

    async fn read_file(&self, path: &Path) -> Result<String> {
        let escaped = shell_escape(&path.display().to_string());
        let cmd = format!("cat {escaped}");
        let output = self.run_command(&cmd).await?;

        if output.success() {
            Ok(output.stdout)
        } else {
            anyhow::bail!("Failed to read {}: {}", path.display(), output.stderr)
        }
    }

    async fn read_file_optional(&self, path: &Path) -> Result<Option<String>> {
        let escaped = shell_escape(&path.display().to_string());
        let cmd = format!("cat {escaped} 2>/dev/null");
        let output = self.run_command(&cmd).await?;

        if output.success() {
            Ok(Some(output.stdout))
        } else {
            Ok(None)
        }
    }

    async fn write_file(&self, path: &Path, content: &str) -> Result<()> {
        let escaped = shell_escape(&path.display().to_string());
        let delim = unique_delimiter(content);
        let cmd = format!(
            "sudo tee {escaped} > /dev/null << '{delim}'\n{content}\n{delim}"
        );
        let output = self.run_command(&cmd).await?;

        if output.success() {
            Ok(())
        } else {
            anyhow::bail!("Failed to write {}: {}", path.display(), output.stderr)
        }
    }

    async fn path_exists(&self, path: &Path) -> Result<bool> {
        let escaped = shell_escape(&path.display().to_string());
        let cmd = format!("test -e {escaped} && echo yes || echo no");

        let output = self.run_command(&cmd).await?;
        Ok(output.stdout.trim() == "yes")
    }

    async fn file_metadata(&self, path: &Path) -> Result<FileMetadata> {
        let escaped = shell_escape(&path.display().to_string());
        let cmd = format!(
            "stat -c '%F %a %s' {escaped} 2>/dev/null || echo 'NOTFOUND'"
        );
        let output = self.run_command(&cmd).await?;

        let stdout = output.stdout.trim();
        if stdout == "NOTFOUND" || stdout.is_empty() {
            return Ok(FileMetadata {
                exists: false,
                is_file: false,
                is_dir: false,
                mode: 0,
                size: 0,
            });
        }

        // Parse stat output: "regular file 644 1234"
        let parts: Vec<&str> = stdout.rsplitn(3, ' ').collect();
        if parts.len() >= 3 {
            let size_str = parts[0];
            let mode_str = parts[1];
            let file_type = parts[2];

            Ok(FileMetadata {
                exists: true,
                is_file: file_type.contains("regular") || file_type.contains("file"),
                is_dir: file_type.contains("directory"),
                mode: u32::from_str_radix(mode_str, 8).unwrap_or(0),
                size: size_str.parse().unwrap_or(0),
            })
        } else {
            anyhow::bail!("Failed to parse stat output: {}", stdout)
        }
    }

    async fn execute_command(&self, program: &str, args: &[&str]) -> Result<CommandOutput> {
        let output = self
            .session
            .command(program)
            .args(args)
            .output()
            .await
            .with_context(|| format!("SSH command failed: {} {}", program, args.join(" ")))?;
        
        Ok(CommandOutput { 
            stdout: String::from_utf8_lossy(&output.stdout).to_string(), 
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or(-1),
        })

    }

    async fn command_exists(&self, program: &str) -> Result<bool> {
        let output = self.execute_command("which", &[program]).await?;
        Ok(output.success())
    }
}
