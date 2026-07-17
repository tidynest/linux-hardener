//! SSH-based system executor for remote hosts.

use super::{CommandOutput, FileMetadata, SystemExecutor};
use anyhow::{Context, Result};
use async_trait::async_trait;
use openssh::{KnownHosts, Session, SessionBuilder};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

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

/// Builds the remote heredoc write command. The separator newline before the
/// delimiter is only inserted when the content does not already end with one,
/// so newline-terminated content round-trips byte-exact (matching
/// `LocalExecutor`). Content without a final newline still gains one; a
/// heredoc body is always newline-terminated.
fn tee_command(path: &Path, content: &str) -> String {
    let escaped = shell_escape(&path.display().to_string());
    let delim = unique_delimiter(content);
    let sep = if content.is_empty() || content.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    format!("sudo tee {escaped} > /dev/null << '{delim}'\n{content}{sep}{delim}")
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
        let output = self.run_command(&tee_command(path, content)).await?;

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
        let cmd = format!("stat -c '%F %a %s %u %g' {escaped} 2>/dev/null || echo 'NOTFOUND'");
        let output = self.run_command(&cmd).await?;

        parse_stat_metadata(&output.stdout)
            .ok_or_else(|| anyhow::anyhow!("Failed to parse stat output: {}", output.stdout.trim()))
    }

    async fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>> {
        let escaped = shell_escape(&path.display().to_string());
        // find prints one absolute path per line; config-dir entries never
        // contain newlines. ponytail: newline-in-filename unsupported.
        let cmd = format!("find {escaped} -mindepth 1 -maxdepth 1 2>/dev/null");
        let output = self.run_command(&cmd).await?;
        Ok(output
            .stdout
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(PathBuf::from)
            .collect())
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

/// Parses `stat -c '%F %a %s %u %g'` output (or the `NOTFOUND` sentinel) into
/// `FileMetadata`. Pure (no I/O) so the parse is unit-testable off a real host.
///
/// The file-type bit from `%F` is OR-ed into `mode`, so any existing path has a
/// non-zero mode. Checkpoint rollback reads `mode == 0` as "did not exist at
/// capture" and removes the path; without the type bit a legitimate 0000-perm
/// file (e.g. Arch's `/etc/shadow`) would be deleted on a remote rollback. This
/// mirrors the local executor, which returns the full `st_mode`. Returns `None`
/// when the line has too few fields to parse.
fn parse_stat_metadata(stdout: &str) -> Option<FileMetadata> {
    let stdout = stdout.trim();
    if stdout == "NOTFOUND" || stdout.is_empty() {
        return Some(FileMetadata {
            exists: false,
            is_file: false,
            is_dir: false,
            mode: 0,
            size: 0,
            uid: 0,
            gid: 0,
        });
    }

    // "%F %a %s %u %g": %F (file type) may contain spaces, so split from the
    // right: rsplitn(5, ' ') yields [gid, uid, size, mode, file_type].
    let parts: Vec<&str> = stdout.rsplitn(5, ' ').collect();
    if parts.len() < 5 {
        return None;
    }
    let file_type = parts[4];
    let is_dir = file_type.contains("directory");
    let permission_bits = u32::from_str_radix(parts[3], 8).unwrap_or(0);
    // S_IFDIR for directories, S_IFREG otherwise, covers every path the
    // checkpoint layer captures (special files are never checkpointed).
    let type_bit = if is_dir { 0o040000 } else { 0o100000 };

    Some(FileMetadata {
        exists: true,
        is_file: file_type.contains("regular") || file_type.contains("file"),
        is_dir,
        mode: type_bit | permission_bits,
        size: parts[2].parse().unwrap_or(0),
        uid: parts[1].parse().unwrap_or(0),
        gid: parts[0].parse().unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tee_command_round_trips_newline_terminated_content() {
        // A remote apply→rollback cycle must not grow files: content that
        // already ends in a newline gets no separator before the delimiter.
        let content = "Hello!\n";
        let delim = unique_delimiter(content);
        let cmd = tee_command(Path::new("/tmp/t"), content);
        assert!(
            cmd.ends_with(&format!("<< '{delim}'\n{content}{delim}")),
            "newline-terminated content must not be doubled: {cmd}"
        );
    }

    #[test]
    fn tee_command_terminates_bare_content_with_single_newline() {
        let content = "Hello!";
        let delim = unique_delimiter(content);
        let cmd = tee_command(Path::new("/tmp/t"), content);
        assert!(
            cmd.ends_with(&format!("<< '{delim}'\n{content}\n{delim}")),
            "bare content gains exactly one heredoc newline: {cmd}"
        );
    }

    #[test]
    fn tee_command_writes_empty_content_as_empty_body() {
        let delim = unique_delimiter("");
        let cmd = tee_command(Path::new("/tmp/t"), "");
        assert!(
            cmd.ends_with(&format!("<< '{delim}'\n{delim}")),
            "empty content must produce an empty heredoc body: {cmd}"
        );
    }

    #[test]
    fn parse_stat_zero_perm_file_is_not_confused_with_missing() {
        // A remote 0000-perm regular file (e.g. Arch's /etc/shadow): rollback reads
        // mode 0 as "did not exist" and deletes it, so an existing file must never
        // parse to mode 0. Parity with local.rs::metadata_of_zero_perm_file_*.
        let meta = parse_stat_metadata("regular empty file 0 0 0 0").expect("parse");
        assert!(meta.exists && meta.is_file);
        assert_ne!(
            meta.mode, 0,
            "existing 0000-perm remote file must not report mode 0"
        );
        assert_eq!(
            meta.mode & 0o777,
            0,
            "permission bits must still read as 0000"
        );
    }

    #[test]
    fn parse_stat_notfound_keeps_zero_mode_sentinel() {
        let meta = parse_stat_metadata("NOTFOUND").expect("parse");
        assert!(!meta.exists);
        assert_eq!(
            meta.mode, 0,
            "absent path keeps the mode-0 'did not exist' sentinel"
        );
    }

    #[test]
    fn parse_stat_directory_preserves_perms_and_type() {
        let meta = parse_stat_metadata("directory 755 4096 0 0").expect("parse");
        assert!(meta.is_dir);
        assert_eq!(meta.mode & 0o777, 0o755);
        assert_ne!(meta.mode & 0o170000, 0, "type bit present for existing dir");
    }

    #[test]
    fn parse_stat_regular_file_parses_all_fields() {
        // rsplitn from the right: gid=42, uid=0, size=1234, mode=640, type="regular file".
        let meta = parse_stat_metadata("regular file 640 1234 0 42").expect("parse");
        assert_eq!(meta.mode & 0o777, 0o640);
        assert_eq!(meta.size, 1234);
        assert_eq!(meta.uid, 0);
        assert_eq!(meta.gid, 42);
    }
}
