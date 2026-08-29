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

/// ssh-agent / key hint appended when a connect failure names an auth problem.
const SSH_AUTH_HINT: &str =
    "no usable SSH key - load one with `ssh-add` or configure a key file for this host";

/// Builds the user-facing connect error from the target `host` and the
/// underlying ssh failure `detail` (openssh's full chain, rendered `{e:#}`).
/// The reason always reaches the user; the ssh-agent/key hint is appended only
/// when `detail` names an authentication/agent failure, never a network one
/// (connection refused, timeout, no route, name resolution), so a genuine
/// network outage is never mislabelled as auth. Pure: unit-tested without a
/// live sshd, since the connect path itself needs one.
fn connect_error_message(host: &str, detail: &str) -> String {
    let detail = detail.trim();
    let base = format!("Failed to connect to {host}: {detail}");
    if hardener_common::error::message_indicates_ssh_auth_failure(detail) {
        format!("{base} ({SSH_AUTH_HINT})")
    } else {
        base
    }
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

        // The one place every connection passes through, whichever front end
        // built the config. The CLI prints a warning on stderr when its own
        // flag lowers the policy, but the desktop builds the same permissive
        // variant with no such warning, and stderr is not where a later audit
        // of the log looks. This line is the durable record that the run
        // skipped host-key verification, and it fires once per connection
        // however the config was assembled.
        if matches!(config.known_hosts, KnownHosts::Accept) {
            tracing::warn!(
                host = %config.host,
                "SSH host key verification is disabled for this connection; it is vulnerable to on-path impersonation"
            );
        }

        if let Some(ref identity) = config.identity_file {
            builder.keyfile(identity);
        }

        builder.connect_timeout(config.connect_timeout);

        // openssh folds the real ssh reason (auth/agent vs network) into its
        // `source()` chain - the leaf io error carries "Connection refused",
        // "Permission denied (publickey)", etc. `openssh::Error`'s own Display
        // stops at its top line, so wrap it in anyhow first and render `{:#}` to
        // walk the whole chain, then bake that into the message. Every caller -
        // batch's `e.to_string()` and the desktop's `safe_err` alike - then
        // surfaces the reason without reaching for the alternate formatter.
        let session = builder.connect(&config.host).await.map_err(|e| {
            let detail = format!("{:#}", anyhow::Error::new(e));
            anyhow::anyhow!(connect_error_message(&config.host, &detail))
        })?;

        Ok(Self {
            session,
            host: config.host,
            user: config.user,
            port: config.port,
        })
    }

    /// The account this connection reaches the host as.
    ///
    /// Exactly the user [`SystemExecutor::description`] embeds, because both go
    /// through [`effective_ssh_user`], so a caller reporting who it connected as
    /// cannot name a different account than the checkpoints it takes are filed
    /// under. Resolved on demand rather than stored: `connect` never learns the
    /// account when the target names none, since `openssh` lets ssh itself pick
    /// it, and asking `ssh -G` afterwards is the only way back to the answer.
    pub fn effective_user(&self) -> String {
        effective_ssh_user(self.user.as_deref(), &self.host)
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

/// The host key a remote target's checkpoints are filed under, derived from the
/// target alone so a run can know it before opening a connection.
///
/// [`SshExecutor::description`] returns exactly this, and `host_key_for` returns
/// that description for any remote executor, so this is the one place the string
/// is built. A caller that needs the key in advance, such as a fleet run
/// checking that its selected hosts can be told apart, must call this rather
/// than reassemble the format, or the predicted key and the recorded one could
/// drift apart without any test noticing.
///
/// A target that names no user is resolved rather than assumed. Earlier
/// releases substituted the literal `root`, which was not a claim about the
/// remote account but a fabrication: ssh resolves a bare target through the
/// operator's `~/.ssh/config`, so the account it lands on is frequently
/// something else. It made `--ssh h` and `--ssh root@h` one key while they were
/// two targets everywhere else.
///
/// Checkpoints filed under the fabricated key are still found, because lookups
/// accept [`legacy_checkpoint_host_key`] alongside this one. They cannot be
/// migrated: `ssh://root@h:22` cannot say whether the operator wrote `root@h`
/// or wrote `h` and had the `root` invented for them, so a rewrite would
/// corrupt whichever of the two it guessed wrong.
pub fn checkpoint_host_key(user: Option<&str>, host: &str, port: u16) -> String {
    checkpoint_host_key_with(resolve_ssh_user, user, host, port)
}

/// The user earlier releases assumed when a target named none.
const ASSUMED_USER: &str = "root";

/// The key a release before the user was resolved filed this target under.
///
/// Lookups accept it beside the resolved key, so an operator's existing remote
/// checkpoints stay visible and stay offered as rollback points. Captures never
/// write it.
pub fn legacy_checkpoint_host_key(host: &str, port: u16) -> String {
    format!("ssh://{ASSUMED_USER}@{host}:{port}")
}

/// The account ssh will reach `host` as, given what the target named.
///
/// The user half of [`checkpoint_host_key`], and the same string it embeds, so
/// anything reporting "you are connected as X" agrees with the key that host's
/// checkpoints are filed under. The desktop's connection banner said
/// `whoami::username()` until 2026-08-26 while its checkpoints went to whatever
/// `~/.ssh/config` resolved, so one connection gave two answers and the one an
/// operator read was the one nothing depended on.
pub fn effective_ssh_user(user: Option<&str>, host: &str) -> String {
    effective_ssh_user_with(resolve_ssh_user, user, host)
}

/// [`effective_ssh_user`] with the resolver injected, so the precedence and the
/// fallback can be tested without depending on the machine's `~/.ssh/config`.
fn effective_ssh_user_with(
    resolve: impl Fn(&str) -> Option<String>,
    user: Option<&str>,
    host: &str,
) -> String {
    match user {
        Some(named) => named.to_string(),
        // A resolver that cannot answer leaves the old fabrication in place
        // rather than inventing a different one. That is the pre-existing
        // behaviour, and the collision refusal in `batch` is what catches the
        // two targets it can still merge.
        None => resolve(host).unwrap_or_else(|| ASSUMED_USER.to_string()),
    }
}

/// [`checkpoint_host_key`] with the resolver injected, so the format and the
/// fallback can be tested without depending on the machine's `~/.ssh/config`.
fn checkpoint_host_key_with(
    resolve: impl Fn(&str) -> Option<String>,
    user: Option<&str>,
    host: &str,
    port: u16,
) -> String {
    let effective = effective_ssh_user_with(resolve, user, host);
    format!("ssh://{effective}@{host}:{port}")
}

/// The user ssh itself would use for `host`, without opening a connection.
///
/// `ssh -G` prints the effective configuration for a target, `user` included,
/// after applying every matching `Host` block in the operator's config. It
/// connects to nothing, which is what keeps the key derivable before a
/// connection exists: the fleet collision check needs it in advance.
///
/// `None` only when ssh cannot be run or prints no `user` line at all, which in
/// practice means ssh is missing, and then nothing else here works either.
fn resolve_ssh_user(host: &str) -> Option<String> {
    let output = std::process::Command::new("ssh")
        .args(["-G", "--", host])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())?
        .lines()
        .find_map(|line| line.strip_prefix("user ").map(str::trim))
        .filter(|user| !user.is_empty())
        .map(str::to_string)
}

#[async_trait]
impl SystemExecutor for SshExecutor {
    fn description(&self) -> String {
        checkpoint_host_key(self.user.as_deref(), &self.host, self.port)
    }

    /// Only a target that named no user moved: its key used to name the
    /// fabricated `root`. A target that named its user has always been filed
    /// under exactly what it named, so it has nothing to fall back to.
    fn legacy_description(&self) -> Option<String> {
        self.user
            .is_none()
            .then(|| legacy_checkpoint_host_key(&self.host, self.port))
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
        parse_path_exists_probe(&output.stdout)
            .with_context(|| format!("Failed to determine whether {} exists", path.display()))
    }

    async fn file_metadata(&self, path: &Path) -> Result<FileMetadata> {
        let output = self.run_command(&metadata_probe_command(path)).await?;
        parse_metadata_probe(&output.stdout)
            .with_context(|| format!("Failed to determine metadata for {}", path.display()))
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
}

/// Classifies the trimmed output of `path_exists`'s `test -e {path} && echo
/// yes || echo no` probe.
///
/// The command can only print `yes` or `no` on success, so matching is exact
/// rather than a substring or prefix check: a login banner, a sudo password
/// prompt, or any other shell noise mixed into stdout must not be folded into
/// `no`. Rollback's undeletable-path guard treats an `Err` here as "cannot be
/// determined" and refuses to delete; reading unexpected output as absence
/// would make that fail-closed arm unreachable over SSH, the same defect
/// `parse_metadata_probe` fixed for `file_metadata`. Pure (no I/O) so the
/// classification is unit-testable without a live connection.
fn parse_path_exists_probe(stdout: &str) -> Result<bool> {
    match stdout.trim() {
        "yes" => Ok(true),
        "no" => Ok(false),
        other => Err(anyhow::anyhow!(
            "unrecognised path_exists probe output: {other:?}"
        )),
    }
}

/// Builds the metadata probe: an existence marker, then `stat` output when
/// `stat` succeeds. Both probes run in one shell invocation, so this costs a
/// single round trip and leaves the smallest window a remote check can.
///
/// `stat` alone cannot carry this. It exits non-zero for a missing path and for
/// an unreadable one alike, so the previous `|| echo NOTFOUND` shape reported
/// every failure as absence, and rollback deletes what it recorded as absent.
///
/// **`LC_ALL=C` is load-bearing** (#155). `%F` is a translated string, so a
/// remote host running under any other locale answers in that language and
/// [`parse_stat_fields`] matches neither `regular` nor `directory`: a file
/// reports as not a file, checkpoint capture skips it, and a directory takes
/// the wrong type bit. Measured: `LC_ALL=sv_SE.utf8 stat -c '%F' /etc/passwd`
/// prints `normal fil` and the same command on `/etc` prints `katalog`. Only
/// `stat` needs the pin; the existence marker is a literal this command
/// chooses, and every other remote probe parses paths, numbers or exit codes.
/// `LocalExecutor` reads `std::fs::Metadata` and carries no locale at all, so
/// pinning here is also what keeps the two executors answering alike.
fn metadata_probe_command(path: &Path) -> String {
    let escaped = shell_escape(&path.display().to_string());
    format!(
        "test -e {escaped} && echo E || echo N; LC_ALL=C stat -c '%F %a %s %u %g' {escaped} 2>/dev/null || true"
    )
}

/// Parses one `stat -c '%F %a %s %u %g'` line into `FileMetadata`.
///
/// The file-type bit from `%F` is OR-ed into `mode`, so any existing path has a
/// non-zero mode. Checkpoint rollback reads `mode == 0` as "did not exist at
/// capture" and removes the path; without the type bit a legitimate 0000-perm
/// file (for example Arch's `/etc/shadow`) would be deleted on a remote
/// rollback. This mirrors the local executor, which returns the full `st_mode`.
/// Returns `None` when the line has too few fields to parse.
fn parse_stat_fields(line: &str) -> Option<FileMetadata> {
    // "%F %a %s %u %g": %F (file type) may contain spaces, so split from the
    // right: rsplitn(5, ' ') yields [gid, uid, size, mode, file_type].
    let parts: Vec<&str> = line.rsplitn(5, ' ').collect();
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
        // `regular file` and `regular empty file` are the only `%F` strings for
        // one, so `regular` alone decides it. A second `contains("file")` arm
        // used to sit here, and it made `character special file` and `block
        // special file` report as files while `LocalExecutor`, which answers
        // from `std::fs::Metadata::is_file`, reported them as not. Checkpoint
        // capture gates on this field, so the two executors disagreed about
        // the same path. This match and `is_dir` above are English-only, which
        // is why `metadata_probe_command` pins `LC_ALL=C`: see the note there,
        // and do not remove the pin without teaching both matches every
        // translation of `%F`.
        is_file: file_type.contains("regular"),
        is_dir,
        mode: type_bit | permission_bits,
        size: parts[2].parse().unwrap_or(0),
        uid: parts[1].parse().unwrap_or(0),
        gid: parts[0].parse().unwrap_or(0),
    })
}

/// Classifies the two-line probe emitted by `metadata_probe_command`.
///
/// Line 1 is the existence marker (`E` or `N`); line 2, when present, is the
/// `stat -c '%F %a %s %u %g'` output. Pure (no I/O) so the classification is
/// unit-testable off a real host.
///
/// Three outcomes, and the distinction is load bearing. `Ok(exists: false)`
/// means absence was positively confirmed; `Err` means existence or metadata
/// could not be determined. Checkpoint rollback deletes a path it recorded as
/// absent, so an unverifiable path must never be reported as missing.
fn parse_metadata_probe(stdout: &str) -> Result<FileMetadata> {
    let mut lines = stdout.trim().lines();
    let marker = lines.next().unwrap_or("").trim();
    let stat_line = lines.next().unwrap_or("").trim();

    // A parsed stat line is stronger evidence than the marker: if `test -e` lost
    // a race with the path being created, trust the metadata actually read.
    if !stat_line.is_empty() {
        return parse_stat_fields(stat_line)
            .ok_or_else(|| anyhow::anyhow!("Unparseable stat output: {stat_line}"));
    }

    match marker {
        "N" => Ok(FileMetadata {
            exists: false,
            is_file: false,
            is_dir: false,
            mode: 0,
            size: 0,
            uid: 0,
            gid: 0,
        }),
        "E" => Err(anyhow::anyhow!(
            "path exists but its metadata could not be read (stat failed or is incompatible)"
        )),
        other => Err(anyhow::anyhow!(
            "unrecognised metadata probe output: {other:?}"
        )),
    }
}

#[cfg(test)]
mod tests;
