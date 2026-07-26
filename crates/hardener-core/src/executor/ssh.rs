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

    async fn command_exists(&self, program: &str) -> Result<bool> {
        let output = self.execute_command("which", &[program]).await?;
        Ok(output.success())
    }
}

/// Builds the metadata probe: an existence marker, then `stat` output when
/// `stat` succeeds. Both probes run in one shell invocation, so this costs a
/// single round trip and leaves the smallest window a remote check can.
///
/// `stat` alone cannot carry this. It exits non-zero for a missing path and for
/// an unreadable one alike, so the previous `|| echo NOTFOUND` shape reported
/// every failure as absence, and rollback deletes what it recorded as absent.
fn metadata_probe_command(path: &Path) -> String {
    let escaped = shell_escape(&path.display().to_string());
    format!(
        "test -e {escaped} && echo E || echo N; stat -c '%F %a %s %u %g' {escaped} 2>/dev/null || true"
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
        is_file: file_type.contains("regular") || file_type.contains("file"),
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
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn connect_error_carries_reason_and_no_hint_on_network_failure() {
        // openssh's `{e:#}` for a closed port; the reason must reach the user
        // and a genuine network fault must never get the auth hint.
        let detail = "failed to connect to the remote host: connect to host 10.0.0.5 port 22: Connection refused";
        let msg = connect_error_message("10.0.0.5", detail);
        assert!(msg.starts_with("Failed to connect to 10.0.0.5: "));
        assert!(msg.contains("Connection refused"), "reason surfaced: {msg}");
        assert!(
            !msg.contains("ssh-add"),
            "network failure must not get the auth hint: {msg}"
        );
    }

    #[test]
    fn connect_error_appends_hint_on_auth_failure() {
        let detail =
            "failed to connect to the remote host: root@10.0.0.5: Permission denied (publickey).";
        let msg = connect_error_message("10.0.0.5", detail);
        assert!(
            msg.contains("Permission denied (publickey)"),
            "reason surfaced: {msg}"
        );
        assert!(
            msg.contains("ssh-add"),
            "auth failure gets the ssh-agent/key hint: {msg}"
        );
    }

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
        let meta = parse_metadata_probe("E\nregular empty file 0 0 0 0").expect("parse");
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
    fn parse_stat_directory_preserves_perms_and_type() {
        let meta = parse_metadata_probe("E\ndirectory 755 4096 0 0").expect("parse");
        assert!(meta.is_dir);
        assert_eq!(meta.mode & 0o777, 0o755);
        assert_ne!(meta.mode & 0o170000, 0, "type bit present for existing dir");
    }

    #[test]
    fn parse_stat_regular_file_parses_all_fields() {
        // rsplitn from the right: gid=42, uid=0, size=1234, mode=640, type="regular file".
        let meta = parse_metadata_probe("E\nregular file 640 1234 0 42").expect("parse");
        assert_eq!(meta.mode & 0o777, 0o640);
        assert_eq!(meta.size, 1234);
        assert_eq!(meta.uid, 0);
        assert_eq!(meta.gid, 42);
    }

    #[test]
    fn probe_marks_existing_but_unreadable_path_as_unverifiable() {
        // The whole point of the change: `stat` failed on a path that is there.
        // Reporting this as absent is what let rollback delete /etc/passwd.
        let err = parse_metadata_probe("E\n").expect_err("must not report absence");
        let message = format!("{err:#}");
        assert!(
            message.contains("could not be read"),
            "error must say the metadata was unreadable, got: {message}"
        );
    }

    #[test]
    fn probe_reports_confirmed_absence_as_ok() {
        // `test -e` said no and `stat` printed nothing: absence is confirmed, and
        // this must stay a non-error so hosts lacking an optional path still work.
        let meta = parse_metadata_probe("N\n").expect("confirmed absence is not an error");
        assert!(!meta.exists);
        assert_eq!(
            meta.mode, 0,
            "absent path keeps the mode-0 'did not exist' sentinel"
        );
    }

    #[test]
    fn probe_trusts_a_parsed_stat_line_over_a_losing_marker() {
        // `test -e` can lose a race with a path being created between the two
        // probes. A parsed stat line is the stronger evidence.
        let meta = parse_metadata_probe("N\nregular file 640 1234 0 42")
            .expect("a stat line wins over the marker");
        assert!(meta.exists);
        assert_eq!(meta.mode & 0o777, 0o640);
    }

    #[test]
    fn probe_rejects_an_unrecognised_marker() {
        // A shell that emitted something else entirely must not be read as absence.
        parse_metadata_probe("something unexpected\n")
            .expect_err("an unrecognised marker must not report absence");
    }

    #[test]
    fn metadata_probe_confirms_existence_and_reads_stat_in_one_round_trip() {
        let cmd = metadata_probe_command(Path::new("/etc/shadow"));
        assert!(
            cmd.contains("test -e"),
            "absence must be positively confirmed, not inferred from stat failing"
        );
        assert!(cmd.contains("stat -c '%F %a %s %u %g'"));
        assert!(cmd.contains("echo E") && cmd.contains("echo N"));
        assert!(
            !cmd.contains("NOTFOUND"),
            "the sentinel that conflated absent with unreadable must be gone"
        );
    }

    #[test]
    fn metadata_probe_escapes_a_path_with_spaces() {
        // Both occurrences of the path must be escaped, or a crafted path could
        // break out of one of them.
        let cmd = metadata_probe_command(Path::new("/etc/my dir/file"));
        assert!(
            !cmd.contains("/etc/my dir/file "),
            "unescaped path leaked into the command: {cmd}"
        );
    }

    // The two tests above assert on substrings of the command text. A command
    // with `&&`/`||` swapped, or a `stat` gated on the wrong branch, still
    // contains every one of those substrings and would still pass them - that
    // textual match is exactly how the original `|| echo 'NOTFOUND'` survived
    // review. The tests below run the real command through a real shell
    // instead, so they exercise the actual branch behaviour.

    /// Scratch directory unique to one test run, so parallel test binaries and
    /// repeated runs never collide. Removed on drop, including on panic, so a
    /// failing assertion never leaks a directory under the system temp dir.
    struct ScratchDir(PathBuf);

    impl ScratchDir {
        fn new(label: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos();
            let dir = std::env::temp_dir().join(format!(
                "hardener-ssh-metadata-probe-{label}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).expect("create scratch dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Runs `metadata_probe_command(path)` through a real `/bin/sh -c`,
    /// optionally shadowing PATH lookups with `fake_bin_dir` prepended ahead
    /// of the real PATH (used to make `stat` resolve to a binary that always
    /// fails), and returns raw stdout for `parse_metadata_probe` to classify.
    /// The shell itself is located by absolute path so overriding PATH for
    /// `stat` resolution never breaks finding `sh`.
    fn run_probe(path: &Path, fake_bin_dir: Option<&Path>) -> String {
        let mut command = std::process::Command::new("/bin/sh");
        command.arg("-c").arg(metadata_probe_command(path));
        if let Some(dir) = fake_bin_dir {
            let real_path = std::env::var("PATH").unwrap_or_default();
            command.env("PATH", format!("{}:{real_path}", dir.display()));
        }
        let output = command
            .output()
            .expect("run the metadata probe under a real shell");
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    #[test]
    fn metadata_probe_execution_confirms_an_existing_readable_path() {
        let dir = ScratchDir::new("exists");
        let file = dir.path().join("target");
        std::fs::write(&file, b"content").expect("write fixture file");

        let stdout = run_probe(&file, None);
        assert!(
            stdout.starts_with("E\n"),
            "an existing path must be positively confirmed, got: {stdout:?}"
        );
        let meta = parse_metadata_probe(&stdout).expect("existing readable path must parse");
        assert!(meta.exists, "readable existing path must report exists");
    }

    #[test]
    fn metadata_probe_execution_confirms_an_absent_path() {
        let dir = ScratchDir::new("absent");
        let missing = dir.path().join("does-not-exist");

        let stdout = run_probe(&missing, None);
        assert_eq!(
            stdout.trim(),
            "N",
            "an absent path must yield a bare N marker, got: {stdout:?}"
        );
        let meta = parse_metadata_probe(&stdout).expect("confirmed absence must not be an error");
        assert!(!meta.exists, "absent path must report exists = false");
    }

    #[test]
    fn metadata_probe_execution_flags_an_existing_unreadable_path_as_unverifiable() {
        let dir = ScratchDir::new("stat-fails");
        let file = dir.path().join("target");
        std::fs::write(&file, b"content").expect("write fixture file");

        // Shadow `stat` on PATH with a binary that always fails, so the path
        // genuinely exists while the stat probe genuinely produces nothing -
        // the same shape an incompatible `stat` or a permission error
        // produces on a real host. `test` and `echo` are shell builtins, so
        // they still resolve correctly under this restricted PATH.
        let fake_bin = dir.path().join("fakebin");
        std::fs::create_dir_all(&fake_bin).expect("create fake bin dir");
        let fake_stat = fake_bin.join("stat");
        std::fs::write(&fake_stat, b"#!/bin/sh\nexit 1\n").expect("write fake stat binary");
        let mut perms = std::fs::metadata(&fake_stat)
            .expect("stat the fake stat binary")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&fake_stat, perms).expect("make fake stat executable");

        let stdout = run_probe(&file, Some(&fake_bin));
        assert_eq!(
            stdout.trim(),
            "E",
            "existing path with a failing stat must yield a bare E marker, got: {stdout:?}"
        );
        let err = parse_metadata_probe(&stdout)
            .expect_err("a path that exists but cannot be stat'd must never read as absent");
        let message = format!("{err:#}");
        assert!(
            message.contains("could not be read"),
            "error must say the metadata was unreadable, got: {message}"
        );
    }
}
