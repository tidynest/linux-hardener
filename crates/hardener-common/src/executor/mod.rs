//! Executor abstraction shared across crates (local/remote file + command ops).

use anyhow::Result;
use async_trait::async_trait;
use std::path::{Path, PathBuf};

pub mod mock;
pub use mock::MockExecutor;

/// Output from executing a system command.
#[derive(Clone, Debug)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

impl CommandOutput {
    /// Returns true if the command exited successfully (code 0).
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

/// File metadata information.
#[derive(Clone, Debug)]
pub struct FileMetadata {
    pub exists: bool,
    pub is_file: bool,
    pub is_dir: bool,
    pub mode: u32,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
}

/// The one round trip behind [`SystemExecutor::link_target_as_writer`].
///
/// `$1` is the path, passed as a positional argument rather than interpolated,
/// so no quoting is involved anywhere and a path holding a space or a `;` is
/// one argument. `$2` is the elevation to use, also a positional argument
/// rather than baked into the script: see [`SystemExecutor::link_target_as_writer`]
/// for what each shipped executor passes and why.
///
/// The uid check stays regardless of what `$2` holds. A session that is
/// already root needs no elevation even when asked for one, and a root
/// container may ship no `sudo` binary at all; `E` is empty whenever the
/// session is root, so that case is unaffected by `$2`.
///
/// The parent gate is what makes `NOTLINK` trustworthy. GNU `readlink` exits 1
/// for "not a symlink", for `ENOENT` and for a traversal it may not make, one
/// status for three meanings, and only the first is an answer. A parent that
/// resolves proves traverse permission is held, so the `lstat` behind `test -h`
/// looked at something rather than failing to look. Telling the three apart by
/// reading errno text instead was rejected: those strings are locale-dependent,
/// which would turn this gate into a coin flip on a host with `LC_MESSAGES`
/// set.
///
/// `readlink -e` resolves **every** component, which is why the link is not
/// followed hop by hop with `..` flattened by name. With `<allowed>/dlink` a
/// link to a directory outside the allowlist, `<allowed>/f -> dlink/../victim`
/// collapses by name to `<allowed>/victim`, which an allowlist admits, while
/// the write lands on `<outside>/victim`. Only the kernel knows that `..`
/// follows `dlink` first.
pub(crate) const LINK_PROBE_SCRIPT: &str = r#"if [ "$(id -u)" -eq 0 ]; then E=""; else E="$2"; fi
d=$(dirname -- "$1")
$E readlink -e -n -- "$d" >/dev/null 2>&1 || { printf UNDETERMINED; exit 0; }
if $E test -h "$1"; then
  t=$($E readlink -e -n -- "$1") && printf 'LINK %s' "$t" || printf UNDETERMINED
else
  printf NOTLINK
fi"#;

/// Classifies the stdout of [`LINK_PROBE_SCRIPT`].
///
/// Exact matching, not a prefix or a substring search: a login banner, a sudo
/// lecture or any other shell noise must not be folded into a positive answer.
/// Everything the script cannot have printed, `UNDETERMINED` included, is the
/// refusing answer, so the fail-closed arm is reached by anything unexpected
/// rather than only by the one token that names it. Pure, so the
/// classification is unit-testable without a live connection.
pub(crate) fn parse_link_probe(stdout: &str) -> Result<Option<PathBuf>> {
    let answer = stdout.trim();

    if answer == "NOTLINK" {
        return Ok(None);
    }
    if let Some(target) = answer.strip_prefix("LINK ")
        && !target.is_empty()
    {
        return Ok(Some(PathBuf::from(target)));
    }

    Err(crate::error::HardeningError::Executor(format!(
        "could not determine whether the path is a symlink; the probe said {answer:?}"
    ))
    .into())
}

/// Strips the trailing `/` characters from `path` before it is handed to
/// [`LINK_PROBE_SCRIPT`].
///
/// A trailing slash makes `test -h` follow the link: POSIX requires a
/// trailing slash to resolve the component it follows, so the terminal
/// component is dereferenced before the `lstat` behind `test -h` ever runs.
/// That turns the probe's admitting answer, `NOTLINK`, into a lie about a
/// path that is in fact a symlink. Trimming the slash names the same inode a
/// write would land on, so this changes no answer that was already correct;
/// it only stops the terminal component being resolved away before the check
/// is made.
///
/// An all-slash path trims to nothing, which is not a path the script can be
/// handed, so that case is mapped back to `/`: the filesystem root, which is
/// what an all-slash path names.
pub(crate) fn normalise_probe_path(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Trait for abstracting file and command operations.
///
/// Implementations can target local systems or remote systems via SSH.
#[async_trait]
pub trait SystemExecutor: Send + Sync {
    /// Returns a description of this executor (e.g., "local" or "ssh://user@host").
    fn description(&self) -> String;

    /// Returns true if this is a remote executor.
    fn is_remote(&self) -> bool;

    // === File Operations ===

    /// Reads the entire contents of a file as a string.
    async fn read_file(&self, path: &Path) -> Result<String>;

    /// Reads a file, returning None if the file doesn't exist.
    async fn read_file_optional(&self, path: &Path) -> Result<Option<String>>;

    /// Writes content to a file.
    async fn write_file(&self, path: &Path, content: &str) -> Result<()>;

    /// Checks if a file path exists.
    async fn path_exists(&self, path: &Path) -> Result<bool>;

    /// The target of `path` if it is a symlink, `None` if it is not one.
    ///
    /// Three outcomes, the same shape as [`Self::file_metadata`]: a target, a
    /// positive "not a symlink", or `Err` meaning could not determine. `Err`
    /// must never be read as "not a symlink", because a checkpoint that stores a
    /// symlink's followed content instead of its target cannot restore it: the
    /// write would go through the link into whatever it points at.
    ///
    /// Provided rather than required, so local and remote answer it the same
    /// way. `readlink` is POSIX and the executor already runs commands on both;
    /// a local-only `std::fs::read_link` would make every remote capture report
    /// "not a symlink" for a path it never looked at.
    async fn read_link(&self, path: &Path) -> Result<Option<String>> {
        let path_str = path.to_string_lossy();
        let output = self
            .execute_command("readlink", &["-n", "--", &path_str])
            .await?;
        match output.exit_code {
            0 => Ok(Some(output.stdout.trim().to_string())),
            // readlink(1) exits 1 for a path that is not a symlink, which is the
            // positive answer. Any other status is readlink itself failing, 127
            // when it is absent on a remote host being the likely one, and that
            // is "could not determine" rather than "not a symlink".
            1 => Ok(None),
            code => Err(crate::error::HardeningError::Executor(format!(
                "readlink {path_str} exited {code}: {}",
                output.stderr.trim()
            ))
            .into()),
        }
    }

    /// Where `path` leads, asked at the privilege the restoring write uses.
    ///
    /// Three outcomes, the contract shape [`Self::file_metadata`] establishes:
    ///
    /// - `Ok(None)`: **positively** not a symlink. The caller may write the
    ///   path itself.
    /// - `Ok(Some(p))`: a symlink, with every component resolved, matching
    ///   `realpath(3)`.
    /// - `Err`: could not be determined. The caller must refuse, and must
    ///   never read this as "not a symlink".
    ///
    /// Distinct from [`Self::read_link`] on both axes. `read_link` answers
    /// about one name at the login user's privilege, which suits checkpoint
    /// capture: capture reads content with `cat` as that same user, and its
    /// degrading to content-only is an accepted ceiling. This one is for the
    /// rollback guard, which authorises a write that happens as this
    /// executor's own [`Self::write_file`], so it asks at whatever privilege
    /// that write happens at and refuses whatever it cannot see. Reasoning
    /// for the script itself is at [`LINK_PROBE_SCRIPT`].
    ///
    /// The elevation is this executor's own property, taken from
    /// [`Self::is_remote`], because the two shipped implementations disagree
    /// on it. `SshExecutor::write_file` goes through `sudo tee`, so its writes
    /// elevate and its probe must ask `sudo -n` too, or it would answer for a
    /// different user than the one that acts. `LocalExecutor::write_file`
    /// calls `std::fs::write` directly with no elevation at all, so a probe
    /// that asked for `sudo -n` on a local session would answer as root for a
    /// write that happens as the process user, the same mismatch this guard
    /// exists to remove, pointed the other way. A remote executor therefore
    /// passes `sudo -n` as the script's elevation argument and a local one
    /// passes nothing.
    ///
    /// Provided rather than required, for the reason [`Self::read_link`] is:
    /// local and remote must not come to ask different questions, and the call
    /// still routes through this executor's own [`Self::execute_command`], so
    /// the probe runs on whichever host that executor targets.
    ///
    /// The exit status is checked before stdout is read at all. The script
    /// reports its own outcome on stdout and exits 0 for all three of its own
    /// outcomes, so a non-zero status can only mean it did not run to
    /// completion, `sh` absent (127) or the process killed after it had
    /// already flushed a token that happens to parse, and that is the
    /// refusing answer rather than whatever stdout holds.
    ///
    /// `path` is expected to be absolute. A relative one is resolved against
    /// the shell's working directory, which is unspecified for both the local
    /// and the SSH executor; the rollback guard, the only caller, refuses a
    /// non-absolute path before it ever probes.
    async fn link_target_as_writer(&self, path: &Path) -> Result<Option<PathBuf>> {
        let path_str = path.to_string_lossy();
        let normalised = normalise_probe_path(&path_str);
        let elevation = if self.is_remote() { "sudo -n" } else { "" };
        let output = self
            .execute_command(
                "sh",
                &["-c", LINK_PROBE_SCRIPT, "_", &normalised, elevation],
            )
            .await?;
        if output.exit_code != 0 {
            return Err(crate::error::HardeningError::Executor(format!(
                "the link probe exited {}: {}",
                output.exit_code,
                output.stderr.trim()
            ))
            .into());
        }
        parse_link_probe(&output.stdout)
    }

    /// Where `path` leads once **every** component of it is resolved, or `None`
    /// if it does not resolve to a path that exists.
    ///
    /// `realpath(3)` semantics, and the distinction from [`Self::read_link`] is
    /// the whole of why this exists. `read_link` answers about one name; a
    /// decision about where a write would *land* needs the parents resolved
    /// too. A caller that follows one hop at a time and flattens `..` itself
    /// gets a different answer from the kernel's whenever the component before
    /// a `..` is a link, and gets it in the admitting direction: with
    /// `a/dlink -> /elsewhere/sub`, resolving `a/dlink/../victim` by name alone
    /// yields `a/victim` while the write lands on `/elsewhere/victim`.
    ///
    /// `None` for every unresolvable path, rather than distinguishing them:
    /// `readlink` gives a dangling target, a missing component, a traversal it
    /// may not make and a symlink loop the same status, and unlike
    /// [`Self::read_link`]'s `None` this one is the *refusing* answer, so
    /// collapsing them costs a caller nothing. A caller that admits `None` has
    /// read it backwards.
    ///
    /// Provided rather than required, for the reason [`Self::read_link`] is:
    /// `readlink -e` is what `Path::canonicalize` was, and one implementation
    /// keeps local and remote answering alike.
    async fn canonical_path(&self, path: &Path) -> Result<Option<PathBuf>> {
        let path_str = path.to_string_lossy();
        let output = self
            .execute_command("readlink", &["-e", "-n", "--", &path_str])
            .await?;
        Ok((output.exit_code == 0).then(|| PathBuf::from(output.stdout.trim())))
    }

    /// Reads metadata for `path`.
    ///
    /// The three outcomes are a contract every implementation must honour,
    /// because callers act on the difference:
    ///
    /// - `Ok(FileMetadata { exists: true, .. })`: the path exists and its
    ///   metadata was read.
    /// - `Ok(FileMetadata { exists: false, .. })`: absence was **positively
    ///   confirmed**.
    /// - `Err`: existence or metadata **could not be determined**. Callers must
    ///   fail closed and must never treat this as absence.
    ///
    /// The distinction is not cosmetic. Checkpoint capture records an absent
    /// path with `file_permissions: 0`, and rollback removes any path it
    /// recorded that way, so an implementation that reports an unreadable path
    /// as absent makes a later rollback delete it.
    ///
    /// Known limitation: over SSH, absence is confirmed with `test -e`, which is
    /// also false when a parent directory cannot be traversed. Such a path reads
    /// as absent rather than unverifiable.
    ///
    /// **`mode` carries the file-type bits, not the permission bits alone.**
    /// That is the fourth clause of the same contract and it is load-bearing for
    /// the same reason: checkpoint capture stores an absent path as mode 0 and
    /// rollback removes anything it recorded that way, so an existing path whose
    /// mode read as 0 would be deleted. A regular file with 0000 permissions is
    /// exactly that path, and `/etc/shadow` is 0000 on Arch, so this is not a
    /// hypothetical. Returning the full `st_mode` makes it unreachable, because
    /// every existing path has a type bit set: `0o100000` for a regular file,
    /// `0o040000` for a directory.
    ///
    /// It was reachable once. `0b96045` fixed both shipped implementations,
    /// which had masked with `& 0o777` locally and used `stat %a` remotely, and
    /// on a host with a 0000-perm account file a rollback deleted it. Callers
    /// that want permission bits alone mask for themselves.
    async fn file_metadata(&self, path: &Path) -> Result<FileMetadata>;

    /// Lists the immediate children of a directory (non-recursive),
    /// mirroring `std::fs::read_dir`. Returns absolute paths.
    /// A missing or empty directory yields an empty vec; behaviour on a
    /// non-directory path is executor-defined (callers gate with `file_metadata`).
    async fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>>;

    // === Command Operations ===

    /// Executes a command with arguments.
    async fn execute_command(&self, program: &str, args: &[&str]) -> Result<CommandOutput>;

    /// Checks whether `program` is a command this executor could spawn.
    ///
    /// The three outcomes match [`Self::file_metadata`]'s contract: `Ok(true)`
    /// present, `Ok(false)` positively absent, `Err` could not be determined.
    ///
    /// Probing with `which` conflated the last two, because `which` is a
    /// separate package that Fedora, RHEL and openSUSE do not install: on those
    /// hosts every question about every command answered "could not determine",
    /// which callers surface as a plugin failure. [`COMMAND_EXISTS_PROBE`] asks
    /// the shell instead, and a shell is the one thing a host running this tool
    /// is guaranteed to have.
    ///
    /// Provided rather than required so the local and remote executors cannot
    /// come to ask different questions; each still routes through its own
    /// [`Self::execute_command`], so the probe runs on whichever host that
    /// executor targets.
    async fn command_exists(&self, program: &str) -> Result<bool> {
        // `sh -c <script> <argv0> <program>`: the name is a positional argument
        // rather than part of the script, so one containing shell
        // metacharacters cannot alter what runs.
        let output = self
            .execute_command("sh", &["-c", COMMAND_EXISTS_PROBE, "sh", program])
            .await?;
        Ok(output.success())
    }
}

/// Shell probe behind [`SystemExecutor::command_exists`], answering "is this a
/// command that could be spawned here?".
///
/// `command -v` is a shell builtin, so it cannot be spawned directly and must
/// run under `sh`. Its output is required to be an absolute path because it
/// also reports shell builtins and functions, naming them without a path;
/// `execute_command` spawns a binary and cannot run either, so accepting them
/// would widen the answer past what the callers are asking about.
///
/// POSIX only, and exercised under both dash and bash: `sh` is dash on Debian
/// and bash on openSUSE.
pub const COMMAND_EXISTS_PROBE: &str =
    r#"case $(command -v -- "$1") in /*) exit 0 ;; *) exit 1 ;; esac"#;

/// Derives the host key used to scope checkpoints: the executor's description
/// for a remote target, or `"local"` for the controller. Single source of truth
/// for host-key derivation: capture, rollback, and the CLI all call it so the
/// cross-host rollback guard can never drift between sites.
pub fn host_key_for(executor: &dyn SystemExecutor) -> String {
    if executor.is_remote() {
        executor.description()
    } else {
        "local".to_string()
    }
}

/// The scan-history key for one session: the host that was actually scanned.
///
/// Single source of truth for that key, and it is here rather than beside
/// either caller because both write the same `scan_sessions` table: the CLI's
/// `scan`, and the scheduler daemon's own runs. They derived it separately for
/// as long as they both existed, so one machine could hold two series and each
/// side would see no history at all before its own first row.
///
/// **A remote is keyed by the target it was reached at, not by the name it
/// reports.** Asking the remote for its `/etc/hostname` would move the
/// collision rather than remove it: the name is not unique, since two fresh
/// Rocky hosts both answer `localhost.localdomain` and would share one row, and
/// it is not stable either, since a session that could not read the file would
/// key the same host differently from one that could. [`host_key_for`] is
/// unique per target and is already what scopes checkpoints, so the two agree.
/// A host reached both by name and by address does get two rows, which loses
/// continuity but corrupts nothing, and it is what `batch` has always done.
///
/// The local key stays the host's own name so that history written by earlier
/// releases keeps its rows. `hostname(5)` allows comment lines and permits the
/// name to be followed by anything, so the first line that is neither blank nor
/// a comment is the name; the rest of the file is not part of the key. A file
/// that cannot be read, or that holds no such line, falls back to
/// [`host_key_for`], which is `"local"`, rather than to the literal `localhost`
/// this used before: that name is indistinguishable from a real remote's, and
/// on the daemon's side it was the fallback whenever the kernel could not
/// answer at all.
pub async fn session_host_key(executor: &dyn SystemExecutor) -> String {
    if executor.is_remote() {
        return host_key_for(executor);
    }
    let Ok(contents) = executor.read_file(Path::new("/etc/hostname")).await else {
        return host_key_for(executor);
    };
    hostname_file_name(&contents)
        .map(str::to_string)
        .unwrap_or_else(|| host_key_for(executor))
}

/// The name a `/etc/hostname` file declares, if it declares one.
///
/// Separate from [`session_host_key`] because the scheduler daemon needs the
/// same rule without an executor: it only ever runs against the host it is on,
/// and it is built on a synchronous path. Keeping the rule in one place is what
/// matters, since the two surfaces write the same table and a machine whose
/// name is read differently by each of them holds two disjoint histories.
///
/// `hostname(5)` allows blank lines and `#` comments, and says the name ends at
/// the first whitespace, so the first line that is neither blank nor a comment
/// is the name and the rest of the file is not part of it.
pub fn hostname_file_name(contents: &str) -> Option<&str> {
    contents
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
}

/// Whether the executor's session is already uid 0.
///
/// One definition because two grew independently and each answered a slightly
/// different question with the same command: the CLI's privilege gate, which
/// also accepts passwordless sudo, and the ssh plugin's remote-root guard.
/// Both reduce to this, and a third caller wanted it: an unchecked entry
/// deciding whether a privileged re-run could reach a check it could not
/// perform.
///
/// **This is not "could this session elevate".** A session that is not root but
/// holds passwordless sudo has a privileged re-run available to it, so a check
/// it could not perform is still worth offering that re-run for. Only a session
/// already at uid 0 has nothing left to try, which is precisely the case the
/// unchecked entries had no way to express. The CLI's gate composes this with
/// its sudo probe rather than the other way round.
///
/// Asks the executor rather than the process, because `geteuid` on the
/// controller says nothing about the far end of an `--ssh` session.
///
/// Fails closed: any error, any non-zero exit, anything that is not exactly
/// `0` is "not root". A probe that could not answer must never be read as an
/// answer.
pub async fn session_is_root(executor: &dyn SystemExecutor) -> bool {
    matches!(
        executor.execute_command("id", &["-u"]).await,
        Ok(out) if out.success() && out.stdout.trim() == "0"
    )
}

#[cfg(test)]
mod tests;
