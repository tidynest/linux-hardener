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

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{anyhow, bail};

    /// A host that ships no `which`, which is every Red Hat and SUSE image the
    /// cross-distro suite builds. Only `execute_command` is implemented, so
    /// `command_exists` is exercised through the trait's own default body
    /// rather than through an override that could answer a different question.
    struct WhichlessHost {
        /// Programs present in `PATH`, as `command -v` would resolve them.
        installed: &'static [&'static str],
    }

    #[async_trait]
    impl SystemExecutor for WhichlessHost {
        fn description(&self) -> String {
            "whichless".to_string()
        }

        fn is_remote(&self) -> bool {
            false
        }

        async fn execute_command(&self, program: &str, args: &[&str]) -> Result<CommandOutput> {
            // A missing binary cannot be spawned, so the executor never gets an
            // exit status to report: it fails the whole call. This is the exact
            // shape of the shipped symptom, "Executor error: Failed to execute
            // command which".
            if program != "sh" {
                bail!("Failed to execute command {program}");
            }
            // `sh -c <script> sh <program>`: the probe passes the program as a
            // positional argument, so the name under test is the last one.
            let queried = args.last().copied().unwrap_or_default();
            Ok(CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: i32::from(!self.installed.contains(&queried)),
            })
        }

        async fn read_file(&self, _path: &Path) -> Result<String> {
            Err(anyhow!("unused"))
        }
        async fn read_file_optional(&self, _path: &Path) -> Result<Option<String>> {
            Err(anyhow!("unused"))
        }
        async fn write_file(&self, _path: &Path, _content: &str) -> Result<()> {
            Err(anyhow!("unused"))
        }
        async fn path_exists(&self, _path: &Path) -> Result<bool> {
            Err(anyhow!("unused"))
        }
        async fn file_metadata(&self, _path: &Path) -> Result<FileMetadata> {
            Err(anyhow!("unused"))
        }
        async fn read_dir(&self, _path: &Path) -> Result<Vec<PathBuf>> {
            Err(anyhow!("unused"))
        }
    }

    #[tokio::test]
    async fn an_installed_command_is_found_without_which() {
        let host = WhichlessHost {
            installed: &["systemctl"],
        };
        assert!(
            host.command_exists("systemctl").await.unwrap(),
            "a host without `which` must still be able to confirm systemctl"
        );
    }

    #[tokio::test]
    async fn a_missing_command_reads_as_absent_not_as_a_failed_probe() {
        let host = WhichlessHost { installed: &[] };
        assert!(
            !host.command_exists("systemctl").await.unwrap(),
            "an absent command is an answer, not an error: probing with a tool \
             the host lacks turns every caller's question into a plugin failure"
        );
    }
}
