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

    /// Checks if a command exists on the system.
    async fn command_exists(&self, program: &str) -> Result<bool>;
}

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
