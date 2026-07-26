//! Mock executor for unit testing without filesystem access.

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use super::{CommandOutput, FileMetadata, SystemExecutor};

// Type aliases to simplify complex Arc<Mutex<HashMap<...>>> types
type FileStore = Arc<Mutex<HashMap<PathBuf, String>>>;
type MetadataStore = Arc<Mutex<HashMap<PathBuf, FileMetadata>>>;
type CommandStore = Arc<Mutex<HashMap<(String, Vec<String>), CommandOutput>>>;
type CommandSequenceStore = Arc<Mutex<HashMap<(String, Vec<String>), VecDeque<CommandOutput>>>>;
type CommandExistsStore = Arc<Mutex<HashMap<String, bool>>>;
type LogStore = Arc<Mutex<MockExecutorLog>>;
type PermissionDeniedStore = Arc<Mutex<HashSet<PathBuf>>>;
type PathExistsStore = Arc<Mutex<HashMap<PathBuf, bool>>>;

/// Records of operations performed on the mock executor.
#[derive(Clone, Debug, Default)]
pub struct MockExecutorLog {
    pub files_read: Vec<PathBuf>,
    pub files_written: Vec<(PathBuf, String)>,
    pub commands_executed: Vec<(String, Vec<String>)>,
}

/// A mock executor for deterministic unit testing.
///
/// # Examples
///
/// ```ignore
/// // Create executor with virtual files
/// let executor = MockExecutor::new()
///     .with_file("/etc/ssh/sshd_config", "PermitRootLogin no\n")
///     .with_command("systemctl", &["is-enabled", "sshd"], CommandOutput {
///         stdout: "enabled\n".into(),
///         stderr: String::new(),
///         exit_code: 0,
///     });
///
/// // Use in tests!
/// let content = executor.read_file(Path::new("/etc/ssh/sshd_config")).await?;
/// assert_eq!(content, "PermitRootLogin no\n");
///
/// // Check what was called
/// let log = executor.log();
/// assert!(log.files_read.contains(&PathBuf::from("/etc/ssh/sshd_config")));
/// ```
#[derive(Clone)]
pub struct MockExecutor {
    files: FileStore,
    file_metadata: MetadataStore,
    commands: CommandStore,
    command_sequences: CommandSequenceStore,
    command_exists: CommandExistsStore,
    read_permission_denied: PermissionDeniedStore,
    metadata_error: PermissionDeniedStore,
    path_exists_error: PermissionDeniedStore,
    path_exists_override: PathExistsStore,
    log: LogStore,
    is_remote: bool,
    description: String,
}

impl Default for MockExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl MockExecutor {
    /// Creates a new empty mock executor.
    pub fn new() -> Self {
        Self {
            files: Arc::new(Mutex::new(HashMap::new())),
            file_metadata: Arc::new(Mutex::new(HashMap::new())),
            commands: Arc::new(Mutex::new(HashMap::new())),
            command_sequences: Arc::new(Mutex::new(HashMap::new())),
            command_exists: Arc::new(Mutex::new(HashMap::new())),
            read_permission_denied: Arc::new(Mutex::new(HashSet::new())),
            metadata_error: Arc::new(Mutex::new(HashSet::new())),
            path_exists_error: Arc::new(Mutex::new(HashSet::new())),
            path_exists_override: Arc::new(Mutex::new(HashMap::new())),
            log: Arc::new(Mutex::new(MockExecutorLog::default())),
            is_remote: false,
            description: "mock".to_string(),
        }
    }

    /// Sets the executor to behave as remote.
    pub fn remote(mut self) -> Self {
        self.is_remote = true;
        self.description = "mock-remote".to_string();
        self
    }

    /// Sets custom description.
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    /// Adds a file to the virtual filesystem.
    pub fn with_file(self, path: &str, content: &str) -> Self {
        let path_buf = PathBuf::from(path);
        self.files
            .lock()
            .expect("files mutex poisoned")
            .insert(path_buf.clone(), content.to_string());
        // Auto-generate metadata for the file
        self.file_metadata
            .lock()
            .expect("metadata mutex poisoned")
            .insert(
                path_buf,
                FileMetadata {
                    exists: true,
                    is_file: true,
                    is_dir: false,
                    mode: 0o644,
                    size: content.len() as u64,
                    uid: 0,
                    gid: 0,
                },
            );
        self
    }

    /// Adds a file with custom metadata.
    pub fn with_file_metadata(self, path: &str, content: &str, metadata: FileMetadata) -> Self {
        let path_buf = PathBuf::from(path);
        self.files
            .lock()
            .expect("files mutex poisoned")
            .insert(path_buf.clone(), content.to_string());
        self.file_metadata
            .lock()
            .expect("metadata mutex poisoned")
            .insert(path_buf, metadata);
        self
    }

    /// Adds a directory (no content, just metadata).
    pub fn with_directory(self, path: &str) -> Self {
        let path_buf = PathBuf::from(path);
        self.file_metadata
            .lock()
            .expect("metadata mutex poisoned")
            .insert(
                path_buf,
                FileMetadata {
                    exists: true,
                    is_file: false,
                    is_dir: true,
                    mode: 0o755,
                    size: 0,
                    uid: 0,
                    gid: 0,
                },
            );
        self
    }

    /// Registers a command response.
    pub fn with_command(self, program: &str, args: &[&str], output: CommandOutput) -> Self {
        let key = (
            program.to_string(),
            args.iter().map(|s| s.to_string()).collect(),
        );
        self.commands
            .lock()
            .expect("commands mutex poisoned")
            .insert(key, output);
        self
    }

    /// Registers a sequence of responses for repeated invocations of the
    /// same command: each execution consumes the next output in order.
    /// Once the sequence is exhausted, lookups fall back to any
    /// [`with_command`](Self::with_command) registration for the same key.
    pub fn with_command_sequence(
        self,
        program: &str,
        args: &[&str],
        outputs: Vec<CommandOutput>,
    ) -> Self {
        let key = (
            program.to_string(),
            args.iter().map(|s| s.to_string()).collect(),
        );
        self.command_sequences
            .lock()
            .expect("command_sequences mutex poisoned")
            .insert(key, outputs.into());
        self
    }

    /// Registers whether a command exists.
    pub fn with_command_exists(self, program: &str, exists: bool) -> Self {
        self.command_exists
            .lock()
            .expect("command_exists mutex poisoned")
            .insert(program.to_string(), exists);
        self
    }

    /// Marks a path whose read fails with an io PermissionDenied error,
    /// simulating a root-only file seen by an unprivileged scan.
    pub fn with_read_permission_denied(self, path: &str) -> Self {
        self.read_permission_denied
            .lock()
            .expect("read_permission_denied mutex poisoned")
            .insert(PathBuf::from(path));
        self
    }

    /// Marks a path whose metadata read fails, simulating a host whose `stat`
    /// output cannot be parsed. Distinct from an absent path: the executor
    /// contract says `Err` means "could not determine", which callers must treat
    /// as fail closed rather than as absence.
    pub fn with_metadata_error(self, path: &str) -> Self {
        self.metadata_error
            .lock()
            .expect("metadata_error mutex poisoned")
            .insert(PathBuf::from(path));
        self
    }

    /// Sets `path_exists` for a path independently of its stored metadata, so a
    /// test can express "the path is there but its metadata cannot be read".
    /// That divergence is what an incompatible remote `stat` produces, and a
    /// mock keying both answers off one flag cannot reproduce it.
    pub fn with_path_exists(self, path: &str, exists: bool) -> Self {
        self.path_exists_override
            .lock()
            .expect("path_exists_override mutex poisoned")
            .insert(PathBuf::from(path), exists);
        self
    }

    /// Marks a path whose existence probe fails, simulating an executor that
    /// could not determine whether the path exists, for example an SSH command
    /// that failed mid-probe. Distinct from a confirmed absence: the executor
    /// contract says `Err` means "could not determine", which callers must
    /// treat as fail closed rather than as absence.
    pub fn with_path_exists_error(self, path: &str) -> Self {
        self.path_exists_error
            .lock()
            .expect("path_exists_error mutex poisoned")
            .insert(PathBuf::from(path));
        self
    }

    /// Returns the operation log for assertions.
    pub fn log(&self) -> MockExecutorLog {
        self.log.lock().expect("log mutex poisoned").clone()
    }

    /// Clears the operation log.
    pub fn clear_log(&self) {
        *self.log.lock().expect("log mutex poisoned") = MockExecutorLog::default();
    }

    /// Returns all files currently in the virtual filesystem.
    pub fn files(&self) -> HashMap<PathBuf, String> {
        self.files.lock().expect("files mutex poisoned").clone()
    }
}

#[async_trait]
impl SystemExecutor for MockExecutor {
    fn description(&self) -> String {
        self.description.clone()
    }

    fn is_remote(&self) -> bool {
        self.is_remote
    }

    async fn read_file(&self, path: &Path) -> Result<String> {
        self.log
            .lock()
            .expect("log mutex poisoned")
            .files_read
            .push(path.to_path_buf());

        if self
            .read_permission_denied
            .lock()
            .expect("read_permission_denied mutex poisoned")
            .contains(path)
        {
            return Err(anyhow::Error::new(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("Mock: permission denied: {}", path.display()),
            )));
        }

        self.files
            .lock()
            .expect("files mutex poisoned")
            .get(path)
            .cloned()
            .ok_or_else(|| anyhow!("Mock: file not found: {}", path.display()))
    }

    async fn read_file_optional(&self, path: &Path) -> Result<Option<String>> {
        self.log
            .lock()
            .expect("log mutex poisoned")
            .files_read
            .push(path.to_path_buf());

        Ok(self
            .files
            .lock()
            .expect("files mutex poisoned")
            .get(path)
            .cloned())
    }

    async fn write_file(&self, path: &Path, content: &str) -> Result<()> {
        self.log
            .lock()
            .expect("log mutex poisoned")
            .files_written
            .push((path.to_path_buf(), content.to_string()));

        let path_buf = path.to_path_buf();
        self.files
            .lock()
            .expect("files mutex poisoned")
            .insert(path_buf.clone(), content.to_string());
        // Update metadata
        self.file_metadata
            .lock()
            .expect("metadata mutex poisoned")
            .insert(
                path_buf,
                FileMetadata {
                    exists: true,
                    is_file: true,
                    is_dir: false,
                    mode: 0o644,
                    size: content.len() as u64,
                    uid: 0,
                    gid: 0,
                },
            );
        Ok(())
    }

    async fn path_exists(&self, path: &Path) -> Result<bool> {
        if self
            .path_exists_error
            .lock()
            .expect("path_exists_error mutex poisoned")
            .contains(path)
        {
            return Err(anyhow::Error::new(std::io::Error::other(format!(
                "Mock: path_exists unavailable: {}",
                path.display()
            ))));
        }

        if let Some(exists) = self
            .path_exists_override
            .lock()
            .expect("path_exists_override mutex poisoned")
            .get(path)
        {
            return Ok(*exists);
        }
        Ok(self
            .file_metadata
            .lock()
            .expect("metadata mutex poisoned")
            .get(path)
            .map(|m| m.exists)
            .unwrap_or(false))
    }

    async fn file_metadata(&self, path: &Path) -> Result<FileMetadata> {
        if self
            .metadata_error
            .lock()
            .expect("metadata_error mutex poisoned")
            .contains(path)
        {
            return Err(anyhow::Error::new(std::io::Error::other(format!(
                "Mock: metadata unavailable: {}",
                path.display()
            ))));
        }

        Ok(self
            .file_metadata
            .lock()
            .expect("metadata mutex poisoned")
            .get(path)
            .cloned()
            .unwrap_or(FileMetadata {
                exists: false,
                is_file: false,
                is_dir: false,
                mode: 0,
                size: 0,
                uid: 0,
                gid: 0,
            }))
    }

    async fn execute_command(&self, program: &str, args: &[&str]) -> Result<CommandOutput> {
        let args_vec: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        self.log
            .lock()
            .expect("log mutex poisoned")
            .commands_executed
            .push((program.to_string(), args_vec.clone()));

        let key = (program.to_string(), args_vec);
        if let Some(output) = self
            .command_sequences
            .lock()
            .expect("command_sequences mutex poisoned")
            .get_mut(&key)
            .and_then(VecDeque::pop_front)
        {
            return Ok(output);
        }
        self.commands
            .lock()
            .expect("commands mutex poisoned")
            .get(&key)
            .cloned()
            .ok_or_else(|| anyhow!("Mock: command not registered: {} {:?}", program, args))
    }

    async fn command_exists(&self, program: &str) -> Result<bool> {
        // Check explicit registration first
        if let Some(&exists) = self
            .command_exists
            .lock()
            .expect("command_exists mutex poisoned")
            .get(program)
        {
            return Ok(exists);
        }
        // Fall back to checking if any command with this program is registered
        let commands = self.commands.lock().expect("commands mutex poisoned");
        Ok(commands.keys().any(|(p, _)| p == program))
    }

    async fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>> {
        let meta = self.file_metadata.lock().expect("metadata mutex poisoned");
        Ok(meta
            .keys()
            .filter(|child| child.parent() == Some(path))
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_read_dir_returns_seeded_children() {
        let exec = MockExecutor::new()
            .with_directory("/etc/d")
            .with_file("/etc/d/a", "1")
            .with_file("/etc/d/b", "2")
            .with_file("/etc/other", "3");
        let mut got: Vec<String> = exec
            .read_dir(std::path::Path::new("/etc/d"))
            .await
            .unwrap()
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        got.sort();
        assert_eq!(got, vec!["/etc/d/a", "/etc/d/b"]);
    }

    #[tokio::test]
    async fn mock_read_dir_missing_path_is_empty() {
        let got = MockExecutor::new()
            .read_dir(std::path::Path::new("/no/such/dir"))
            .await
            .unwrap();
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn read_permission_denied_surfaces_io_kind() {
        let mock = MockExecutor::new().with_read_permission_denied("/etc/security/pwquality.conf");
        let err = mock
            .read_file(std::path::Path::new("/etc/security/pwquality.conf"))
            .await
            .unwrap_err();
        assert!(crate::error::is_permission_denied(&err));
    }

    #[tokio::test]
    async fn metadata_error_is_not_reported_as_absence() {
        let mock = MockExecutor::new().with_metadata_error("/etc/shadow");
        mock.file_metadata(std::path::Path::new("/etc/shadow"))
            .await
            .expect_err("an unverifiable path must error, never report exists: false");
    }

    #[tokio::test]
    async fn path_exists_can_disagree_with_metadata() {
        // The real divergence on an incompatible host: the path is there, but
        // its metadata cannot be read. A shared flag cannot express this.
        let mock = MockExecutor::new()
            .with_metadata_error("/etc/shadow")
            .with_path_exists("/etc/shadow", true);
        assert!(
            mock.path_exists(std::path::Path::new("/etc/shadow"))
                .await
                .expect("path_exists does not fail here")
        );
        mock.file_metadata(std::path::Path::new("/etc/shadow"))
            .await
            .expect_err("metadata is still unreadable");
    }

    #[tokio::test]
    async fn path_exists_error_is_not_reported_as_absence() {
        let mock = MockExecutor::new().with_path_exists_error("/etc/passwd");
        mock.path_exists(std::path::Path::new("/etc/passwd"))
            .await
            .expect_err("an unverifiable path must error, never report exists: false");
    }
}
