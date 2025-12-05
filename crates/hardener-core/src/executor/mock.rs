//! Mock executor for unit testing without filesystem access.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use super::{CommandOutput, FileMetadata, SystemExecutor};

// Type aliases to simplify complex Arc<Mutex<HashMap<...>>> types
type FileStore = Arc<Mutex<HashMap<PathBuf, String>>>;
type MetadataStore = Arc<Mutex<HashMap<PathBuf, FileMetadata>>>;
type CommandStore = Arc<Mutex<HashMap<(String, Vec<String>), CommandOutput>>>;
type CommandExistsStore = Arc<Mutex<HashMap<String, bool>>>;
type LogStore = Arc<Mutex<MockExecutorLog>>;

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
    command_exists: CommandExistsStore,
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
            command_exists: Arc::new(Mutex::new(HashMap::new())),
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

    /// Registers whether a command exists.
    pub fn with_command_exists(self, program: &str, exists: bool) -> Self {
        self.command_exists
            .lock()
            .expect("command_exists mutex poisoned")
            .insert(program.to_string(), exists);
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
                },
            );
        Ok(())
    }

    async fn path_exists(&self, path: &Path) -> Result<bool> {
        Ok(self
            .file_metadata
            .lock()
            .expect("metadata mutex poisoned")
            .get(path)
            .map(|m| m.exists)
            .unwrap_or(false))
    }

    async fn file_metadata(&self, path: &Path) -> Result<FileMetadata> {
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
}
