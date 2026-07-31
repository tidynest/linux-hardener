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
type CommandProgramStore = Arc<Mutex<HashMap<String, CommandOutput>>>;
type CommandSequenceStore = Arc<Mutex<HashMap<(String, Vec<String>), VecDeque<CommandOutput>>>>;
type CommandExistsStore = Arc<Mutex<HashMap<String, bool>>>;
type LogStore = Arc<Mutex<MockExecutorLog>>;
type PermissionDeniedStore = Arc<Mutex<HashSet<PathBuf>>>;
type PathExistsStore = Arc<Mutex<HashMap<PathBuf, bool>>>;
type SymlinkStore = Arc<Mutex<HashMap<PathBuf, String>>>;

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
    command_programs: CommandProgramStore,
    command_sequences: CommandSequenceStore,
    command_exists: CommandExistsStore,
    read_permission_denied: PermissionDeniedStore,
    metadata_error: PermissionDeniedStore,
    path_exists_error: PermissionDeniedStore,
    path_exists_override: PathExistsStore,
    symlinks: SymlinkStore,
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
            command_programs: Arc::new(Mutex::new(HashMap::new())),
            command_sequences: Arc::new(Mutex::new(HashMap::new())),
            command_exists: Arc::new(Mutex::new(HashMap::new())),
            read_permission_denied: Arc::new(Mutex::new(HashSet::new())),
            metadata_error: Arc::new(Mutex::new(HashSet::new())),
            path_exists_error: Arc::new(Mutex::new(HashSet::new())),
            path_exists_override: Arc::new(Mutex::new(HashMap::new())),
            symlinks: Arc::new(Mutex::new(HashMap::new())),
            log: Arc::new(Mutex::new(MockExecutorLog::default())),
            is_remote: false,
            description: "mock".to_string(),
        }
    }

    /// Registers `path` as a symlink pointing at `target`.
    ///
    /// A path not registered here reads as positively not a symlink, which keeps
    /// every fixture that predates symlink support describing the host it always
    /// described.
    pub fn with_symlink(self, path: &str, target: &str) -> Self {
        self.symlinks
            .lock()
            .expect("symlinks mutex poisoned")
            .insert(PathBuf::from(path), target.to_string());
        self
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
    ///
    /// The recorded mode carries the `S_IFREG` type bit, because that is what
    /// both real executors report: `LocalExecutor` returns the raw `st_mode`
    /// and `SshExecutor` reconstructs it. A fixture holding bare permission
    /// bits would describe a host that cannot exist, and callers that
    /// discriminate a file from a directory by the type bit would take the
    /// wrong branch under the mock alone.
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
                    mode: 0o100644,
                    size: content.len() as u64,
                    uid: 0,
                    gid: 0,
                },
            );
        self
    }

    /// Removes a previously registered file, so a shared fixture can model a
    /// host on which it is absent without duplicating everything else it sets
    /// up.
    ///
    /// Both stores are cleared: `read_file` reads `files` while `path_exists`
    /// reads `file_metadata`, so removing from one alone would leave the path
    /// half present, which is a fixture that lies about the host.
    pub fn without_file(self, path: &str) -> Self {
        let path_buf = PathBuf::from(path);
        self.files
            .lock()
            .expect("files mutex poisoned")
            .remove(&path_buf);
        self.file_metadata
            .lock()
            .expect("metadata mutex poisoned")
            .remove(&path_buf);
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
    ///
    /// The recorded mode carries the `S_IFDIR` type bit for the same reason
    /// [`with_file`](Self::with_file) carries `S_IFREG`: a capture that reads
    /// the type bit back out, as the checkpoint manager does to tell a saved
    /// directory from a saved file, must see under the mock what it would see
    /// on a real host.
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
                    mode: 0o040755,
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

    /// Registers a response for any invocation of `program`, whatever its
    /// arguments, used only when no exact [`with_command`](Self::with_command)
    /// registration matches.
    ///
    /// Exact matching cannot express a command whose arguments the test cannot
    /// predict, such as a backup path carrying a timestamp. Without this, the
    /// only way to make such a command fail was to leave it unregistered, which
    /// produces a spawn error rather than a non-zero exit and so exercises a
    /// different branch than the one under test.
    pub fn with_command_program(self, program: &str, output: CommandOutput) -> Self {
        self.command_programs
            .lock()
            .expect("command_programs mutex poisoned")
            .insert(program.to_string(), output);
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
    ///
    /// The path is also recorded as present, because that is what a root-only
    /// file is: there, and refusing to open. No executor produces "denied, and
    /// also absent": [`crate::executor::SystemExecutor::path_exists`] confirms
    /// absence only on NotFound and returns an error for a denied probe. A
    /// caller that consults the probe before falling back to another location
    /// would otherwise take a branch a real host cannot produce. Same reasoning
    /// as [`Self::without_file`]: a path half present in one store and not the
    /// other is a fixture that lies about the host.
    ///
    /// Metadata already registered is left alone, so builder order cannot
    /// change the answer, and an explicit [`Self::with_path_exists`] still
    /// wins for a test that genuinely wants the impossible state.
    pub fn with_read_permission_denied(self, path: &str) -> Self {
        let path_buf = PathBuf::from(path);
        self.read_permission_denied
            .lock()
            .expect("read_permission_denied mutex poisoned")
            .insert(path_buf.clone());
        self.file_metadata
            .lock()
            .expect("metadata mutex poisoned")
            .entry(path_buf)
            .or_insert(FileMetadata {
                exists: true,
                is_file: true,
                is_dir: false,
                mode: 0o600,
                size: 0,
                uid: 0,
                gid: 0,
            });
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
                    mode: 0o100644,
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

    /// Overridden rather than inherited: the provided body shells out to
    /// `readlink`, and the mock registers no such command, so every fixture
    /// would report "could not determine" for a path it knows perfectly well.
    /// The mock owns its filesystem, so it answers from the registry.
    async fn read_link(&self, path: &Path) -> Result<Option<String>> {
        Ok(self
            .symlinks
            .lock()
            .expect("symlinks mutex poisoned")
            .get(path)
            .cloned())
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
        if let Some(output) = self
            .commands
            .lock()
            .expect("commands mutex poisoned")
            .get(&key)
            .cloned()
        {
            return Ok(output);
        }
        // Fall back to a program-level registration for commands whose exact
        // arguments a test cannot predict.
        self.command_programs
            .lock()
            .expect("command_programs mutex poisoned")
            .get(program)
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

    /// The mock answers `read_link` from its own registry, and an unregistered
    /// path is positively not a symlink.
    ///
    /// The second half is what lets every fixture written before symlinks existed
    /// go on describing the same host: the inherited body shells out to
    /// `readlink`, which no fixture registers, so it would report "could not
    /// determine" for paths the mock knows exactly.
    #[tokio::test]
    async fn read_link_answers_from_the_registry_and_defaults_to_not_a_symlink() {
        let executor = MockExecutor::new()
            .with_file("/etc/plain.conf", "x\n")
            .with_symlink("/etc/link.conf", "/usr/etc/plain.conf");

        assert_eq!(
            executor
                .read_link(Path::new("/etc/link.conf"))
                .await
                .expect("registered link"),
            Some("/usr/etc/plain.conf".to_string())
        );
        assert_eq!(
            executor
                .read_link(Path::new("/etc/plain.conf"))
                .await
                .expect("registered file"),
            None,
            "a path with no registered link must read as not a symlink"
        );
    }
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
    async fn a_read_denied_path_still_reports_as_present() {
        // A root-only file is present and refuses to open. No executor
        // produces "denied, and also absent": LocalExecutor::path_exists
        // confirms absence only on NotFound and returns an error for a denied
        // probe. A mock that reported such a path as absent is gentler than
        // reality, so a caller that consults the probe before falling back
        // takes a branch it could never take on a real host.
        let mock = MockExecutor::new().with_read_permission_denied("/etc/ssh/sshd_config");
        assert!(
            mock.path_exists(std::path::Path::new("/etc/ssh/sshd_config"))
                .await
                .expect("the probe itself succeeds"),
            "a file whose read is denied is still there"
        );
    }

    #[tokio::test]
    async fn a_read_denied_path_keeps_metadata_it_was_already_given() {
        // Denial must not overwrite what a fixture stated deliberately, so
        // ordering in the builder chain cannot change the answer.
        let mock = MockExecutor::new()
            .with_read_permission_denied("/etc/shadow")
            .with_file_metadata(
                "/etc/shadow",
                "root:x:",
                FileMetadata {
                    exists: true,
                    is_file: true,
                    is_dir: false,
                    mode: 0o600,
                    size: 7,
                    uid: 0,
                    gid: 42,
                },
            );
        let metadata = mock
            .file_metadata(std::path::Path::new("/etc/shadow"))
            .await
            .expect("metadata reads");
        assert_eq!(metadata.mode, 0o600, "the stated mode must survive");
        assert_eq!(metadata.gid, 42, "the stated ownership must survive");
    }

    #[tokio::test]
    async fn a_read_denied_path_can_still_be_declared_absent_explicitly() {
        // The escape hatch stays open: an explicit path_exists override wins,
        // so a test that genuinely wants the impossible state can say so.
        let mock = MockExecutor::new()
            .with_read_permission_denied("/etc/nope")
            .with_path_exists("/etc/nope", false);
        assert!(
            !mock
                .path_exists(std::path::Path::new("/etc/nope"))
                .await
                .expect("the probe itself succeeds")
        );
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
