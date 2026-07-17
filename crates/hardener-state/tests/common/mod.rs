//! Shared test utilities for checkpoint system tests.

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use hardener_common::executor::{CommandOutput, FileMetadata, MockExecutor, SystemExecutor};
use hardener_state::{CheckpointManager, init_db};
use sqlx::SqlitePool;
use std::fs::Permissions;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// A minimal executor that performs real filesystem operations on the local host.
///
/// Used in integration tests where rollback must write back to disk so that
/// assertions on real file contents remain valid.  Only the methods exercised
/// by the rollback path are fully implemented; others return plausible values
/// or errors.
pub struct DiskExecutor;

#[async_trait]
impl SystemExecutor for DiskExecutor {
    fn description(&self) -> String {
        "local".to_string()
    }

    fn is_remote(&self) -> bool {
        false
    }

    async fn read_file(&self, path: &Path) -> Result<String> {
        std::fs::read_to_string(path).map_err(|e| anyhow!(e))
    }

    async fn read_file_optional(&self, path: &Path) -> Result<Option<String>> {
        match std::fs::read_to_string(path) {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(anyhow!(e)),
        }
    }

    async fn write_file(&self, path: &Path, content: &str) -> Result<()> {
        std::fs::write(path, content).map_err(|e| anyhow!(e))
    }

    async fn path_exists(&self, path: &Path) -> Result<bool> {
        Ok(path.exists())
    }

    async fn file_metadata(&self, path: &Path) -> Result<FileMetadata> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        match std::fs::symlink_metadata(path) {
            Ok(m) => Ok(FileMetadata {
                exists: true,
                is_file: m.is_file(),
                is_dir: m.is_dir(),
                mode: m.permissions().mode(),
                size: m.len(),
                uid: m.uid(),
                gid: m.gid(),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(FileMetadata {
                exists: false,
                is_file: false,
                is_dir: false,
                mode: 0,
                size: 0,
                uid: 0,
                gid: 0,
            }),
            Err(e) => Err(anyhow!(e)),
        }
    }

    async fn execute_command(&self, program: &str, args: &[&str]) -> Result<CommandOutput> {
        let out = std::process::Command::new(program)
            .args(args)
            .output()
            .map_err(|e| anyhow!("{program}: {e}"))?;
        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            exit_code: out.status.code().unwrap_or(-1),
        })
    }

    async fn command_exists(&self, program: &str) -> Result<bool> {
        Ok(std::process::Command::new("which")
            .arg(program)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false))
    }

    async fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>> {
        let entries = std::fs::read_dir(path).map_err(|e| anyhow!(e))?;
        Ok(entries.flatten().map(|e| e.path()).collect())
    }
}

/// Test fixture containing temporary directories and database.
pub struct TestFixture {
    pub fixture_checkpoint_manager: CheckpointManager,
    #[allow(dead_code)]
    pub fixture_db_pool: SqlitePool,
    pub fixture_temp_dir: TempDir,
}

impl TestFixture {
    /// Creates a new test fixture with isolated temp directory and database.
    pub async fn new() -> TestFixture {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");

        // Create database in temp directory
        let db_path = temp_dir.path().join("test_checkpoints.db");

        let db_pool = init_db(Some(&db_path))
            .await
            .expect("Failed to initialise test database");

        // Create signing key in temp directory (not /var/lib which requires root)
        let key_path = temp_dir.path().join("test_signing.key");
        let signer = hardener_state::CheckpointSigner::new_with_path(&key_path)
            .expect("Failed to create signer");

        // Allow temp directory paths for test rollbacks
        let temp_prefix = temp_dir.path().to_string_lossy().to_string();
        let checkpoint_manager =
            CheckpointManager::new_with_allowlist(db_pool.clone(), signer, vec![temp_prefix])
                .expect("Failed to create checkpoint manager");

        TestFixture {
            fixture_checkpoint_manager: checkpoint_manager,
            fixture_db_pool: db_pool,
            fixture_temp_dir: temp_dir,
        }
    }

    /// Creates a test file with specified content.
    pub fn create_test_file(&self, name: &str, content: &str) -> PathBuf {
        let file_path = self.fixture_temp_dir.path().join(name);
        std::fs::write(&file_path, content).expect("Failed to write file");
        file_path
    }

    /// Creates a test file with specific permissions.
    pub fn create_test_file_with_permissions(
        &self,
        name: &str,
        content: &str,
        mode: u32,
    ) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let file_path = self.create_test_file(name, content);
        let permissions = Permissions::from_mode(mode);
        std::fs::set_permissions(&file_path, permissions).expect("Failed to set permissions");

        file_path
    }

    /// Creates a test directory with specific permissions.
    pub fn create_test_dir_with_permissions(&self, name: &str, mode: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let dir_path = self.fixture_temp_dir.path().join(name);
        std::fs::create_dir_all(&dir_path).expect("Failed to create directory");
        std::fs::set_permissions(&dir_path, Permissions::from_mode(mode))
            .expect("Failed to set directory permissions");
        dir_path
    }

    /// Reads the content of a file as a string.
    pub fn read_file(&self, path: &Path) -> String {
        std::fs::read_to_string(path).expect("Failed to read file")
    }

    /// Builds a `MockExecutor` seeded with the current on-disk state of the given paths.
    ///
    /// Files are seeded with their content and real mode bits; directories are seeded
    /// with their mode bits only (no recursion; callers seed each path they need).
    /// This lets `create_checkpoint` use the executor path while rollback still writes
    /// to the real tempdir on disk.
    pub fn mock_for_paths(&self, paths: &[&Path]) -> MockExecutor {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let mut exec = MockExecutor::new();
        for &path in paths {
            let meta = std::fs::symlink_metadata(path).expect("mock_for_paths: stat");
            if meta.is_dir() {
                exec = exec.with_file_metadata(
                    &path.to_string_lossy(),
                    "",
                    FileMetadata {
                        exists: true,
                        is_file: false,
                        is_dir: true,
                        mode: meta.permissions().mode(),
                        size: 0,
                        uid: meta.uid(),
                        gid: meta.gid(),
                    },
                );
                // Also seed immediate children for directory-recursive capture.
                if let Ok(entries) = std::fs::read_dir(path) {
                    for entry in entries.flatten() {
                        let child = entry.path();
                        let child_meta =
                            std::fs::symlink_metadata(&child).expect("mock_for_paths: child stat");
                        if child_meta.is_file() {
                            let content = std::fs::read_to_string(&child).unwrap_or_default();
                            exec = exec.with_file_metadata(
                                &child.to_string_lossy(),
                                &content,
                                FileMetadata {
                                    exists: true,
                                    is_file: true,
                                    is_dir: false,
                                    mode: child_meta.permissions().mode(),
                                    size: child_meta.len(),
                                    uid: child_meta.uid(),
                                    gid: child_meta.gid(),
                                },
                            );
                        }
                    }
                }
            } else {
                let content = std::fs::read_to_string(path).unwrap_or_default();
                exec = exec.with_file_metadata(
                    &path.to_string_lossy(),
                    &content,
                    FileMetadata {
                        exists: true,
                        is_file: true,
                        is_dir: false,
                        mode: meta.permissions().mode(),
                        size: meta.len(),
                        uid: meta.uid(),
                        gid: meta.gid(),
                    },
                );
            }
        }
        exec
    }
}
