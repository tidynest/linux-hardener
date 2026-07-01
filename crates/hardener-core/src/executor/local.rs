//! Local system executor - wraps direct filesystem and command operations.

use super::{CommandOutput, FileMetadata, SystemExecutor};
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

/// Local system executor that operates on the current machine.
#[derive(Clone, Debug, Default)]
pub struct LocalExecutor;

impl LocalExecutor {
    pub fn new() -> LocalExecutor {
        LocalExecutor
    }
}

#[async_trait]
impl SystemExecutor for LocalExecutor {
    fn description(&self) -> String {
        "local".to_string()
    }

    fn is_remote(&self) -> bool {
        false
    }

    async fn read_file(&self, path: &Path) -> Result<String> {
        std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read file {}", path.display()))
    }

    async fn read_file_optional(&self, path: &Path) -> Result<Option<String>> {
        match std::fs::read_to_string(path) {
            Ok(content) => Ok(Some(content)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("Failed to read file {}", path.display())),
        }
    }

    async fn write_file(&self, path: &Path, content: &str) -> Result<()> {
        hardener_common::file_utils::update_file_atomically(path, content)
            .with_context(|| format!("Failed to write file {}", path.display()))
    }

    async fn path_exists(&self, path: &Path) -> Result<bool> {
        Ok(path.exists())
    }

    async fn file_metadata(&self, path: &Path) -> Result<FileMetadata> {
        match std::fs::metadata(path) {
            Ok(meta) => Ok(FileMetadata {
                exists: true,
                is_file: meta.is_file(),
                is_dir: meta.is_dir(),
                // Full st_mode (type + setuid/setgid/sticky + perms). Scan callers
                // mask with `& 0o777` themselves; checkpoint capture needs the type
                // bit so an existing 0000-perm file is not read as "did not exist"
                // (which would make rollback delete it).
                mode: meta.permissions().mode(),
                size: meta.len(),
                uid: meta.uid(),
                gid: meta.gid(),
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
            Err(e) => Err(e).with_context(|| format!("Failed to get metadata {}", path.display())),
        }
    }

    async fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>> {
        let read = match std::fs::read_dir(path) {
            Ok(read) => read,
            // Contract: missing directory → empty vec (matches the ssh/mock impls).
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(e).with_context(|| format!("Failed to read dir {}", path.display()));
            }
        };
        let mut entries = Vec::new();
        for entry in read {
            let entry =
                entry.with_context(|| format!("Failed to read dir entry in {}", path.display()))?;
            entries.push(entry.path());
        }
        Ok(entries)
    }

    async fn execute_command(&self, program: &str, args: &[&str]) -> Result<CommandOutput> {
        let resolved = hardener_common::binary_utils::resolve_binary(program);
        let output = Command::new(&resolved)
            .args(args)
            .output()
            .with_context(|| format!("Failed to execute command {}", resolved))?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_read_dir_lists_immediate_children_only() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.conf"), "x").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/b.conf"), "y").unwrap();
        let exec = LocalExecutor::new();
        let mut got: Vec<String> = exec
            .read_dir(dir.path())
            .await
            .unwrap()
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        got.sort();
        assert_eq!(got, vec!["a.conf", "sub"]);
    }

    #[tokio::test]
    async fn local_read_dir_missing_path_is_empty_not_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        let got = LocalExecutor::new().read_dir(&missing).await.unwrap();
        assert!(
            got.is_empty(),
            "missing directory must yield an empty vec, not an error"
        );
    }

    #[tokio::test]
    async fn metadata_of_zero_perm_file_is_not_confused_with_missing() {
        // Checkpoint rollback treats a stored `mode` of 0 as the sentinel for
        // "path did not exist at capture" (→ the path is removed on restore). An
        // existing file with permissions 0000 (e.g. Arch's /etc/shadow) must
        // therefore never report mode 0, or a rollback would delete it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zero.conf");
        std::fs::write(&path, "x").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

        let meta = LocalExecutor::new().file_metadata(&path).await.unwrap();

        assert!(meta.exists);
        assert_ne!(
            meta.mode, 0,
            "existing 0000-perm file must not report mode 0 (collides with the \
             'did not exist' sentinel checkpoint rollback relies on)"
        );
        assert_eq!(
            meta.mode & 0o777,
            0,
            "permission bits must still read as 0000"
        );
    }
}
