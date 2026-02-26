//! Local system executor - wraps direct filesystem and command operations.

use super::{CommandOutput, FileMetadata, SystemExecutor};
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::{os::unix::fs::PermissionsExt, path::Path, process::Command};

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
                mode: meta.permissions().mode() & 0o777,
                size: meta.len(),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(FileMetadata {
                exists: false,
                is_file: false,
                is_dir: false,
                mode: 0,
                size: 0,
            }),
            Err(e) => Err(e).with_context(|| format!("Failed to get metadata {}", path.display())),
        }
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
