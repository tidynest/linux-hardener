//! Local system executor - wraps direct filesystem and command operations.

use super::{CommandOutput, FileMetadata, SystemExecutor};
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};
use tokio::process::Command;

/// Returns true for paths under the kernel-interface pseudo-filesystems
/// (`/proc`, `/sys`).
///
/// procfs and sysfs forbid creating new files (no `O_CREAT`) and their
/// entries cannot be replaced by a rename, so the usual atomic
/// temp-file-plus-rename write is impossible there. It is also unnecessary:
/// a write to an existing kernel-interface entry is a single syscall and is
/// therefore already atomic, with no risk of the partial-write states the
/// temp-file dance guards against on ordinary filesystems.
fn is_kernel_interface_path(path: &Path) -> bool {
    path.starts_with("/proc") || path.starts_with("/sys")
}

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
        if is_kernel_interface_path(path) {
            std::fs::write(path, content)
                .with_context(|| format!("Failed to write file {}", path.display()))
        } else {
            hardener_common::file_utils::update_file_atomically(path, content)
                .with_context(|| format!("Failed to write file {}", path.display()))
        }
    }

    async fn path_exists(&self, path: &Path) -> Result<bool> {
        // Not `path.exists()`: that folds every error into `false`, so a path
        // this process may not stat (an unsearchable parent directory) reads as
        // positive confirmation of absence. Callers that fail closed on "could
        // not determine" then take the "confirmed absent" branch instead, which
        // is how the rollback guard protecting /etc/shadow and friends became
        // unreachable on a local target. Same rule as `file_metadata` below:
        // only NotFound confirms absence.
        match std::fs::metadata(path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e)
                .with_context(|| format!("Failed to determine whether {} exists", path.display())),
        }
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
            // Only NotFound is positive confirmation of absence. Every other
            // error means "could not determine" and must propagate: see the
            // contract on SystemExecutor::file_metadata.
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
        // tokio's process spawn keeps this future non-blocking, so plugins
        // scanned concurrently genuinely overlap their command waits.
        let output = Command::new(&resolved)
            .args(args)
            .output()
            .await
            .with_context(|| format!("Failed to execute command {}", resolved))?;

        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or(-1),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_interface_path_matches_proc_and_sys() {
        assert!(is_kernel_interface_path(Path::new(
            "/proc/sys/net/ipv4/ip_forward"
        )));
        assert!(is_kernel_interface_path(Path::new(
            "/sys/kernel/mm/transparent_hugepage/enabled"
        )));
    }

    #[test]
    fn kernel_interface_path_rejects_ordinary_and_lookalike_paths() {
        assert!(!is_kernel_interface_path(Path::new(
            "/etc/sysctl.d/99-hardening.conf"
        )));
        assert!(!is_kernel_interface_path(Path::new("/etc/procmail.conf")));
        assert!(!is_kernel_interface_path(Path::new("/etc/sysprep.conf")));
        assert!(!is_kernel_interface_path(Path::new(
            "/home/user/proc/notes"
        )));
        assert!(!is_kernel_interface_path(Path::new("relative/proc/path")));
    }

    #[tokio::test]
    async fn write_file_to_ordinary_path_still_round_trips_atomically() {
        // A real /proc write needs root and cannot be exercised here, so
        // this test instead pins down the non-kernel-interface branch:
        // ordinary paths (the vast majority of writes, e.g. /etc/sysctl.d
        // drop-ins) must keep going through update_file_atomically after
        // the dispatch is introduced, preserving existing permissions and
        // surviving a mid-write crash without truncating the target.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("99-hardening.conf");
        std::fs::write(&path, "old\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let exec = LocalExecutor::new();
        exec.write_file(&path, "new\n").await.unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new\n");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644,
            "atomic write must preserve original permissions"
        );
    }

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

    /// Guards the probe string against a real shell rather than a fake
    /// executor. It passes against the shipped `which` probe too, because this
    /// host has `which`; what it adds is proof that the replacement asks a
    /// real shell the same question and gets the same three answers.
    #[tokio::test]
    async fn command_exists_answers_against_a_real_shell() {
        let executor = LocalExecutor::new();

        assert!(
            executor.command_exists("sh").await.unwrap(),
            "sh is spawnable here or nothing in this suite could have run"
        );
        assert!(
            !executor
                .command_exists("__no_such_program__")
                .await
                .unwrap(),
            "an absent program is an answer, not an error"
        );
        assert!(
            !executor.command_exists("cd").await.unwrap(),
            "`cd` is a shell builtin with no binary behind it: execute_command \
             could not spawn it, so command_exists must not claim it is there"
        );
    }
}
