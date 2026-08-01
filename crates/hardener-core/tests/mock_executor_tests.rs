//! Unit tests for MockExecutor.
//!
//! These tests verify the MockExecutor correctly simulates file and command operations.

use hardener_core::{CommandOutput, FileMetadata, LocalExecutor, MockExecutor, SystemExecutor};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[tokio::test]
async fn test_mock_executor_description() {
    let executor = MockExecutor::new();
    assert_eq!(executor.description(), "mock");
    assert!(
        !executor.is_remote(),
        "default mock executor should not be remote"
    );

    let remote = MockExecutor::new().remote();
    assert_eq!(remote.description(), "mock-remote");
    assert!(
        remote.is_remote(),
        "remote mock executor should report as remote"
    );

    let custom = MockExecutor::new().with_description("test-executor");
    assert_eq!(custom.description(), "test-executor");
}

#[tokio::test]
async fn test_mock_executor_read_file() {
    let executor = MockExecutor::new().with_file("/etc/test.conf", "key=value\n");

    let content = executor
        .read_file(Path::new("/etc/test.conf"))
        .await
        .unwrap();
    assert_eq!(content, "key=value\n");

    // Verify read was logged
    let log = executor.log();
    assert_eq!(log.files_read.len(), 1);
    assert_eq!(log.files_read[0].to_str().unwrap(), "/etc/test.conf");
}

#[tokio::test]
async fn test_mock_executor_read_file_not_found() {
    let executor = MockExecutor::new();

    let result = executor.read_file(Path::new("/nonexistent")).await;
    assert!(
        result.is_err(),
        "reading nonexistent file should return error, got: {result:?}"
    );
    assert!(result.unwrap_err().to_string().contains("file not found"));
}

#[tokio::test]
async fn test_mock_executor_read_file_optional() {
    let executor = MockExecutor::new().with_file("/etc/exists.conf", "content");

    // File exists
    let result = executor
        .read_file_optional(Path::new("/etc/exists.conf"))
        .await
        .unwrap();
    assert_eq!(result, Some("content".to_string()));

    // File doesn't exist
    let result = executor
        .read_file_optional(Path::new("/etc/missing.conf"))
        .await
        .unwrap();
    assert_eq!(result, None);
}

#[tokio::test]
async fn test_mock_executor_write_file() {
    let executor = MockExecutor::new();

    executor
        .write_file(Path::new("/etc/new.conf"), "new content")
        .await
        .unwrap();

    // Verify file was written
    let content = executor
        .read_file(Path::new("/etc/new.conf"))
        .await
        .unwrap();
    assert_eq!(content, "new content");

    // Verify write was logged
    let log = executor.log();
    assert_eq!(log.files_written.len(), 1);
    assert_eq!(log.files_written[0].0.to_str().unwrap(), "/etc/new.conf");
    assert_eq!(log.files_written[0].1, "new content");
}

#[tokio::test]
async fn test_mock_executor_path_exists() {
    let executor = MockExecutor::new()
        .with_file("/etc/exists.conf", "")
        .with_directory("/etc/mydir");

    assert!(
        executor
            .path_exists(Path::new("/etc/exists.conf"))
            .await
            .unwrap(),
        "registered file path should exist"
    );
    assert!(
        executor.path_exists(Path::new("/etc/mydir")).await.unwrap(),
        "registered directory path should exist"
    );
    assert!(
        !executor
            .path_exists(Path::new("/etc/missing"))
            .await
            .unwrap(),
        "unregistered path should not exist"
    );
}

#[tokio::test]
async fn test_mock_executor_file_metadata() {
    let executor = MockExecutor::new()
        .with_file("/etc/test.conf", "12345")
        .with_directory("/etc/mydir");

    // File metadata
    let meta = executor
        .file_metadata(Path::new("/etc/test.conf"))
        .await
        .unwrap();
    assert!(meta.exists, "file metadata should report exists");
    assert!(meta.is_file, "file metadata should report is_file");
    assert!(!meta.is_dir, "file metadata should not report is_dir");
    // Full st_mode, `S_IFREG` included, as both real executors report it.
    assert_eq!(meta.mode, 0o100644);
    assert_eq!(meta.size, 5); // "12345" = 5 bytes

    // Directory metadata
    let meta = executor
        .file_metadata(Path::new("/etc/mydir"))
        .await
        .unwrap();
    assert!(meta.exists, "directory metadata should report exists");
    assert!(
        !meta.is_file,
        "directory metadata should not report is_file"
    );
    assert!(meta.is_dir, "directory metadata should report is_dir");
    // `S_IFDIR` likewise: a caller reading the type bit back out must see a
    // directory here, or a mock-based test of directory handling silently
    // exercises the file path instead.
    assert_eq!(meta.mode, 0o040755);

    // Nonexistent path
    let meta = executor
        .file_metadata(Path::new("/nonexistent"))
        .await
        .unwrap();
    assert!(
        !meta.exists,
        "nonexistent path metadata should not report exists"
    );
}

#[tokio::test]
async fn test_mock_executor_custom_file_metadata() {
    let custom_meta = FileMetadata {
        exists: true,
        is_file: true,
        is_dir: false,
        mode: 0o600,
        size: 100,
        uid: 0,
        gid: 0,
    };

    let executor = MockExecutor::new().with_file_metadata("/etc/secret.key", "secret", custom_meta);

    let meta = executor
        .file_metadata(Path::new("/etc/secret.key"))
        .await
        .unwrap();
    assert_eq!(meta.mode, 0o600);
    assert_eq!(meta.size, 100); // Custom size, not actual content length
}

#[tokio::test]
async fn test_mock_executor_execute_command() {
    let executor = MockExecutor::new().with_command(
        "systemctl",
        &["status", "sshd"],
        CommandOutput {
            stdout: "active (running)\n".to_string(),
            stderr: String::new(),
            exit_code: 0,
        },
    );

    let output = executor
        .execute_command("systemctl", &["status", "sshd"])
        .await
        .unwrap();
    assert!(
        output.success(),
        "registered command should report success, exit_code: {}",
        output.exit_code
    );
    assert_eq!(output.stdout, "active (running)\n");
    assert_eq!(output.exit_code, 0);

    // Verify command was logged
    let log = executor.log();
    assert_eq!(log.commands_executed.len(), 1);
    assert_eq!(log.commands_executed[0].0, "systemctl");
    assert_eq!(log.commands_executed[0].1, vec!["status", "sshd"]);
}

#[tokio::test]
async fn test_mock_executor_command_not_registered() {
    let executor = MockExecutor::new();

    let result = executor.execute_command("unknown", &["arg"]).await;
    assert!(
        result.is_err(),
        "unregistered command should return error, got: {result:?}"
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("command not registered"),
        "error should mention 'command not registered'"
    );
}

#[tokio::test]
async fn test_mock_executor_command_exists() {
    let executor = MockExecutor::new()
        .with_command_exists("systemctl", true)
        .with_command_exists("nonexistent", false)
        .with_command(
            "sshd",
            &["-t"],
            CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        );

    // Explicitly registered
    assert!(
        executor.command_exists("systemctl").await.unwrap(),
        "explicitly registered command should exist"
    );
    assert!(
        !executor.command_exists("nonexistent").await.unwrap(),
        "explicitly non-existent command should not exist"
    );

    // Inferred from registered command
    assert!(
        executor.command_exists("sshd").await.unwrap(),
        "command inferred from registered args should exist"
    );

    // Unknown command
    assert!(
        !executor.command_exists("unknown").await.unwrap(),
        "unknown command should not exist"
    );
}

#[tokio::test]
async fn test_mock_executor_log_operations() {
    let executor = MockExecutor::new()
        .with_file("/etc/test", "content")
        .with_command(
            "echo",
            &["hello"],
            CommandOutput {
                stdout: "hello\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        );

    // Perform operations
    let _ = executor.read_file(Path::new("/etc/test")).await;
    let _ = executor.write_file(Path::new("/etc/new"), "new").await;
    let _ = executor.execute_command("echo", &["hello"]).await;

    let log = executor.log();
    assert_eq!(log.files_read.len(), 1);
    assert_eq!(log.files_written.len(), 1);
    assert_eq!(log.commands_executed.len(), 1);

    // Clear log and verify
    executor.clear_log();
    let log = executor.log();
    assert!(
        log.files_read.is_empty(),
        "cleared log should have no files_read, found: {:?}",
        log.files_read
    );
    assert!(
        log.files_written.is_empty(),
        "cleared log should have no files_written, found: {:?}",
        log.files_written
    );
    assert!(
        log.commands_executed.is_empty(),
        "cleared log should have no commands_executed, found: {:?}",
        log.commands_executed
    );
}

#[tokio::test]
async fn test_mock_executor_files_accessor() {
    let executor = MockExecutor::new()
        .with_file("/etc/a.conf", "a")
        .with_file("/etc/b.conf", "b");

    let files = executor.files();
    assert_eq!(files.len(), 2);
    assert_eq!(files.get(Path::new("/etc/a.conf")).unwrap(), "a");
    assert_eq!(files.get(Path::new("/etc/b.conf")).unwrap(), "b");
}

#[tokio::test]
async fn test_mock_executor_clone_shares_state() {
    let executor = MockExecutor::new().with_file("/etc/test", "original");

    let clone = executor.clone();

    // Write via clone
    clone
        .write_file(Path::new("/etc/test"), "modified")
        .await
        .unwrap();

    // Original sees the change (they share Arc<Mutex<...>>)
    let content = executor.read_file(Path::new("/etc/test")).await.unwrap();
    assert_eq!(content, "modified");
}

/// The `mode` clause of the `file_metadata` contract, asserted against every
/// implementation in one place rather than once per implementation.
///
/// An existing path must report a mode with its file-type bits set, because
/// checkpoint capture stores an absent path as mode 0 and rollback removes
/// anything recorded that way. An implementation returning permission bits
/// alone makes a 0000-perm file, such as `/etc/shadow` on Arch, indistinguishable
/// from a path that was never there. `0b96045` fixed exactly that in both
/// shipped implementations, and the three regression tests it left behind each
/// sit beside the implementation they cover, so nothing stated the rule itself.
/// A fourth implementation could honour every documented outcome and still
/// reintroduce the defect.
async fn assert_existing_path_carries_a_type_bit(
    executor: &dyn SystemExecutor,
    path: &Path,
    label: &str,
) {
    let meta = executor
        .file_metadata(path)
        .await
        .unwrap_or_else(|e| panic!("{label}: metadata for an existing path must be readable: {e}"));
    assert!(meta.exists, "{label}: the fixture path must exist");
    assert_ne!(
        meta.mode & 0o170000,
        0,
        "{label}: an existing path reported mode {:#o}, which carries no file-type \
         bits. Checkpoint rollback removes any path it recorded with mode 0, so this \
         makes an existing file deletable. Return the full st_mode.",
        meta.mode
    );
}

#[tokio::test]
async fn every_executor_reports_an_existing_path_with_its_type_bits() {
    // The mock, whose fixtures are what most of this workspace's tests see.
    let mock = MockExecutor::new()
        .with_file("/etc/zero-perm", "")
        .with_directory("/etc/somewhere");
    assert_existing_path_carries_a_type_bit(&mock, Path::new("/etc/zero-perm"), "mock file").await;
    assert_existing_path_carries_a_type_bit(&mock, Path::new("/etc/somewhere"), "mock dir").await;

    // The local executor, against a real 0000-perm file, which is the exact
    // shape that was being deleted before `0b96045`.
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("zero-perm");
    std::fs::write(&file, b"").expect("write");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    assert_existing_path_carries_a_type_bit(&LocalExecutor::new(), &file, "local 0000-perm file")
        .await;
    assert_existing_path_carries_a_type_bit(&LocalExecutor::new(), dir.path(), "local dir").await;
}
