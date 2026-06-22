mod common;

use common::TestFixture;

/// Tests basic checkpoint creation and retrieval.
///
/// Verifies that:
/// - Checkpoints can be created with multiple files
/// - Checkpoint metadata is stored correctly
/// - File states are captured
/// - Ed25519 signature is generated (64 bytes)
#[tokio::test]
async fn test_checkpoint_creation() {
    let fixture = TestFixture::new().await;

    let file1 = fixture.create_test_file("config.txt", "original content");
    let file2 = fixture.create_test_file("settings.conf", "setting=value");

    let exec = fixture.mock_for_paths(&[&file1, &file2]);

    let checkpoint_id = fixture
        .fixture_checkpoint_manager
        .create_checkpoint(&exec, "test checkpoint", &[&file1, &file2])
        .await
        .expect("Failed to create checkpoint");

    let (checkpoint, file_states) = fixture
        .fixture_checkpoint_manager
        .get_checkpoint(&checkpoint_id)
        .await
        .expect("Failed to retrieve checkpoint");

    assert_eq!(checkpoint.checkpoint_name, "test checkpoint");
    assert_eq!(file_states.len(), 2);
    assert_eq!(checkpoint.checkpoint_signature.len(), 64); // Ed25519 signature
}

/// Tests that file state capture includes content, permissions, and ownership.
///
/// Verifies that:
/// - File content is captured correctly as bytes
/// - Unix permissions are preserved
/// - File path is stored accurately
#[tokio::test]
async fn test_file_state_capture() {
    let fixture = TestFixture::new().await;

    let file_path = fixture.create_test_file_with_permissions("test.conf", "test content", 0o644);
    let exec = fixture.mock_for_paths(&[&file_path]);

    let checkpoint_id = fixture
        .fixture_checkpoint_manager
        .create_checkpoint(&exec, "state capture test", &[&file_path])
        .await
        .expect("Failed to create checkpoint");

    let (_checkpoint, file_states) = fixture
        .fixture_checkpoint_manager
        .get_checkpoint(&checkpoint_id)
        .await
        .expect("Failed to retrieve checkpoint");

    assert_eq!(file_states.len(), 1);

    let file_state = &file_states[0];
    assert_eq!(file_state.file_path, file_path.to_string_lossy());
    assert_eq!(file_state.file_content.as_ref().unwrap(), b"test content");
    assert_eq!(file_state.file_permissions & 0o777, 0o644);
}

/// Tests complete rollback workflow: checkpoint → modify → rollback → verify.
///
/// Verifies that:
/// - Files are restored to exact original content
/// - File permissions are restored correctly
/// - Modified files return to checkpoint state
/// - This is the core functionality ensuring safe hardening
#[tokio::test]
async fn test_rollback_restores_files() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = TestFixture::new().await;

    let file_path =
        fixture.create_test_file_with_permissions("important.conf", "original content", 0o644);
    let exec = fixture.mock_for_paths(&[&file_path]);

    let checkpoint_id = fixture
        .fixture_checkpoint_manager
        .create_checkpoint(&exec, "before modification", &[&file_path])
        .await
        .expect("Failed to create checkpoint");

    // Simulate hardening changes on disk
    std::fs::write(&file_path, "modified content").expect("Failed to modify file");
    std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o600))
        .expect("Failed to change permissions");

    assert_eq!(fixture.read_file(&file_path), "modified content");

    fixture
        .fixture_checkpoint_manager
        .rollback(&checkpoint_id)
        .await
        .expect("Failed to rollback");

    assert_eq!(fixture.read_file(&file_path), "original content");

    let metadata = std::fs::metadata(&file_path).expect("Failed to get metadata");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o644);
}

/// Tests listing all checkpoints in the database.
///
/// Verifies that:
/// - Multiple checkpoints can be created
/// - list_checkpoints() returns all checkpoints
/// - Checkpoints are sorted by timestamp (newest first)
#[tokio::test]
async fn test_list_checkpoints() {
    let fixture = TestFixture::new().await;

    let file_path = fixture.create_test_file("test.txt", "content");
    let exec = fixture.mock_for_paths(&[&file_path]);

    let checkpoint1 = fixture
        .fixture_checkpoint_manager
        .create_checkpoint(&exec, "first checkpoint", &[&file_path])
        .await
        .expect("Failed to create checkpoint 1");

    // Small delay to ensure different timestamps
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    let checkpoint2 = fixture
        .fixture_checkpoint_manager
        .create_checkpoint(&exec, "second checkpoint", &[&file_path])
        .await
        .expect("Failed to create checkpoint 2");

    let checkpoints = fixture
        .fixture_checkpoint_manager
        .list_checkpoints()
        .await
        .expect("Failed to list checkpoints");

    assert_eq!(checkpoints.len(), 2);
    assert_eq!(checkpoints[0].checkpoint_id, checkpoint2);
    assert_eq!(checkpoints[1].checkpoint_id, checkpoint1);
    assert_eq!(checkpoints[0].checkpoint_name, "second checkpoint");
    assert_eq!(checkpoints[1].checkpoint_name, "first checkpoint");
}

/// Tests checkpoint deletion functionality.
///
/// Verifies that:
/// - Checkpoints can be deleted
/// - Associated file states are also removed
/// - Deleted checkpoints don't appear in listings
/// - get_checkpoint() fails after deletion
#[tokio::test]
async fn test_delete_checkpoint() {
    let fixture = TestFixture::new().await;

    let file1 = fixture.create_test_file("file1.txt", "content1");
    let file2 = fixture.create_test_file("file2.txt", "content2");
    let exec = fixture.mock_for_paths(&[&file1, &file2]);

    let checkpoint_id = fixture
        .fixture_checkpoint_manager
        .create_checkpoint(&exec, "to be deleted", &[&file1, &file2])
        .await
        .expect("Failed to create checkpoint");

    let checkpoints_before = fixture
        .fixture_checkpoint_manager
        .list_checkpoints()
        .await
        .expect("Failed to list checkpoints");
    assert_eq!(checkpoints_before.len(), 1);

    fixture
        .fixture_checkpoint_manager
        .delete_checkpoint(&checkpoint_id)
        .await
        .expect("Failed to delete checkpoint");

    let checkpoints_after = fixture
        .fixture_checkpoint_manager
        .list_checkpoints()
        .await
        .expect("Failed to list checkpoints");
    assert_eq!(checkpoints_after.len(), 0);

    let result = fixture
        .fixture_checkpoint_manager
        .get_checkpoint(&checkpoint_id)
        .await;
    assert!(
        result.is_err(),
        "Expected error when retrieving deleted checkpoint"
    );
}

/// Tests that directory permissions are captured and restored during rollback.
///
/// Verifies that:
/// - Directory metadata (permissions) is captured without reading file contents
/// - Rollback restores directory permissions to their original state
/// - Files inside the directory are unaffected by directory-level rollback
#[tokio::test]
async fn test_checkpoint_captures_and_restores_directory_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = TestFixture::new().await;

    let dir_path = fixture.create_test_dir_with_permissions("protected_dir", 0o755);
    let child_file = fixture.create_test_file_with_permissions(
        "protected_dir/child.conf",
        "child content",
        0o644,
    );

    // Seed mock with both the directory and its child
    let exec = fixture.mock_for_paths(&[&dir_path]);

    let checkpoint_id = fixture
        .fixture_checkpoint_manager
        .create_checkpoint(&exec, "dir permissions test", &[&dir_path])
        .await
        .expect("Failed to create checkpoint");

    std::fs::set_permissions(&dir_path, std::fs::Permissions::from_mode(0o700))
        .expect("Failed to change directory permissions");
    assert_eq!(
        std::fs::metadata(&dir_path).unwrap().permissions().mode() & 0o777,
        0o700
    );

    fixture
        .fixture_checkpoint_manager
        .rollback(&checkpoint_id)
        .await
        .expect("Failed to rollback");

    let restored_mode = std::fs::metadata(&dir_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(restored_mode, 0o755, "Directory permissions not restored");

    assert_eq!(fixture.read_file(&child_file), "child content");
    let child_mode = std::fs::metadata(&child_file).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        child_mode, 0o644,
        "Child file permissions should be unchanged"
    );
}

/// Tests that metadata-only checkpoints capture permissions without file contents.
///
/// Verifies that:
/// - `create_checkpoint_metadata_only` stores permission/ownership data
/// - No file content is stored (saves space for large directories like /boot)
/// - Rollback still restores permissions correctly
#[tokio::test]
async fn test_metadata_only_checkpoint() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = TestFixture::new().await;

    let dir_path = fixture.create_test_dir_with_permissions("metadata_dir", 0o755);
    let exec = fixture.mock_for_paths(&[&dir_path]);

    let checkpoint_id = fixture
        .fixture_checkpoint_manager
        .create_checkpoint_metadata_only(&exec, "metadata test", &[&dir_path])
        .await
        .expect("Failed to create metadata-only checkpoint");

    let (_checkpoint, file_states) = fixture
        .fixture_checkpoint_manager
        .get_checkpoint(&checkpoint_id)
        .await
        .expect("Failed to retrieve checkpoint");

    assert_eq!(file_states.len(), 1);
    assert!(
        file_states[0].file_content.is_none(),
        "Metadata-only checkpoint should not store content"
    );
    assert_ne!(
        file_states[0].file_permissions, 0,
        "Should have real permissions"
    );

    std::fs::set_permissions(&dir_path, std::fs::Permissions::from_mode(0o700)).unwrap();

    fixture
        .fixture_checkpoint_manager
        .rollback(&checkpoint_id)
        .await
        .expect("Failed to rollback metadata-only checkpoint");

    let restored_mode = std::fs::metadata(&dir_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        restored_mode, 0o755,
        "Metadata-only rollback should restore permissions"
    );
}
