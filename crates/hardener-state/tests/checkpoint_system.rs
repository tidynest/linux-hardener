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

    // Create test files
    let file1 = fixture.create_test_file("config.txt", "original content");
    let file2 = fixture.create_test_file("settings.conf", "setting=value");

    // Create checkpoint
    let checkpoint_id = fixture
        .checkpoint_manager
        .create_checkpoint("test checkpoint", &[&file1, &file2])
        .await
        .expect("Failed to create checkpoint");

    // Verify checkpoint was created
    let (checkpoint, file_states) = fixture
        .checkpoint_manager
        .get_checkpoint(&checkpoint_id)
        .await
        .expect("Failed to retrieve checkpoint");

    assert_eq!(checkpoint.checkpoint_name, "test checkpoint");
    assert_eq!(file_states.len(), 2);
    assert_eq!(checkpoint.checkpoint_signature.len(), 64);
    // Ed25519 signature
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

    // Create file with specific permissions
    let file_path = fixture.create_test_file_with_permissions(
        "test.conf",
        "test content",
        0o644,
    );

    // Create checkpoint
    let checkpoint_id = fixture
        .checkpoint_manager
        .create_checkpoint("state capture test", &[&file_path])
        .await
        .expect("Failed to create checkpoint");

    // Retrieve and verify file state
    let (_checkpoint, file_states) = fixture
        .checkpoint_manager
        .get_checkpoint(&checkpoint_id)
        .await
        .expect("Failed to retrieve checkpoint");

    assert_eq!(file_states.len(), 1);

    let file_state = &file_states[0];
    assert_eq!(
        file_state.file_path,
        file_path.to_string_lossy());
    assert_eq!(
        file_state.file_content.as_ref().unwrap(),
        b"test content"
    );
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

    // Create original file
    let file_path =
        fixture.create_test_file_with_permissions(
            "important.conf",
            "original content",
            0o644,
        );

    // Create checkpoint
    let checkpoint_id = fixture
        .checkpoint_manager
        .create_checkpoint("before modification", &[&file_path])
        .await
        .expect("Failed to create checkpoint");

    // Modify the file (simulating hardening changes)
    std::fs::write(&file_path, "modified content")
        .expect("Failed to modify file");
    std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o600))
        .expect("Failed to change permissions");

    // Verify file was modified
    assert_eq!(fixture.read_file(&file_path), "modified content");

    // Rollback to checkpoint
    fixture
        .checkpoint_manager
        .rollback(&checkpoint_id)
        .await
        .expect("Failed to rollback");

    // Verify file is restored to original state
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

    // Create test file
    let file_path = fixture.create_test_file("test.txt", "content");

    // Create multiple checkpoints
    let checkpoint1 = fixture
        .checkpoint_manager
        .create_checkpoint("first checkpoint", &[&file_path])
        .await
        .expect("Failed to create checkpoint 1");

    // Small delay to ensure different timestamps
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    let checkpoint2 = fixture
        .checkpoint_manager
        .create_checkpoint("second checkpoint", &[&file_path])
        .await
        .expect("Failed to create checkpoint 2");

    // List all checkpoints
    let checkpoints = fixture
        .checkpoint_manager
        .list_checkpoints()
        .await
        .expect("Failed to list checkpoints");

    // Verify both checkpoints exist
    assert_eq!(checkpoints.len(), 2);

    // Verify they're sorted by timestamp (newest first)
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

    // Create test files
    let file1 = fixture.create_test_file("file1.txt", "content1");
    let file2 = fixture.create_test_file("file2.txt", "content2");

    // Create checkpoint
    let checkpoint_id = fixture
        .checkpoint_manager
        .create_checkpoint("to be deleted", &[&file1, &file2])
        .await
        .expect("Failed to create checkpoint");

    // Verify checkpoint exists
    let checkpoints_before = fixture
        .checkpoint_manager
        .list_checkpoints()
        .await
        .expect("Failed to list checkpoints");
    assert_eq!(checkpoints_before.len(), 1);

    // Delete checkpoint
    fixture
        .checkpoint_manager
        .delete_checkpoint(&checkpoint_id)
        .await
        .expect("Failed to delete checkpoint");

    // Verify checkpoint is gone
    let checkpoints_after = fixture
        .checkpoint_manager
        .list_checkpoints()
        .await
        .expect("Failed to list checkpoints");
    assert_eq!(checkpoints_after.len(), 0);

    // Verify get_checkpoint fails
    let result = fixture
        .checkpoint_manager
        .get_checkpoint(&checkpoint_id)
        .await;
    assert!(result.is_err(), "Expected error when retrieving deleted checkpoint");
}
