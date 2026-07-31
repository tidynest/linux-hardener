mod common;

use common::{DiskExecutor, TestFixture};
use std::path::Path;

/// The packaged unit an enablement symlink points at. Outside every rollback
/// allowlist and deliberately not created here: a restore recreates the link,
/// it never follows it, so a target that is not there must make no difference.
const PACKAGED_UNIT: &str = "/usr/lib/systemd/system/bluetooth.service";

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
        .rollback(&DiskExecutor, &checkpoint_id)
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
        .rollback(&DiskExecutor, &checkpoint_id)
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
        .rollback(&DiskExecutor, &checkpoint_id)
        .await
        .expect("Failed to rollback metadata-only checkpoint");

    let restored_mode = std::fs::metadata(&dir_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        restored_mode, 0o755,
        "Metadata-only rollback should restore permissions"
    );
}

/// Locates one path's entry in a rollback result, panicking with the path if it
/// is absent. Shared by the two tests below so each can assert per entry rather
/// than on the aggregate, which reports only that something went wrong.
fn restore_entry<'a>(
    result: &'a hardener_state::checkpoint::RollbackResult,
    path: &Path,
) -> &'a hardener_state::checkpoint::FileRestoreResult {
    result
        .rollback_files
        .iter()
        .find(|f| f.restore_path == path.to_string_lossy())
        .unwrap_or_else(|| panic!("{} missing from the rollback result", path.display()))
}

/// `systemctl disable` removes the enablement symlink and, once that empties the
/// `*.target.wants` directory, the directory with it. A rollback has to put both
/// back and could put back neither: `chmod` on an absent directory fails, and
/// `ln` will not create the directory its link belongs in.
///
/// Measured on all five test distributions: `hardener rollback` of a
/// `service-minimisation-pre-apply` checkpoint exited 1 with exactly these two
/// failures per host, while a sibling symlink in the surviving
/// `/etc/systemd/system` came back in the same run.
///
/// [`DiskExecutor`] rather than a `MockExecutor`: the defect is that `chmod` and
/// `ln` fail on a path whose directory is gone, and the mock answers a
/// registered command from its registry without consulting its virtual
/// filesystem, so a mock fixture reports success either way and cannot fail
/// before the fix.
#[tokio::test]
async fn rollback_recreates_a_wants_directory_and_symlink_that_vanished_together() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = TestFixture::new().await;

    let wants_dir = fixture.create_test_dir_with_permissions("bluetooth.target.wants", 0o755);
    let link = wants_dir.join("bluetooth.service");
    // Where a real enablement symlink points: at the packaged unit, outside
    // anything this tool may write. Restoring recreates the link rather than
    // writing through it, so the target is never touched and need not exist.
    std::os::unix::fs::symlink(PACKAGED_UNIT, &link).expect("Failed to create enablement symlink");

    let checkpoint_id = fixture
        .fixture_checkpoint_manager
        .create_checkpoint(
            &DiskExecutor,
            "service-minimisation-pre-apply",
            &[&wants_dir],
        )
        .await
        .expect("Failed to create checkpoint");

    // What `systemctl disable bluetooth` leaves behind.
    std::fs::remove_file(&link).expect("Failed to remove symlink");
    std::fs::remove_dir(&wants_dir).expect("Failed to remove wants directory");

    let result = fixture
        .fixture_checkpoint_manager
        .rollback(&DiskExecutor, &checkpoint_id)
        .await
        .expect("Failed to rollback");

    // The symlink is asserted first so that a regression in the directory half
    // cannot hide whether this half was reached at all.
    let link_entry = restore_entry(&result, &link);
    assert!(
        link_entry.restore_success,
        "the enablement symlink must be recreated, got: {:?}",
        link_entry.restore_error
    );
    let dir_entry = restore_entry(&result, &wants_dir);
    assert!(
        dir_entry.restore_success,
        "the emptied wants directory must be recreated before its mode is restored, got: {:?}",
        dir_entry.restore_error
    );
    assert!(
        result.rollback_success,
        "a rollback that restored every path is a successful one, got: {:?}",
        result.rollback_files
    );

    // Reported success is not the claim; both paths are back on disk, the
    // directory with the mode the checkpoint recorded and the link pointing
    // where it pointed.
    let restored_mode = std::fs::metadata(&wants_dir)
        .expect("the wants directory must exist again")
        .permissions()
        .mode();
    assert_eq!(restored_mode & 0o777, 0o755, "directory mode not restored");
    assert_eq!(
        std::fs::read_link(&link).expect("the symlink must exist again"),
        Path::new(PACKAGED_UNIT)
    );
}

/// A row carrying no content is not therefore a directory, and the rows that are
/// not must never have a directory made in their place.
///
/// `create_checkpoint_metadata_only` stores mode and ownership and no content at
/// all, which is how the permissions plugin checkpoints `/etc/passwd`,
/// `/etc/shadow`, `/etc/gshadow` and `/etc/sudoers`: deliberately, so that no
/// password file's contents are ever written to the checkpoint database. A
/// best-effort capture of an unreadable file found by recursing into a declared
/// directory produces the same shape. Either is indistinguishable from a
/// captured directory's row but for the file-type bit in the recorded mode.
/// Were that bit not consulted, restoring such a row whose file had since been
/// removed would run `mkdir -p` over it and leave a *directory* named
/// `/etc/shadow` behind, with the chmod and chown that follow both succeeding on
/// it, so the rollback would report the path restored.
///
/// The honest outcome asserted here is that the row cannot be restored: a
/// metadata-only checkpoint holds nothing to recreate the file from, so the
/// rollback reports the failure and leaves the path alone. That is a real
/// failure, unlike the mode-0 case, because this row recorded the path as
/// present.
#[tokio::test]
async fn a_metadata_only_row_for_a_vanished_file_is_never_restored_as_a_directory() {
    let fixture = TestFixture::new().await;

    // A regular file, captured the way an account database is captured.
    let account_file = fixture.create_test_file_with_permissions("shadow", "root:!:20000\n", 0o600);

    let checkpoint_id = fixture
        .fixture_checkpoint_manager
        .create_checkpoint_metadata_only(
            &DiskExecutor,
            "permissions-hardening-pre-apply",
            &[&account_file],
        )
        .await
        .expect("Failed to create checkpoint");

    std::fs::remove_file(&account_file).expect("Failed to remove the account file");

    let result = fixture
        .fixture_checkpoint_manager
        .rollback(&DiskExecutor, &checkpoint_id)
        .await
        .expect("Failed to rollback");

    // Asserted first, and on disk, because this is the harm: everything below
    // is a consequence of it.
    assert!(
        !account_file.is_dir(),
        "a metadata-only row for a file must never be restored as a directory"
    );
    assert!(
        !account_file.exists(),
        "a metadata-only checkpoint holds no content, so nothing can recreate \
         the file and nothing may be put in its place"
    );

    let entry = restore_entry(&result, &account_file);
    assert!(
        !entry.restore_success,
        "a recorded path that cannot be restored must say so, not report success"
    );
    assert!(
        entry
            .restore_error
            .as_deref()
            .unwrap_or_default()
            .contains(&account_file.to_string_lossy().into_owned()),
        "the failure must name the path it could not restore, got: {:?}",
        entry.restore_error
    );
    assert!(
        !result.rollback_success,
        "a rollback that could not restore a recorded path is not a successful one"
    );
}

/// The directory a restored symlink needs is created for that symlink's sake,
/// not as a side effect of some other row.
///
/// In the measured case the checkpoint also held a row for the wants directory,
/// and that row happens to be restored first, because the file-state query
/// orders by path and a parent's path is a prefix of its children's. A
/// checkpoint naming the link alone carries no such row, and nothing in the
/// rollback promises one: an ordering no code asserts is not a fix.
#[tokio::test]
async fn rollback_recreates_the_directory_a_restored_symlink_needs() {
    let fixture = TestFixture::new().await;

    let wants_dir = fixture.create_test_dir_with_permissions("sockets.target.wants", 0o755);
    let link = wants_dir.join("dbus.socket");
    std::os::unix::fs::symlink(PACKAGED_UNIT, &link).expect("Failed to create enablement symlink");

    // The link alone, so no row for its directory can restore it first.
    let checkpoint_id = fixture
        .fixture_checkpoint_manager
        .create_checkpoint(&DiskExecutor, "link-only-pre-apply", &[&link])
        .await
        .expect("Failed to create checkpoint");

    std::fs::remove_file(&link).expect("Failed to remove symlink");
    std::fs::remove_dir(&wants_dir).expect("Failed to remove wants directory");

    let result = fixture
        .fixture_checkpoint_manager
        .rollback(&DiskExecutor, &checkpoint_id)
        .await
        .expect("Failed to rollback");

    let link_entry = restore_entry(&result, &link);
    assert!(
        link_entry.restore_success,
        "the symlink must be recreated even with no row for its directory, got: {:?}",
        link_entry.restore_error
    );
    assert!(
        result.rollback_success,
        "a rollback that restored every path is a successful one, got: {:?}",
        result.rollback_files
    );
    assert_eq!(
        std::fs::read_link(&link).expect("the symlink must exist again"),
        Path::new(PACKAGED_UNIT)
    );
}
