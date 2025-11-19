//! Shared test utilities for checkpoint system tests.

use std::fs::Permissions;
use hardener_state::{
    CheckpointManager,
    CheckpointSigner,
    init_db,
};
use sqlx::SqlitePool;
use std::path::{
    Path,
    PathBuf,
};
use tempfile::TempDir;

/// Test fixture containing temporary directories and database.
pub struct TestFixture {
    pub checkpoint_manager: CheckpointManager,
    pub db_pool: SqlitePool,
    pub temp_dir: TempDir,
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

        // Manually create CheckpointManager with test signer
        let checkpoint_manager = CheckpointManager::new_with_signer(
            db_pool.clone(),
            signer,
        ).expect("Failed to create checkpoint manager");

        TestFixture {
            checkpoint_manager,
            db_pool,
            temp_dir,
        }
    }

    /// Creates a test file with specified content.
    pub fn create_test_file(
        &self,
        name: &str,
        content: &str,
    ) -> PathBuf {
        let file_path = self.temp_dir.path().join(name);
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

    /// Reads the content of a file as a string.
    pub fn read_file(
        &self,
        path: &Path,
    ) -> String {
        std::fs::read_to_string(path).expect("Failed to read file")
    }
}
