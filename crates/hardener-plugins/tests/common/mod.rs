//! Helpers shared between the plugin test suites.
//!
//! Every file directly under `tests/` is compiled as its own crate, so a helper
//! several of them need has nowhere to live but a module each one declares. The
//! subdirectory is the point: cargo builds a test binary per top-level
//! `tests/*.rs`, so a `tests/common.rs` would become a suite of its own that
//! contains no tests, whereas `tests/common/mod.rs` is only ever compiled as
//! part of whichever suite says `mod common;`.

/// Builds a CheckpointManager backed by a temporary SQLite database and a
/// freshly generated signing key: no root access or production paths needed.
pub async fn test_checkpoint_manager() -> hardener_state::CheckpointManager {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("test_checkpoints.db");
    let key_path = dir.path().join("test.key");

    let db_pool = hardener_state::init_db(Some(&db_path))
        .await
        .expect("init_db");
    let signer =
        hardener_state::CheckpointSigner::new_with_path(&key_path).expect("CheckpointSigner");

    // Keep the tempdir alive for the duration of the process.
    std::mem::forget(dir);

    hardener_state::CheckpointManager::new_with_signer(db_pool, signer).expect("CheckpointManager")
}
