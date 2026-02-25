use hardener_state::init_db;
use tempfile::tempdir;

#[tokio::test]
async fn test_init_db_creates_database() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let pool = init_db(Some(&db_path)).await.unwrap();

    assert!(db_path.exists());

    // Verify tables exist by querying them
    let result: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM checkpoints")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(result.0, 0);

    let result: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM file_states")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(result.0, 0);

    pool.close().await;
}

#[tokio::test]
async fn test_init_db_creates_parent_directory() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("subdir").join("nested").join("test.db");

    let pool = init_db(Some(&db_path)).await.unwrap();

    assert!(db_path.exists());
    assert!(db_path.parent().unwrap().exists());

    pool.close().await;
}

#[tokio::test]
async fn test_init_db_idempotent() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    // Initialize twice - should not fail
    let pool1 = init_db(Some(&db_path)).await.unwrap();
    pool1.close().await;

    let pool2 = init_db(Some(&db_path)).await.unwrap();
    pool2.close().await;
}

#[tokio::test]
async fn test_init_db_schema_tables_exist() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let pool = init_db(Some(&db_path)).await.unwrap();

    // Test checkpoints table structure by inserting a row
    let result = sqlx::query(
        "INSERT INTO checkpoints (id, name, timestamp, username, signature, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind("test-id")
    .bind("test checkpoint")
    .bind(1234567890_i64)
    .bind("testuser")
    .bind(vec![0u8; 64])
    .bind(1234567890_i64)
    .execute(&pool)
    .await;

    assert!(result.is_ok());

    pool.close().await;
}
