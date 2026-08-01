#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`json_store`](super).
//!
//! Split out of `json_store.rs`. This file sits in the `json_store/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`,
//! so `super` still resolves to `crate::json_store` and every import carried
//! across unchanged, private items included.

use super::*;
use serde::{Deserialize, Serialize};
use tempfile::tempdir;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct TestData {
    id: String,
    value: i32,
}

#[tokio::test]
async fn write_and_read_json() {
    let dir = tempdir().unwrap();
    let store = JsonStore::new(dir.path()).await.unwrap();

    let data = TestData {
        id: "test-123".into(),
        value: 42,
    };

    let (path, hash) = store.write("abcd1234-5678", &data).await.unwrap();
    assert!(path.contains("scan_"));
    assert!(path.ends_with(".json"));

    let read_data: TestData = store.read(Path::new(&path), &hash).await.unwrap();
    assert_eq!(read_data, data);
}

#[tokio::test]
async fn verify_hash_integrity() {
    let dir = tempdir().unwrap();
    let store = JsonStore::new(dir.path()).await.unwrap();

    let data = TestData {
        id: "integrity-test".into(),
        value: 100,
    };

    let (path, hash) = store.write("efgh5678-1234", &data).await.unwrap();

    assert!(store.verify(Path::new(&path), &hash).await.unwrap());
    assert!(!store.verify(Path::new(&path), "wronghash").await.unwrap());
}

#[tokio::test]
async fn list_files_newest_first() {
    let dir = tempdir().unwrap();
    let store = JsonStore::new(dir.path()).await.unwrap();

    let data = TestData {
        id: "list-test".into(),
        value: 1,
    };

    store.write("aaaa1111-0000", &data).await.unwrap();
    store.write("bbbb2222-0000", &data).await.unwrap();
    store.write("cccc3333-0000", &data).await.unwrap();

    let files = store.list().await.unwrap();
    assert_eq!(files.len(), 3);
}

#[tokio::test]
async fn cleanup_keeps_recent() {
    let dir = tempdir().unwrap();
    let store = JsonStore::new(dir.path()).await.unwrap();

    let data = TestData {
        id: "cleanup".into(),
        value: 0,
    };

    for i in 0..5 {
        store
            .write(&format!("file{:04}-0000", i), &data)
            .await
            .unwrap();
    }

    let deleted = store.cleanup(2).await.unwrap();
    assert_eq!(deleted, 3);

    let remaining = store.list().await.unwrap();
    assert_eq!(remaining.len(), 2);
}
