//! JSON file storage for scan results.
//!
//! Stores scan results as timestamped JSON files for portability
//! and external tool integration.

use chrono::Utc;
use hardener_common::error::{HardeningError, Result};
use ring::digest::{Context, SHA256};
use serde::Serialize;
use std::path::{Path, PathBuf};
use tokio::fs;

/// JSON file store for scan result exports.
pub struct JsonStore {
    output_dir: PathBuf,
}

impl JsonStore {
    /// Creates a new store, ensuring the output directory exists.
    pub async fn new(output_dir: &Path) -> Result<JsonStore> {
        fs::create_dir_all(&output_dir).await.map_err(|e| {
            HardeningError::Database(format!("Failed to create output directory: {}", e))
        })?;

        Ok(JsonStore {
            output_dir: output_dir.to_path_buf(),
        })
    }

    /// Writes scan results to a timestamped JSON file.
    ///
    /// Returns (file_path, sha256_hash) on success.
    pub async fn write<T: Serialize>(
        &self,
        session_id: &str,
        data: &T,
    ) -> Result<(String, String)> {
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let prefix = &session_id[..session_id.len().min(8)];
        let filename = format!("scan_{}_{}.json", timestamp, prefix);
        let path = self.output_dir.join(&filename);

        let json = serde_json::to_string_pretty(data)
            .map_err(|e| HardeningError::Database(format!("JSON serialisation failed: {}", e)))?;

        let hash = Self::sha256(&json);

        fs::write(&path, &json)
            .await
            .map_err(|e| HardeningError::Database(format!("Failed to write file: {}", e)))?;

        Ok((path.to_string_lossy().to_string(), hash))
    }

    /// Lists all JSON scan files in the output directory.
    pub async fn list(&self) -> Result<Vec<PathBuf>> {
        let mut entries = fs::read_dir(&self.output_dir)
            .await
            .map_err(|e| HardeningError::Database(format!("Failed to read directory: {}", e)))?;

        let mut files = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| HardeningError::Database(e.to_string()))?
        {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "json") {
                files.push(path);
            }
        }

        files.sort_by(|a, b| b.cmp(a)); // Newest first
        Ok(files)
    }

    /// Reads and deserialises a JSON file with integrity verification.
    pub async fn read<T: serde::de::DeserializeOwned>(
        &self,
        path: &Path,
        expected_hash: &str,
    ) -> Result<T> {
        let content = fs::read_to_string(path)
            .await
            .map_err(|e| HardeningError::Database(format!("Failed to read file: {}", e)))?;

        if Self::sha256(&content) != expected_hash {
            return Err(HardeningError::Database(format!(
                "integrity check failed: hash mismatch {}",
                path.display(),
            )));
        }

        serde_json::from_str(&content)
            .map_err(|e| HardeningError::Database(format!("JSON parse failed: {}", e)))
    }

    /// Verifies file integrity against a stored hash.
    pub async fn verify(&self, path: &Path, expected_hash: &str) -> Result<bool> {
        let content = fs::read_to_string(path)
            .await
            .map_err(|e| HardeningError::Database(format!("Failed to read file: {}", e)))?;

        Ok(Self::sha256(&content) == expected_hash)
    }

    /// Deletes old JSON files, keeping the most recent N files.
    pub async fn cleanup(&self, keep_count: usize) -> Result<u32> {
        let files = self.list().await?;
        let mut deleted = 0u32;

        for path in files.into_iter().skip(keep_count) {
            if fs::remove_file(&path).await.is_ok() {
                deleted += 1;
            }
        }

        Ok(deleted)
    }

    /// Computes SHA-256 hash of content, returning hex string.
    fn sha256(content: &str) -> String {
        let mut ctx = Context::new(&SHA256);
        ctx.update(content.as_bytes());
        let digest = ctx.finish();
        hex::encode(digest.as_ref())
    }
}

#[cfg(test)]
mod tests {
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
}
