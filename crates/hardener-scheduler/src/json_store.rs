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
mod tests;
