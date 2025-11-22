//! File operation utilities following CODE_PATTERNS.md best practices.
//!
//! This module provides safe file operations with atomic writes and backup support.

use crate::error::Result;
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

/// Updates a file atomically using a temporary file and atomic rename.
///
/// This function ensures that:
/// 1. The file content is written to a temporary file in the same directory
/// 2. The temporary file is synced to disk
/// 3. The temporary file is atomically renamed to the target path
///
/// This prevents partial writes and ensures the file is either fully updated or not changed at all.
///
/// # Arguments
/// * `path` - The path to the file to update
/// * `content` - The new file content
///
/// # Returns
/// `Ok(())` on success, or an error if the operation fails
///
/// # Example
/// ```ignore
/// update_file_atomically(Path::new("/etc/ssh/sshd_config"), "PermitRootLogin no\n")?;
/// ```
pub fn update_file_atomically(path: &Path, content: &str) -> Result<()> {
    let dir = path.parent().ok_or_else(|| {
        crate::error::HardeningError::Plugin(
            format!("No parent directory for path: {}", path.display())
        )
    })?;

    // Create temp file in same directory (same filesystem) for atomic rename
    let mut temp = NamedTempFile::new_in(dir)
        .map_err(|e| crate::error::HardeningError::Plugin(
            format!("Failed to create temporary file: {}", e)
        ))?;

    // Write content
    temp.write_all(content.as_bytes())
        .map_err(|e| crate::error::HardeningError::Plugin(
            format!("Failed to write to temporary file: {}", e)
        ))?;

    // Sync to disk before making visible
    temp.as_file().sync_all()
        .map_err(|e| crate::error::HardeningError::Plugin(
            format!("Failed to sync temporary file: {}", e)
        ))?;

    // Atomic rename
    temp.persist(path)
        .map_err(|e| crate::error::HardeningError::Plugin(
            format!("Failed to persist temporary file to {}: {}", path.display(), e)
        ))?;

    Ok(())
}

/// Creates a backup of a file before modification.
///
/// # Arguments
/// * `path` - The path to the file to backup
///
/// # Returns
/// `Ok(PathBuf)` with the backup file path on success, or an error
///
/// # Example
/// ```ignore
/// let backup_path = backup_file(Path::new("/etc/ssh/sshd_config"))?;
/// // ... modify original file ...
/// // If successful, optionally remove backup
/// ```
pub fn backup_file(path: &Path) -> Result<std::path::PathBuf> {
    let backup_path = path.with_extension("backup");
    std::fs::copy(path, &backup_path)
        .map_err(|e| crate::error::HardeningError::Plugin(
            format!("Failed to create backup of {}: {}", path.display(), e)
        ))?;
    Ok(backup_path)
}

/// Safely modifies a file with automatic backup and atomic write.
///
/// This function:
/// 1. Creates a backup of the original file
/// 2. Reads the current content
/// 3. Applies the modifier function
/// 4. Writes the new content atomically
/// 5. Removes the backup on success or restores it on failure
///
/// # Arguments
/// * `path` - The path to the file to modify
/// * `modifier` - A function that takes the current content and returns new content
///
/// # Returns
/// `Ok(())` on success, or an error if the operation fails
///
/// # Example
/// ```ignore
/// safe_modify_file(Path::new("/etc/ssh/sshd_config"), |content| {
///     content.replace("PermitRootLogin yes", "PermitRootLogin no")
/// })?;
/// ```
pub fn safe_modify_file<F>(path: &Path, modifier: F) -> Result<()>
where
    F: FnOnce(&str) -> String,
{
    // Backup
    let backup = backup_file(path)?;

    // Read current content
    let content = std::fs::read_to_string(path)
        .map_err(|e| crate::error::HardeningError::Plugin(
            format!("Failed to read {}: {}", path.display(), e)
        ))?;

    // Modify
    let new_content = modifier(&content);

    // Write atomically
    match update_file_atomically(path, &new_content) {
        Ok(_) => {
            // Success, remove backup
            std::fs::remove_file(backup)
                .map_err(|e| crate::error::HardeningError::Plugin(
                    format!("Failed to remove backup file: {}", e)
                ))?;
            Ok(())
        }
        Err(e) => {
            // Failure, restore backup
            std::fs::rename(&backup, path)
                .map_err(|restore_err| crate::error::HardeningError::Plugin(
                    format!(
                        "Failed to update file: {}. Also failed to restore backup: {}",
                        e, restore_err
                    )
                ))?;
            Err(e)
        }
    }
}
