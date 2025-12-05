//! File operation utilities following CODE_PATTERNS.md best practices.
//!
//! This module provides safe file operations with atomic writes and backup support.

use crate::error::Result;
use std::io::Write;
use std::path::{Path, PathBuf};
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
        crate::error::HardeningError::Plugin(format!(
            "No parent directory for path: {}",
            path.display()
        ))
    })?;

    // Create temp file in same directory (same filesystem) for atomic rename
    let mut temp = NamedTempFile::new_in(dir).map_err(|e| {
        crate::error::HardeningError::Plugin(format!("Failed to create temporary file: {}", e))
    })?;

    // Write content
    temp.write_all(content.as_bytes()).map_err(|e| {
        crate::error::HardeningError::Plugin(format!("Failed to write to temporary file: {}", e))
    })?;

    // Sync to disk before making visible
    temp.as_file().sync_all().map_err(|e| {
        crate::error::HardeningError::Plugin(format!("Failed to sync temporary file: {}", e))
    })?;

    // Atomic rename
    temp.persist(path).map_err(|e| {
        crate::error::HardeningError::Plugin(format!(
            "Failed to persist temporary file to {}: {}",
            path.display(),
            e
        ))
    })?;

    Ok(())
}

/// Reads a configuration file with standardised error handling.
///
/// # Arguments
/// * `path` - Path to the configuration file
///
/// # Returns
/// File contents as String, or HardeningError on failure
pub fn read_config_file(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| {
        crate::error::HardeningError::Plugin(format!("Failed to read {}: {}", path.display(), e))
    })
}

/// Reads a configuration file, returning None if it doesn't exist.
///
/// Useful for optional config files that may not be present on all systems.
pub fn read_config_file_optional(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(content) => Ok(Some(content)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(crate::error::HardeningError::Plugin(format!(
            "Failed to read {}: {}",
            path.display(),
            e
        ))),
    }
}

/// Configuration file format for parsing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigFormat {
    /// Space-separated: `Key Value` (e.g., SSH config).
    SpaceSeparated,
    /// Key-Value with equals: `Key = Value` or `Key=Value` (e.g., PAM-config).
    KeyValue,
    /// Auto-detected format (tries both).
    Auto,
}

/// Parses a configuration directive value from file content.
///
/// # Arguments
/// * `content` - The file content to search
/// * `directive_name` - The directive/key to find
/// * `format` - The config file format
/// * `case_sensitive` - Whether directive names are case-sensitive
///
/// # Returns
/// The value if found, None otherwise
pub fn parse_config_value(
    content: &str,
    directive_name: &str,
    format: ConfigFormat,
    case_sensitive: bool,
) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();

        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        match format {
            ConfigFormat::SpaceSeparated => {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    let matches = if case_sensitive {
                        parts[0] == directive_name
                    } else {
                        parts[0].eq_ignore_ascii_case(directive_name)
                    };
                    if matches {
                        return Some(parts[1].to_string());
                    }
                }
            }
            ConfigFormat::KeyValue => {
                if let Some(stripped) =
                    strip_prefix_with_case(trimmed, directive_name, case_sensitive)
                {
                    let remainder = stripped.trim();
                    // Handle "key = value" format
                    if let Some(value) = remainder.strip_prefix('=') {
                        return Some(value.trim().to_string());
                    }
                    // Handle "key value" format (space after key)
                    if remainder.starts_with(char::is_whitespace) {
                        return Some(remainder.trim().to_string());
                    }
                }
            }
            ConfigFormat::Auto => {
                // Try space-separated first, then key-value
                if let Some(v) = parse_config_value(
                    content,
                    directive_name,
                    ConfigFormat::SpaceSeparated,
                    case_sensitive,
                ) {
                    return Some(v);
                }
                return parse_config_value(
                    content,
                    directive_name,
                    ConfigFormat::KeyValue,
                    case_sensitive,
                );
            }
        }
    }
    None
}

fn strip_prefix_with_case<'a>(s: &'a str, prefix: &str, case_sensitive: bool) -> Option<&'a str> {
    if case_sensitive {
        s.strip_prefix(prefix)
    } else if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// Sets or updates a directive in configuration content.
///
/// If the directive exists (even if commented), it will be updated.
/// If not found, it will be appended to the end.
///
/// # Arguments
/// * `content` - The current file content
/// * `directive_name` - The directive/key to set
/// * `value` - The value to set
/// * `format` - The config file format (affects output format)
/// * `case_sensitive` - Whether to match directive names case-sensitively
///
/// # Returns
/// New content with the directive set.
pub fn set_config_directive(
    content: &str,
    directive_name: &str,
    value: &str,
    format: ConfigFormat,
    case_sensitive: bool,
) -> String {
    let mut lines: Vec<String> = content.lines().map(String::from).collect();
    let mut found = false;

    let new_line = match format {
        ConfigFormat::SpaceSeparated | ConfigFormat::Auto => {
            format!("{} {}", directive_name, value)
        }
        ConfigFormat::KeyValue => {
            format!("{} {}", directive_name, value)
        }
    };

    for line in &mut lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Check both commented and uncommented lines
        let check_line = trimmed.trim_start_matches('#').trim();
        let parts: Vec<&str> = check_line.split_whitespace().collect();

        if !parts.is_empty() {
            let matches = if case_sensitive {
                parts[0] == directive_name
            } else {
                parts[0].eq_ignore_ascii_case(directive_name)
            };
            if matches {
                *line = new_line.clone();
                found = true;
                break;
            }
        }
    }

    if !found {
        lines.push(new_line);
    }

    lines.join("\n")
}

/// Creates a timestamped backup of a file.
///
/// Creates backup at `path` - Path to the file to backup
///
/// # Returns
/// Path to the backup file,
pub fn create_timestamped_backup(path: &Path) -> Result<PathBuf> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| {
            crate::error::HardeningError::Plugin(format!("Failed to get system time: {}", e))
        })?
        .as_secs();

    let backup_path = PathBuf::from(format!("{}.backup.{}", path.display(), timestamp));

    std::fs::copy(path, &backup_path).map_err(|e| {
        crate::error::HardeningError::Plugin(format!("Failed to get system time: {}", e))
    })?;

    Ok(backup_path)
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
pub fn backup_file(path: &Path) -> Result<PathBuf> {
    let backup_path = path.with_extension("backup");
    std::fs::copy(path, &backup_path).map_err(|e| {
        crate::error::HardeningError::Plugin(format!(
            "Failed to create backup of {}: {}",
            path.display(),
            e
        ))
    })?;
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
    let content = std::fs::read_to_string(path).map_err(|e| {
        crate::error::HardeningError::Plugin(format!("Failed to read {}: {}", path.display(), e))
    })?;

    // Modify
    let new_content = modifier(&content);

    // Write atomically
    match update_file_atomically(path, &new_content) {
        Ok(_) => {
            // Success, remove backup
            std::fs::remove_file(backup).map_err(|e| {
                crate::error::HardeningError::Plugin(format!("Failed to remove backup file: {}", e))
            })?;
            Ok(())
        }
        Err(e) => {
            // Failure, restore backup
            std::fs::rename(&backup, path).map_err(|restore_err| {
                crate::error::HardeningError::Plugin(format!(
                    "Failed to update file: {}. Also failed to restore backup: {}",
                    e, restore_err
                ))
            })?;
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_update_file_atomically_creates_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");

        update_file_atomically(&file_path, "hello world").unwrap();

        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "hello world");
    }

    #[test]
    fn test_update_file_atomically_overwrites_existing() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");

        fs::write(&file_path, "original content").unwrap();
        update_file_atomically(&file_path, "new content").unwrap();

        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "new content");
    }

    #[test]
    fn test_update_file_atomically_no_parent_error() {
        // Path with no parent directory
        let result = update_file_atomically(Path::new(""), "content");
        assert!(result.is_err());
    }

    #[test]
    fn test_backup_file_creates_backup() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");

        fs::write(&file_path, "original content").unwrap();
        let backup_path = backup_file(&file_path).unwrap();

        assert!(backup_path.exists());
        assert_eq!(backup_path, file_path.with_extension("backup"));
        let backup_content = fs::read_to_string(&backup_path).unwrap();
        assert_eq!(backup_content, "original content");
    }

    #[test]
    fn test_backup_file_nonexistent_error() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("nonexistent.txt");

        let result = backup_file(&file_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_safe_modify_file_success() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");

        fs::write(&file_path, "hello world").unwrap();
        safe_modify_file(&file_path, |content| content.replace("world", "rust")).unwrap();

        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "hello rust");

        // Backup should be removed on success
        let backup_path = file_path.with_extension("backup");
        assert!(!backup_path.exists());
    }

    #[test]
    fn test_safe_modify_file_preserves_content_structure() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("config.txt");

        let original = "key1=value1\nkey2=value2\nkey3=value3\n";
        fs::write(&file_path, original).unwrap();

        safe_modify_file(&file_path, |content| content.replace("value2", "modified")).unwrap();

        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "key1=value1\nkey2=modified\nkey3=value3\n");
    }
}
