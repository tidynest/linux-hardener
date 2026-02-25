use hardener_common::file_utils::{backup_file, safe_modify_file, update_file_atomically};
use std::fs;
use std::path::Path;
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
