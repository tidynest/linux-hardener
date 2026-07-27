//! File operation utilities following CODE_PATTERNS.md best practices.
//!
//! This module provides safe file operations with atomic writes and backup support.

use crate::error::Result;
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use tracing::warn;

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
    use std::fs;

    let dir = path.parent().ok_or_else(|| {
        crate::error::HardeningError::Plugin(format!(
            "No parent directory for path: {}",
            path.display()
        ))
    })?;

    // Capture original permissions before overwriting. Only a genuinely
    // missing file has none to restore; folding every other stat failure into
    // that case left the rewritten file wearing the temp file's mode instead
    // of the original's, with no error and no log line. This runs before the
    // temp file is created, so refusing here leaves the target untouched.
    let original_permissions = match fs::metadata(path) {
        Ok(metadata) => Some(metadata.permissions()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(crate::error::HardeningError::Plugin(format!(
                "Refusing to rewrite {}: its current permissions could not be read ({}), \
                 and rewriting it would silently change them",
                path.display(),
                e
            )));
        }
    };

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

    // Restore original permissions (persist() replaces the inode, losing them)
    if let Some(perms) = original_permissions {
        fs::set_permissions(path, perms).map_err(|e| {
            crate::error::HardeningError::Plugin(format!(
                "Failed to restore permissions on {}: {}",
                path.display(),
                e
            ))
        })?;
    }

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

/// The part of an sshd_config that applies to every connection: everything
/// above the first live `Match` line.
///
/// A directive inside a `Match` block applies only to connections the block
/// selects, so reading one and presenting it as the host's setting is a false
/// pass. `Match Address 10.0.0.0/8` followed by `PermitRootLogin no` says
/// nothing about root login from anywhere else, yet a whole-file read returns
/// `no` and the caller concludes the host is hardened. Worse, apply then sees
/// the target value already in place, writes nothing, and records no change at
/// all, leaving the real global directive at sshd's compiled default.
///
/// The writer already stops at the same boundary. This is its counterpart, so
/// the two agree on what "global" means rather than each deciding separately.
///
/// A commented `Match` opens no block and does not stop anything.
pub fn global_scope(content: &str) -> &str {
    let mut offset = 0;
    for line in content.split_inclusive('\n') {
        let trimmed = line.trim();
        if !trimmed.starts_with('#') {
            let (first, _) = split_directive(trimmed);
            if first.eq_ignore_ascii_case(MATCH_KEYWORD) {
                return &content[..offset];
            }
        }
        offset += line.len();
    }
    content
}

/// Parses a configuration directive value from file content.
///
/// Reads the whole content. For sshd_config, where a `Match` block scopes the
/// lines below it to particular connections, wrap the input in
/// [`global_scope`] before calling this.
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
                // The key boundary is shared with the writer: a directive the
                // writer rewrites in place must not read as unset here, or the
                // caller acts on a value the file does not hold. That gap is
                // what let a remote root apply "downgrade" an operator's
                // `PermitRootLogin=no` to `prohibit-password`.
                let (key, value_text) = split_directive(trimmed);
                let matches = if case_sensitive {
                    key == directive_name
                } else {
                    key.eq_ignore_ascii_case(directive_name)
                };
                if matches && let Some(value) = value_text.split_whitespace().next() {
                    return Some(value.to_string());
                }
            }
            ConfigFormat::KeyValue => {
                if let Some(stripped) =
                    strip_prefix_with_case(trimmed, directive_name, case_sensitive)
                {
                    // Test the text as it sits after the key. Trimming first
                    // destroys the whitespace that separates a key from its
                    // value, which is what made a space separated directive
                    // invisible to this arm.
                    if let Some(value) = stripped.trim_start().strip_prefix('=') {
                        return Some(value.trim().to_string());
                    }
                    if stripped.starts_with(char::is_whitespace)
                        && let Some(value) = stripped.split_whitespace().next()
                    {
                        return Some(value.to_string());
                    }
                }
            }
            ConfigFormat::Auto => {
                // Try key-value first (it also accepts "key value" with no
                // "="), then fall back to space-separated. Trying
                // space-separated first would split "key = value" into
                // ["key", "="], returning the literal "=" as the value.
                if let Some(v) = parse_config_value(
                    content,
                    directive_name,
                    ConfigFormat::KeyValue,
                    case_sensitive,
                ) {
                    return Some(v);
                }
                return parse_config_value(
                    content,
                    directive_name,
                    ConfigFormat::SpaceSeparated,
                    case_sensitive,
                );
            }
        }
    }
    None
}

/// Splits a configuration line into its key and the text of its value.
///
/// `sshd_config(5)` and the `security/*.conf` files accept `Key=Value` as
/// readily as `Key Value`, so a key ends at whitespace or at `=`, whichever
/// comes first, and the separator is not part of the value. Splitting on
/// whitespace alone makes `deny=10` a single token that matches no directive:
/// the writer then leaves the operator's line in place and defines the key a
/// second time somewhere else, and the reader calls the directive unset. An
/// empty key means the line opens with a separator and defines nothing; empty
/// value text means the key stands alone, which is not a definition either.
fn split_directive(line: &str) -> (&str, &str) {
    let end = line
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(line.len());
    let (key, rest) = line.split_at(end);
    let rest = rest.trim_start();
    (key, rest.strip_prefix('=').map_or(rest, str::trim_start))
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

/// Whether a second definition of the same directive is meaningful in this
/// file.
///
/// `login.defs` takes one definition per key, so a second is stale and should
/// go. `sshd_config` scopes a repeated directive to its enclosing `Match`
/// block, so removing one would change which hosts a rule applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Duplicates {
    /// Leave every other definition where it is.
    Keep,
    /// Remove other uncommented definitions of this key.
    Remove,
}

/// The keyword that opens a conditional block in `sshd_config`, and so ends
/// the region [`set_config_directive`] treats as global.
///
/// Applied to every file the writer touches rather than being a caller opt-in.
/// The other four are flat: `login.defs(5)`, `pwquality.conf`,
/// `faillock.conf` and `pwhistory.conf` define no directive of this name and
/// have no block syntax at all, so the boundary can never fire in them. A
/// caller that could switch it off would only ever be able to switch off the
/// protection.
const MATCH_KEYWORD: &str = "Match";

/// Sets or updates a directive in configuration content.
///
/// Only the file's global region is considered: the text above the first live
/// `Match` line (see [`MATCH_KEYWORD`]). Within it, a live (uncommented)
/// definition is what the daemon reads, so it is always the line that gets
/// rewritten. A commented line naming the directive is only a target when the
/// region has no live definition at all, which is how a commented default gets
/// activated. If neither exists the directive is inserted just above the
/// boundary, or appended when the file has none.
///
/// # Arguments
/// * `content` - The current file content
/// * `directive_name` - The directive/key to set
/// * `value` - The value to set
/// * `format` - The config file format (affects output format)
/// * `case_sensitive` - Whether to match directive names case-sensitively
/// * `duplicates` - Whether a further live definition of the key is meaningful
///   in this file, or stale and safe to drop
///
/// # Returns
/// New content with the directive set.
pub fn set_config_directive(
    content: &str,
    directive_name: &str,
    value: &str,
    format: ConfigFormat,
    case_sensitive: bool,
    duplicates: Duplicates,
) -> String {
    let mut lines: Vec<String> = content.lines().map(String::from).collect();

    let new_line = match format {
        ConfigFormat::SpaceSeparated | ConfigFormat::Auto => {
            format!("{} {}", directive_name, value)
        }
        ConfigFormat::KeyValue => {
            format!("{} = {}", directive_name, value)
        }
    };

    let mut live: Option<usize> = None;
    let mut commented: Option<usize> = None;
    let mut extra: Vec<usize> = Vec::new();
    let mut boundary: Option<usize> = None;

    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let is_comment = trimmed.starts_with('#');
        let check_line = trimmed.trim_start_matches('#').trim();
        let (first, _) = split_directive(check_line);
        if first.is_empty() {
            continue;
        }
        // Everything below a live `Match` belongs to a conditional block and
        // is not a global setting. Without this stop, the writer would rewrite
        // a block scoped directive when that is the file's only live
        // occurrence, silently narrowing a host wide setting to whatever the
        // block matches while the global one stays at the daemon's compiled
        // default. That is a false pass, not a cosmetic issue: it is how
        // `PermitRootLogin no` ended up applying to one subnet while root
        // login stayed open everywhere else. Do not remove this.
        // A commented `Match` opens no block, so it does not stop anything.
        if !is_comment && first.eq_ignore_ascii_case(MATCH_KEYWORD) {
            boundary = Some(index);
            break;
        }
        let matches = if case_sensitive {
            first == directive_name
        } else {
            first.eq_ignore_ascii_case(directive_name)
        };
        if !matches {
            continue;
        }
        // A live directive is what the daemon reads, so it wins. A comment is
        // only a target when there is no live line to rewrite.
        if is_comment {
            commented.get_or_insert(index);
        } else if live.is_none() {
            live = Some(index);
        } else {
            extra.push(index);
        }
    }

    match (live.or(commented), boundary) {
        (Some(index), _) => lines[index] = new_line,
        // Appending would drop the directive inside the trailing block.
        (None, Some(index)) => lines.insert(index, new_line),
        (None, None) => lines.push(new_line),
    }

    // Only when the caller says a second definition cannot be meaningful.
    // `extra` holds live lines after the one just rewritten, so removing them
    // in reverse leaves the rewritten index valid.
    if duplicates == Duplicates::Remove {
        for index in extra.into_iter().rev() {
            lines.remove(index);
        }
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

    safe_copy_to_new(path, &backup_path)?;

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
    safe_copy_to_new(path, &backup_path)?;
    Ok(backup_path)
}

/// Copies `src` to `dst`, refusing to overwrite or follow symlinks at the destination.
///
/// Uses `O_CREAT | O_EXCL` to atomically create the destination, preventing
/// symlink race attacks on predictable backup paths.
fn safe_copy_to_new(src: &Path, dst: &Path) -> Result<()> {
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::unix::fs::OpenOptionsExt;

    // Reject if destination is an existing symlink or file
    if dst.exists() || dst.is_symlink() {
        return Err(crate::error::HardeningError::Plugin(format!(
            "Backup destination already exists: {}",
            dst.display()
        )));
    }

    let mut src_file = File::open(src).map_err(|e| {
        crate::error::HardeningError::Plugin(format!(
            "Failed to open source {}: {}",
            src.display(),
            e
        ))
    })?;

    // O_CREAT | O_EXCL: fails if path already exists (atomic, no symlink follow)
    let mut dst_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dst)
        .map_err(|e| {
            crate::error::HardeningError::Plugin(format!(
                "Failed to create backup {}: {}",
                dst.display(),
                e
            ))
        })?;

    let mut buf = Vec::new();
    src_file.read_to_end(&mut buf).map_err(|e| {
        crate::error::HardeningError::Plugin(format!("Failed to read {}: {}", src.display(), e))
    })?;

    dst_file.write_all(&buf).map_err(|e| {
        crate::error::HardeningError::Plugin(format!(
            "Failed to write backup {}: {}",
            dst.display(),
            e
        ))
    })?;

    Ok(())
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
            // Success: cleanup backup (non-fatal if this fails)
            if let Err(e) = std::fs::remove_file(backup) {
                warn!("Failed to remove backup file: {}", e);
            }
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

    /// `update_file_atomically` replaces the inode, so it re-applies the
    /// original mode afterwards. A stat failure used to be indistinguishable
    /// from "the file did not exist", leaving the rewritten file wearing the
    /// temp file's 0600 instead of the original's mode, silently. Refusing is
    /// safe here because nothing has been written yet.
    #[test]
    fn a_stat_failure_refuses_the_write_instead_of_changing_the_mode() {
        let dir = tempfile::tempdir().unwrap();
        // A regular file standing where a directory belongs: stat on a path
        // below it fails with ENOTDIR, which is emphatically not NotFound.
        let not_a_dir = dir.path().join("not-a-dir");
        std::fs::write(&not_a_dir, "regular file").unwrap();
        let target = not_a_dir.join("config");

        let kind = std::fs::metadata(&target).unwrap_err().kind();
        assert_ne!(
            kind,
            std::io::ErrorKind::NotFound,
            "test needs a non-NotFound stat failure, got {kind:?}"
        );

        let err = update_file_atomically(&target, "key = value\n")
            .expect_err("an unreadable mode must not be silently replaced");
        let message = err.to_string();
        assert!(
            message.contains("permissions could not be read"),
            "the refusal must name the cause: {message}"
        );
    }

    /// The genuinely-absent case still creates the file, since a file that
    /// does not exist has no mode to preserve.
    #[test]
    fn a_missing_file_is_still_created() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("new.conf");

        update_file_atomically(&target, "key = value\n").expect("creating a new file must work");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "key = value\n");
    }

    /// The mode of an existing file survives the inode swap.
    #[test]
    fn an_existing_files_mode_survives_the_rewrite() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("existing.conf");
        std::fs::write(&target, "old\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();

        update_file_atomically(&target, "new\n").unwrap();

        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "the original mode must be restored");
    }

    #[test]
    fn auto_parses_key_equals_value_with_spaces() {
        assert_eq!(
            parse_config_value("minlen = 14\n", "minlen", ConfigFormat::Auto, true),
            Some("14".to_string())
        );
    }

    #[test]
    fn auto_still_parses_space_separated() {
        assert_eq!(
            parse_config_value(
                "PASS_MAX_DAYS 99999\n",
                "PASS_MAX_DAYS",
                ConfigFormat::Auto,
                true
            ),
            Some("99999".to_string())
        );
    }

    #[test]
    fn auto_parses_key_equals_value_without_spaces() {
        assert_eq!(
            parse_config_value("minlen=14\n", "minlen", ConfigFormat::Auto, true),
            Some("14".to_string())
        );
    }

    /// `sshd_config(5)` accepts `Key=Value`, and `sshd -t` accepts it too, so
    /// reading such a line as "not set" reports a directive the host plainly
    /// holds as absent.
    #[test]
    fn space_separated_reads_an_equals_separated_directive() {
        assert_eq!(
            parse_config_value(
                "PermitRootLogin=no\n",
                "PermitRootLogin",
                ConfigFormat::SpaceSeparated,
                false
            ),
            Some("no".to_string()),
        );
    }

    /// The value is what a caller compares against its target, so the
    /// separator must never be returned in its place.
    #[test]
    fn space_separated_reads_a_spaced_equals_separator() {
        assert_eq!(
            parse_config_value(
                "PermitRootLogin = no\n",
                "PermitRootLogin",
                ConfigFormat::SpaceSeparated,
                false
            ),
            Some("no".to_string()),
        );
    }

    /// Ending a key at `=` must not end it anywhere else.
    #[test]
    fn space_separated_does_not_match_a_longer_key_that_starts_the_same() {
        assert_eq!(
            parse_config_value(
                "ClientAliveInterval=300\n",
                "ClientAlive",
                ConfigFormat::SpaceSeparated,
                false
            ),
            None,
        );
    }

    #[test]
    fn space_separated_ignores_a_key_with_no_value() {
        assert_eq!(
            parse_config_value(
                "PermitRootLogin\n",
                "PermitRootLogin",
                ConfigFormat::SpaceSeparated,
                false
            ),
            None,
        );
    }

    const REAL_LOGIN_DEFS: &str = "\
#\tPASS_MAX_DAYS\tMaximum number of days a password may be used.
#
PASS_MAX_DAYS\t99999
PASS_MIN_DAYS\t0
";

    #[test]
    fn key_value_reads_a_whitespace_separated_directive() {
        assert_eq!(
            parse_config_value(
                REAL_LOGIN_DEFS,
                "PASS_MAX_DAYS",
                ConfigFormat::KeyValue,
                true
            ),
            Some("99999".to_string()),
        );
    }

    #[test]
    fn key_value_still_reads_an_equals_separated_directive() {
        assert_eq!(
            parse_config_value("minlen = 14\n", "minlen", ConfigFormat::KeyValue, true),
            Some("14".to_string()),
        );
    }

    #[test]
    fn key_value_does_not_match_a_longer_key_that_starts_the_same() {
        assert_eq!(
            parse_config_value(REAL_LOGIN_DEFS, "PASS_MAX", ConfigFormat::KeyValue, true),
            None,
            "the separator test is what enforces the key boundary",
        );
    }

    #[test]
    fn key_value_ignores_a_key_with_no_value() {
        assert_eq!(
            parse_config_value(
                "PASS_MAX_DAYS\n",
                "PASS_MAX_DAYS",
                ConfigFormat::KeyValue,
                true
            ),
            None,
        );
    }

    #[test]
    fn a_damaged_file_reports_the_live_line_not_the_appended_one() {
        let damaged = format!("{REAL_LOGIN_DEFS}PASS_MAX_DAYS = 90\n");
        assert_eq!(
            parse_config_value(&damaged, "PASS_MAX_DAYS", ConfigFormat::Auto, true),
            Some("99999".to_string()),
            "the live line comes first and is what the system enforces",
        );
    }

    #[test]
    fn the_live_line_is_rewritten_not_the_comment_above_it() {
        let out = set_config_directive(
            REAL_LOGIN_DEFS,
            "PASS_MAX_DAYS",
            "90",
            ConfigFormat::SpaceSeparated,
            true,
            Duplicates::Keep,
        );
        assert!(
            out.contains("#\tPASS_MAX_DAYS\tMaximum number of days"),
            "the explanatory comment must survive:\n{out}",
        );
        assert!(
            out.contains("PASS_MAX_DAYS 90"),
            "the live line must carry the new value:\n{out}",
        );
        assert!(
            !out.contains("99999"),
            "and the old value must be gone:\n{out}",
        );
    }

    #[test]
    fn a_commented_default_with_no_live_line_is_still_replaced() {
        let out = set_config_directive(
            "#PermitRootLogin prohibit-password\n",
            "PermitRootLogin",
            "no",
            ConfigFormat::SpaceSeparated,
            true,
            Duplicates::Keep,
        );
        assert_eq!(out.trim(), "PermitRootLogin no");
    }

    #[test]
    fn remove_drops_a_later_definition_of_the_same_key() {
        // The commented occurrence sits BELOW the live line, in the same
        // stretch the removal loop walks. A comment above it could never be a
        // removal candidate, so it proves nothing about the loop.
        let damaged = format!("{REAL_LOGIN_DEFS}#PASS_MAX_DAYS 12345\nPASS_MAX_DAYS = 90\n");
        let out = set_config_directive(
            &damaged,
            "PASS_MAX_DAYS",
            "90",
            ConfigFormat::SpaceSeparated,
            true,
            Duplicates::Remove,
        );
        assert!(out.contains("PASS_MAX_DAYS 90"), "{out}");
        assert!(
            !out.contains("PASS_MAX_DAYS = 90"),
            "the appended line must go:\n{out}"
        );
        assert!(
            out.contains("#\tPASS_MAX_DAYS\tMaximum number of days"),
            "a comment is documentation and is never removed:\n{out}",
        );
        assert!(
            out.contains("#PASS_MAX_DAYS 12345"),
            "a comment below the live line is not a duplicate either:\n{out}",
        );
    }

    #[test]
    fn keep_leaves_a_match_block_directive_alone() {
        let sshd = "\
PermitRootLogin yes
Match Address 10.0.0.0/8
    PermitRootLogin yes
";
        let out = set_config_directive(
            sshd,
            "PermitRootLogin",
            "no",
            ConfigFormat::SpaceSeparated,
            true,
            Duplicates::Keep,
        );
        assert!(out.contains("PermitRootLogin no"), "{out}");
        assert!(
            out.contains("    PermitRootLogin yes"),
            "a Match scoped directive is not a duplicate and must survive:\n{out}",
        );
    }

    /// The only live occurrence of a directive can sit inside a `Match` block
    /// while the global setting exists only as a commented default. Rewriting
    /// the block line would leave the global at sshd's compiled default and
    /// narrow the new value to the block's scope, so the commented global is
    /// the only correct target.
    #[test]
    fn a_global_directive_is_never_written_inside_a_match_block() {
        let sshd = "\
#PermitRootLogin prohibit-password
Match Address 10.0.0.0/8
    PermitRootLogin yes
";
        let out = set_config_directive(
            sshd,
            "PermitRootLogin",
            "no",
            ConfigFormat::SpaceSeparated,
            true,
            Duplicates::Keep,
        );

        assert_eq!(
            out.lines().next(),
            Some("PermitRootLogin no"),
            "the commented global default is the line to rewrite:\n{out}",
        );
        assert!(
            out.contains("Match Address 10.0.0.0/8\n    PermitRootLogin yes"),
            "the block must survive byte for byte, indentation included:\n{out}",
        );
        assert_eq!(
            out.lines().count(),
            3,
            "no line may be added inside the block:\n{out}",
        );
        assert_eq!(
            out.lines()
                .filter(|l| l.trim() == "PermitRootLogin no")
                .count(),
            1,
            "the new value belongs to the global scope only:\n{out}",
        );
    }

    /// Appending a brand new directive at the end of the file would land it
    /// inside a trailing block, scoping a global setting to whatever that
    /// block matches.
    #[test]
    fn a_new_directive_is_inserted_above_a_trailing_match_block() {
        let sshd = "\
Port 22
Match User deploy
    PasswordAuthentication yes
";
        let out = set_config_directive(
            sshd,
            "PermitRootLogin",
            "no",
            ConfigFormat::SpaceSeparated,
            true,
            Duplicates::Keep,
        );
        assert_eq!(
            out,
            "Port 22\nPermitRootLogin no\nMatch User deploy\n    PasswordAuthentication yes",
        );
    }

    /// A commented `Match` opens no block, so it must not shorten the region
    /// the writer may consider.
    #[test]
    fn a_commented_match_does_not_end_the_global_region() {
        let sshd = "\
#Match Address 10.0.0.0/8
PermitRootLogin yes
";
        let out = set_config_directive(
            sshd,
            "PermitRootLogin",
            "no",
            ConfigFormat::SpaceSeparated,
            true,
            Duplicates::Keep,
        );
        assert_eq!(out, "#Match Address 10.0.0.0/8\nPermitRootLogin no");
    }

    /// `faillock.conf` and its siblings ship their defaults commented out, and
    /// an operator writes `deny=10` as readily as `deny = 10`. A key that ends
    /// at the `=` rather than at whitespace is still the live definition, so it
    /// is the line to rewrite: activating the comment above it would leave the
    /// operator's own setting standing below the tool's.
    #[test]
    fn a_live_key_equals_value_line_beats_the_comment_above_it() {
        let faillock = "\
# deny = 3
deny=10
";
        let out = set_config_directive(
            faillock,
            "deny",
            "5",
            ConfigFormat::KeyValue,
            true,
            Duplicates::Remove,
        );
        assert_eq!(out, "# deny = 3\ndeny = 5");
    }

    /// A file the writer cannot see through is rewritten on every run and never
    /// converges: the tool reports the value it wrote while its own reader
    /// still returns the one it left in place.
    #[test]
    fn rewriting_a_key_equals_value_line_converges_in_one_pass() {
        let out = set_config_directive(
            "minlen=8\n",
            "minlen",
            "14",
            ConfigFormat::KeyValue,
            true,
            Duplicates::Remove,
        );
        assert_eq!(out, "minlen = 14");
        assert_eq!(
            parse_config_value(&out, "minlen", ConfigFormat::Auto, true),
            Some("14".to_string()),
            "the reader must agree with what the writer just wrote:\n{out}",
        );
    }

    /// Ending the key at `=` must not end it anywhere else: `PASS_MAX` is not
    /// a definition of `PASS_MAX_DAYS`, so the writer appends its own line
    /// rather than rewriting the longer key's.
    #[test]
    fn the_writer_does_not_match_a_longer_key_that_starts_the_same() {
        let out = set_config_directive(
            REAL_LOGIN_DEFS,
            "PASS_MAX",
            "1",
            ConfigFormat::SpaceSeparated,
            true,
            Duplicates::Keep,
        );
        assert!(
            out.contains("PASS_MAX_DAYS\t99999"),
            "the longer key is a different directive and must be untouched:\n{out}",
        );
        assert!(
            out.ends_with("PASS_MAX 1"),
            "the new directive is appended as its own line:\n{out}",
        );
    }

    /// sshd reads `match` as readily as `Match`, so the boundary is ASCII
    /// case insensitive.
    #[test]
    fn a_lowercase_match_ends_the_global_region_too() {
        let sshd = "\
#PermitRootLogin prohibit-password
match address 10.0.0.0/8
    PermitRootLogin yes
";
        let out = set_config_directive(
            sshd,
            "PermitRootLogin",
            "no",
            ConfigFormat::SpaceSeparated,
            true,
            Duplicates::Keep,
        );
        assert_eq!(
            out.lines().next(),
            Some("PermitRootLogin no"),
            "the commented global default is the line to rewrite:\n{out}",
        );
        assert!(
            out.contains("    PermitRootLogin yes"),
            "the block line must survive:\n{out}",
        );
    }
}

#[cfg(test)]
mod global_scope_tests {
    use super::*;

    const MATCH_ONLY: &str = "\
PasswordAuthentication no
Match Address 10.0.0.0/8
    PermitRootLogin no
";

    #[test]
    fn a_directive_only_inside_a_match_block_is_not_a_global_value() {
        // The whole-file read returns "no" and the caller concludes root login
        // is closed, when the block scopes that to one subnet and the global
        // setting is still sshd's compiled default.
        assert_eq!(
            parse_config_value(
                MATCH_ONLY,
                "PermitRootLogin",
                ConfigFormat::SpaceSeparated,
                false
            )
            .as_deref(),
            Some("no"),
            "whole-file read is the behaviour global_scope exists to correct"
        );
        assert_eq!(
            parse_config_value(
                global_scope(MATCH_ONLY),
                "PermitRootLogin",
                ConfigFormat::SpaceSeparated,
                false
            ),
            None,
            "a Match-scoped directive must not be read as the global value"
        );
    }

    #[test]
    fn directives_above_the_match_block_are_still_global() {
        assert_eq!(
            parse_config_value(
                global_scope(MATCH_ONLY),
                "PasswordAuthentication",
                ConfigFormat::SpaceSeparated,
                false
            )
            .as_deref(),
            Some("no")
        );
    }

    #[test]
    fn a_commented_match_opens_no_block() {
        let content = "# Match Address 10.0.0.0/8\nPermitRootLogin no\n";
        assert_eq!(
            parse_config_value(
                global_scope(content),
                "PermitRootLogin",
                ConfigFormat::SpaceSeparated,
                false
            )
            .as_deref(),
            Some("no"),
            "a commented Match must not truncate the global scope"
        );
    }

    #[test]
    fn a_file_with_no_match_block_is_entirely_global() {
        let content = "PermitRootLogin no\nMaxAuthTries 3\n";
        assert_eq!(global_scope(content), content);
    }

    #[test]
    fn the_match_keyword_is_matched_case_insensitively() {
        // sshd accepts any case for keywords, so a lowercase `match` opens a
        // block just as a capitalised one does.
        let content = "match Address 10.0.0.0/8\n    PermitRootLogin no\n";
        assert_eq!(global_scope(content), "");
    }
}
