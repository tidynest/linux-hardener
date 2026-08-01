//! File operation utilities following CODE_PATTERNS.md best practices.
//!
//! This module provides safe file operations with atomic writes and backup support.

use crate::error::Result;
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use tracing::warn;

/// The mode given to a file this tool creates, as against one it rewrites.
///
/// A rewritten file keeps its own mode; only a file that did not exist needs
/// one chosen for it, and the choice cannot be left to the temporary file the
/// content is staged in. `NamedTempFile` creates 0600 so a partly written file
/// is never readable, which is correct for a temporary file and wrong for the
/// configuration file it becomes: at 0600 the ordinary-user tools that read
/// these files cannot, and fall back to their built-in defaults without saying
/// so. That is how this tool's `/etc/security/pwquality.conf` came to sit at
/// 0600 against the vendor's 0644 on openSUSE.
///
/// 0644 is not a guess. It is what every distribution ships these files as,
/// what a remote write through `SshExecutor` already produces (it pipes through
/// `tee`, so the file lands 0644 under the standard umask), and therefore the
/// only value that makes a local apply and a remote apply agree.
///
/// It is deliberately not umask-derived. A hardening tool whose output depends
/// on the shell it was launched from cannot be reasoned about, and under a
/// loose umask an inherited mode would be group writable.
const CREATED_FILE_MODE: u32 = 0o644;

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

    // A file being created has no original mode to put back, and the temporary
    // file it is about to become is 0600: right for a temporary file, wrong for
    // the configuration file it turns into. Set before the rename rather than
    // after, so the target never exists at the temporary file's mode.
    if original_permissions.is_none() {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(CREATED_FILE_MODE))
            .map_err(|e| {
                crate::error::HardeningError::Plugin(format!(
                    "Failed to set the mode of the file being created at {}: {}",
                    path.display(),
                    e
                ))
            })?;
    }

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

/// Strips `prefix` from `s`, comparing it with or without regard to case.
/// `None` when `s` does not begin with it under the chosen comparison.
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
/// New content with the directive set, always newline-terminated, because
/// what a caller does with it is write it to a file and something else will
/// append to that file later.
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

    // `str::lines` discards the terminator and `join` does not put one back, so
    // every rewrite used to come back one byte short: not only an appended
    // directive, but a line rewritten where it already stood. Whatever was
    // appended to that file next landed on the last directive, which is how an
    // sshd_config ended in
    // `MACs ...umac-128-etm@openssh.comMaxAuthTries` and sshd refused to start.
    //
    // Pushing one newline rather than restoring what was there is exact, not
    // approximate: a blank line at the end of the input survives `lines` as an
    // empty element, so `"a\n\n"` round-trips through join to `"a\n"` and back
    // to `"a\n\n"`. Only the single final terminator is ever missing.
    let mut out = lines.join("\n");
    out.push('\n');
    out
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
mod tests;

#[cfg(test)]
mod global_scope_tests;
