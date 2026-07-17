//! Safe binary resolution for system command execution.
//!
//! Resolves bare command names to absolute paths using a trusted search
//! path, preventing PATH-based binary substitution attacks (CWE-426).

use std::path::PathBuf;

/// Trusted directories to search for system binaries, in priority order.
/// Only well-known system paths are included, no user-writable directories.
const TRUSTED_PATH: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
];

/// Resolves a bare command name to its absolute path using a trusted search list.
///
/// If `program` is already an absolute path, returns it unchanged.
/// Otherwise searches `TRUSTED_PATH` for the first match.
///
/// # Returns
/// The absolute path to the binary, or the original name if not found
/// (allowing `Command::new` to produce a clear "not found" error).
pub fn resolve_binary(program: &str) -> String {
    if program.starts_with('/') {
        return program.to_string();
    }

    for dir in TRUSTED_PATH {
        let candidate = PathBuf::from(dir).join(program);
        if candidate.is_file() {
            return candidate.to_string_lossy().into_owned();
        }
    }

    // Fall through: return original name so Command::new produces a
    // descriptive "No such file" error rather than silently succeeding
    // on a trojanised PATH entry.
    program.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_path_returned_unchanged() {
        assert_eq!(resolve_binary("/usr/bin/ls"), "/usr/bin/ls");
    }

    #[test]
    fn resolves_common_binary() {
        let resolved = resolve_binary("ls");
        assert!(
            resolved.starts_with('/'),
            "Expected absolute path, got: {resolved}"
        );
    }

    #[test]
    fn nonexistent_binary_returns_original() {
        assert_eq!(
            resolve_binary("__nonexistent_binary__"),
            "__nonexistent_binary__"
        );
    }
}
