//! Safe binary resolution for system command execution.
//!
//! Resolves bare command names to absolute paths using a trusted search
//! path, preventing PATH-based binary substitution attacks (CWE-426).

use std::path::PathBuf;

/// Trusted directories to search for system binaries, in priority order.
/// Only well-known system paths are included, no user-writable directories.
///
/// Visible to the crate so a shell script that cannot go through
/// [`resolve_binary`] can still pin the same list: see the `PATH` assignment
/// at the top of [`crate::executor::LINK_PROBE_SCRIPT`], which resolves its
/// own `id`, `dirname`, `test` and `readlink` and so must be pinned in the
/// shell rather than in Rust.
pub(crate) const TRUSTED_PATH: &[&str] = &[
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
mod tests;
