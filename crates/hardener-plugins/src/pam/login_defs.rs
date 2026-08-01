//! Carrying a vendor configuration file over to `/etc` before editing it.
//!
//! openSUSE (Leap 15.6+, Tumbleweed, MicroOS) ships vendor configuration under
//! `/usr/etc` and reserves `/etc` for administrator overrides. The override is
//! whole-file, not per directive: the first file found wins entirely. So a
//! three-directive `/etc/login.defs` silences the other 35 keys
//! `/usr/etc/login.defs` sets, among them `ENCRYPT_METHOD`, which chooses the
//! password hashing algorithm for every password set afterwards, and `UMASK`,
//! `FAIL_DELAY`, `LOGIN_RETRIES` and `LOGIN_TIMEOUT`, which are login-hardening
//! settings this plugin exists to strengthen.
//!
//! The answer is to copy the vendor file's contents first and edit the managed
//! directives into that copy, so nothing the vendor set is lost. 1.5.1 refused
//! the write instead, which was honest but left the host unhardened.

use hardener_core::context::Context;
use std::path::Path;

/// Mode given to a file created from a vendor copy whose own mode could not be
/// read.
///
/// Every distribution ships these files world readable, and `pwscore` and
/// `pwmake` are ordinary-user tools that read `/etc/security/pwquality.conf`.
/// Guessing here is deliberate and one-directional: the alternative is the
/// temporary file's 0600, under which those tools cannot read the file at all
/// and silently fall back to their built-in defaults.
const FALLBACK_CREATE_MODE: u32 = 0o644;

/// The mode a file materialised from `vendor_path` should be given.
///
/// Read from the vendor file rather than assumed, so the copy matches what the
/// distribution intended. This is not cosmetic:
/// [`hardener_common::file_utils::update_file_atomically`] restores an
/// *original* mode, and a file being created has none, so without setting it
/// explicitly the copy wears whatever mode the temporary file happened to have.
/// That is how this tool's `/etc/security/pwquality.conf` landed 0600 on
/// openSUSE against the vendor's 0644.
pub(super) async fn mode_for_copy_of(ctx: &Context, vendor_path: &str) -> u32 {
    match ctx.executor().file_metadata(Path::new(vendor_path)).await {
        // Only the permission bits: the mode a metadata probe reports includes
        // the file type, and passing that to chmod would be nonsense.
        Ok(metadata) => metadata.mode & 0o7777,
        Err(e) => {
            tracing::warn!(
                "Could not read the mode of {}, creating the copy {:o}: {}",
                vendor_path,
                FALLBACK_CREATE_MODE,
                e
            );
            FALLBACK_CREATE_MODE
        }
    }
}

#[cfg(test)]
mod tests;
