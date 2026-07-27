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

use hardener_common::types::{FindingCategory, Severity};
use hardener_core::context::Context;
use hardener_core::plugin::Finding;
use std::collections::BTreeSet;
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

/// The keys `vendor` sets that `admin` does not, sorted and named once each.
///
/// The comparison is a set difference over the first whitespace-delimited token
/// of every line that sets something, which is the key in both the `NAME VALUE`
/// form `login.defs` takes and the `name = value` form the `security/*.conf`
/// files take. Case is significant, as it is to shadow: an `/etc` file writing
/// `umask 022` sets nothing shadow reads, so the vendor's `UMASK` really is
/// masked and naming it is correct.
pub(super) fn masked_keys(admin: &str, vendor: &str) -> Vec<String> {
    let admin_keys: BTreeSet<&str> = keys_set_by(admin).collect();
    keys_set_by(vendor)
        .filter(|key| !admin_keys.contains(key))
        .map(str::to_string)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// The key of every line that sets one, skipping comments and blank lines.
fn keys_set_by(content: &str) -> impl Iterator<Item = &str> {
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_whitespace().next())
}

/// The finding naming keys an `/etc/login.defs` masks, given a non-empty
/// difference from [`masked_keys`].
///
/// `Severity::Low` and no compliance mapping: the masked keys have reverted to
/// shadow's built-in defaults, which is worth knowing and is occasionally
/// deliberate, but no framework has a control for it and a mapping here would
/// let a housekeeping observation drive a control to Fail.
///
/// The remediation is deliberately manual. `apply` carries the vendor file over
/// only when `/etc` is confirmed absent; once the `/etc` file exists it is the
/// host's own and this tool edits the directives it manages rather than
/// importing keys the operator may have dropped on purpose. Telling the
/// operator to run `apply` would be advice that does nothing.
pub(super) fn masked_keys_finding(vendor_path: &str, keys: &[String]) -> Finding {
    let named = keys.join(", ");
    Finding {
        finding_id: "pam-login-defs-masked-keys".to_string(),
        finding_category: FindingCategory::Authentication,
        finding_current_value: named.clone(),
        finding_description: format!(
            "/etc/login.defs masks {count} key(s) that {vendor_path} sets: {named}",
            count = keys.len(),
        ),
        finding_explanation: "A distribution that ships vendor configuration under /usr/etc is \
             overridden whole-file, not per directive: once /etc/login.defs \
             exists, every key it omits falls back to shadow's built-in default \
             rather than to the vendor's value."
            .to_string(),
        finding_impact: "Settings the distribution chose are silently not in force, among them \
             the password hashing method and the default umask for new sessions."
            .to_string(),
        finding_recommended_value: format!("the values {vendor_path} sets for {named}"),
        finding_remediation_steps: vec![format!(
            "Copy {named} and their values from {vendor_path} into /etc/login.defs, \
             or remove from /etc/login.defs any key you did not mean to override"
        )],
        finding_severity: Severity::Low,
        finding_title: "Vendor login.defs keys masked by /etc/login.defs".to_string(),
        finding_compliance: vec![],
        // No directive to match an exception against: this names a set of keys
        // the tool does not manage, so there is no setting for a configured
        // exception to be about.
        finding_policy_exception: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hardener_common::executor::{FileMetadata, MockExecutor};
    use std::sync::Arc;

    /// A vendor file of the shape openSUSE ships, trimmed to the keys the
    /// assertions need.
    const VENDOR: &str = "\
UMASK           022
ENCRYPT_METHOD  yescrypt
PASS_MAX_DAYS   99999
PASS_MIN_DAYS   0
PASS_WARN_AGE   7
";

    #[test]
    fn a_key_the_admin_file_omits_is_masked() {
        assert_eq!(
            masked_keys("PASS_MAX_DAYS 90\n", VENDOR),
            vec![
                "ENCRYPT_METHOD".to_string(),
                "PASS_MIN_DAYS".to_string(),
                "PASS_WARN_AGE".to_string(),
                "UMASK".to_string(),
            ],
            "the difference is vendor minus admin, sorted, and PASS_MAX_DAYS is \
             overridden rather than lost"
        );
    }

    #[test]
    fn a_commented_key_is_not_a_key_on_either_side() {
        // Sharper than it looks. A commented key in /etc does not set anything,
        // so the vendor's value is still masked and must still be named; a
        // commented key in the vendor file was never in force, so naming it
        // would invent drift. Blank and whitespace-only lines are neither.
        assert_eq!(
            masked_keys(
                "# ENCRYPT_METHOD sha512\n\n   \n",
                "ENCRYPT_METHOD yescrypt\n"
            ),
            vec!["ENCRYPT_METHOD".to_string()],
            "a commented admin key sets nothing, so the vendor value is masked"
        );
        assert!(
            masked_keys("", "  # UMASK 022\n\n").is_empty(),
            "a commented vendor key is not in force and cannot be masked"
        );
    }

    #[test]
    fn a_key_the_vendor_repeats_is_named_once() {
        assert_eq!(
            masked_keys("", "UMASK 022\nUMASK 027\n"),
            vec!["UMASK".to_string()]
        );
    }

    #[test]
    fn an_admin_file_keeping_every_vendor_key_masks_nothing() {
        // Opposite direction: true of an implementation that reports nothing at
        // all, so it is not evidence. It pins that a full copy stays quiet.
        assert!(masked_keys(VENDOR, VENDOR).is_empty());
    }

    #[tokio::test]
    async fn the_copy_takes_the_vendor_file_s_permission_bits() {
        let executor = MockExecutor::new().with_file_metadata(
            "/usr/etc/login.defs",
            "UMASK 022\n",
            FileMetadata {
                exists: true,
                is_file: true,
                is_dir: false,
                // As a metadata probe reports it: regular file plus 0644.
                mode: 0o100_644,
                size: 10,
                uid: 0,
                gid: 0,
            },
        );
        let ctx = Context::with_executor(Arc::new(executor));
        assert_eq!(mode_for_copy_of(&ctx, "/usr/etc/login.defs").await, 0o644);
    }

    #[tokio::test]
    async fn an_unreadable_vendor_mode_never_yields_the_temporary_file_s_0600() {
        let executor = MockExecutor::new().with_metadata_error("/usr/etc/login.defs");
        let ctx = Context::with_executor(Arc::new(executor));
        // Asserted as a literal, not against the constant: comparing the
        // fallback to itself is true whatever the fallback is, so such a test
        // passes just as happily against the 0600 that is the defect.
        assert_eq!(
            mode_for_copy_of(&ctx, "/usr/etc/login.defs").await,
            0o644,
            "a mode that could not be read must not leave the file unreadable to \
             the tools that need it"
        );
    }
}
