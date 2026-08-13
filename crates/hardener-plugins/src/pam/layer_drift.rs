//! Reporting keys an `/etc` file hides from its `/usr/etc` counterpart.
//!
//! openSUSE (Leap 15.6+, Tumbleweed, MicroOS) ships vendor configuration under
//! `/usr/etc` and reserves `/etc` for administrator overrides, and Fedora is
//! moving the same way. **The override is whole-file, not per directive**: the
//! first file found wins entirely, so every key the `/etc` copy omits falls
//! back to the consuming library's built-in default rather than to the value
//! the distribution chose.
//!
//! That property belongs to the layering, not to any one file. It was first
//! found on `/etc/login.defs`, where it drops password hashing to DES, but
//! `/etc/security/{pwquality,faillock,pwhistory}.conf` mask their vendor
//! counterparts identically. Every file this plugin reads through the layered
//! reader is checked here, so a file added to [`LAYERED_CONFS`] is covered by
//! arriving in the table rather than by someone remembering a second place.

use hardener_common::types::{FindingCategory, Severity};
use hardener_core::plugin::Finding;
use hardener_types::ExceptionOutcome;
use std::collections::BTreeSet;

/// One configuration file that can be masked, and what masking it costs.
///
/// The consequence is per file and is the reason this is a table rather than a
/// format string: a masked `ENCRYPT_METHOD` is a measured data-loss event, a
/// masked `difok` is a weaker password policy. Describing both in one sentence
/// would either overstate the second or understate the first.
pub(super) struct LayeredConf {
    /// The `/etc` path. Its `/usr/etc` counterpart comes from
    /// `vendor_config::vendor_path_for`, so it is never spelled twice.
    pub(super) admin_path: &'static str,
    /// Stable finding id. `pam-login-defs-masked-keys` shipped in 1.5.1 and is
    /// documented in `docs/reference/configuration.md`, so it keeps its name;
    /// the other three follow its shape.
    pub(super) finding_id: &'static str,
    /// What reads this file, named so the operator can tell what reverted.
    pub(super) consumer: &'static str,
    /// The measured or reasoned consequence of the keys going missing.
    pub(super) impact: &'static str,
}

/// Every file this plugin reads through the layered reader.
///
/// `/etc/pam.d` is deliberately absent: it is a directory of stack files, not a
/// key-value configuration, and a set difference over its lines would be
/// meaningless.
pub(super) const LAYERED_CONFS: &[LayeredConf] = &[
    LayeredConf {
        admin_path: "/etc/login.defs",
        finding_id: "pam-login-defs-masked-keys",
        consumer: "shadow",
        impact: "Settings the distribution chose are silently not in force. Where \
             ENCRYPT_METHOD is among them, shadow falls back to DES, which truncates every \
             password set afterwards at eight characters however long it was typed; where \
             HOME_MODE is, new home directories are created world readable.",
    },
    LayeredConf {
        admin_path: "/etc/security/pwquality.conf",
        finding_id: "pam-pwquality-conf-masked-keys",
        consumer: "pam_pwquality, pwscore and pwmake",
        impact: "Password quality rules the distribution chose are not applied. Every masked \
             key reverts to libpwquality's own built-in default, so passwords are accepted \
             against a weaker policy than the vendor file describes, and pwscore and pwmake \
             report against that weaker policy too.",
    },
    LayeredConf {
        admin_path: super::FAILLOCK_CONF,
        finding_id: "pam-faillock-conf-masked-keys",
        consumer: "pam_faillock",
        impact: "Account lockout runs on pam_faillock's built-in defaults rather than the \
             distribution's for every masked key, so the number of failures tolerated, how \
             long a lockout lasts, or whether root is covered may all differ from what the \
             vendor file states.",
    },
    LayeredConf {
        admin_path: super::PWHISTORY_CONF,
        finding_id: "pam-pwhistory-conf-masked-keys",
        consumer: "pam_pwhistory",
        impact: "Password reuse prevention runs on pam_pwhistory's built-in defaults rather \
             than the distribution's for every masked key, so a user may be able to reuse a \
             password the vendor file meant to forbid.",
    },
];

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

/// The finding naming keys `conf.admin_path` masks, given a non-empty
/// difference from [`masked_keys`].
///
/// `Severity::Medium`, because reverting to a library's built-in defaults is
/// not housekeeping. Measured on an openSUSE Leap container: masking a vendor
/// `login.defs` that sets `ENCRYPT_METHOD SHA512` drops password hashing to
/// DES, which truncates every password at eight characters. Every release up to
/// 1.5.0 wrote exactly such a file there, and this tool cannot repair the
/// damage, because an `/etc` file that already exists is edited rather than
/// replaced. This finding is the only thing that tells such an operator
/// anything, and at `Low` it would not reach them: the scheduler drops findings
/// below its `min_severity`, whose default is `medium`
/// (`scheduler/src/runner.rs:376`, `config.rs:58`), so a fleet host with DES
/// passwords would record nothing. The same severity applies to the other three
/// files, because the scheduler's filter does not care which file drifted.
///
/// Still no compliance mapping. No framework has a control for a masked
/// configuration file, and a mapping here would let this drive a control to
/// Fail on evidence no framework asked for.
///
/// The remediation is deliberately manual. `apply` carries the vendor file over
/// only when `/etc` is confirmed absent; once the `/etc` file exists it is the
/// host's own and this tool edits the directives it manages rather than
/// importing keys the operator may have dropped on purpose. Telling the
/// operator to run `apply` would be advice that does nothing.
pub(super) fn masked_keys_finding(
    conf: &LayeredConf,
    vendor_path: &str,
    keys: &[String],
) -> Finding {
    let named = keys.join(", ");
    let admin_path = conf.admin_path;
    Finding {
        finding_id: conf.finding_id.to_string(),
        finding_category: FindingCategory::Authentication,
        finding_current_value: named.clone(),
        finding_description: format!(
            "{admin_path} masks {count} key(s) that {vendor_path} sets: {named}",
            count = keys.len(),
        ),
        finding_explanation: format!(
            "A distribution that ships vendor configuration under /usr/etc is \
             overridden whole-file, not per directive: once {admin_path} \
             exists, every key it omits falls back to {consumer}'s built-in default \
             rather than to the vendor's value.",
            consumer = conf.consumer,
        ),
        finding_impact: conf.impact.to_string(),
        finding_recommended_value: format!("the values {vendor_path} sets for {named}"),
        finding_remediation_steps: vec![format!(
            "Copy {named} and their values from {vendor_path} into {admin_path}, \
             or remove from {admin_path} any key you did not mean to override"
        )],
        finding_severity: Severity::Medium,
        finding_title: format!("Vendor keys masked by {admin_path}"),
        finding_compliance: vec![],
        // No directive to match an exception against: this names a set of keys
        // the tool does not manage, so there is no setting for a configured
        // exception to be about.
        finding_exception: ExceptionOutcome::NotConfigured,
        finding_exception_key: None,
    }
}

#[cfg(test)]
mod tests;
