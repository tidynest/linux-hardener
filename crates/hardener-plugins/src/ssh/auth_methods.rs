//! Which logins sshd's `AuthenticationMethods` lets a password finish.
//!
//! sshd has two methods a typed account password can satisfy. `password` is
//! the plain one. `keyboard-interactive` is the other wherever `UsePAM yes`
//! hands its prompt to pam_unix, and `PasswordAuthentication no` does not
//! close it. On openSUSE Leap 16.0 a hardened host still took the account
//! password that way (#186). Whether PAM asks for the password or for a
//! one-time code is not something sshd_config can show,
//! so both methods count as password methods here.
//!
//! Switching such a method off is not always right. Under
//! `AuthenticationMethods publickey,keyboard-interactive` it is the second
//! factor behind a key, sshd needs it on, and `sshd -t` rejects a
//! configuration that disables it. What matters is whether some list lets
//! password methods finish a login with no other factor beside them.

/// The keyword whose lists decide which methods must succeed together.
pub(super) const AUTHENTICATION_METHODS: &str = "AuthenticationMethods";

/// The methods a typed password can satisfy.
const PASSWORD_METHODS: &[&str] = &["password", "keyboard-interactive"];

/// Whether `method` can complete a login in which every step is a password.
///
/// `lists` is the effective `AuthenticationMethods` value, one comma-separated
/// list per element, or `None` where nothing sets it. sshd accepts a login
/// that satisfies any one list in full.
///
/// Unset and `any` both mean every enabled method is enough alone, and so
/// does an empty value, which sshd refuses to start on and which must not
/// read as safe here.
///
/// Names are compared as written, because sshd matches them with `strcmp` and
/// rejects `ANY` and `PublicKey` outright. A submethod,
/// `keyboard-interactive:pam`, names the method before the colon.
pub(super) fn finishes_alone(lists: Option<&[&str]>, method: &str) -> bool {
    match lists {
        None | Some([] | ["any"]) => true,
        Some(lists) => lists.iter().any(|list| {
            let names: Vec<&str> = list
                .split(',')
                .map(|name| name.split_once(':').map_or(name, |(base, _)| base))
                .collect();
            names.contains(&method) && names.iter().all(|name| PASSWORD_METHODS.contains(name))
        }),
    }
}

#[cfg(test)]
mod tests;
