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
pub(super) const PASSWORD_METHODS: &[&str] = &["password", "keyboard-interactive"];

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

/// The method names in one comma-separated list, each submethod reduced to
/// the method before its colon.
pub(super) fn method_names(list: &str) -> Vec<&str> {
    list.split(',')
        .map(|name| name.split_once(':').map_or(name, |(base, _)| base))
        .collect()
}

/// Whether every list asks for a key before the account password, which is
/// the second factor an operator opts into under `[ssh.directives]` (#185).
///
/// Each list has to name `publickey` ahead of `keyboard-interactive`, and no
/// password method may come before the key. Order matters because sshd offers
/// only the methods that come next in some list: with the key first, nobody
/// without it ever reaches the password prompt, so they can neither guess at
/// the password nor run up the account's PAM failure count. A list that names
/// `password` does not count either, because the baseline holds
/// `PasswordAuthentication no` and sshd skips a list naming a method it has
/// switched off.
///
/// A list asking for more than this, a second key or a host key as well, still
/// counts, so a host stricter than the policy is never rewritten to it.
pub(super) fn requires_key_then_password(lists: Option<&[&str]>) -> bool {
    match lists {
        None | Some([] | ["any"]) => false,
        Some(lists) => lists.iter().all(|list| {
            let names = method_names(list);
            let first_key = names.iter().position(|name| *name == "publickey");
            let first_password = names
                .iter()
                .position(|name| PASSWORD_METHODS.contains(name));
            !names.contains(&"password")
                && matches!(
                    (first_key, first_password),
                    (Some(key), Some(prompt)) if key < prompt
                )
        }),
    }
}

/// Whether a single key is enough to finish a login, which is all this tool's
/// own remote mode can offer: it connects with `BatchMode=yes` and cannot
/// answer a prompt.
///
/// `lists` is what `sshd -T` prints for one connection, which is `any` where
/// nothing sets the keyword. A list of `publickey,publickey` needs two keys and
/// does not count.
pub(super) fn key_alone_suffices(lists: &[&str]) -> bool {
    lists
        .iter()
        .any(|list| *list == "any" || method_names(list) == ["publickey"])
}

#[cfg(test)]
mod tests;
