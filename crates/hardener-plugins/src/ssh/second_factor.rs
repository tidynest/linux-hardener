//! The opt-in second factor: an SSH key, then the account password (#185).
//!
//! An operator asks for it in their own config, and nothing turns it on by
//! default:
//!
//! ```toml
//! [ssh.directives]
//! AuthenticationMethods = "publickey,keyboard-interactive"
//! ```
//!
//! The plugin then holds three settings together, in the fragment it owns,
//! which sshd reads before every other file on the six validated families:
//!
//! - `AuthenticationMethods`, so the key comes first and a prompt after it;
//! - `KbdInteractiveAuthentication yes`, the method that carries the prompt,
//!   which every other path of this plugin holds at `no`;
//! - `UsePAM yes`, because on Linux PAM is keyboard-interactive's only device,
//!   and `UsePAM no` passes `sshd -t` while turning every login away after the
//!   key.
//!
//! `PasswordAuthentication` stays at `no`. The prompt arrives through PAM, so
//! it asks for whatever sshd's PAM stack asks for, which is the account
//! password wherever that stack reaches pam_unix.
//!
//! This is the one change in the plugin that can lock people out without
//! breaking sshd, because `sshd -t` checks only the global lists, and only
//! whether their methods are switched on. [`check`] reads the staged candidate
//! the way sshd will run it, globally and for each account that logs in with
//! a key, before anything is written, and an apply that fails a check leaves
//! the second factor out, hardens everything else, and says why. The ways it
//! looks for are listed on [`check`]; the ones it cannot see are listed in the
//! configuration reference.

use super::{auth_methods, dropin, include::ResolvedConfig};
use hardener_common::types::{ComplianceFramework, ComplianceMapping};
use hardener_core::{
    Change, ChangeType, PluginConfig, config_validation::SSH_SECOND_FACTOR_POLICIES,
    executor::SystemExecutor,
};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use tracing::warn;

/// The exception key that accepts, by name, the accounts the second factor
/// would leave with no way in over SSH.
///
/// A subsystem-state key in the style of `firewall-enabled`, because no sshd
/// directive describes the outcome. Its `value` is the list of accounts,
/// sorted and comma-separated, exactly as the refusal prints it: a new account
/// appearing in that list is not one anybody accepted, so the exception stops
/// matching and the apply refuses again.
pub(super) const LOCKOUT_EXCEPTION_KEY: &str = "second-factor-lockout";

/// The exception key that accepts logins through key sources the account
/// check cannot list: user certificates under `TrustedUserCAKeys`, and keys an
/// `AuthorizedKeysCommand` hands over. Its `value` names those settings,
/// sorted and comma-separated, exactly as the refusal prints them.
pub(super) const UNLISTED_KEYS_EXCEPTION_KEY: &str = "second-factor-unlisted-keys";

/// The PAM service sshd uses unless `PAMServiceName` (OpenSSH 10.0 and later)
/// names another.
pub(super) const DEFAULT_PAM_SERVICE: &str = "sshd";

/// The setting that names another PAM service, in sshd_config's spelling.
pub(super) const PAM_SERVICE_NAME: &str = "PAMServiceName";

/// Each setting that switches an authentication method on, as `sshd -T`
/// prints it, with the name `AuthenticationMethods` gives the method. sshd
/// before 8.7 printed keyboard-interactive's switch under its older name.
const METHOD_SWITCHES: &[(&str, &str)] = &[
    ("pubkeyauthentication", "publickey"),
    ("kbdinteractiveauthentication", "keyboard-interactive"),
    ("challengeresponseauthentication", "keyboard-interactive"),
    ("passwordauthentication", "password"),
    ("hostbasedauthentication", "hostbased"),
    ("gssapiauthentication", "gssapi-with-mic"),
];

/// The settings that let an account log in with a key no file lists, as
/// `sshd -T` prints them (`none` where unset), with their sshd_config names.
const UNLISTED_KEY_SOURCES: &[(&str, &str)] = &[
    ("authorizedkeyscommand", "AuthorizedKeysCommand"),
    ("trustedusercakeys", "TrustedUserCAKeys"),
];

/// The method that carries the prompt.
pub(super) const KBD_INTERACTIVE: &str = "KbdInteractiveAuthentication";

/// What hands that prompt to PAM.
pub(super) const USE_PAM: &str = "UsePAM";

/// The two settings the policy needs beside the list itself, as the fragment
/// writes them.
pub(super) const COMPANIONS: &[(&str, &str)] = &[(KBD_INTERACTIVE, "yes"), (USE_PAM, "yes")];

/// PAM modules that check an account's own password: the local one, and SSSD's
/// for an account whose password lives in a directory.
const ACCOUNT_PASSWORD_MODULES: &[&str] = &["pam_unix.so", "pam_sss.so"];

/// Where a PAM service file may live, administrator's first. openSUSE ships
/// sshd's under `/usr/lib/pam.d` and leaves `/etc/pam.d` for overrides; older
/// SUSE releases used `/usr/etc/pam.d`.
const PAM_DIRECTORIES: &[&str] = &["/etc/pam.d", "/usr/lib/pam.d", "/usr/etc/pam.d"];

/// Far deeper than any shipped stack nests (Arch and Gentoo go three deep), and
/// shallow enough that a loop stops quickly.
const MAX_PAM_DEPTH: usize = 10;

/// The address another account's login is checked as on a local apply, which
/// has no client address of its own to offer.
const LOCAL_PROBE_ADDRESS: &str = "127.0.0.1";

/// The policy the config asks for, when it asks for one this plugin applies.
///
/// The value is checked at load time against the same list, so an unsupported
/// one only reaches here from a config built some other way. It is ignored
/// rather than written, with a warning, because a list this plugin cannot
/// judge is one it cannot keep anybody logged in under.
pub(super) fn requested(config: &PluginConfig) -> Option<&'static str> {
    let asked = config
        .directives
        .get(auth_methods::AUTHENTICATION_METHODS)?;
    let policy = SSH_SECOND_FACTOR_POLICIES
        .iter()
        .copied()
        .find(|policy| *policy == asked);
    if policy.is_none() {
        warn!(
            "[ssh.directives] AuthenticationMethods = {asked:?} is not a second factor this \
             tool applies; accepted: {}",
            SSH_SECOND_FACTOR_POLICIES.join(", ")
        );
    }
    policy
}

/// What an apply does about a requested second factor on this host.
pub(super) struct Plan {
    /// The policy asked for.
    pub policy: &'static str,
    /// Whether the fragment carries `AuthenticationMethods`. Not where a file
    /// beneath the fragment already asks for at least as much: writing the
    /// policy over a stricter list would loosen it, and the fragment is read
    /// first.
    pub writes_methods: bool,
    /// How the host falls short of the policy today, or `None` where it
    /// already enforces it.
    pub shortfall: Option<String>,
}

/// The plan for `policy` on the host `resolved` describes.
pub(super) fn plan(policy: &'static str, resolved: &ResolvedConfig) -> Plan {
    let beneath = resolved
        .effective_arguments_without(auth_methods::AUTHENTICATION_METHODS, dropin::DROPIN_PATH);
    Plan {
        policy,
        writes_methods: !auth_methods::requires_key_then_password(beneath.as_deref()),
        shortfall: shortfall(resolved),
    }
}

/// The `AuthenticationMethods` lists in force once an apply carrying `plan`
/// lands.
///
/// Scan judges keyboard-interactive against the host as it is. Apply and its
/// preview judge it against the host as it will be, because they rewrite the
/// fragment: where the fragment holds the policy today and the operator has
/// since taken it out of their config, the rewrite drops it, and a
/// `KbdInteractiveAuthentication yes` judged against the list about to vanish
/// would be left on with nothing in front of it.
pub(super) fn planned_lists<'a>(
    plan: Option<&Plan>,
    resolved: &'a ResolvedConfig,
) -> Option<Vec<&'a str>> {
    match plan {
        Some(plan) if plan.writes_methods => Some(vec![plan.policy]),
        _ => resolved
            .effective_arguments_without(auth_methods::AUTHENTICATION_METHODS, dropin::DROPIN_PATH),
    }
}

/// How the host falls short of a key-then-password login, in the words a
/// finding reports and an exception documents, or `None` where it does not.
///
/// The list comes first, because it is what decides who gets in. Where the list
/// is right, the two settings it depends on come next: sshd's own default is
/// `yes` for keyboard-interactive and `no` for UsePAM, so an unset UsePAM is a
/// shortfall and an unset keyboard-interactive is not.
pub(super) fn shortfall(resolved: &ResolvedConfig) -> Option<String> {
    let lists = resolved.effective_arguments(auth_methods::AUTHENTICATION_METHODS);
    let methods = lists
        .as_ref()
        .map_or_else(|| "not set".to_string(), |lists| lists.join(" "));
    if !auth_methods::requires_key_then_password(lists.as_deref()) {
        return Some(methods);
    }
    if let Some(kbd) = resolved.effective(KBD_INTERACTIVE)
        && !kbd.value.eq_ignore_ascii_case("yes")
    {
        return Some(format!("{methods} with {KBD_INTERACTIVE} {}", kbd.value));
    }
    match resolved.effective(USE_PAM) {
        Some(pam) if pam.value.eq_ignore_ascii_case("yes") => None,
        Some(pam) => Some(format!("{methods} with {USE_PAM} {}", pam.value)),
        None => Some(format!("{methods} with {USE_PAM} not set")),
    }
}

/// The directives the fragment carries for `plan`.
pub(super) fn directives(plan: &Plan) -> Vec<dropin::Directive> {
    let methods = plan.writes_methods.then(|| dropin::Directive {
        keyword: auth_methods::AUTHENTICATION_METHODS,
        value: plan.policy.to_string(),
        note: " (a key first, then the account password through PAM)",
    });
    methods
        .into_iter()
        .chain(COMPANIONS.iter().map(|(keyword, value)| dropin::Directive {
            keyword,
            value: value.to_string(),
            note: "",
        }))
        .collect()
}

/// The settings whose value in force differs from what the fragment will hold
/// for `plan`: each directive, with the value in force now (`None` where
/// nothing sets it).
///
/// One list for the apply's changes and its preview's lines, so the two
/// cannot name different settings.
pub(super) fn pending(
    plan: &Plan,
    resolved: &ResolvedConfig,
) -> Vec<(dropin::Directive, Option<String>)> {
    directives(plan)
        .into_iter()
        .filter_map(|directive| {
            let now = match directive.keyword {
                auth_methods::AUTHENTICATION_METHODS => resolved
                    .effective_arguments(directive.keyword)
                    .map(|lists| lists.join(" ")),
                keyword => resolved.effective(keyword).map(|effective| effective.value),
            };
            let unchanged = now
                .as_deref()
                .is_some_and(|now| now.eq_ignore_ascii_case(&directive.value));
            (!unchanged).then_some((directive, now))
        })
        .collect()
}

/// The changes an apply carrying `plan` reports, one per [`pending`] setting.
pub(super) fn changes(plan: &Plan, resolved: &ResolvedConfig) -> Vec<Change> {
    pending(plan, resolved)
        .into_iter()
        .map(|(directive, now)| Change {
            change_description: format!(
                "{}: {} -> {}{}",
                directive.keyword,
                now.unwrap_or_else(|| "not set".to_string()),
                directive.value,
                directive.note,
            ),
            change_type: ChangeType::ConfigFile,
            change_success: true,
            change_error: None,
        })
        .collect()
}

/// The controls a host short of an opted-in second factor fails.
///
/// Deliberately absent from `coverage()`. Declaring them there would make every
/// host that never opted in pass multi-factor authentication on the strength of
/// a check that did not run, and a key on its own is one factor. The finding
/// carries them so a host that asked for the second factor and lacks it fails
/// them where they are reported.
///
/// Titles are the NIST SP 800-53 Rev 5.2.0 catalogue's own (OSCAL release of
/// 2026-10-22). NIST SP 800-63B-4 section 2.2.1 counts a key file plus a
/// password as two factors at AAL2.
pub(super) fn compliance() -> Vec<ComplianceMapping> {
    [
        (
            "IA-2(1)",
            "Multi-factor Authentication to Privileged Accounts",
        ),
        (
            "IA-2(2)",
            "Multi-factor Authentication to Non-privileged Accounts",
        ),
    ]
    .into_iter()
    .map(|(id, title)| ComplianceMapping {
        compliance_framework: ComplianceFramework::NIST,
        compliance_control_id: id.to_string(),
        compliance_control_title: title.to_string(),
        compliance_section: Some("Identification and Authentication".to_string()),
    })
    .collect()
}

// =============================================================================
// The guards
// =============================================================================

/// The outcome of [`check`].
#[derive(Debug, Eq, PartialEq)]
pub(super) enum Verdict {
    /// Nothing is locked out that nobody accepted. The notes say what was
    /// accepted, by which exception, for the apply to report.
    Proceed(Vec<String>),
    /// The second factor must stay out of this apply, for the reason given.
    Refuse(String),
}

/// Runs every guard against the candidate staged at `staged`, with the
/// configuration in force today at `live` for comparison.
///
/// In order:
///
/// 1. The candidate as sshd will run it globally (`sshd -T`) has to ask for a
///    key and then the password, with keyboard-interactive switched on and
///    PAM handing it the prompt. A line sshd reads before the fragment, such
///    as a `UsePAM no` above the main file's `Include`, keeps the fragment's
///    value out, and `UsePAM no` passes `sshd -t` while turning every login
///    away after the key.
/// 2. The PAM service sshd uses (`PAMServiceName`, `sshd` unless set) has to
///    reach a module that checks the account password, or the prompt after
///    the key asks for something else or for nothing.
/// 3. No setting may let accounts in with keys no file lists
///    (`AuthorizedKeysCommand`, or user certificates under
///    `TrustedUserCAKeys`), unless
///    `[ssh.exceptions."second-factor-unlisted-keys"]` names them: the
///    account check below cannot see who logs in that way.
/// 4. Over a remote executor, the account this apply connected as has to keep
///    a way in on its key alone, where it has one today. This tool's remote
///    mode runs `ssh` with `BatchMode=yes` and cannot answer a prompt, so
///    without that the next scan, apply or rollback of this host from here
///    fails. Root under `PermitRootLogin prohibit-password` is refused every
///    keyboard-interactive login by sshd itself, password or not, which makes
///    this the guard a remote root apply meets first.
/// 5. Every account with a key file sshd reads, whatever its login shell
///    (sshd lets a `nologin` account authenticate, which is how SFTP-only and
///    tunnel-only accounts work), is read as sshd will run it for that
///    account (`sshd -T -C`), with each list naming a method that is switched
///    off for it dropped, as sshd drops it. Each has to keep a way in: a list
///    its key alone satisfies (a `Match` block keeping it on its key), or one
///    its key and a usable password satisfy. Root's password counts only under
///    `PermitRootLogin yes`, which this tool never writes. What is left is
///    refused unless `[ssh.exceptions."second-factor-lockout"]` names exactly
///    those accounts.
///
/// Any probe that cannot answer refuses: a guard that could not look has not
/// found the host safe. A verdict to go ahead carries notes for the apply to
/// report, among them every account that will now be asked for its password
/// after the key, because a script logging in as one of them with a key alone
/// stops working.
pub(super) async fn check(
    executor: &dyn SystemExecutor,
    config: &PluginConfig,
    staged: &str,
    live: &str,
) -> Verdict {
    let global = match sshd_dump(executor, staged, None).await {
        Ok(global) => global,
        Err(reason) => return Verdict::Refuse(reason),
    };
    if let Some(reason) = candidate_refusal(&global) {
        return Verdict::Refuse(reason);
    }

    let mut pam_checked = BTreeSet::new();
    if let Some(reason) = pam_refusal(executor, &global, &mut pam_checked).await {
        return Verdict::Refuse(reason);
    }

    let mut notes = Vec::new();
    if !global.unlisted_key_sources.is_empty() {
        let named = global.unlisted_key_sources.join(",");
        match config.matching_exception(UNLISTED_KEYS_EXCEPTION_KEY, &named) {
            Some(exception) => notes.push(format!(
                "Second factor: accounts logging in through {named} were not checked \
                 (exception: {})",
                exception.reason
            )),
            None => {
                return Verdict::Refuse(format!(
                    "{named} lets accounts log in with keys no file lists, so this check \
                     cannot tell who the password step would lock out. Accept that with \
                     [ssh.exceptions.\"{UNLISTED_KEYS_EXCEPTION_KEY}\"] value = \"{named}\""
                ));
            }
        }
    }

    let accounts = match read_accounts(executor).await {
        Ok(accounts) => accounts,
        Err(reason) => return Verdict::Refuse(reason),
    };

    let probe_address = if executor.is_remote() {
        let (user, address) = match session_identity(executor).await {
            Ok(identity) => identity,
            Err(reason) => return Verdict::Refuse(reason),
        };
        // An account `passwd` does not list (one from a directory service) is
        // judged by its name, which is the only thing sshd's root rule and
        // this one can both see.
        let uid = accounts
            .iter()
            .find(|account| account.name == user)
            .map_or(if user == "root" { 0 } else { u32::MAX }, |account| {
                account.uid
            });
        let after = match sshd_dump(executor, staged, Some((&user, &address))).await {
            Ok(after) => after,
            Err(reason) => return Verdict::Refuse(reason),
        };
        let before = match sshd_dump(executor, live, Some((&user, &address))).await {
            Ok(before) => before,
            Err(reason) => return Verdict::Refuse(reason),
        };
        if key_gets_in(&before, uid) && !key_gets_in(&after, uid) {
            return Verdict::Refuse(format!(
                "this apply runs over SSH as {user} from {address}, and the second factor \
                 would stop that account logging in on its key alone, which is all this \
                 tool's remote mode can offer. Add a Match block giving {user} from \
                 {address} `AuthenticationMethods publickey` (see the configuration \
                 reference), or apply from a session on the host itself"
            ));
        }
        address
    } else {
        LOCAL_PROBE_ADDRESS.to_string()
    };

    let mut stranded = BTreeSet::new();
    let mut asked = BTreeSet::new();
    for account in &accounts {
        if !has_key_file(executor, &global.authorized_keys_files, account).await {
            continue;
        }
        let effective =
            match sshd_dump(executor, staged, Some((&account.name, &probe_address))).await {
                Ok(effective) => effective,
                Err(reason) => return Verdict::Refuse(reason),
            };
        // Root under `PermitRootLogin no` has no SSH login to lose.
        if account.uid == 0 && effective.permit_root_login.eq_ignore_ascii_case("no") {
            continue;
        }
        // A `Match` block may hand this account a PAM service of its own.
        if let Some(reason) = pam_refusal(executor, &effective, &mut pam_checked).await {
            return Verdict::Refuse(format!(
                "{reason}; that is the PAM service sshd uses for {}",
                account.name
            ));
        }
        if key_gets_in(&effective, account.uid) {
            continue;
        }
        if password_gets_in(&effective, account) {
            asked.insert(account.name.clone());
        } else {
            stranded.insert(account.name.clone());
        }
    }

    if !asked.is_empty() {
        notes.push(format!(
            "Second factor: {} will be asked for the account password after the key from \
             now on, so a script or tool that logs in as one of them with a key alone \
             (a backup job, git, rsync, Ansible) stops working unless a Match block keeps \
             it on its key",
            asked.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    if stranded.is_empty() {
        return Verdict::Proceed(notes);
    }
    let named = stranded.into_iter().collect::<Vec<_>>().join(",");
    if let Some(exception) = config.matching_exception(LOCKOUT_EXCEPTION_KEY, &named) {
        notes.push(format!(
            "Second factor: SSH access for {named} accepted as lost (exception: {})",
            exception.reason
        ));
        return Verdict::Proceed(notes);
    }
    Verdict::Refuse(format!(
        "these accounts log in with a key and could not get past the password prompt, \
         so the second factor would lock them out of SSH: {named} (checked as a login \
         from {probe_address}). Give each a password, keep it on its key with a Match \
         block, or accept the loss with [ssh.exceptions.\"{LOCKOUT_EXCEPTION_KEY}\"] \
         value = \"{named}\""
    ))
}

/// Why the candidate, as sshd will run it globally, does not deliver the
/// second factor the fragment asks for, or `None` where it does.
///
/// The fragment is read before every file a distribution ships, but not
/// before a line above the main file's `Include`, which sshd reads first and
/// which therefore wins.
pub(super) fn candidate_refusal(global: &Effective) -> Option<String> {
    let lists: Vec<&str> = global.methods.iter().map(String::as_str).collect();
    let before = format!(
        "because a line sshd reads before {}, such as one above the main file's \
         Include, sets it",
        dropin::DROPIN_PATH
    );
    if !auth_methods::requires_key_then_password(Some(&lists)) {
        return Some(format!(
            "with this candidate sshd would still run with AuthenticationMethods {}, {before}",
            lists.join(" ")
        ));
    }
    match global.use_pam {
        None => {
            return Some(
                "this sshd prints no UsePAM setting, so it was built without PAM and the \
                 prompt after the key has nothing to ask the account password with"
                    .to_string(),
            );
        }
        Some(false) => {
            return Some(format!(
                "with this candidate sshd would run with UsePAM no, {before}. Without PAM the \
                 prompt after the key cannot ask for the password, so every login would stop \
                 there. Set UsePAM yes in that file"
            ));
        }
        Some(true) => {}
    }
    if !global.enabled.contains("keyboard-interactive") {
        return Some(format!(
            "with this candidate sshd would run with KbdInteractiveAuthentication no, \
             {before}, so the step after the key could never be taken"
        ));
    }
    None
}

/// Checks the PAM service `effective` names, once per service.
async fn pam_refusal(
    executor: &dyn SystemExecutor,
    effective: &Effective,
    checked: &mut BTreeSet<String>,
) -> Option<String> {
    let service = effective
        .pam_service
        .clone()
        .unwrap_or_else(|| DEFAULT_PAM_SERVICE.to_string());
    if !checked.insert(service.clone()) {
        return None;
    }
    pam_answers_with_password(executor, &service)
        .await
        .refusal()
}

/// Whether `method` can be used at all under `effective`. Keyboard-interactive
/// needs PAM as well, because on Linux PAM is its only device.
fn method_works(effective: &Effective, method: &str) -> bool {
    effective.enabled.contains(method)
        && (method != "keyboard-interactive" || effective.use_pam == Some(true))
}

/// The `AuthenticationMethods` lists sshd keeps for a connection: each list
/// naming a method that is switched off is dropped, as sshd's
/// `auth2_setup_methods_lists` drops it. Where none is left sshd disconnects
/// with "no authentication methods enabled", and `sshd -t` never sees it,
/// because it checks the global lists only.
pub(super) fn usable_lists(effective: &Effective) -> Vec<&str> {
    effective
        .methods
        .iter()
        .map(String::as_str)
        .filter(|list| {
            *list == "any"
                || auth_methods::method_names(list)
                    .iter()
                    .all(|method| method_works(effective, method))
        })
        .collect()
}

/// Whether one key is enough for `uid` under `effective`, which is what this
/// tool's remote mode and every other key-only client can offer.
pub(super) fn key_gets_in(effective: &Effective, uid: u32) -> bool {
    method_works(effective, "publickey")
        && auth_methods::key_alone_suffices(&usable_lists(effective))
        && (uid != 0
            || ["yes", "prohibit-password", "without-password"]
                .contains(&effective.permit_root_login.as_str()))
}

/// Whether `account` can finish a login with its key and its password under
/// `effective`: it has a password pam_unix will take, sshd lets it use one
/// (root only under `PermitRootLogin yes`), and some list it keeps asks for
/// nothing beyond a key and a password.
pub(super) fn password_gets_in(effective: &Effective, account: &Account) -> bool {
    if !account.usable_password || (account.uid == 0 && effective.permit_root_login != "yes") {
        return false;
    }
    usable_lists(effective).iter().any(|list| {
        if *list == "any" {
            return auth_methods::PASSWORD_METHODS
                .iter()
                .any(|method| method_works(effective, method));
        }
        let names = auth_methods::method_names(list);
        names
            .iter()
            .any(|name| auth_methods::PASSWORD_METHODS.contains(name))
            && names
                .iter()
                .all(|name| *name == "publickey" || auth_methods::PASSWORD_METHODS.contains(name))
    })
}

// -----------------------------------------------------------------------------
// PAM
// -----------------------------------------------------------------------------

/// What sshd's PAM stack does with the prompt.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum PamAnswer {
    /// It reaches `module`, in `file`, which checks the account password.
    Password { module: String, file: String },
    /// It reaches no such module. `files` names every file read.
    NoPassword { files: Vec<String> },
    /// A file could not be found or read, so the answer is unknown.
    Unknown(String),
}

impl PamAnswer {
    /// Why the second factor cannot go ahead on this answer, or `None` where
    /// it can.
    pub(super) fn refusal(&self) -> Option<String> {
        match self {
            Self::Password { .. } => None,
            Self::NoPassword { files } => Some(format!(
                "sshd's PAM stack ({}) reaches neither pam_unix nor pam_sss, so the prompt \
                 after the key would not ask for the account password",
                files.join(", ")
            )),
            Self::Unknown(reason) => Some(format!(
                "could not confirm that sshd's PAM stack asks for the account password: {reason}"
            )),
        }
    }
}

/// One step of an `auth` stack.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum AuthStep {
    /// `include`, `substack` or `@include`: another service file.
    Include(String),
    /// A module, by the file name it loads.
    Module(String),
}

/// The `auth` steps a PAM service file takes, in order.
///
/// `@include` pulls in every type, `auth`; a leading `-` only says a missing
/// module is not an error; and a bracketed control such as
/// `[success=1 default=ignore]` may span several words. Whether a module that
/// is reached is also the one that answers depends on the controls above it,
/// which this does not model: it shows the stack can ask for the account
/// password, not that nothing else answers first.
pub(super) fn auth_steps(content: &str) -> Vec<AuthStep> {
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            if words.first() == Some(&"@include") {
                return words.get(1).map(|name| AuthStep::Include(name.to_string()));
            }
            let kind = words.first()?.trim_start_matches('-');
            if !kind.eq_ignore_ascii_case("auth") {
                return None;
            }
            let control = words.get(1)?;
            let module_at = if control.starts_with('[') {
                words[1..].iter().position(|word| word.ends_with(']'))? + 2
            } else {
                2
            };
            let module = words.get(module_at)?;
            match *control {
                "include" | "substack" => Some(AuthStep::Include(module.to_string())),
                _ => Some(AuthStep::Module(
                    module.rsplit('/').next().unwrap_or(module).to_string(),
                )),
            }
        })
        .collect()
}

/// Follows the `auth` stack of the PAM service `service` until it reaches a
/// module that checks the account password.
///
/// sshd's service is `sshd` unless `PAMServiceName` (OpenSSH 10.0 and later)
/// names another, which is the one sshd hands to `pam_start`.
pub(super) async fn pam_answers_with_password(
    executor: &dyn SystemExecutor,
    service: &str,
) -> PamAnswer {
    let mut pending = vec![(service.to_string(), 0usize)];
    let mut read = Vec::new();
    let mut seen = BTreeSet::new();
    while let Some((service, depth)) = pending.pop() {
        if !seen.insert(service.clone()) {
            continue;
        }
        if depth > MAX_PAM_DEPTH {
            return PamAnswer::Unknown(format!(
                "PAM includes nest deeper than {MAX_PAM_DEPTH} levels at {service}"
            ));
        }
        let (path, content) = match read_pam_service(executor, &service).await {
            Ok(found) => found,
            Err(reason) => return PamAnswer::Unknown(reason),
        };
        for step in auth_steps(&content) {
            match step {
                AuthStep::Module(module) if ACCOUNT_PASSWORD_MODULES.contains(&module.as_str()) => {
                    return PamAnswer::Password { module, file: path };
                }
                AuthStep::Module(_) => {}
                AuthStep::Include(name) => pending.push((name, depth + 1)),
            }
        }
        read.push(path);
    }
    PamAnswer::NoPassword { files: read }
}

/// A PAM service file and where it was found.
async fn read_pam_service(
    executor: &dyn SystemExecutor,
    service: &str,
) -> Result<(String, String), String> {
    let candidates: Vec<PathBuf> = if service.starts_with('/') {
        vec![PathBuf::from(service)]
    } else {
        PAM_DIRECTORIES
            .iter()
            .map(|directory| Path::new(directory).join(service))
            .collect()
    };
    for path in &candidates {
        match executor.read_file_optional(path).await {
            Ok(Some(content)) => return Ok((path.display().to_string(), content)),
            Ok(None) => {}
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        }
    }
    Err(format!(
        "no PAM service file named {service} in {}",
        PAM_DIRECTORIES.join(", ")
    ))
}

// -----------------------------------------------------------------------------
// sshd -T
// -----------------------------------------------------------------------------

/// The settings the guards read from `sshd -T`, for one connection or for the
/// global scope.
#[derive(Debug, Default, Eq, PartialEq)]
pub(super) struct Effective {
    /// One element per list, `any` where nothing sets it.
    pub methods: Vec<String>,
    /// As sshd prints it, lower case.
    pub permit_root_login: String,
    /// Each `AuthorizedKeysFile` template, `%h` and `%u` unexpanded.
    pub authorized_keys_files: Vec<String>,
    /// The methods switched on, by the names `AuthenticationMethods` uses.
    pub enabled: BTreeSet<&'static str>,
    /// `UsePAM`, or `None` where sshd prints no such line, which a build
    /// without PAM does not.
    pub use_pam: Option<bool>,
    /// `PAMServiceName`, which OpenSSH prints from 10.0 on.
    pub pam_service: Option<String>,
    /// The settings that let accounts in with keys no file lists, by their
    /// sshd_config names, sorted.
    pub unlisted_key_sources: Vec<&'static str>,
}

/// Reads what `sshd -T` prints. `None` where it printed no
/// `authenticationmethods` line, which every sshd since 6.2 does, so its
/// absence means the output is not what this expects.
pub(super) fn parse_sshd_dump(stdout: &str) -> Option<Effective> {
    let mut effective = Effective::default();
    let mut saw_methods = false;
    for line in stdout.lines() {
        let Some((keyword, value)) = line.trim().split_once(char::is_whitespace) else {
            continue;
        };
        let value = value.trim();
        let words = value.split_whitespace().map(str::to_string);
        let keyword = keyword.to_ascii_lowercase();
        match keyword.as_str() {
            "authenticationmethods" => {
                saw_methods = true;
                effective.methods = words.collect();
            }
            "permitrootlogin" => effective.permit_root_login = value.to_ascii_lowercase(),
            "authorizedkeysfile" => effective.authorized_keys_files = words.collect(),
            "usepam" => effective.use_pam = Some(value.eq_ignore_ascii_case("yes")),
            "pamservicename" => effective.pam_service = Some(value.to_string()),
            keyword => {
                if let Some((_, method)) = METHOD_SWITCHES.iter().find(|(name, _)| *name == keyword)
                    && value.eq_ignore_ascii_case("yes")
                {
                    effective.enabled.insert(method);
                }
                if let Some((_, setting)) = UNLISTED_KEY_SOURCES
                    .iter()
                    .find(|(name, _)| *name == keyword)
                    && !value.eq_ignore_ascii_case("none")
                {
                    effective.unlisted_key_sources.push(setting);
                }
            }
        }
    }
    effective.unlisted_key_sources.sort_unstable();
    saw_methods.then_some(effective)
}

/// Runs `sshd -T -f config`, with `-C` for one connection where `connection`
/// names a user and an address.
///
/// The address stands in for the host name as well, which sshd would otherwise
/// look up, so a `Match Host` block is judged against the address as written.
async fn sshd_dump(
    executor: &dyn SystemExecutor,
    config: &str,
    connection: Option<(&str, &str)>,
) -> Result<Effective, String> {
    let spec =
        connection.map(|(user, address)| format!("user={user},host={address},addr={address}"));
    let mut args = vec!["-T", "-f", config];
    if let Some(spec) = spec.as_deref() {
        args.extend(["-C", spec]);
    }
    let described = match connection {
        Some((user, address)) => format!("for {user} from {address}"),
        None => "for the global scope".to_string(),
    };
    match executor.execute_command("sshd", &args).await {
        Ok(output) if output.success() => parse_sshd_dump(&output.stdout).ok_or_else(|| {
            format!(
                "`sshd -T` printed no AuthenticationMethods {described}, so it cannot be checked"
            )
        }),
        Ok(output) => Err(format!(
            "`sshd -T` could not read the candidate {described}: {}",
            output.stderr.trim()
        )),
        Err(e) => Err(format!("`sshd -T` could not be run {described}: {e:#}")),
    }
}

/// The account this remote session runs as, and the address it connected from.
async fn session_identity(executor: &dyn SystemExecutor) -> Result<(String, String), String> {
    let user = match executor.execute_command("id", &["-un"]).await {
        Ok(output) if output.success() && !output.stdout.trim().is_empty() => {
            output.stdout.trim().to_string()
        }
        Ok(output) => {
            return Err(format!(
                "could not tell which account this SSH session runs as: {}",
                output.stderr.trim()
            ));
        }
        Err(e) => {
            return Err(format!(
                "could not tell which account this SSH session runs as: {e:#}"
            ));
        }
    };
    let address = match executor
        .execute_command("printenv", &["SSH_CONNECTION"])
        .await
    {
        Ok(output) if output.success() => {
            output.stdout.split_whitespace().next().map(str::to_string)
        }
        _ => None,
    };
    address.map(|address| (user, address)).ok_or_else(|| {
        "could not tell which address this SSH session comes from: SSH_CONNECTION is not set"
            .to_string()
    })
}

// -----------------------------------------------------------------------------
// Accounts
// -----------------------------------------------------------------------------

/// An account from `/etc/passwd`, with what `/etc/shadow` says of its password.
///
/// The login shell is deliberately not read. sshd refuses an account only
/// where its shell does not exist or is not executable (`allowed_user` in
/// auth.c), and `nologin` and `false` are both executable: an SFTP-only
/// account behind `ForceCommand internal-sftp`, or one that only holds a
/// tunnel open with `ssh -N`, authenticates with its key like any other, and
/// the password step locks it out like any other.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct Account {
    pub name: String,
    pub uid: u32,
    pub home: String,
    /// False for an empty, locked (`!`, `!!`) or disabled (`*`) hash, none of
    /// which pam_unix will accept a password for. An empty one fails too,
    /// because sshd passes `PAM_DISALLOW_NULL_AUTHTOK` under
    /// `PermitEmptyPasswords no`, which this tool holds.
    pub usable_password: bool,
}

/// The accounts `passwd` lists, each marked by what `shadow` holds for it. An
/// account `shadow` does not list has no usable password.
pub(super) fn parse_accounts(passwd: &str, shadow: &str) -> Vec<Account> {
    let hashes: HashMap<&str, &str> = shadow
        .lines()
        .filter_map(|line| {
            let mut fields = line.split(':');
            Some((fields.next()?, fields.next()?))
        })
        .collect();
    passwd
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            let [name, _, uid, _, _, home, _shell] = fields.as_slice() else {
                return None;
            };
            Some(Account {
                name: name.to_string(),
                uid: uid.parse().ok()?,
                home: home.to_string(),
                usable_password: hashes.get(name).is_some_and(|hash| {
                    !hash.is_empty() && !hash.starts_with('!') && !hash.starts_with('*')
                }),
            })
        })
        .collect()
}

/// The accounts on this host, read as the apply's own session.
async fn read_accounts(executor: &dyn SystemExecutor) -> Result<Vec<Account>, String> {
    let passwd = executor
        .read_file(Path::new("/etc/passwd"))
        .await
        .map_err(|e| {
            format!("could not read /etc/passwd to check who would be locked out: {e:#}")
        })?;
    let shadow = executor
        .read_file(Path::new("/etc/shadow"))
        .await
        .map_err(|e| {
            format!("could not read /etc/shadow to check which accounts have a password: {e:#}")
        })?;
    Ok(parse_accounts(&passwd, &shadow))
}

/// The key files sshd reads for `account`: each `AuthorizedKeysFile` template
/// with `%h`, `%u` and `%%` expanded, relative to the home directory where it
/// is not absolute. `none` reads nothing.
pub(super) fn key_files(templates: &[String], account: &Account) -> Vec<PathBuf> {
    templates
        .iter()
        .filter(|template| !template.eq_ignore_ascii_case("none"))
        .map(|template| {
            let expanded = template
                .replace("%%", "\u{0}")
                .replace("%h", &account.home)
                .replace("%u", &account.name)
                .replace('\u{0}', "%");
            let path = PathBuf::from(&expanded);
            if path.is_absolute() {
                path
            } else {
                Path::new(&account.home).join(path)
            }
        })
        .collect()
}

/// Whether `account` has a key file sshd would read. A file that cannot be
/// checked counts as present, which sends the account through the stricter
/// path rather than past it.
async fn has_key_file(
    executor: &dyn SystemExecutor,
    templates: &[String],
    account: &Account,
) -> bool {
    for path in key_files(templates, account) {
        match executor.path_exists(&path).await {
            Ok(false) => {}
            Ok(true) | Err(_) => return true,
        }
    }
    false
}

#[cfg(test)]
mod tests;
