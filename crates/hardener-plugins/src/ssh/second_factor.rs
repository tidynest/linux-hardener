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
//! the way sshd will run it, globally and for each account that can log in
//! over SSH, beside the same apply staged without the second factor, before
//! anything is written, and an apply that fails a check leaves the second
//! factor out, hardens everything else, and says why. The ways it looks for
//! are listed on [`check`]; the ones it cannot see are listed in the
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

/// The exception key that accepts logins the account check cannot list: user
/// certificates under `TrustedUserCAKeys`, keys an `AuthorizedKeysCommand`
/// hands over, Kerberos tickets (`GSSAPIAuthentication`, where a keytab
/// exists) and trusted hosts (`HostbasedAuthentication`). Its `value` names
/// those settings, sorted and comma-separated, exactly as the refusal prints
/// them.
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

/// The address every account's login is also checked from: TEST-NET-3
/// (RFC 5737), which no real `Match Address` block names. An exemption scoped
/// to loopback, or to the controller a remote apply runs from, would
/// otherwise hide a lockout for logins from anywhere else: measured with
/// OpenSSH 9.6p1, `Match Address 127.0.0.1,192.0.2.10` kept an account on its
/// key from those two addresses and asked every other one for the password.
pub(super) const ELSEWHERE_PROBE_ADDRESS: &str = "203.0.113.254";

/// Where sshd's Kerberos acceptor looks for its keys unless krb5.conf's
/// `default_keytab_name` or `KRB5_KTNAME` says otherwise. Without it nobody
/// logs in through `gssapi-with-mic`, whatever `GSSAPIAuthentication` says.
const KERBEROS_KEYTAB: &str = "/etc/krb5.keytab";

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

/// Runs every guard against the candidate staged at `staged`, with the same
/// apply drafted without the second factor staged at `baseline`, so what the
/// second factor takes away is told apart from what the rest of the apply
/// does anyway.
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
/// 3. No setting may let accounts in without a key file this check can read,
///    unless `[ssh.exceptions."second-factor-unlisted-keys"]` names them: keys
///    an `AuthorizedKeysCommand` hands over, user certificates under
///    `TrustedUserCAKeys`, trusted hosts under `HostbasedAuthentication`, and
///    Kerberos tickets under `GSSAPIAuthentication` where a keytab exists. The
///    account check below cannot see who logs in that way, and the policy
///    turns every one of them away unless they also hold a key and a password.
///    Rocky and Fedora switch `GSSAPIAuthentication` on in 50-redhat.conf, so
///    without a keytab that is a note rather than a refusal.
/// 4. Over a remote executor, the account this apply connected as has to keep
///    a way in on its key alone, where it has one without the second factor.
///    This tool's remote mode runs `ssh` with `BatchMode=yes` and cannot
///    answer a prompt, so without that the next scan, apply or rollback of
///    this host from here fails. Root under `PermitRootLogin prohibit-password`
///    is refused every keyboard-interactive login by sshd itself, password or
///    not, which makes this the guard a remote root apply meets first.
/// 5. Every account that can log in over SSH is read as sshd will run it for
///    that account (`sshd -T -C`), from the session's address (or loopback)
///    and from [`ELSEWHERE_PROBE_ADDRESS`], with each list naming a method that
///    is switched off for it dropped, as sshd drops it. That is every account
///    with a key file sshd reads, whatever its login shell (sshd lets a
///    `nologin` account authenticate, which is how SFTP-only and tunnel-only
///    accounts work), and every account with a usable password that the apply
///    without the second factor would let in on that password alone (an
///    exception keeping `PasswordAuthentication yes`, for one). Each has to
///    keep a way in from both addresses: its key alone (a `Match` block
///    keeping it on its key), its key and a usable password, or its password
///    alone where that was already so. Root's password counts only under
///    `PermitRootLogin yes`, which this tool never writes. What is left is
///    refused unless `[ssh.exceptions."second-factor-lockout"]` names exactly
///    those accounts. The account this apply runs as over `--ssh` needs only
///    the session's address: losing the rest is a note, because the
///    documented `Match` block keeps it to one address on purpose.
/// 6. No probed login may finish on a password alone where the apply without
///    the second factor would not have let it: switching keyboard-interactive
///    on for every connection wakes a `Match` list that names it on its own,
///    which sshd had been dropping. The apply also refuses any `Match` block
///    in the files that does so, which reaches addresses no probe names (see
///    [`match_refusal`]).
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
    baseline: &str,
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
    let mut unlisted = global.unlisted_key_sources.clone();
    if global.enabled.contains("hostbased") {
        unlisted.push("HostbasedAuthentication");
    }
    if global.enabled.contains("gssapi-with-mic") {
        match executor.path_exists(Path::new(KERBEROS_KEYTAB)).await {
            Ok(false) => notes.push(format!(
                "Second factor: GSSAPIAuthentication is on, but {KERBEROS_KEYTAB} does not \
                 exist, so nobody logs in with a Kerberos ticket today; once a keytab is \
                 added, such a login needs the key and the password as well"
            )),
            Ok(true) | Err(_) => unlisted.push("GSSAPIAuthentication"),
        }
    }
    unlisted.sort_unstable();
    if !unlisted.is_empty() {
        let named = unlisted.join(",");
        match config.matching_exception(UNLISTED_KEYS_EXCEPTION_KEY, &named) {
            Some(exception) => notes.push(format!(
                "Second factor: accounts logging in through {named} were not checked \
                 (exception: {})",
                exception.reason
            )),
            None => {
                return Verdict::Refuse(format!(
                    "{named} lets accounts log in without a key file this check can read, so \
                     it cannot tell who the password step would lock out: every such login \
                     needs a key and the password from now on. Accept that with \
                     [ssh.exceptions.\"{UNLISTED_KEYS_EXCEPTION_KEY}\"] value = \"{named}\""
                ));
            }
        }
    }

    let accounts = match read_accounts(executor).await {
        Ok(accounts) => accounts,
        Err(reason) => return Verdict::Refuse(reason),
    };

    let mut session_user = None;
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
        let before = match sshd_dump(executor, baseline, Some((&user, &address))).await {
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
        session_user = Some(user);
        address
    } else {
        LOCAL_PROBE_ADDRESS.to_string()
    };
    let addresses = [probe_address.as_str(), ELSEWHERE_PROBE_ADDRESS];

    let mut stranded = BTreeSet::new();
    let mut asked = BTreeSet::new();
    for account in &accounts {
        let keyed = has_key_file(executor, &global.authorized_keys_files, account).await;
        // No key file and no password pam_unix will take: nothing this check
        // can list lets the account in today, so it has nothing to lose.
        if !keyed && !account.usable_password {
            continue;
        }
        let is_session = session_user.as_deref() == Some(account.name.as_str());
        for address in addresses {
            let probe = Probe {
                executor,
                staged,
                baseline,
                account,
                keyed,
                address,
            };
            match probe.judge(&mut pam_checked).await {
                Ok(Outcome::KeepsAWayIn) => {}
                Ok(Outcome::Asked) => {
                    asked.insert(account.name.clone());
                }
                Ok(Outcome::Stranded) if is_session && address == ELSEWHERE_PROBE_ADDRESS => {
                    notes.push(format!(
                        "Second factor: {}, which this apply runs as, keeps its key-only login \
                         from {probe_address}; from any other address it can no longer log in",
                        account.name
                    ));
                }
                Ok(Outcome::Stranded) => {
                    stranded.insert(account.name.clone());
                }
                Err(reason) => return Verdict::Refuse(reason),
            }
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
        "these accounts log in over SSH today and could not get past the password prompt, \
         so the second factor would lock them out: {named} (checked as a login from \
         {probe_address} and from {ELSEWHERE_PROBE_ADDRESS}, an address no Match block \
         names). Give each a key and a password, keep it on its key with a Match block \
         that is not tied to one address, or accept the loss with \
         [ssh.exceptions.\"{LOCKOUT_EXCEPTION_KEY}\"] value = \"{named}\""
    ))
}

/// What one account's login from one address comes to under the candidate.
enum Outcome {
    /// It gets in as it does without the second factor, or on its key alone.
    KeepsAWayIn,
    /// It gets in on its key and its password.
    Asked,
    /// It had a way in without the second factor, and has none with it.
    Stranded,
}

/// One account's login from one address, read from both staged candidates.
struct Probe<'a> {
    executor: &'a dyn SystemExecutor,
    staged: &'a str,
    baseline: &'a str,
    account: &'a Account,
    keyed: bool,
    address: &'a str,
}

impl Probe<'_> {
    /// Reads the login under the candidate, and under the apply without the
    /// second factor where the answer depends on it.
    async fn judge(&self, pam_checked: &mut BTreeSet<String>) -> Result<Outcome, String> {
        let name = self.account.name.as_str();
        let uid = self.account.uid;
        let after = sshd_dump(self.executor, self.staged, Some((name, self.address))).await?;
        // Root under `PermitRootLogin no` has no SSH login to lose.
        if uid == 0 && after.permit_root_login.eq_ignore_ascii_case("no") {
            return Ok(Outcome::KeepsAWayIn);
        }
        // A `Match` block may hand this account a PAM service of its own.
        if let Some(reason) = pam_refusal(self.executor, &after, pam_checked).await {
            return Err(format!(
                "{reason}; that is the PAM service sshd uses for {name}"
            ));
        }
        let alone_after = password_alone(&after, uid);
        let alone_before = if alone_after || !self.keyed {
            let before =
                sshd_dump(self.executor, self.baseline, Some((name, self.address))).await?;
            password_alone(&before, uid)
        } else {
            false
        };
        if alone_after && !alone_before {
            return Err(format!(
                "with the second factor on, {name} could log in from {} with the password \
                 alone: a Match block that applies to it has a list of password methods only, \
                 or `any`, which sshd dropped while keyboard-interactive was off. Put \
                 publickey first in that list, or set KbdInteractiveAuthentication no inside \
                 the block",
                self.address
            ));
        }
        let password_still_does = alone_after && self.account.usable_password;
        if !self.keyed {
            // Without a key file the account got in, if at all, on its
            // password alone.
            return Ok(
                if !(alone_before && self.account.usable_password) || password_still_does {
                    Outcome::KeepsAWayIn
                } else {
                    Outcome::Stranded
                },
            );
        }
        Ok(if key_gets_in(&after, uid) || password_still_does {
            Outcome::KeepsAWayIn
        } else if password_gets_in(&after, self.account) {
            Outcome::Asked
        } else {
            Outcome::Stranded
        })
    }
}

/// The `Match` blocks in the files that would let a password alone finish a
/// login once the second factor is on, as a refusal, or `None` where there is
/// none.
///
/// The opt-in switches keyboard-interactive on for every connection. A block
/// whose own `AuthenticationMethods` has a list of password methods only, or
/// `any`, named a switched-off method until then, and sshd dropped the list;
/// with the opt-in it is a login on the password alone. Measured with OpenSSH
/// 9.6p1: `Match Address 10.0.0.0/8` with `AuthenticationMethods publickey
/// keyboard-interactive` gave a client from 10.1.2.3
/// `kbdinteractiveauthentication yes` and that list once the fragment was in
/// place, and `sshd -t` passed. A block that switches keyboard-interactive
/// off itself keeps the list inert, and is left alone. The per-account probes
/// catch the same thing where a probe falls inside the block; this reaches the
/// addresses and users no probe names.
pub(super) fn match_refusal(resolved: &ResolvedConfig) -> Option<String> {
    let openings: Vec<String> = resolved
        .match_blocks()
        .iter()
        .filter_map(|block| {
            let lists = block.arguments(auth_methods::AUTHENTICATION_METHODS)?;
            let switched_off = block
                .arguments(KBD_INTERACTIVE)
                .and_then(|arguments| arguments.first().copied())
                .is_some_and(|value| !value.eq_ignore_ascii_case("yes"));
            (!switched_off && auth_methods::finishes_alone(Some(&lists), "keyboard-interactive"))
                .then(|| {
                    format!(
                        "`Match {}` in {} (AuthenticationMethods {})",
                        block.criteria,
                        block.source,
                        lists.join(" ")
                    )
                })
        })
        .collect();
    (!openings.is_empty()).then(|| {
        format!(
            "with keyboard-interactive switched on for the second factor, these Match blocks \
             would let a password alone finish a login: {}. Put publickey first in each \
             list there, or set KbdInteractiveAuthentication no inside the block",
            openings.join("; ")
        )
    })
}

/// Why the candidate, as sshd will run it globally, does not deliver the
/// second factor the fragment asks for, or `None` where it does.
///
/// The fragment is read before every file a distribution ships, but not
/// before a line above the main file's `Include`, which sshd reads first and
/// which therefore wins, nor before a drop-in whose name sorts ahead of
/// `00-hardener.conf`.
///
/// A global `KbdInteractiveAuthentication no` is not among these: under a
/// list that asks for keyboard-interactive after the key, sshd itself refuses
/// such a candidate ("AuthenticationMethods cannot be satisfied"), so
/// `sshd -T` fails before this is reached, and [`explain_unsatisfiable`]
/// names the line instead.
pub(super) fn candidate_refusal(global: &Effective) -> Option<String> {
    let lists: Vec<&str> = global.methods.iter().map(String::as_str).collect();
    let before = format!(
        "because a line sshd reads before {} sets it: one above the main file's Include, \
         or one in a drop-in whose name sorts ahead of it",
        dropin::DROPIN_PATH
    );
    if !auth_methods::requires_key_then_password(Some(&lists)) {
        return Some(format!(
            "with this candidate sshd would still run with AuthenticationMethods {}, {before}",
            lists.join(" ")
        ));
    }
    match global.use_pam {
        None => Some(
            "this sshd prints no UsePAM setting, so it was built without PAM and the \
             prompt after the key has nothing to ask the account password with"
                .to_string(),
        ),
        Some(false) => Some(format!(
            "with this candidate sshd would run with UsePAM no, {before}. Without PAM the \
             prompt after the key cannot ask for the password, so every login would stop \
             there. Set UsePAM yes in that file"
        )),
        Some(true) => None,
    }
}

/// `reason`, with the line that switches keyboard-interactive off named,
/// where `reason` is sshd refusing the candidate's lists for it.
///
/// sshd says only that the method is disabled. The line responsible is the
/// first one outside this tool's fragment that sets the option, under any of
/// its names: a candidate whose fragment says `yes` fails only where that line
/// is read first and says otherwise.
pub(super) fn explain_unsatisfiable(reason: String, resolved: &ResolvedConfig) -> String {
    if !reason.contains("Disabled method \"keyboard-interactive\"") {
        return reason;
    }
    match resolved
        .effective_without(KBD_INTERACTIVE, dropin::DROPIN_PATH)
        .filter(|line| !line.value.eq_ignore_ascii_case("yes"))
    {
        Some(line) => format!(
            "{reason}. `{} {}` in {} is read before {} and switches keyboard-interactive off; \
             change it to yes there, or remove it",
            line.keyword,
            line.value,
            line.source,
            dropin::DROPIN_PATH
        ),
        None => format!(
            "{reason}. A line sshd reads before {} switches keyboard-interactive off",
            dropin::DROPIN_PATH
        ),
    }
}

/// The settings the files set that let accounts in without a key file the
/// guard can read, sorted, as a preview reads them: the apply reads the same
/// switches from `sshd -T`, which a preview does not stage a candidate for.
/// Kerberos counts only where the keytab exists, or cannot be looked for.
pub(super) async fn unlisted_logins_in_files(
    executor: &dyn SystemExecutor,
    resolved: &ResolvedConfig,
) -> Vec<&'static str> {
    let set = |keyword: &str| {
        resolved
            .effective(keyword)
            .is_some_and(|effective| !effective.value.eq_ignore_ascii_case("none"))
    };
    let on = |keyword: &str| {
        resolved
            .effective(keyword)
            .is_some_and(|effective| effective.value.eq_ignore_ascii_case("yes"))
    };
    let mut unlisted: Vec<&'static str> = UNLISTED_KEY_SOURCES
        .iter()
        .map(|(_, setting)| *setting)
        .filter(|setting| set(setting))
        .collect();
    if on("HostbasedAuthentication") {
        unlisted.push("HostbasedAuthentication");
    }
    if on("GSSAPIAuthentication")
        && !matches!(
            executor.path_exists(Path::new(KERBEROS_KEYTAB)).await,
            Ok(false)
        )
    {
        unlisted.push("GSSAPIAuthentication");
    }
    unlisted.sort_unstable();
    unlisted
}

/// Whether a password, with no key, finishes a login under `effective`: some
/// list sshd keeps is made of password methods only, or is `any` with one of
/// them switched on. Root's password counts only under `PermitRootLogin yes`.
pub(super) fn password_alone(effective: &Effective, uid: u32) -> bool {
    if uid == 0 && effective.permit_root_login != "yes" {
        return false;
    }
    usable_lists(effective).iter().any(|list| {
        if *list == "any" {
            return auth_methods::PASSWORD_METHODS
                .iter()
                .any(|method| method_works(effective, method));
        }
        auth_methods::method_names(list)
            .iter()
            .all(|name| auth_methods::PASSWORD_METHODS.contains(name))
    })
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
