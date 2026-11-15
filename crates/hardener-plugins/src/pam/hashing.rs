//! How a password set on this host is stored: the algorithm, its cost, and a
//! count of stored hashes that still use an older scheme (#191).
//!
//! Three settings decide it, and they live in two places that disagree about
//! which one wins.
//!
//! - `ENCRYPT_METHOD` in `/etc/login.defs` is what shadow's own tools use
//!   (`chpasswd -c`, `chgpasswd`, `gpasswd`, and `chpasswd` and `newusers`
//!   outright on a shadow built without PAM, which RHEL 9's is; RHEL 10's is
//!   built with it). shadow compares it case-sensitively.
//! - `pam_unix` reads the same key as a **preset** and lets an algorithm named
//!   on its own `password` line override it (Linux-PAM `support.c`, "preset
//!   encryption method with value from /etc/login.defs"). It compares the key
//!   case-insensitively, by prefix. `passwd`, and `chpasswd` on a PAM build,
//!   hash through it.
//! - The cost travels separately: `rounds=` on the `pam_unix` line wins, then
//!   `YESCRYPT_COST_FACTOR` or `SHA_CRYPT_MAX_ROUNDS` from `login.defs`. Linux-PAM
//!   before 1.6.0 never reads `YESCRYPT_COST_FACTOR`, so on those hosts only
//!   `rounds=` raises the cost of a user's password.
//!
//! So the value judged here is the **weakest** of every path a new password can
//! take, and `apply` writes only `login.defs`. A `pam_unix` line that overrides
//! it is reported as a manual step, never edited, for the reason the rest of
//! this plugin gives: a malformed stack edit can lock everyone out.
//!
//! Choosing `YESCRYPT` is gated on positive evidence that every consumer on
//! the host understands it. shadow 4.9, which RHEL 9 ships built without yescrypt,
//! answers an unknown `ENCRYPT_METHOD` with "Defaulting to DES", and pam_unix
//! refuses a password change outright when the crypto library lacks the
//! algorithm. A host that cannot confirm yescrypt, or that runs in FIPS mode,
//! is held to SHA-512 with enough rounds instead.
//!
//! Scan, apply and validate share one plan: the `login.defs` keys apply would
//! write, computed by [`Hashing::plan_writes`]. Whatever still falls short once
//! that plan is projected onto the file is, by construction, a stack line
//! `login.defs` cannot reach, so all three name the same manual steps.
//!
//! Existing hashes never change here. Each one carries its own algorithm and
//! cost, and is rewritten only when that password is next set, so the stored
//! hashes are counted, by scheme only, and reported for the operator to act on.

use super::parsing::apply_exact_directive;
use super::{
    ConfRead, PamConfigFile, PamDirective, read_conf_classified, unchecked_pam_directive,
    unreadable_issue, unreadable_reason,
};
use crate::strictness::Strictness;
use hardener_common::file_utils::{
    ConfigFormat, Duplicates, parse_config_value, set_config_directive,
};
use hardener_common::types::{FindingCategory, Severity};
use hardener_core::{
    Change, ChangeType, Context, PluginConfig,
    plugin::{Finding, UncheckedBlocker, UncheckedCheck, ValidationIssue},
};
use hardener_types::ExceptionOutcome;
use std::path::Path;
use tracing::{info, warn};

/// The algorithm key, and the exception key that excuses its finding.
pub(super) const ENCRYPT_METHOD: &str = "ENCRYPT_METHOD";
/// The yescrypt cost key, judged only where new passwords are yescrypt.
pub(super) const YESCRYPT_COST_FACTOR: &str = "YESCRYPT_COST_FACTOR";
/// The SHA-512 rounds key, judged only where new passwords are SHA-512.
pub(super) const SHA_CRYPT_MIN_ROUNDS: &str = "SHA_CRYPT_MIN_ROUNDS";
/// Written beside the minimum, because it is the only one `pam_unix` reads.
pub(super) const SHA_CRYPT_MAX_ROUNDS: &str = "SHA_CRYPT_MAX_ROUNDS";

/// The finding id for the stored-hash count, which has no directive behind it.
pub(super) const STORED_HASHES_ID: &str = "pam-stored-password-hashes";

/// The highest cost shadow, pam_unix and libxcrypt can all generate. libxcrypt
/// refuses 12 with `EINVAL`, shadow clamps to 11, and Linux-PAM before 1.6.0
/// resets anything above 11 to 5, so a larger override would be written and
/// then quietly ignored.
const YESCRYPT_COST_MAX: u64 = 11;
/// The cost every consumer uses when nothing names one.
const YESCRYPT_COST_DEFAULT: u64 = 5;
/// pam_unix caps SHA rounds just below ten million; shadow allows more, so the
/// pam cap is the one both agree on.
const SHA_ROUNDS_MAX: u64 = 9_999_999;
/// sha512crypt's own default, used wherever no setting names a number.
const SHA_ROUNDS_DEFAULT: u64 = 5000;

/// Weakest first. `BCRYPT` ranks below SHA-512 because bcrypt reads only the
/// first 72 bytes of a password, which is the wrong property for the long
/// passphrases this plugin's quality settings favour. `GOST_YESCRYPT` is
/// pam_unix's yescrypt variant and is the same strength.
const METHOD_ORDER: &[&[&str]] = &[
    &["DES"],
    &["MD5"],
    &["SHA256"],
    &["BCRYPT", "BLOWFISH"],
    &["SHA512"],
    &["YESCRYPT", "GOST_YESCRYPT"],
];

/// The three hashing settings, in the shape every other PAM directive takes so
/// coverage, unchecked entries and exceptions treat them alike.
///
/// Kept out of `PAM_DIRECTIVES` on purpose. The generic loop there judges a
/// `login.defs` key by its value in the file, which is wrong for all three:
/// the stack can override the algorithm, and which cost applies depends on the
/// algorithm and on the Linux-PAM release.
pub(super) const HASHING_DIRECTIVES: &[PamDirective] = &[
    PamDirective {
        pam_directive_name: ENCRYPT_METHOD,
        pam_secure_value: "YESCRYPT",
        pam_description: "Hash new passwords with yescrypt, or with SHA-512 where FIPS mode is on \
                          or this host cannot use yescrypt",
        pam_severity: Severity::High,
        pam_config_file: PamConfigFile::LoginDefs,
        pam_compare: Strictness::Ranked(METHOD_ORDER),
    },
    PamDirective {
        pam_directive_name: YESCRYPT_COST_FACTOR,
        pam_secure_value: "5",
        pam_description: "Hash yescrypt passwords at a cost of at least 5 (16 MiB and about 20 ms \
                          per password check)",
        pam_severity: Severity::Medium,
        pam_config_file: PamConfigFile::LoginDefs,
        pam_compare: Strictness::AtLeast,
    },
    PamDirective {
        pam_directive_name: SHA_CRYPT_MIN_ROUNDS,
        pam_secure_value: "100000",
        pam_description: "Hash SHA-512 passwords with at least 100000 rounds",
        pam_severity: Severity::Medium,
        pam_config_file: PamConfigFile::LoginDefs,
        pam_compare: Strictness::AtLeast,
    },
];

/// Whether `name` is one of the three settings above.
pub(super) fn is_hashing_directive(name: &str) -> bool {
    HASHING_DIRECTIVES
        .iter()
        .any(|d| d.pam_directive_name == name)
}

/// The table entry for `name`. Every caller passes one of the three
/// constants above, so the fallback to the first entry is never taken.
fn directive(name: &str) -> &'static PamDirective {
    HASHING_DIRECTIVES
        .iter()
        .find(|d| d.pam_directive_name == name)
        .unwrap_or(&HASHING_DIRECTIVES[0])
}

// ---------------------------------------------------------------------------
// The algorithm model
// ---------------------------------------------------------------------------

/// A password hashing scheme, ordered weakest first so `min` is the weakest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum HashMethod {
    Des,
    Md5,
    Sha256,
    Bcrypt,
    Sha512,
    Yescrypt,
}

impl HashMethod {
    /// The spelling shadow accepts in `login.defs`, which is the one this
    /// tool writes.
    pub(super) fn login_defs_name(self) -> &'static str {
        match self {
            HashMethod::Des => "DES",
            HashMethod::Md5 => "MD5",
            HashMethod::Sha256 => "SHA256",
            HashMethod::Bcrypt => "BCRYPT",
            HashMethod::Sha512 => "SHA512",
            HashMethod::Yescrypt => "YESCRYPT",
        }
    }

    /// The `pam_unix` argument that selects it.
    pub(super) fn pam_token(self) -> &'static str {
        match self {
            HashMethod::Des => "bigcrypt",
            HashMethod::Md5 => "md5",
            HashMethod::Sha256 => "sha256",
            HashMethod::Bcrypt => "blowfish",
            HashMethod::Sha512 => "sha512",
            HashMethod::Yescrypt => "yescrypt",
        }
    }

    /// `ENCRYPT_METHOD` as shadow reads it: exact and case-sensitive, because
    /// shadow compares with `streq`. A lowercase `yescrypt` is not a value
    /// shadow knows, and shadow then falls back to SHA-512, or to DES on
    /// releases as recent as 4.9.
    pub(super) fn from_login_defs(value: &str) -> Option<HashMethod> {
        match value {
            "DES" => Some(HashMethod::Des),
            "MD5" => Some(HashMethod::Md5),
            "SHA256" => Some(HashMethod::Sha256),
            "BCRYPT" => Some(HashMethod::Bcrypt),
            "SHA512" => Some(HashMethod::Sha512),
            "YESCRYPT" => Some(HashMethod::Yescrypt),
            _ => None,
        }
    }

    /// A scheme by the name the host probe gives a stored hash. Anything the
    /// probe could not name ranks with DES, the weakest.
    pub(super) fn from_stored_scheme(scheme: &str) -> HashMethod {
        match scheme {
            "yescrypt" | "gost-yescrypt" | "scrypt" => HashMethod::Yescrypt,
            "sha512" => HashMethod::Sha512,
            "bcrypt" => HashMethod::Bcrypt,
            "sha256" => HashMethod::Sha256,
            "md5" => HashMethod::Md5,
            _ => HashMethod::Des,
        }
    }
}

/// The hash-algorithm arguments `pam_unix` knows, in the order its argument
/// table lists them, because it takes the first entry that matches as a prefix.
const PAM_HASH_TOKENS: &[(&str, HashMethod)] = &[
    ("md5", HashMethod::Md5),
    ("bigcrypt", HashMethod::Des),
    ("sha256", HashMethod::Sha256),
    ("sha512", HashMethod::Sha512),
    ("blowfish", HashMethod::Bcrypt),
    ("gost_yescrypt", HashMethod::Yescrypt),
    ("yescrypt", HashMethod::Yescrypt),
];

/// The algorithm a `pam_unix` argument selects, if it selects one.
///
/// Prefix matching, because that is how `pam_unix` matches its arguments
/// (`pam_str_skip_prefix_len`), and case-sensitive like it.
fn pam_arg_method(arg: &str) -> Option<HashMethod> {
    PAM_HASH_TOKENS
        .iter()
        .find(|(token, _)| arg.starts_with(token))
        .map(|(_, method)| *method)
}

/// `ENCRYPT_METHOD` as `pam_unix` reads it: case-insensitive and by prefix
/// (`strncasecmp` against each token's length). `DES` and `BCRYPT` name no
/// `pam_unix` token, so it ignores them and keeps its built-in default.
pub(super) fn pam_login_defs_method(value: &str) -> Option<HashMethod> {
    PAM_HASH_TOKENS
        .iter()
        .find(|(token, _)| {
            value
                .get(..token.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(token))
        })
        .map(|(_, method)| *method)
}

// ---------------------------------------------------------------------------
// The PAM stack
// ---------------------------------------------------------------------------

/// The stack files that can carry the `pam_unix` line new passwords go
/// through. The shared files the distributions use, plus the two services that
/// set passwords, which may carry a line of their own rather than include one.
pub(super) const HASHING_STACK_FILES: &[&str] = &[
    "/etc/pam.d/common-password",
    "/etc/pam.d/system-auth",
    "/etc/pam.d/password-auth",
    "/etc/pam.d/passwd",
    "/etc/pam.d/chpasswd",
];

/// One `password` line loading `pam_unix.so`, reduced to what decides hashing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PamUnixLine {
    /// The stack file it was read from.
    pub(super) file: &'static str,
    /// The algorithm the line names itself. The last one wins, as in
    /// `pam_unix`, whose argument table masks the previous choice off.
    pub(super) method: Option<HashMethod>,
    /// `rounds=` as written, also last one wins.
    pub(super) rounds: Option<String>,
}

/// The configuration lines of a stack file, assembled the way Linux-PAM does
/// (`libpam_internal/pam_line.c`): `#` ends a line wherever it appears, and a
/// trailing backslash joins the next line unless the line holds a comment.
fn logical_pam_lines(content: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut pending = String::new();
    for raw in content.lines() {
        let has_comment = raw.contains('#');
        let body = raw.split('#').next().unwrap_or_default();
        if !has_comment && let Some(head) = body.trim_end().strip_suffix('\\') {
            pending.push_str(head);
            pending.push(' ');
            continue;
        }
        pending.push_str(body);
        lines.push(std::mem::take(&mut pending));
    }
    if !pending.trim().is_empty() {
        lines.push(pending);
    }
    lines
}

/// Every `password` line in `content` that loads `pam_unix.so`.
///
/// The type is compared case-insensitively and may carry the `-` that tells
/// Linux-PAM to skip a missing module. A bracketed control field may hold
/// spaces (`[success=1 default=ignore]`), so it is consumed up to its closing
/// bracket before the module path is read.
pub(super) fn pam_unix_password_lines(file: &'static str, content: &str) -> Vec<PamUnixLine> {
    let mut found = Vec::new();
    for line in logical_pam_lines(content) {
        let mut tokens = line.split_whitespace();
        let Some(kind) = tokens.next() else {
            continue;
        };
        if !kind
            .trim_start_matches('-')
            .eq_ignore_ascii_case("password")
        {
            continue;
        }
        let Some(control) = tokens.next() else {
            continue;
        };
        if control.starts_with('[') && !control.ends_with(']') {
            for token in tokens.by_ref() {
                if token.ends_with(']') {
                    break;
                }
            }
        }
        let Some(module) = tokens.next() else {
            continue;
        };
        if module.rsplit('/').next() != Some("pam_unix.so") {
            continue;
        }
        let mut parsed = PamUnixLine {
            file,
            method: None,
            rounds: None,
        };
        for arg in tokens {
            if let Some(rounds) = arg.strip_prefix("rounds=") {
                parsed.rounds = Some(rounds.to_string());
            } else if let Some(method) = pam_arg_method(arg) {
                parsed.method = Some(method);
            }
        }
        found.push(parsed);
    }
    found
}

// ---------------------------------------------------------------------------
// What the host can do: one probe, one round trip
// ---------------------------------------------------------------------------

/// A yes, a no, or a probe that could not tell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Tri {
    Yes,
    No,
    Unknown,
}

impl Tri {
    fn parse(value: &str) -> Tri {
        match value {
            "yes" => Tri::Yes,
            "no" => Tri::No,
            _ => Tri::Unknown,
        }
    }
}

/// How the stored hashes divide by scheme, or why they could not be counted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum StoredHashes {
    /// One scheme name per account that holds a usable hash.
    Schemes(Vec<String>),
    /// `/etc/shadow` exists and this run may not read it.
    Denied,
    /// No `/etc/shadow` at all.
    Absent,
    /// The probe did not run or said something unexpected.
    Unknown(String),
}

/// What the host's software can do, asked of the target in one script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct HostProbe {
    /// `pam_unix.so` knows the `yescrypt` argument.
    pub(super) pam_unix_yescrypt: Tri,
    /// The libcrypt `pam_unix.so` links against implements `$y$`.
    pub(super) libcrypt_yescrypt: Tri,
    /// shadow was built with yescrypt (`chpasswd --help` lists it).
    pub(super) shadow_yescrypt: Tri,
    /// `pam_unix` reads `YESCRYPT_COST_FACTOR` (Linux-PAM 1.6.0 and later).
    pub(super) pam_reads_cost_factor: Tri,
    /// The kernel is in FIPS mode.
    pub(super) fips: Tri,
    /// The stored hashes, by scheme only.
    pub(super) stored: StoredHashes,
}

impl HostProbe {
    /// What a probe that could not run at all knows: nothing.
    pub(super) fn unknown(reason: String) -> HostProbe {
        HostProbe {
            pam_unix_yescrypt: Tri::Unknown,
            libcrypt_yescrypt: Tri::Unknown,
            shadow_yescrypt: Tri::Unknown,
            pam_reads_cost_factor: Tri::Unknown,
            fips: Tri::Unknown,
            stored: StoredHashes::Unknown(reason),
        }
    }

    /// Yes only if pam_unix, libcrypt and shadow all said yes; no if any said
    /// no. This is the gate on ever writing `YESCRYPT`.
    pub(super) fn yescrypt(&self) -> Tri {
        let parts = [
            self.pam_unix_yescrypt,
            self.libcrypt_yescrypt,
            self.shadow_yescrypt,
        ];
        if parts.contains(&Tri::No) {
            Tri::No
        } else if parts.iter().all(|part| *part == Tri::Yes) {
            Tri::Yes
        } else {
            Tri::Unknown
        }
    }
}

/// The probe, run with `sh -c` so it is one round trip over SSH and needs
/// nothing a minimal install lacks.
///
/// - The library questions are asked of the binaries, the way #69 asks
///   `chage --help`: whether `pam_unix.so` carries the `yescrypt` argument and
///   reads `YESCRYPT_COST_FACTOR`, and whether the libcrypt it links against
///   carries the `$y$` prefix. Each string is in the binary exactly when the
///   feature was compiled in. Measured on 2026-11-15: PAM 1.5.3 (Ubuntu
///   24.04) has no `YESCRYPT_COST_FACTOR`, PAM 1.7.0 (Ubuntu 26.04) has it.
/// - Which libcrypt that is, is read off `pam_unix.so` itself: the soname it
///   names. libxcrypt is `libcrypt.so.2` when built without the glibc
///   compatibility API, which is how Fedora, RHEL 9 and 10 and Arch ship it,
///   with `libcrypt.so.1` only in an optional compat package; Debian, Ubuntu
///   and openSUSE ship `libcrypt.so.1`. Where no `pam_unix.so` names one,
///   both sonames are searched.
/// - shadow is asked through `chpasswd --help`, whose `--crypt-method` line
///   lists the methods the build supports. Only that line counts: the
///   `--sha-rounds` line names YESCRYPT whatever the build.
/// - FIPS mode is `/proc/sys/crypto/fips_enabled`; no file means no FIPS.
/// - `/etc/shadow` (the first argument, so a test can name a fixture) is
///   read inside the target's own shell and only a scheme name per account
///   leaves it. **No hash, salt or user name is ever
///   printed**, so none can reach this process, a log or a report.
/// - The second argument, empty on a real host, is a directory the library
///   and `/proc` paths are read under, so a test can lay out another
///   distribution's files. `chpasswd` is always the one on `PATH`.
pub(super) const HOST_PROBE_SCRIPT: &str = r#"PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH
LC_ALL=C
export PATH LC_ALL
root=${2:-}
found() {
    needle=$1
    shift
    seen=no
    for f in "$@"; do
        [ -f "$f" ] || continue
        grep -q -a -F -e "$needle" "$f" 2>/dev/null
        case $? in
            0) echo yes; return ;;
            1) seen=yes ;;
        esac
    done
    if [ "$seen" = yes ]; then echo no; else echo unknown; fi
}
pams="$root/usr/lib64/security/pam_unix.so $root/lib64/security/pam_unix.so $root/usr/lib/security/pam_unix.so $root/lib/security/pam_unix.so $(echo $root/usr/lib/*/security/pam_unix.so $root/lib/*/security/pam_unix.so)"
soname=
for p in $pams; do
    [ -f "$p" ] || continue
    soname=$(grep -a -o -e 'libcrypt\.so\.[0-9][0-9]*' "$p" 2>/dev/null | head -n 1)
    [ -n "$soname" ] && break
done
if [ -n "$soname" ]; then
    libs="$root/usr/lib64/$soname $root/lib64/$soname $root/usr/lib/$soname $root/lib/$soname $(echo $root/usr/lib/*/$soname $root/lib/*/$soname)"
else
    libs=$(echo $root/usr/lib64/libcrypt.so.[12] $root/lib64/libcrypt.so.[12] $root/usr/lib/libcrypt.so.[12] $root/lib/libcrypt.so.[12] $root/usr/lib/*/libcrypt.so.[12] $root/lib/*/libcrypt.so.[12])
fi
echo "pam_unix_yescrypt=$(found yescrypt $pams)"
echo "pam_unix_cost_factor=$(found YESCRYPT_COST_FACTOR $pams)"
echo "libcrypt_yescrypt=$(found '$y$' $libs)"
line=$(chpasswd --help 2>&1 | grep -e '--crypt-method')
case $line in
    '') echo shadow_yescrypt=unknown ;;
    *YESCRYPT*) echo shadow_yescrypt=yes ;;
    *) echo shadow_yescrypt=no ;;
esac
fips=$(cat "$root/proc/sys/crypto/fips_enabled" 2>/dev/null)
if [ ! -e "$root/proc/sys/crypto/fips_enabled" ]; then
    echo fips=no
elif [ "$fips" = 1 ]; then
    echo fips=yes
elif [ "$fips" = 0 ]; then
    echo fips=no
else
    echo fips=unknown
fi
shadow=${1:-/etc/shadow}
if [ ! -e "$shadow" ]; then
    echo shadow=absent
elif [ ! -r "$shadow" ]; then
    echo shadow=denied
else
    echo shadow=read
    while IFS=: read -r _ field _ || [ -n "$field" ]; do
        case $field in
            ''|'!'*|'*'*) ;;
            '$y$'*) echo scheme=yescrypt ;;
            '$gy$'*) echo scheme=gost-yescrypt ;;
            '$7$'*) echo scheme=scrypt ;;
            '$2a$'*|'$2b$'*|'$2x$'*|'$2y$'*) echo scheme=bcrypt ;;
            '$6$'*) echo scheme=sha512 ;;
            '$5$'*) echo scheme=sha256 ;;
            '$1$'*) echo scheme=md5 ;;
            '$'*) echo scheme=other ;;
            *) echo scheme=des ;;
        esac
        field=
    done < "$shadow"
fi
echo end=1"#;

/// Reads the probe's output. Pure, so every shape a host can print is a test.
///
/// Fails closed: a missing `end` line means the script did not finish, and
/// then the stored hashes are unknown however much was printed before.
pub(super) fn parse_host_probe(stdout: &str) -> HostProbe {
    let mut probe = HostProbe::unknown(String::new());
    let mut shadow_state = None;
    let mut schemes = Vec::new();
    let mut finished = false;
    for line in stdout.lines() {
        let Some((key, value)) = line.trim().split_once('=') else {
            continue;
        };
        match key {
            "pam_unix_yescrypt" => probe.pam_unix_yescrypt = Tri::parse(value),
            "libcrypt_yescrypt" => probe.libcrypt_yescrypt = Tri::parse(value),
            "shadow_yescrypt" => probe.shadow_yescrypt = Tri::parse(value),
            "pam_unix_cost_factor" => probe.pam_reads_cost_factor = Tri::parse(value),
            "fips" => probe.fips = Tri::parse(value),
            "shadow" => shadow_state = Some(value.to_string()),
            "scheme" => schemes.push(value.to_string()),
            "end" => finished = true,
            _ => {}
        }
    }
    probe.stored = match (finished, shadow_state.as_deref()) {
        (false, _) => StoredHashes::Unknown("the host probe did not finish".to_string()),
        (true, Some("read")) => StoredHashes::Schemes(schemes),
        (true, Some("denied")) => StoredHashes::Denied,
        (true, Some("absent")) => StoredHashes::Absent,
        (true, _) => {
            StoredHashes::Unknown("the host probe gave no answer about /etc/shadow".to_string())
        }
    };
    probe
}

async fn probe_host(ctx: &Context) -> HostProbe {
    match ctx
        .executor()
        .execute_command("sh", &["-c", HOST_PROBE_SCRIPT, "sh", "/etc/shadow"])
        .await
    {
        Ok(output) => parse_host_probe(&output.stdout),
        Err(e) => {
            warn!("Could not probe password hashing support: {}", e);
            HostProbe::unknown(format!("the host probe could not be run: {e}"))
        }
    }
}

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------

/// The algorithm this host is held to, and why when it is not yescrypt.
///
/// yescrypt where the host confirms it and is not in FIPS mode; SHA-512
/// otherwise. A `[pam.directives] ENCRYPT_METHOD` override may tighten that,
/// which is how an operator chooses yescrypt on a FIPS host, but nothing can
/// raise it to yescrypt on a host that has not confirmed it can use it.
pub(super) fn method_target(config: &PluginConfig, probe: &HostProbe) -> (HashMethod, String) {
    let (baseline, why) = match (probe.yescrypt(), probe.fips) {
        (Tri::Yes, Tri::No) => (HashMethod::Yescrypt, String::new()),
        (Tri::Yes, _) => (
            HashMethod::Sha512,
            "FIPS mode is on, or could not be ruled out, and yescrypt is not a FIPS-approved \
             algorithm"
                .to_string(),
        ),
        (Tri::No, _) => (
            HashMethod::Sha512,
            "this host's shadow, pam_unix or libcrypt does not support yescrypt".to_string(),
        ),
        (Tri::Unknown, _) => (
            HashMethod::Sha512,
            "whether this host's shadow, pam_unix and libcrypt all support yescrypt could not \
             be confirmed"
                .to_string(),
        ),
    };
    let resolved = directive(ENCRYPT_METHOD).pam_compare.resolved_target(
        config,
        ENCRYPT_METHOD,
        baseline.login_defs_name(),
    );
    let mut target = HashMethod::from_login_defs(&resolved)
        .or_else(|| pam_login_defs_method(&resolved))
        .unwrap_or(baseline);
    if target == HashMethod::Yescrypt && probe.yescrypt() != Tri::Yes {
        info!("Not raising ENCRYPT_METHOD to YESCRYPT: {}", why);
        target = HashMethod::Sha512;
    }
    (target, why)
}

/// The cost target for `name`, override-clamped and capped where the tools
/// stop honouring it.
fn cost_target(config: &PluginConfig, name: &str, cap: u64) -> u64 {
    let d = directive(name);
    d.pam_compare
        .resolved_target(config, name, d.pam_secure_value)
        .parse::<u64>()
        .unwrap_or(0)
        .min(cap)
}

// ---------------------------------------------------------------------------
// Readings: pure functions of login.defs, the stack and the probe
// ---------------------------------------------------------------------------

fn login_defs_value(login_defs: &str, key: &str) -> Option<String> {
    parse_config_value(login_defs, key, ConfigFormat::SpaceSeparated, true)
}

/// `ENCRYPT_METHOD` as shadow on this host takes it: the spelling must be
/// exact, and `YESCRYPT` counts only where shadow was not shown to lack it.
fn shadow_method(value: &str, probe: &HostProbe) -> Option<HashMethod> {
    HashMethod::from_login_defs(value)
        .filter(|m| *m != HashMethod::Yescrypt || probe.shadow_yescrypt != Tri::No)
}

/// A yescrypt choice counts on a `pam_unix` path only where pam_unix and
/// libcrypt were not shown to lack it: pam_unix refuses the password change
/// outright when the crypto library cannot make the hash.
fn pam_method(method: Option<HashMethod>, probe: &HostProbe) -> Option<HashMethod> {
    method.filter(|m| {
        *m != HashMethod::Yescrypt
            || (probe.pam_unix_yescrypt != Tri::No && probe.libcrypt_yescrypt != Tri::No)
    })
}

/// The algorithm new passwords get, by the weakest path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct MethodReading {
    /// `None` when any path is unset or holds a value its reader rejects.
    pub(super) weakest: Option<HashMethod>,
    /// What the report shows and an exception documents.
    pub(super) display: String,
    /// One plain sentence per path that falls short, for the finding.
    pub(super) notes: Vec<String>,
}

/// The algorithm on every path a new password can take, and the weakest.
pub(super) fn read_method(
    login_defs: &str,
    stack: &[PamUnixLine],
    probe: &HostProbe,
) -> MethodReading {
    let raw = login_defs_value(login_defs, ENCRYPT_METHOD);
    let shadow_view = raw.as_deref().and_then(|v| shadow_method(v, probe));
    let pam_view = pam_method(raw.as_deref().and_then(pam_login_defs_method), probe);
    let mut notes = Vec::new();
    match (&raw, shadow_view) {
        (None, _) => notes.push(
            "/etc/login.defs sets no ENCRYPT_METHOD, so shadow's tools use their built-in \
             default, which is DES on older releases"
                .to_string(),
        ),
        (Some(value), None) if HashMethod::from_login_defs(value).is_some() => notes.push(format!(
            "/etc/login.defs sets ENCRYPT_METHOD to '{value}', which this host's shadow \
                 was built without, so its tools fall back to SHA512 or, on older releases, DES"
        )),
        (Some(value), None) => notes.push(format!(
            "/etc/login.defs sets ENCRYPT_METHOD to '{value}', which shadow does not accept \
             (it compares case-sensitively), so its tools fall back to a default"
        )),
        _ => {}
    }
    let mut paths = vec![shadow_view];
    for line in stack {
        let method = if line.method.is_some() {
            pam_method(line.method, probe)
        } else {
            pam_view
        };
        match (line.method, method) {
            (Some(named), None) => notes.push(format!(
                "{} names {} on its pam_unix line, which this host's pam_unix or libcrypt \
                 cannot make, so password changes through it fail",
                line.file,
                named.pam_token()
            )),
            (Some(named), Some(_)) if shadow_view.is_none_or(|s| named < s) => notes.push(format!(
                "{} names {} on its pam_unix line, which overrides /etc/login.defs for \
                     every password set through it",
                line.file,
                named.pam_token()
            )),
            (None, None) => notes.push(format!(
                "{} names no algorithm on its pam_unix line and /etc/login.defs gives it none it \
                 can use, so pam_unix uses its built-in default, which is DES before Linux-PAM \
                 1.7.3",
                line.file
            )),
            _ => {}
        }
        paths.push(method);
    }
    // Where login.defs is the only weak path, say so: on stock Ubuntu 24.04 a
    // user's password is already yescrypt and only shadow's own tools are not,
    // which "new passwords are SHA512" alone would misstate.
    let stack_paths = &paths[1..];
    if let Some(shadow) = shadow_view
        && !stack_paths.is_empty()
        && stack_paths.iter().all(|m| m.is_some_and(|m| m > shadow))
        && let Some(stack_weakest) = stack_paths.iter().flatten().min()
    {
        notes.push(format!(
            "/etc/login.defs ENCRYPT_METHOD {} is what shadow's own tools use (chpasswd -c, \
             gpasswd and chgpasswd, and chpasswd and newusers on a shadow built without PAM); \
             passwords set through pam_unix, as passwd sets them, already get {} from the PAM \
             stack",
            shadow.login_defs_name(),
            stack_weakest.pam_token()
        ));
    }
    let weakest = if paths.iter().any(Option::is_none) {
        None
    } else {
        paths.into_iter().flatten().min()
    };
    let display = match (weakest, raw) {
        (Some(method), _) => method.login_defs_name().to_string(),
        (None, Some(value)) => value,
        (None, None) => "not set".to_string(),
    };
    MethodReading {
        weakest,
        display,
        notes,
    }
}

/// A cost on every path, and the lowest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CostReading {
    /// `None` when a value could not be read as a number.
    pub(super) lowest: Option<u64>,
    /// The highest cost any path may use, over the paths that could be read.
    /// What a password check can be made to spend, where `lowest` is what an
    /// attacker with the hash can count on.
    pub(super) highest: Option<u64>,
    pub(super) display: String,
    /// Stack lines whose cost is below the target, each with the reason.
    pub(super) stack_shortfalls: Vec<String>,
}

fn lowest_of(paths: &[Option<u64>]) -> Option<u64> {
    if paths.iter().any(Option::is_none) {
        None
    } else {
        paths.iter().flatten().min().copied()
    }
}

fn display_cost(lowest: Option<u64>) -> String {
    lowest.map_or_else(|| "not a number".to_string(), |n| n.to_string())
}

/// The release-specific answer as `(lowest, highest)`: both the same where
/// the Linux-PAM release is known, and the two answers where it could not be
/// told apart.
fn release_range(reads_cost_factor: Tri, new: u64, old: u64) -> (u64, u64) {
    match reads_cost_factor {
        Tri::Yes => (new, new),
        Tri::No => (old, old),
        Tri::Unknown => (new.min(old), new.max(old)),
    }
}

/// Picks the release-specific answer, or the lower of the two where the
/// Linux-PAM release could not be told apart.
fn by_release(reads_cost_factor: Tri, new: u64, old: u64) -> u64 {
    release_range(reads_cost_factor, new, old).0
}

/// The yescrypt cost each path gets.
///
/// `rounds=` wins on a `pam_unix` line. Without it, Linux-PAM 1.6.0 and later
/// read `YESCRYPT_COST_FACTOR` and clamp it to 3..11; older releases use 5.
/// The two releases also treat an out-of-range `rounds=` differently: 1.6.0
/// clamps it, 1.5.x resets it to 5. shadow clamps the factor to 1..11.
pub(super) fn read_yescrypt_cost(
    login_defs: &str,
    stack: &[PamUnixLine],
    probe: &HostProbe,
    target: u64,
) -> CostReading {
    let factor =
        login_defs_value(login_defs, YESCRYPT_COST_FACTOR).map(|v| v.trim().parse::<i64>().ok());
    let shadow_cost = match factor {
        None => Some(YESCRYPT_COST_DEFAULT),
        Some(Some(n)) => Some(n.clamp(1, YESCRYPT_COST_MAX as i64) as u64),
        Some(None) => None,
    };
    let clamp_new = |n: i64| n.clamp(3, YESCRYPT_COST_MAX as i64) as u64;
    let reset_old = |n: i64| {
        if (3..=YESCRYPT_COST_MAX as i64).contains(&n) {
            n as u64
        } else {
            YESCRYPT_COST_DEFAULT
        }
    };
    // An invalid factor is logged and ignored by pam_unix 1.6.0 and later.
    let from_factor = match factor {
        Some(Some(n)) => clamp_new(n),
        _ => YESCRYPT_COST_DEFAULT,
    };
    let reads = probe.pam_reads_cost_factor;
    let mut paths = vec![shadow_cost];
    let mut highest = shadow_cost;
    let mut stack_shortfalls = Vec::new();
    for line in stack {
        if line.method.is_some_and(|m| m != HashMethod::Yescrypt) {
            continue;
        }
        let range = match &line.rounds {
            Some(raw) => raw
                .trim()
                .parse::<i64>()
                .ok()
                .map(|n| release_range(reads, clamp_new(n), reset_old(n))),
            None => Some(release_range(reads, from_factor, YESCRYPT_COST_DEFAULT)),
        };
        let cost = range.map(|(low, _)| low);
        if let Some((_, high)) = range {
            highest = Some(highest.map_or(high, |h| h.max(high)));
        }
        if cost.is_none_or(|c| c < target) {
            let why = match (&line.rounds, reads) {
                (Some(raw), _) => format!("sets rounds={raw} on its pam_unix line"),
                (None, Tri::No) => "is read by a Linux-PAM older than 1.6.0, which ignores \
                                    YESCRYPT_COST_FACTOR, so only rounds= on its pam_unix line \
                                    raises the cost"
                    .to_string(),
                (None, _) => "may be read by a Linux-PAM older than 1.6.0, which ignores \
                              YESCRYPT_COST_FACTOR, so only rounds= on its pam_unix line is \
                              sure to raise the cost"
                    .to_string(),
            };
            stack_shortfalls.push(format!("{} {}", line.file, why));
        }
        paths.push(cost);
    }
    let lowest = lowest_of(&paths);
    CostReading {
        lowest,
        highest,
        display: display_cost(lowest),
        stack_shortfalls,
    }
}

/// pam_unix's treatment of a SHA rounds value: below 1000 means its default,
/// at or above ten million is capped.
fn pam_sha_rounds(n: i64) -> u64 {
    if n < 1000 {
        SHA_ROUNDS_DEFAULT
    } else {
        (n as u64).min(SHA_ROUNDS_MAX)
    }
}

/// The SHA-512 rounds each path gets.
///
/// shadow picks between `SHA_CRYPT_MIN_ROUNDS` and `SHA_CRYPT_MAX_ROUNDS`, each
/// standing in for the other when only one is set, so the minimum is what it
/// may use. pam_unix reads `SHA_CRYPT_MAX_ROUNDS` only, and Linux-PAM 1.5.x
/// reads it only while `ENCRYPT_METHOD` itself names a SHA method.
pub(super) fn read_sha_rounds(
    login_defs: &str,
    stack: &[PamUnixLine],
    probe: &HostProbe,
    target: u64,
) -> CostReading {
    let number =
        |key: &str| login_defs_value(login_defs, key).map(|v| v.trim().parse::<i64>().ok());
    let min = number(SHA_CRYPT_MIN_ROUNDS);
    let max = number(SHA_CRYPT_MAX_ROUNDS);
    let shadow_rounds = match (min, max) {
        (Some(None), _) | (_, Some(None)) => None,
        (None, None) => Some(SHA_ROUNDS_DEFAULT),
        (Some(Some(lowest)), _) | (None, Some(Some(lowest))) => {
            Some(lowest.clamp(1000, 999_999_999) as u64)
        }
    };
    let sha_preset = login_defs_value(login_defs, ENCRYPT_METHOD)
        .as_deref()
        .and_then(pam_login_defs_method)
        .is_some_and(|m| matches!(m, HashMethod::Sha256 | HashMethod::Sha512));
    let from_max = match max {
        Some(Some(n)) => pam_sha_rounds(n),
        _ => SHA_ROUNDS_DEFAULT,
    };
    let reads = if sha_preset {
        Tri::Yes
    } else {
        probe.pam_reads_cost_factor
    };
    let mut paths = vec![shadow_rounds];
    let mut stack_shortfalls = Vec::new();
    for line in stack {
        if line
            .method
            .is_some_and(|m| !matches!(m, HashMethod::Sha256 | HashMethod::Sha512))
        {
            continue;
        }
        let rounds = match &line.rounds {
            Some(raw) => raw.trim().parse::<i64>().ok().map(pam_sha_rounds),
            None => Some(by_release(reads, from_max, SHA_ROUNDS_DEFAULT)),
        };
        if rounds.is_none_or(|r| r < target) {
            let why = match &line.rounds {
                Some(raw) => format!("sets rounds={raw} on its pam_unix line"),
                None => "is read by a pam_unix that may take SHA_CRYPT_MAX_ROUNDS from \
                         /etc/login.defs only while ENCRYPT_METHOD there names a SHA method \
                         (Linux-PAM before 1.6.0), so only rounds= on its pam_unix line is sure \
                         to raise the rounds"
                    .to_string(),
            };
            stack_shortfalls.push(format!("{} {}", line.file, why));
        }
        paths.push(rounds);
    }
    let lowest = lowest_of(&paths);
    CostReading {
        lowest,
        highest: paths.iter().flatten().max().copied(),
        display: display_cost(lowest),
        stack_shortfalls,
    }
}

// ---------------------------------------------------------------------------
// The shared plan
// ---------------------------------------------------------------------------

/// Everything the three entry points share, read once per run.
pub(super) struct Hashing {
    pub(super) login_defs: String,
    pub(super) stack: Vec<PamUnixLine>,
    pub(super) probe: HostProbe,
    pub(super) target: HashMethod,
    pub(super) why_not_yescrypt: String,
    pub(super) method: MethodReading,
    pub(super) method_excepted: bool,
    /// The `ENCRYPT_METHOD` apply writes, if it writes one.
    pub(super) method_write: Option<HashMethod>,
    pub(super) cost_method: HashMethod,
    /// `MemTotal` in KiB, or why it could not be read. Read once, so the
    /// memory guard is part of the plan all three entry points share.
    pub(super) mem_total_kib: Result<u64, String>,
}

/// Which cost applies: the one of the algorithm new passwords will use once
/// this plugin has done its part, so `reading` is taken on the file as the
/// `ENCRYPT_METHOD` write leaves it. That is the target, unless the host keeps
/// something stronger (kept, never lowered) or an exception accepts the
/// weaker algorithm it has.
fn cost_method(target: HashMethod, reading: &MethodReading, excepted: bool) -> HashMethod {
    match reading.weakest {
        Some(weakest) if excepted || weakest > target => weakest,
        _ => target,
    }
}

/// The `ENCRYPT_METHOD` apply writes, if any. Pure.
///
/// Tighten-only. It is written when shadow cannot use the value there or it
/// is weaker than the target, and never below what the file already gives
/// pam_unix: a lowercase `yescrypt` is yescrypt to pam_unix even though shadow
/// rejects the spelling, so it is respelled rather than replaced. Respelling
/// changes nothing for the worse on any host, since shadow rejects both
/// spellings alike where it lacks yescrypt. Only a host shown to lack yescrypt
/// gets SHA512 instead, because there the lowercase value was already failing
/// shadow.
fn plan_method(
    login_defs: &str,
    probe: &HostProbe,
    target: HashMethod,
    excepted: bool,
) -> Option<HashMethod> {
    if excepted {
        return None;
    }
    let raw = login_defs_value(login_defs, ENCRYPT_METHOD);
    if raw
        .as_deref()
        .and_then(|v| shadow_method(v, probe))
        .is_some_and(|m| m >= target)
    {
        return None;
    }
    let floor = pam_method(raw.as_deref().and_then(pam_login_defs_method), probe)
        .filter(|m| *m != HashMethod::Yescrypt || probe.yescrypt() != Tri::No);
    Some(floor.map_or(target, |f| f.max(target)))
}

/// `content` with `key` set to `value`, written the way login.defs takes it.
fn set_login_defs(content: &str, key: &str, value: &str) -> String {
    set_config_directive(
        content,
        key,
        value,
        ConfigFormat::SpaceSeparated,
        true,
        Duplicates::Remove,
    )
}

impl Hashing {
    /// Builds the shared view from what was read. Pure.
    pub(super) fn new(
        config: &PluginConfig,
        login_defs: String,
        stack: Vec<PamUnixLine>,
        probe: HostProbe,
        mem_total_kib: Result<u64, String>,
    ) -> Hashing {
        let (target, why_not_yescrypt) = method_target(config, &probe);
        let method = read_method(&login_defs, &stack, &probe);
        let method_excepted = config
            .matching_exception(ENCRYPT_METHOD, &method.display)
            .is_some();
        let method_write = plan_method(&login_defs, &probe, target, method_excepted);
        let planned = match method_write {
            Some(m) => read_method(
                &set_login_defs(&login_defs, ENCRYPT_METHOD, m.login_defs_name()),
                &stack,
                &probe,
            ),
            None => method.clone(),
        };
        let cost_method = cost_method(target, &planned, method_excepted);
        Hashing {
            login_defs,
            stack,
            probe,
            target,
            why_not_yescrypt,
            method,
            method_excepted,
            method_write,
            cost_method,
            mem_total_kib,
        }
    }

    /// Whether the algorithm falls short of the target.
    pub(super) fn method_violated(&self) -> bool {
        self.method.weakest.is_none_or(|w| w < self.target)
    }

    /// The cost directive that applies, its target, and its reading of
    /// `login_defs`, which is the file as read or as projected.
    pub(super) fn cost_on(
        &self,
        config: &PluginConfig,
        login_defs: &str,
    ) -> Option<(&'static str, u64, CostReading)> {
        match self.cost_method {
            HashMethod::Yescrypt => {
                let target = cost_target(config, YESCRYPT_COST_FACTOR, YESCRYPT_COST_MAX);
                let reading = read_yescrypt_cost(login_defs, &self.stack, &self.probe, target);
                Some((YESCRYPT_COST_FACTOR, target, reading))
            }
            HashMethod::Sha512 | HashMethod::Sha256 => {
                let target = cost_target(config, SHA_CRYPT_MIN_ROUNDS, SHA_ROUNDS_MAX);
                let reading = read_sha_rounds(login_defs, &self.stack, &self.probe, target);
                Some((SHA_CRYPT_MIN_ROUNDS, target, reading))
            }
            _ => None,
        }
    }

    /// Whether an exception documents the cost this host has now.
    fn cost_excepted(&self, config: &PluginConfig) -> bool {
        self.cost_on(config, &self.login_defs)
            .is_some_and(|(name, _, reading)| {
                config.matching_exception(name, &reading.display).is_some()
            })
    }

    /// The yescrypt cost this host would be raised to but will not be, and
    /// the whole message why, with what to do instead. Pure.
    ///
    /// Judged on the **target**, not on the write: a host whose `login.defs`
    /// already holds the cost but whose stack line does not is refused just the
    /// same, because the only thing left to do there is put that cost on the
    /// stack line, and on a Linux-PAM older than 1.6.0 that line is what every
    /// user's password gets. While a refusal stands, neither the write nor a
    /// `rounds=` manual step for that cost is planned anywhere.
    pub(super) fn cost_refusal(&self, config: &PluginConfig) -> Option<(u64, String)> {
        let (name, target, reading) = self.cost_on(config, &self.login_defs)?;
        if name != YESCRYPT_COST_FACTOR
            || self.cost_excepted(config)
            || reading.lowest.is_some_and(|lowest| lowest >= target)
        {
            return None;
        }
        let reason = unaffordable(target, &self.mem_total_kib)?;
        Some((
            target,
            format!("{reason}. {}", lower_override_advice(&self.mem_total_kib)),
        ))
    }

    /// The `login.defs` keys apply writes, in order. Pure, and the one
    /// definition scan, apply and validate all use. Tighten-only throughout:
    /// see [`plan_method`] for the algorithm, and a cost is raised to the
    /// target only where the file holds less and the host can afford it
    /// (see [`Hashing::cost_refusal`]).
    pub(super) fn plan_writes(&self, config: &PluginConfig) -> Vec<(&'static str, String)> {
        let mut writes = Vec::new();
        if let Some(method) = self.method_write {
            writes.push((ENCRYPT_METHOD, method.login_defs_name().to_string()));
        }
        if let Some((name, target, reading)) = self.cost_on(config, &self.login_defs)
            && !self.cost_excepted(config)
            && reading.lowest.is_none_or(|lowest| lowest < target)
            && self.cost_refusal(config).is_none()
        {
            let number = |key: &str| {
                login_defs_value(&self.login_defs, key).and_then(|v| v.trim().parse::<u64>().ok())
            };
            if name == YESCRYPT_COST_FACTOR {
                if number(YESCRYPT_COST_FACTOR).is_none_or(|n| n < target) {
                    writes.push((YESCRYPT_COST_FACTOR, target.to_string()));
                }
            } else {
                // pam_unix reads only the maximum, and shadow lets either
                // stand in for the other, so the minimum needs writing only
                // where it is set too low or neither is enough.
                let max_ok = number(SHA_CRYPT_MAX_ROUNDS).is_some_and(|n| n >= target);
                let min_ok = number(SHA_CRYPT_MIN_ROUNDS).map_or(max_ok, |n| n >= target);
                if !min_ok {
                    writes.push((SHA_CRYPT_MIN_ROUNDS, target.to_string()));
                }
                if !max_ok {
                    writes.push((SHA_CRYPT_MAX_ROUNDS, target.to_string()));
                }
            }
        }
        writes
    }

    /// `login.defs` as it will read once `writes` are made.
    pub(super) fn projected(&self, writes: &[(&'static str, String)]) -> String {
        writes
            .iter()
            .fold(self.login_defs.clone(), |content, (key, value)| {
                set_login_defs(&content, key, value)
            })
    }

    /// The manual steps left once `projected` is in place: stack lines that
    /// name a weaker algorithm, and stack lines whose cost `login.defs`
    /// cannot reach. Each is `(directive, sentence)`. A cost the host cannot
    /// afford yields no step: the refusal says what to do instead, and a
    /// `rounds=` naming that cost is the lockout the refusal exists to avoid.
    pub(super) fn manual_steps(
        &self,
        config: &PluginConfig,
        projected: &str,
    ) -> Vec<(&'static str, String)> {
        let mut steps = Vec::new();
        if !self.method_excepted {
            for line in &self.stack {
                if let Some(named) = line.method
                    && pam_method(Some(named), &self.probe).is_none_or(|m| m < self.target)
                {
                    steps.push((
                        ENCRYPT_METHOD,
                        format!(
                            "{} names {} on its pam_unix line, which overrides /etc/login.defs; \
                             change it to {}",
                            line.file,
                            named.pam_token(),
                            self.target.pam_token()
                        ),
                    ));
                }
            }
        }
        if !self.cost_excepted(config)
            && self.cost_refusal(config).is_none()
            && let Some((name, target, after)) = self.cost_on(config, projected)
        {
            for shortfall in after.stack_shortfalls {
                steps.push((name, format!("{shortfall}; set rounds={target} there")));
            }
        }
        steps
    }
}

/// Reads the stack and probes the host, or names the file that stopped it.
///
/// `Err` carries the unreadable path and whether root would help. A stack file
/// that could not be read stops everything, because a `pam_unix` line there
/// would override `login.defs`.
async fn gather(
    ctx: &Context,
    config: &PluginConfig,
    login_defs: &ConfRead,
) -> Result<Hashing, (String, bool)> {
    let login_defs = match login_defs {
        ConfRead::Content(content, _) => content.clone(),
        ConfRead::Absent => String::new(),
        ConfRead::Unreadable {
            path,
            permission_denied,
            ..
        } => return Err((path.clone(), *permission_denied)),
    };
    let mut stack = Vec::new();
    for file in HASHING_STACK_FILES {
        match read_conf_classified(ctx, file).await {
            ConfRead::Content(content, _) => {
                stack.extend(pam_unix_password_lines(file, &content));
            }
            ConfRead::Absent => {}
            ConfRead::Unreadable {
                permission_denied, ..
            } => return Err((file.to_string(), permission_denied)),
        }
    }
    let probe = probe_host(ctx).await;
    let mem_total_kib = read_mem_total(ctx).await;
    Ok(Hashing::new(
        config,
        login_defs,
        stack,
        probe,
        mem_total_kib,
    ))
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------

/// How serious a weak algorithm is. DES keeps only the first eight
/// characters and MD5 falls to a single graphics card; SHA-512 is still sound,
/// just not memory-hard.
fn method_severity(weakest: Option<HashMethod>) -> Severity {
    match weakest {
        None | Some(HashMethod::Des) | Some(HashMethod::Md5) => Severity::High,
        Some(HashMethod::Sha256) | Some(HashMethod::Bcrypt) => Severity::Medium,
        Some(_) => Severity::Low,
    }
}

/// The words of a hashing finding, apart from what the directive supplies.
struct FindingText {
    description: String,
    impact: &'static str,
    remediation: Vec<String>,
    severity: Severity,
}

fn hashing_finding(
    config: &PluginConfig,
    name: &str,
    observed: &str,
    target: &str,
    text: FindingText,
) -> Finding {
    Finding {
        finding_id: format!("pam-{name}"),
        finding_category: FindingCategory::Authentication,
        finding_current_value: observed.to_string(),
        finding_description: text.description,
        finding_explanation: directive(name).pam_description.to_string(),
        finding_impact: text.impact.to_string(),
        finding_recommended_value: target.to_string(),
        finding_remediation_steps: text.remediation,
        finding_severity: text.severity,
        finding_title: format!("Weak password hashing: {name}"),
        finding_compliance: super::get_pam_compliance_mappings(name),
        finding_exception: config.exception_outcome(name, observed),
        finding_exception_key: Some(name.to_string()),
    }
}

/// Where a manual stack step is done, said once.
const STACK_ADVICE: &str = "Edit the pam_unix line yourself, or through the tool that \
                            manages the stack on this distribution (authselect on Fedora and \
                            RHEL, pam-auth-update on Debian and Ubuntu, pam-config on \
                            openSUSE, the sha512 and yescrypt USE flags of sys-auth/pambase \
                            on Gentoo). This tool never edits /etc/pam.d";

/// The finding id for a yescrypt cost the host's memory cannot carry.
pub(super) const COST_MEMORY_ID: &str = "pam-yescrypt-cost-memory";

/// The scan's view of password hashing.
pub(super) struct HashingScan {
    pub(super) findings: Vec<Finding>,
    pub(super) unchecked: Vec<UncheckedCheck>,
}

/// The scan half: up to two directive findings, and the stored-hash count.
pub(super) async fn scan(
    ctx: &Context,
    config: &PluginConfig,
    login_defs: &ConfRead,
) -> HashingScan {
    match gather(ctx, config, login_defs).await {
        Ok(hashing) => scan_findings(config, &hashing),
        Err((path, permission_denied)) => HashingScan {
            findings: Vec::new(),
            unchecked: HASHING_DIRECTIVES
                .iter()
                .map(|d| {
                    unchecked_pam_directive(
                        d,
                        unreadable_reason(&path, permission_denied),
                        permission_denied,
                    )
                })
                .collect(),
        },
    }
}

/// The findings for a host already read. Pure.
pub(super) fn scan_findings(config: &PluginConfig, h: &Hashing) -> HashingScan {
    let mut findings = Vec::new();
    let mut unchecked = Vec::new();
    let writes = h.plan_writes(config);
    let projected = h.projected(&writes);
    let steps = h.manual_steps(config, &projected);
    let steps_for = |name: &str| {
        steps
            .iter()
            .filter(|(directive, _)| *directive == name)
            .map(|(_, step)| format!("{step}. {STACK_ADVICE}"))
            .collect::<Vec<_>>()
    };

    if h.method_violated() {
        let target = h.target.login_defs_name();
        let mut remediation = Vec::new();
        if let Some((_, value)) = writes.iter().find(|(key, _)| *key == ENCRYPT_METHOD) {
            remediation.push(format!(
                "Set ENCRYPT_METHOD {value} in /etc/login.defs (apply does this)"
            ));
        }
        remediation.extend(steps_for(ENCRYPT_METHOD));
        remediation.push(format!(
            "Existing passwords keep their old hash until each one is next set; see the \
             {STORED_HASHES_ID} finding"
        ));
        let mut description = format!(
            "The weakest way a new password can be hashed here is {}, below the target of \
             {target}",
            h.method.display
        );
        if h.target != HashMethod::Yescrypt && !h.why_not_yescrypt.is_empty() {
            description.push_str(&format!(" (not yescrypt: {})", h.why_not_yescrypt));
        }
        if !h.method.notes.is_empty() {
            description.push_str(". ");
            description.push_str(&h.method.notes.join("; "));
        }
        findings.push(hashing_finding(
            config,
            ENCRYPT_METHOD,
            &h.method.display,
            target,
            FindingText {
                description,
                impact: "A weaker algorithm lets anyone who obtains /etc/shadow test far more \
                         password guesses per second, and DES keeps only the first eight \
                         characters of a password",
                remediation,
                severity: method_severity(h.method.weakest),
            },
        ));
    }

    if let Some((name, target, reading)) = h.cost_on(config, &h.login_defs)
        && reading.lowest.is_none_or(|lowest| lowest < target)
    {
        let mut remediation: Vec<String> = writes
            .iter()
            .filter(|(key, _)| *key != ENCRYPT_METHOD)
            .map(|(key, value)| format!("Set {key} {value} in /etc/login.defs (apply does this)"))
            .collect();
        if let Some((cost, message)) = h.cost_refusal(config) {
            remediation.push(format!(
                "apply will not raise the cost to {cost} here: {message}"
            ));
        }
        remediation.extend(steps_for(name));
        let baseline: u64 = directive(name).pam_secure_value.parse().unwrap_or(0);
        let severity = if reading.lowest.is_none_or(|lowest| lowest < baseline) {
            Severity::Medium
        } else {
            Severity::Low
        };
        let measure = if name == YESCRYPT_COST_FACTOR {
            "a cost of"
        } else {
            "rounds of"
        };
        findings.push(hashing_finding(
            config,
            name,
            &reading.display,
            &target.to_string(),
            FindingText {
                description: format!(
                    "New {} passwords are hashed at {measure} {}, below the target of {target}",
                    h.cost_method.login_defs_name(),
                    reading.display
                ),
                impact: "A lower cost makes every guess against a stolen hash cheaper",
                remediation,
                severity,
            },
        ));
    }

    if let Some(finding) = cost_memory_finding(config, h) {
        findings.push(finding);
    }

    match stored_hashes_finding(&h.probe.stored, h.cost_method) {
        StoredOutcome::Finding(finding) => findings.push(*finding),
        StoredOutcome::Unchecked(check) => unchecked.push(check),
        StoredOutcome::Nothing => {}
    }

    HashingScan {
        findings,
        unchecked,
    }
}

/// A yescrypt cost already in force that this host's memory cannot carry, by
/// the same measure the guard applies to a cost apply would write. Pure.
///
/// Advisory: the cost check is tighten-only and apply never lowers a cost, so
/// a host where someone set a high cost by hand (the 1 GiB the issue proposed,
/// say) would otherwise scan clean. The highest cost on any path counts, since
/// that is what a password check can be made to spend. Silent where the
/// memory could not be read, and at or below the default, which every
/// consumer uses already. No compliance mapping: this is about availability,
/// not about how strongly a password is stored.
pub(super) fn cost_memory_finding(config: &PluginConfig, h: &Hashing) -> Option<Finding> {
    if h.cost_method != HashMethod::Yescrypt {
        return None;
    }
    let (_, _, reading) = h.cost_on(config, &h.login_defs)?;
    let highest = reading.highest?;
    let kib = *h.mem_total_kib.as_ref().ok()?;
    let ceiling = max_affordable_cost(kib);
    if highest <= YESCRYPT_COST_DEFAULT || highest <= ceiling {
        return None;
    }
    let lower_to = ceiling.max(YESCRYPT_COST_DEFAULT);
    let observed = highest.to_string();
    Some(Finding {
        finding_id: COST_MEMORY_ID.to_string(),
        finding_category: FindingCategory::Authentication,
        finding_current_value: observed.clone(),
        finding_description: format!(
            "A yescrypt cost of {highest} is in force on at least one path a password can take \
             here, and each check of such a password needs {} MiB. {} MiB of memory fits ten \
             simultaneous checks in half of it only up to a cost of {ceiling}",
            1u64 << (highest - 1),
            kib / 1024
        ),
        finding_explanation: "The cost is stored in each hash, so every check of a password set \
                              at this cost needs that memory, whatever the configuration says \
                              later, and a check that cannot get it rejects the correct password"
            .to_string(),
        finding_impact: "Logins, su, sudo and screen unlocks can fail for the right password when \
                         memory is short, and simultaneous password checks can exhaust the \
                         host's memory"
            .to_string(),
        finding_recommended_value: format!("{lower_to} or less"),
        finding_remediation_steps: vec![
            format!(
                "Lower YESCRYPT_COST_FACTOR in /etc/login.defs, and any rounds= on a pam_unix \
                 line, to {lower_to} or less. apply never lowers a cost, so this is a manual \
                 step"
            ),
            "Passwords already set at this cost keep it until each one is set again, so set \
             them again with passwd once the cost is lowered"
                .to_string(),
            format!(
                "If the cost was chosen on purpose for a host with few simultaneous logins, \
                 accept it with [pam.exceptions.YESCRYPT_COST_FACTOR] and value = \"{observed}\""
            ),
        ],
        finding_severity: Severity::Medium,
        finding_title: "Password hashing cost is more than this host's memory can carry"
            .to_string(),
        finding_compliance: vec![],
        finding_exception: config.exception_outcome(YESCRYPT_COST_FACTOR, &observed),
        finding_exception_key: Some(YESCRYPT_COST_FACTOR.to_string()),
    })
}

// ---------------------------------------------------------------------------
// Stored hashes (read-only)
// ---------------------------------------------------------------------------

/// What the stored-hash count adds to a scan.
pub(super) enum StoredOutcome {
    Finding(Box<Finding>),
    Unchecked(UncheckedCheck),
    Nothing,
}

/// A count of accounts whose stored hash is weaker than `reference`.
///
/// Read-only by design and keyed to no directive. Nothing about the
/// configuration changes a stored hash: each is rewritten only when that
/// password is next set, so the finding advises and `apply` does nothing.
/// It carries **no compliance mapping**: the STIG rule for stored hashes
/// demands SHA-512 specifically, and a count measured against yescrypt would
/// pass or fail that control on a question it does not ask.
pub(super) fn stored_hashes_finding(stored: &StoredHashes, reference: HashMethod) -> StoredOutcome {
    let unchecked = |reason: String, blocker: UncheckedBlocker| {
        StoredOutcome::Unchecked(UncheckedCheck {
            unchecked_check_id: STORED_HASHES_ID.to_string(),
            unchecked_title: "Stored password hashes".to_string(),
            unchecked_category: FindingCategory::Authentication,
            unchecked_reason: reason,
            unchecked_blocker: blocker,
            unchecked_compliance: vec![],
        })
    };
    let schemes = match stored {
        StoredHashes::Schemes(schemes) => schemes,
        StoredHashes::Denied => {
            return unchecked(
                "reading /etc/shadow requires root".to_string(),
                UncheckedBlocker::Privilege,
            );
        }
        StoredHashes::Absent => return StoredOutcome::Nothing,
        StoredHashes::Unknown(reason) => {
            return unchecked(reason.clone(), UncheckedBlocker::Environment);
        }
    };
    let mut weaker: Vec<(String, usize)> = Vec::new();
    let mut worst = reference;
    for scheme in schemes {
        let method = HashMethod::from_stored_scheme(scheme);
        if method >= reference {
            continue;
        }
        worst = worst.min(method);
        match weaker.iter_mut().find(|(name, _)| name == scheme) {
            Some((_, count)) => *count += 1,
            None => weaker.push((scheme.clone(), 1)),
        }
    }
    if weaker.is_empty() {
        return StoredOutcome::Nothing;
    }
    weaker.sort();
    let total: usize = weaker.iter().map(|(_, n)| n).sum();
    let breakdown = weaker
        .iter()
        .map(|(name, n)| format!("{n} {name}"))
        .collect::<Vec<_>>()
        .join(", ");
    let reference_name = reference.login_defs_name();
    StoredOutcome::Finding(Box::new(Finding {
        finding_id: STORED_HASHES_ID.to_string(),
        finding_category: FindingCategory::Authentication,
        finding_current_value: breakdown.clone(),
        finding_description: format!(
            "{total} account(s) still have a password stored with a scheme weaker than \
             {reference_name}: {breakdown}"
        ),
        finding_explanation: "A stored hash keeps the algorithm and cost it was made with until \
                              that password is set again; changing the configuration does not \
                              rehash it"
            .to_string(),
        finding_impact: "Anyone who obtains /etc/shadow attacks these accounts at the weaker \
                         scheme's speed, whatever the configuration now says"
            .to_string(),
        finding_recommended_value: format!("every stored hash at {reference_name} or stronger"),
        finding_remediation_steps: vec![
            "List each account with the scheme of its stored hash, on the host itself so the \
             names stay there: sudo awk -F: '$2 !~ /^[!*]/ && $2 != \"\" {split($2, p, \"$\"); \
             print $1, (p[2] == \"\" ? \"des\" : p[2])}' /etc/shadow (y is yescrypt, 6 is \
             SHA-512, 5 is SHA-256, 1 is MD5)"
                .to_string(),
            "Each one is rehashed with the current method the next time its password is set. \
             Ask those users to change their passwords, or set new ones with passwd"
                .to_string(),
            "chage -d 0 <user> forces a change at the next login, but an account that logs in \
             only with an SSH key may then be refused, so use it with care"
                .to_string(),
        ],
        finding_severity: method_severity(Some(worst)),
        finding_title: "Stored passwords use an older hashing scheme".to_string(),
        finding_compliance: vec![],
        // Not a setting: the count changes as passwords are set, so there is
        // no value for an exception to document and no key to write it under.
        finding_exception: ExceptionOutcome::NotConfigured,
        finding_exception_key: None,
    }))
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

/// The largest yescrypt cost this host can carry: ten simultaneous password
/// checks must fit in half its memory. Cost `c` needs `2^(c-1)` MiB per check,
/// so it is allowed from a `MemTotal` of `10 * 2^c` MiB: 640 MiB for 6,
/// 2.5 GiB for 8, 10 GiB for 10 and 20 GiB for 11. `MemTotal` reads a little
/// below the installed memory, so a machine sold as 20 GB does not reach 11.
///
/// Ten is a safety margin, not a measured load. Local checks run side by side
/// (login, su, sudo, screen lockers, display managers), and where sshd still
/// takes a password or keyboard-interactive answer through PAM, each
/// unauthenticated connection can start one, up to the ten at which sshd's
/// default `MaxStartups 10:30:100` begins refusing. This tool's own SSH
/// baseline turns both off, so on a host it has hardened only a key holder
/// reaches a password prompt. `MemTotal` ignores a container's cgroup limit,
/// which this does not read.
pub(super) fn max_affordable_cost(mem_total_kib: u64) -> u64 {
    let budget_mib = mem_total_kib / 1024 / 2 / 10;
    let mut cost = 0;
    while cost < YESCRYPT_COST_MAX && (1u64 << cost) <= budget_mib {
        cost += 1;
    }
    cost
}

/// `MemTotal` from `/proc/meminfo`, in KiB.
pub(super) fn parse_mem_total_kib(meminfo: &str) -> Option<u64> {
    meminfo.lines().find_map(|line| {
        let rest = line.strip_prefix("MemTotal:")?;
        rest.split_whitespace().next()?.parse().ok()
    })
}

/// `MemTotal` of the target, through the executor so it is the remote host's
/// over `--ssh`, or why it could not be read.
async fn read_mem_total(ctx: &Context) -> Result<u64, String> {
    let meminfo = ctx
        .executor()
        .read_file(Path::new("/proc/meminfo"))
        .await
        .map_err(|e| format!("/proc/meminfo could not be read: {e}"))?;
    parse_mem_total_kib(&meminfo).ok_or_else(|| "/proc/meminfo gives no MemTotal".to_string())
}

/// Why a yescrypt cost is more than this host can carry, or `None` where it
/// is not. The default never is: every consumer uses it already. Pure.
pub(super) fn unaffordable(cost: u64, mem_total_kib: &Result<u64, String>) -> Option<String> {
    if cost <= YESCRYPT_COST_DEFAULT {
        return None;
    }
    match mem_total_kib {
        Err(reason) => Some(format!(
            "this host's memory could not be read ({reason}), so a cost above \
             {YESCRYPT_COST_DEFAULT} cannot be shown to be safe"
        )),
        Ok(total) => {
            let ceiling = max_affordable_cost(*total);
            (cost > ceiling).then(|| {
                format!(
                    "a cost of {cost} needs {} MiB for every password check, and {} MiB of \
                     memory fits ten simultaneous checks in half of it only up to a cost of \
                     {ceiling}. A password the host cannot afford to check is refused even \
                     when it is typed correctly",
                    1u64 << (cost - 1),
                    total / 1024
                )
            })
        }
    }
}

/// What an operator whose cost override was refused can do instead. The
/// override can only tighten, so below the default the answer is to drop it.
fn lower_override_advice(mem_total_kib: &Result<u64, String>) -> String {
    match mem_total_kib {
        Ok(total) if max_affordable_cost(*total) > YESCRYPT_COST_DEFAULT => format!(
            "Lower the [pam.directives] YESCRYPT_COST_FACTOR override to {} or less",
            max_affordable_cost(*total)
        ),
        _ => format!(
            "Remove the [pam.directives] YESCRYPT_COST_FACTOR override, which leaves the \
             default of {YESCRYPT_COST_DEFAULT}"
        ),
    }
}

/// The apply half. Edits the `login.defs` buffer the caller writes, and
/// returns false when something is left that only an operator can finish.
pub(super) async fn apply(
    ctx: &Context,
    config: &PluginConfig,
    login_defs_observed: &ConfRead,
    content: &mut String,
    changed: &mut bool,
    changes: &mut Vec<Change>,
) -> bool {
    let h = match gather(ctx, config, login_defs_observed).await {
        Ok(h) => h,
        Err((path, permission_denied)) => {
            let reason = unreadable_reason(&path, permission_denied);
            warn!("Password hashing left unchanged: {}", reason);
            changes.push(Change {
                change_type: ChangeType::ConfigFile,
                change_description: format!(
                    "Password hashing left unchanged: {reason}, and the value in force cannot be \
                     known without it"
                ),
                change_success: false,
                change_error: Some(reason),
            });
            return false;
        }
    };
    let mut success = true;

    if h.method_excepted
        && let Some(exception) = config.matching_exception(ENCRYPT_METHOD, &h.method.display)
    {
        changes.push(Change {
            change_type: ChangeType::Skipped,
            change_description: format!(
                "{ENCRYPT_METHOD}: skipped (exception: {})",
                exception.reason
            ),
            change_success: true,
            change_error: None,
        });
    }
    if let Some((name, _, reading)) = h.cost_on(config, &h.login_defs)
        && let Some(exception) = config.matching_exception(name, &reading.display)
    {
        changes.push(Change {
            change_type: ChangeType::Skipped,
            change_description: format!("{name}: skipped (exception: {})", exception.reason),
            change_success: true,
            change_error: None,
        });
    }

    if let Some((cost, message)) = h.cost_refusal(config) {
        warn!("Refusing YESCRYPT_COST_FACTOR {}: {}", cost, message);
        success = false;
        changes.push(Change {
            change_type: ChangeType::ConfigFile,
            change_description: format!("Refused to set YESCRYPT_COST_FACTOR {cost}: {message}"),
            change_success: false,
            change_error: Some(message),
        });
    }

    let writes = h.plan_writes(config);
    for (key, value) in &writes {
        apply_exact_directive(
            content,
            changed,
            changes,
            key,
            value,
            ConfigFormat::SpaceSeparated,
            "login.defs",
        );
    }

    // What login.defs cannot reach, judged on the file as the plan leaves it.
    // A refused cost is not among them: see Hashing::cost_refusal.
    for (name, step) in h.manual_steps(config, &h.projected(&writes)) {
        success = false;
        warn!("{}: {}", name, step);
        changes.push(Change {
            change_type: ChangeType::ConfigFile,
            change_description: format!("{step}. {STACK_ADVICE}"),
            change_success: false,
            change_error: Some(hardener_types::PAM_INLINE_OVERRIDE_MARKER.to_string()),
        });
    }
    success
}

// ---------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------

/// The dry run's view, in the shape `validate` assembles.
pub(super) struct HashingPreview {
    pub(super) issues: Vec<ValidationIssue>,
    pub(super) estimated_changes: Vec<String>,
    pub(super) exceptions: Vec<String>,
    pub(super) compliant_count: usize,
}

/// The validate half: what apply would write and what it would leave to the
/// operator, from the same plan, so the preview cannot promise more.
pub(super) async fn validate(
    ctx: &Context,
    config: &PluginConfig,
    login_defs: &ConfRead,
) -> HashingPreview {
    let mut preview = HashingPreview {
        issues: Vec::new(),
        estimated_changes: Vec::new(),
        exceptions: Vec::new(),
        compliant_count: 0,
    };
    let h = match gather(ctx, config, login_defs).await {
        Ok(h) => h,
        Err((path, permission_denied)) => {
            preview.issues.push(unreadable_issue(
                ENCRYPT_METHOD,
                "a strong hashing method",
                &path,
                permission_denied,
            ));
            return preview;
        }
    };

    let mut judged = vec![(
        ENCRYPT_METHOD,
        h.method.display.clone(),
        !h.method_violated(),
    )];
    if let Some((name, target, reading)) = h.cost_on(config, &h.login_defs) {
        let compliant = reading.lowest.is_some_and(|lowest| lowest >= target);
        judged.push((name, reading.display, compliant));
    }
    for (name, value, compliant) in &judged {
        if let Some(exception) = config.matching_exception(name, value) {
            preview
                .exceptions
                .push(hardener_common::types::exception_preview_line(
                    name,
                    value,
                    &exception.reason,
                ));
        } else if *compliant {
            preview.compliant_count += 1;
        }
    }

    if let Some((cost, message)) = h.cost_refusal(config) {
        preview.issues.push(ValidationIssue {
            validation_issue_config_key: Some(YESCRYPT_COST_FACTOR.to_string()),
            validation_issue_message: format!(
                "YESCRYPT_COST_FACTOR will not be set to {cost}: {message}"
            ),
            validation_issue_severity: Severity::High,
        });
    }
    let writes = h.plan_writes(config);
    for (key, value) in &writes {
        let current = login_defs_value(&h.login_defs, key).unwrap_or_else(|| "not set".to_string());
        preview
            .estimated_changes
            .push(format!("{key} will change: {current} -> {value}"));
    }
    for (name, step) in h.manual_steps(config, &h.projected(&writes)) {
        preview.issues.push(ValidationIssue {
            validation_issue_config_key: Some(name.to_string()),
            validation_issue_message: format!(
                "{step}. apply will not edit the PAM stack, so this is a manual step"
            ),
            validation_issue_severity: Severity::High,
        });
    }
    preview
}

#[cfg(test)]
mod tests;
