//! Whether the values this plugin writes actually survive the next boot.
//!
//! [`super::SYSCTL_HARDENER_CONF`] is the plugin's boot-persistence guarantee,
//! and it holds only while nothing applies a looser value after it. Two kinds of
//! file can, and **the first kind usually does not**, which is the asymmetry the
//! whole module is built around:
//!
//! 1. A `sysctl.d` drop-in whose filename sorts after this tool's.
//!    `systemd-sysctl` merges `/etc/sysctl.d`, `/run/sysctl.d`,
//!    `/usr/local/lib/sysctl.d` and `/usr/lib/sysctl.d`, sorts every file by
//!    name and lets the lexicographically last name win, with a same-named file
//!    in a higher-precedence directory replacing the lower one outright
//!    (`sysctl.d(5)`, CONFIGURATION DIRECTORIES AND PRECEDENCE). A drop-in
//!    sorting BEFORE `99-hardener.conf` therefore loses, and reporting one
//!    would be a false finding: Debian 13 ships
//!    `/usr/lib/sysctl.d/50-default.conf` setting `rp_filter = 2`, looser than
//!    this tool's target of 1, and this tool still wins at boot.
//! 2. A file applied by a unit ordered after `systemd-sysctl.service`. ufw is
//!    the one instance this tool knows of, and it is named rather than
//!    inferred; see [`ufw_applied_file`].
//!
//! **The scan's ceiling, stated because a reader would otherwise infer the
//! opposite.** A third file can decide what a host runs and is deliberately not
//! among those two: `/etc/sysctl.conf`, which `procps sysctl --system` reads
//! last of all and so lets override [`super::SYSCTL_HARDENER_CONF`] on every
//! reload, whether an operator runs one by hand or this tool's own rollback
//! does. [`boot_persistence`] cannot see that file and must not learn to: its
//! question is boot persistence, and nothing at boot applies the file. A value
//! there that loosens what this tool persists therefore produces **no scan
//! finding at all**. The one place it is reported is the rollback divergence
//! probe, through [`legacy_sysctl_conf`]; see `super::divergence`.
//!
//! This is report-only. Editing another package's configuration file is not
//! something this tool does, and the precedent is the vendor-layer reporting in
//! `crate::permissions`: the finding names the file, the parameter, the value
//! that file sets and the target it undercuts, so an operator can act without a
//! second investigation, and the apply writes nothing new.

use super::{KERNEL_PARAMS, KernelParameter, SYSCTL_HARDENER_CONF, resolved_target};
use crate::firewall::UFW_CONF;
use crate::shell_config::shell_value;
use hardener_common::{error::is_permission_denied, types::FindingCategory};
use hardener_core::{
    PluginConfig,
    context::Context,
    plugin::{Finding, UncheckedBlocker, UncheckedCheck},
};
use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
};

/// The drop-in directories `systemd-sysctl` merges, **highest precedence
/// first**, as `sysctl.d(5)` lists them in its SYNOPSIS. These four are also
/// the only paths `/usr/lib/systemd/systemd-sysctl` names, read off the binary
/// 2026-07-31 and again 2026-08-08.
///
/// `/etc/sysctl.conf` is deliberately not among them, and the reason is that
/// `systemd-sysctl` does not read it: a file named only there is not applied
/// at boot on a systemd host, so it cannot override what this tool persists,
/// which is the only question the scan asks. An earlier version of this
/// comment gave a different reason, that a distribution wanting the file
/// applied reaches it through an `/etc/sysctl.d/99-sysctl.conf` symlink. No
/// such symlink was found on any of the five distributions measured
/// 2026-08-08 (arch, debian 13, fedora, rhel, opensuse); fedora ships the file
/// as a real file and the rest ship nothing. The conclusion held, its stated
/// evidence did not. Fedora's copy assigns nothing either, being a comment
/// block pointing at `/etc/sysctl.d/`, so a parameter reaching
/// [`legacy_sysctl_conf`] with a value is one an operator wrote by hand.
///
/// `procps sysctl --system` DOES read it, and that is a different question
/// asked by a different caller: see [`legacy_sysctl_conf`].
const SYSCTL_DROPIN_DIRS: &[&str] = &[
    // The one this tool writes into is named once, in the parent module.
    super::SYSCTL_DROPIN_DIR,
    "/run/sysctl.d",
    "/usr/local/lib/sysctl.d",
    "/usr/lib/sysctl.d",
];

/// Where ufw names the sysctl file it applies.
const UFW_DEFAULTS: &str = "/etc/default/ufw";

/// A key spelled the way `/proc/sys` spells it.
///
/// `sysctl` accepts both separators: if the first one is a slash the rest of
/// the name is left exactly as written, and if it is a dot then dots and
/// slashes are interchanged (`sysctl.d(5)`, CONFIGURATION FORMAT). This tool's
/// table and every `sysctl.d` drop-in use dots; ufw's file uses procfs paths,
/// `net/ipv4/conf/all/log_martians=0`. A comparison written for one form
/// matches nothing in the other, matching nothing yields no finding, and no
/// finding is indistinguishable from a host with nothing wrong.
pub(super) fn procfs_key(key: &str) -> String {
    match key.find(['.', '/']) {
        Some(index) if key.as_bytes()[index] == b'/' => key.to_string(),
        Some(_) => key
            .chars()
            .map(|c| match c {
                '.' => '/',
                '/' => '.',
                other => other,
            })
            .collect(),
        None => key.to_string(),
    }
}

/// What one sysctl-format file sets.
#[derive(Default)]
struct SysctlAssignments {
    /// Explicit assignments keyed by [`procfs_key`], a later line in the file
    /// winning over an earlier one, which is the order `sysctl` applies them.
    values: BTreeMap<String, String>,
    /// Glob patterns the file assigns through, keyed by [`procfs_key`] the
    /// same way `values` is, so a pattern written with dots and a key written
    /// with slashes compare alike. **Not resolved to a value here, and never
    /// must be**: the pattern language carries exclusions and an
    /// explicit-key precedence rule, and a half-implemented matcher is how a
    /// false finding gets built. What is kept is narrower than resolution: a
    /// pattern text a caller can ask "could this name key X", never "what
    /// does this assign to X". A file this reader cannot fully resolve is
    /// still not mistaken for a file that agrees.
    glob_patterns: Vec<String>,
}

/// Reads a file in `sysctl` syntax, whether it is a `sysctl.d` drop-in or the
/// file ufw hands to `sysctl -p`. Both are the same format.
fn parse_sysctl(content: &str) -> SysctlAssignments {
    let mut parsed = SysctlAssignments::default();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        // A line with no `=` assigns nothing: it is a glob exclusion, `-key`,
        // which only matters to patterns this reader does not resolve anyway.
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        // A leading `-` makes the assignment failure-tolerant; it still
        // assigns.
        let key = key.trim().strip_prefix('-').unwrap_or(key.trim()).trim();
        if key.contains(['*', '?', '[']) {
            parsed.glob_patterns.push(procfs_key(key));
            continue;
        }
        parsed
            .values
            .insert(procfs_key(key), value.trim().to_string());
    }
    parsed
}

/// Whether `pattern` could name `key`, both already spelled by [`procfs_key`].
///
/// `*` matches any run of characters (including none), `?` matches exactly
/// one, and a `[...]` character class matches exactly one without checking
/// which characters it admits. That last simplification is deliberate: this
/// answers one narrow question, whether attribution should be blocked, and
/// treating a character class as matching more than sysctl actually would is
/// the safe direction there, while treating it as matching less could let a
/// pattern that does name the key through as a false `Diverged` claim.
///
/// This is not the glob resolver the module's own doc comment refuses to
/// write. It never produces a value, only a bool, and an over-broad match
/// costs an operator an "unknown" they did not strictly need, while an
/// under-broad one costs a false measurement. Erring toward blocked is the
/// only direction this function is allowed to be wrong in.
pub(super) fn glob_could_match(pattern: &str, key: &str) -> bool {
    enum Tok {
        Lit(char),
        Any,
        Star,
    }

    let mut toks = Vec::new();
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' => toks.push(Tok::Star),
            '?' => toks.push(Tok::Any),
            '[' => {
                // The exact class is not evaluated; consuming to the closing
                // bracket and treating the whole thing as "one character" is
                // the deliberate over-match described above. An unterminated
                // `[` with no closing bracket is treated the same way sysctl
                // treats a malformed pattern: as a literal `[`.
                if chars.clone().any(|c| c == ']') {
                    for c in chars.by_ref() {
                        if c == ']' {
                            break;
                        }
                    }
                    toks.push(Tok::Any);
                } else {
                    toks.push(Tok::Lit('['));
                }
            }
            other => toks.push(Tok::Lit(other)),
        }
    }

    let key: Vec<char> = key.chars().collect();
    let (mut ti, mut ki) = (0usize, 0usize);
    let (mut star_ti, mut star_ki): (Option<usize>, usize) = (None, 0);
    while ki < key.len() {
        let tok_matches = match toks.get(ti) {
            Some(Tok::Lit(c)) => *c == key[ki],
            Some(Tok::Any) => true,
            _ => false,
        };
        if tok_matches {
            ti += 1;
            ki += 1;
        } else if let Some(Tok::Star) = toks.get(ti) {
            star_ti = Some(ti);
            star_ki = ki;
            ti += 1;
        } else if let Some(sti) = star_ti {
            ti = sti + 1;
            star_ki += 1;
            ki = star_ki;
        } else {
            return false;
        }
    }
    toks[ti..].iter().all(|t| matches!(t, Tok::Star))
}

/// The outcome of looking for a file the boot sequence might apply.
///
/// Three answers rather than two, for the reason the executor contract gives
/// everywhere else: a read that failed is not an absence, and folding the two
/// together is how a file nobody could open comes to look like a file that
/// agrees with this tool.
enum FileRead {
    Content(String),
    Absent,
    Unreadable {
        reason: String,
        needs_privilege: bool,
    },
}

async fn read_boot_file(ctx: &Context, path: &str) -> FileRead {
    let target = Path::new(path);
    match ctx.executor().path_exists(target).await {
        Ok(false) => return FileRead::Absent,
        Ok(true) => {}
        Err(e) => {
            return FileRead::Unreadable {
                reason: format!("could not determine whether {path} exists: {e}"),
                needs_privilege: is_permission_denied(&e),
            };
        }
    }
    match ctx.executor().read_file(target).await {
        Ok(content) => FileRead::Content(content),
        Err(e) => FileRead::Unreadable {
            reason: format!("{path} could not be read: {e}"),
            needs_privilege: is_permission_denied(&e),
        },
    }
}

/// One file that sets kernel parameters after this tool's drop-in has been
/// applied, and therefore decides what the host runs.
struct LaterFile {
    /// The path an operator has to go and look at.
    path: String,
    /// Why this file lands after [`SYSCTL_HARDENER_CONF`]. Carried per file
    /// because the two mechanisms are ordered by different things, and a
    /// finding that explained the wrong one would send an operator to the
    /// wrong lever.
    ordering: String,
    values: SysctlAssignments,
}

/// A stable id for the persistence question about one path.
fn persistence_check_id(path: &str) -> String {
    format!(
        "kernel_boot_persistence{}",
        path.replace(['/', '.', '-'], "_")
    )
}

/// An entry for something this scan could not read.
///
/// It carries every compliance mapping this plugin covers, because any sysctl
/// file can set any sysctl: a file that could not be read leaves the durability
/// of all of them unknown, and a control must not pass on the absence of a
/// finding nobody was able to look for.
fn unchecked_persistence(path: &str, reason: String, needs_privilege: bool) -> UncheckedCheck {
    // `needs_privilege` is derived from the failure rather than asserted, so
    // the two answers this plugin can give map cleanly onto the two the type
    // records. A read DAC or an LSM refused is exactly what root fixes; a
    // parameter this kernel does not carry is not, and no privilege will make
    // it appear.
    let blocker = match needs_privilege {
        true => UncheckedBlocker::Privilege,
        false => UncheckedBlocker::Environment,
    };
    UncheckedCheck {
        unchecked_check_id: persistence_check_id(path),
        unchecked_title: "Kernel parameters survive a reboot".to_string(),
        unchecked_category: FindingCategory::Kernel,
        unchecked_reason: reason,
        unchecked_blocker: blocker,
        unchecked_compliance: super::coverage(),
    }
}

/// Which drop-ins a caller wants read.
///
/// The scan asks which files beat this tool's own, so it filters by name. A
/// rollback probe asks whether anything at all still names a parameter, and
/// this tool's file is gone by then, so it filters by nothing.
pub(super) enum DropinScope {
    AfterOurs,
    All,
}

/// What a drop-in sweep found, including what it could not read.
///
/// The two failures are kept apart because they block different amounts. A
/// directory nobody could list hides an unknown set of NAMES, so nothing can be
/// reasoned about its position in the sort order. A single file nobody could
/// read has a name in hand, and that name is enough to say which parameters it
/// could possibly decide (#145).
struct DropinSweep {
    files: Vec<LaterFile>,
    unchecked: Vec<UncheckedCheck>,
    /// The lexicographically LAST filename this sweep could not read, if any.
    ///
    /// One name rather than the set, because the question every caller asks of
    /// it is "could an unread file have decided this key", and under
    /// last-one-wins that is true of the set exactly when it is true of its
    /// maximum. Measured from both appliers' own documentation on 2026-08-09:
    /// `sysctl.d(5)` says files are "sorted by their filename in lexicographic
    /// order, regardless of which of the directories they reside in" and the
    /// "lexicographically latest name will take precedence"; `sysctl(8)` says
    /// the same of `--system`, which is what a rollback's own reload runs.
    ///
    /// Compared with the same plain string ordering `beats_ours` below already
    /// uses, so the whole module agrees with itself about what "sorts after"
    /// means, whatever the appliers' exact collation turns out to be.
    unreadable_last_name: Option<String>,
    /// True when a directory could not be listed at all, which puts every
    /// parameter out of reach whatever any name says.
    dir_unlisted: bool,
}

/// Every `sysctl.d` drop-in `scope` selects, in the order `systemd-sysctl`
/// applies them.
async fn dropins(ctx: &Context, scope: DropinScope) -> DropinSweep {
    // An empty name here would sort before every drop-in on the host and turn
    // the whole of `sysctl.d` into findings, so this is asserted rather than
    // defaulted: it is this tool's own constant.
    let ours = Path::new(SYSCTL_HARDENER_CONF)
        .file_name()
        .and_then(|name| name.to_str())
        .expect("this tool's own drop-in path must end in a filename");
    let mut unchecked = Vec::new();
    let mut unreadable_last_name: Option<String> = None;
    let mut dir_unlisted = false;
    // Keyed by filename, which is both the precedence order systemd-sysctl
    // sorts by and the identity a higher-precedence directory replaces on.
    let mut chosen: BTreeMap<String, String> = BTreeMap::new();

    for dir in SYSCTL_DROPIN_DIRS {
        let entries = match ctx.executor().read_dir(Path::new(dir)).await {
            Ok(entries) => entries,
            Err(e) => {
                let reason = match scope {
                    DropinScope::AfterOurs => format!(
                        "{dir} could not be listed, so a drop-in overriding \
                         {SYSCTL_HARDENER_CONF} cannot be ruled out: {e}"
                    ),
                    // This tool's own drop-in is gone by the time a rollback
                    // asks: there is nothing left here for another file to
                    // override, only the open question of whether a surviving
                    // file names a managed parameter at all.
                    DropinScope::All => format!(
                        "{dir} could not be listed, so whether a surviving file in it names a \
                         parameter this rollback restored is unknown: {e}"
                    ),
                };
                dir_unlisted = true;
                unchecked.push(unchecked_persistence(dir, reason, is_permission_denied(&e)));
                continue;
            }
        };
        for entry in entries {
            let Some(name) = entry.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            // Only `.conf` is read, and a scan wants only a name sorting
            // strictly after this tool's own; a rollback probe wants every
            // surviving name.
            let beats_ours = match scope {
                DropinScope::AfterOurs => name > ours,
                DropinScope::All => true,
            };
            if !name.ends_with(".conf") || !beats_ours {
                continue;
            }
            // Highest-precedence directory first, so the first spelling of a
            // name found is the copy in force.
            chosen
                .entry(name.to_string())
                .or_insert_with(|| entry.to_string_lossy().into_owned());
        }
    }

    let mut files = Vec::new();
    for (name, path) in chosen {
        match read_boot_file(ctx, &path).await {
            FileRead::Content(content) => files.push(LaterFile {
                ordering: format!(
                    "its name sorts after {ours}, and systemd-sysctl lets the \
                     lexicographically last drop-in decide the value"
                ),
                path,
                values: parse_sysctl(&content),
            }),
            // Listed a moment ago and gone now, which is a real race on
            // /run/sysctl.d. Nothing was read, so nothing is claimed.
            FileRead::Absent => {}
            FileRead::Unreadable {
                reason,
                needs_privilege,
            } => {
                let sentence = match scope {
                    DropinScope::AfterOurs => format!("{reason}, and {name} sorts after {ours}"),
                    // "sorts after ours" is a scan-only fact: the ordering it
                    // states is against this tool's own drop-in, which a
                    // rollback has already restored away from. What the
                    // rollback caller actually wants to know is narrower and
                    // still true here: whether this unread file might name a
                    // parameter the rollback restored.
                    DropinScope::All => format!(
                        "{reason}, so whether it names a parameter this rollback restored is \
                         unknown"
                    ),
                };
                // The name, not the path: `chosen` holds one path per name and
                // the highest-precedence copy at that, so the name is the
                // identity the appliers sort on and the only thing that can be
                // compared against a deciding file.
                if unreadable_last_name
                    .as_deref()
                    .is_none_or(|last| name.as_str() > last)
                {
                    unreadable_last_name = Some(name.clone());
                }
                unchecked.push(unchecked_persistence(&path, sentence, needs_privilege));
            }
        }
    }
    DropinSweep {
        files,
        unchecked,
        unreadable_last_name,
        dir_unlisted,
    }
}

/// The sysctl file ufw applies, when ufw is in a state that applies one.
///
/// ufw is the only instance this tool knows of a unit that applies a sysctl
/// file after `systemd-sysctl.service` has run, and it is named rather than
/// inferred: enumerating every unit on a host that might do the same is
/// unbounded, and guessing at one would be inventing policy. The door is open
/// for a second instance to be added here beside it.
///
/// Read off ufw 0.36.2 on 2026-07-31: `ufw.service` is
/// `After=systemd-sysctl.service`, and `ufw_start` runs
/// `sysctl -e -q -p $IPT_SYSCTL` (`/usr/lib/ufw/ufw-init-functions:387`) from
/// inside `[ "$ENABLED" = "yes" ] || [ "$ENABLED" = "YES" ]` (`:111`), with
/// `IPT_SYSCTL` coming from `/etc/default/ufw` and `ENABLED` from
/// `/etc/ufw/ufw.conf`. The enablement test is why this asks about it: the arch
/// host of that date has ufw installed, `IPT_SYSCTL` active, and
/// `/etc/ufw/sysctl.conf` setting `log_martians=0`, and applies none of it
/// because `ENABLED=no`.
async fn ufw_applied_file(ctx: &Context) -> (Vec<LaterFile>, Vec<UncheckedCheck>) {
    let mut unchecked = Vec::new();

    // ufw-init-functions sources both files and aborts outright when either is
    // missing or empty, so an absent one means nothing is applied.
    let enabled = match read_boot_file(ctx, UFW_CONF).await {
        FileRead::Content(content) => shell_value(&content, "ENABLED").unwrap_or_default(),
        FileRead::Absent => return (Vec::new(), unchecked),
        FileRead::Unreadable {
            reason,
            needs_privilege,
        } => {
            unchecked.push(unchecked_persistence(
                UFW_CONF,
                format!("{reason}, so whether ufw applies its own sysctl file is unknown"),
                needs_privilege,
            ));
            return (Vec::new(), unchecked);
        }
    };
    // The two spellings ufw's own test accepts, and no others.
    if enabled != "yes" && enabled != "YES" {
        return (Vec::new(), unchecked);
    }

    let sysctl_path = match read_boot_file(ctx, UFW_DEFAULTS).await {
        FileRead::Content(content) => shell_value(&content, "IPT_SYSCTL").unwrap_or_default(),
        FileRead::Absent => return (Vec::new(), unchecked),
        FileRead::Unreadable {
            reason,
            needs_privilege,
        } => {
            unchecked.push(unchecked_persistence(
                UFW_DEFAULTS,
                format!("{reason}, so the sysctl file ufw applies at boot is unknown"),
                needs_privilege,
            ));
            return (Vec::new(), unchecked);
        }
    };
    // `[ ! -z "$IPT_SYSCTL" ]`: unset or empty and ufw applies nothing.
    if sysctl_path.is_empty() {
        return (Vec::new(), unchecked);
    }

    match read_boot_file(ctx, &sysctl_path).await {
        FileRead::Content(content) => (
            vec![LaterFile {
                path: sysctl_path,
                ordering: "ufw applies it from ufw.service, which is ordered after \
                           systemd-sysctl.service"
                    .to_string(),
                values: parse_sysctl(&content),
            }],
            unchecked,
        ),
        // `[ -s "$IPT_SYSCTL" ]`: ufw skips a file that is not there.
        FileRead::Absent => (Vec::new(), unchecked),
        FileRead::Unreadable {
            reason,
            needs_privilege,
        } => {
            unchecked.push(unchecked_persistence(
                &sysctl_path,
                format!(
                    "{reason}, and ufw applies it at every start (IPT_SYSCTL in {UFW_DEFAULTS})"
                ),
                needs_privilege,
            ));
            (Vec::new(), unchecked)
        }
    }
}

/// The finding for one managed parameter another package's file decides.
///
/// Severity is the parameter's own, unchanged. It ranks the security
/// consequence of the setting being wrong, and the consequence here is exactly
/// that consequence, arriving at the next boot rather than now; the durability
/// of the deviation is what the title and explanation carry. This follows the
/// vendor-layer finding in `crate::permissions`, which is the same shape and
/// keeps the directive's own severity for a violation this tool will not fix.
fn overridden_finding(
    parameter: &KernelParameter,
    config: &PluginConfig,
    file: &LaterFile,
    value: &str,
    target: &str,
) -> Finding {
    let name = parameter.kernel_parameter_name;
    let path = &file.path;
    Finding {
        finding_category: FindingCategory::Kernel,
        finding_current_value: value.to_string(),
        finding_description: parameter.kernel_description.to_string(),
        finding_explanation: format!(
            "{path} sets {name} to '{value}' after {SYSCTL_HARDENER_CONF} has been applied, \
             because {}. From the next boot the host runs '{value}' rather than the '{target}' \
             this tool persists",
            file.ordering,
        ),
        finding_id: format!("kernel_boot_override_{}", name.replace('.', "_")),
        finding_impact: format!(
            "Hardening of {name} does not survive a reboot, so a host that reports compliant \
             today is not compliant after the next restart"
        ),
        finding_recommended_value: target.to_string(),
        finding_remediation_steps: vec![
            format!(
                "Set {name} to '{target}' in {path}, or remove that line so {SYSCTL_HARDENER_CONF} decides it"
            ),
            format!(
                "This tool does not edit another package's configuration file, so it cannot \
                 correct this for you; run `sysctl -n {}` after the change to confirm it",
                procfs_key(name),
            ),
        ],
        finding_severity: parameter.kernel_severity,
        finding_title: format!("{name} is overridden after boot by {path}"),
        finding_compliance: super::get_compliance_mappings(name),
        finding_exception: config.exception_outcome(name, value),
        finding_exception_key: Some(name.to_string()),
    }
}

/// The unchecked entry for a file this reader could not fully resolve.
fn unchecked_glob(file: &LaterFile) -> UncheckedCheck {
    unchecked_persistence(
        &file.path,
        format!(
            "{} assigns sysctls through glob patterns, which this scan does not resolve, and \
             {}, so whether it overrides these settings is unknown",
            file.path, file.ordering,
        ),
        false,
    )
}

/// The value each parameter ends up with, from a set of files already in
/// application order, later files winning.
fn merge_effective(ordered: &[LaterFile]) -> HashMap<String, (&LaterFile, String)> {
    let mut effective = HashMap::new();
    for file in ordered {
        for (key, value) in &file.values.values {
            effective.insert(key.clone(), (file, value.clone()));
        }
    }
    effective
}

/// Every managed parameter another file decides after this tool's drop-in, and
/// everything about that question this scan could not answer.
///
/// Only a LOOSER value is a finding, judged by the parameter's own
/// [`crate::strictness::Strictness`] rather than by a second spelling of the
/// rule. Read on the arch host 2026-07-31, `/etc/ufw/sysctl.conf` touches eight
/// parameters this plugin manages: two `log_martians` at 0 against a target of
/// 1, and six at exactly their targets (two `rp_filter`, two ipv4
/// `accept_source_route`, two `accept_redirects`). A check that reported a
/// parameter for merely appearing in that file emits those six on every arch
/// and debian host, and one that compared numerically would score `rp_filter`
/// loose mode 2 compliant against strict mode 1.
pub(super) async fn boot_persistence(
    ctx: &Context,
    config: &PluginConfig,
) -> (Vec<Finding>, Vec<UncheckedCheck>) {
    // The scan path wants the findings and the unchecked list only. The name
    // narrowing is a rollback-probe concern: this caller is asking which files
    // beat this tool's own drop-in, not which file decided a running value.
    let DropinSweep {
        files: dropins_read,
        mut unchecked,
        ..
    } = dropins(ctx, DropinScope::AfterOurs).await;
    let (ufw, ufw_unchecked) = ufw_applied_file(ctx).await;
    unchecked.extend(ufw_unchecked);

    // ufw last: it runs from a unit ordered after systemd-sysctl, so it lands
    // after every drop-in whatever those are called. Folding the two mechanisms
    // into one ordered application is what stops a drop-in being reported for a
    // value ufw then sets back, which the host would never actually run.
    let ordered: Vec<LaterFile> = dropins_read.into_iter().chain(ufw).collect();
    let effective = merge_effective(&ordered);

    let mut findings = Vec::new();
    for parameter in KERNEL_PARAMS {
        let Some((file, value)) = effective.get(&procfs_key(parameter.kernel_parameter_name))
        else {
            continue;
        };
        let target = resolved_target(parameter, config);
        if parameter.kernel_compare.violated_by(&target, Some(value)) {
            findings.push(overridden_finding(parameter, config, file, value, &target));
        }
    }

    unchecked.extend(
        ordered
            .iter()
            .filter(|file| !file.values.glob_patterns.is_empty())
            .map(unchecked_glob),
    );
    (findings, unchecked)
}

/// What the configuration surviving a rollback assigns, and which files this
/// reader could not fully resolve.
///
/// The unresolved list is not a detail: a glob-assigning file may or may not
/// name a parameter, and reporting it as "no file names this" would turn an
/// unanswered question into a confident claim.
pub(super) struct EffectiveBoot {
    /// Assignments keyed by [`procfs_key`].
    pub(super) values: BTreeMap<String, String>,
    /// The path of the file each key in `values` took its value from, keyed
    /// alike. [`merge_effective`] already decides which file wins, and a
    /// finding that has to send an operator somewhere is worth far more when
    /// it names the file than when it says "a drop-in": the same key can be
    /// assigned by several, and only one of them decides.
    pub(super) sources: BTreeMap<String, String>,
    /// Paths whose assignments this reader could not resolve, and paths it
    /// could not read at all, each with the reason. Every entry here still
    /// earns its own row: see the caller in `divergence.rs`.
    pub(super) unresolved: Vec<String>,
    /// Glob patterns, keyed by [`procfs_key`], from files this reader COULD
    /// read but whose glob assignments it did not resolve. A parameter's
    /// attribution is blocked only when [`glob_could_match`] says one of
    /// these could name it: a pattern is evidence against the specific keys
    /// it might reach, not against every managed parameter at once.
    pub(super) glob_patterns: Vec<String>,
    /// True when a source is unresolved in a way no name can narrow: a
    /// directory that could not be listed, or a ufw file that could not be
    /// read. The first hides an unknown set of names; the second is chained
    /// last whatever it is called. Either could name anything, so this blocks
    /// attribution for every parameter.
    pub(super) blocks_all: bool,
    /// The lexicographically last drop-in FILE this reader could not read.
    ///
    /// Kept apart from `blocks_all` because a name is evidence (#145). Under
    /// last-one-wins, an unread file whose name sorts before the file that
    /// decided a key cannot have decided that key, so it need not block it.
    /// See [`decided_after`], which is the only place that comparison is made.
    pub(super) unreadable_last_name: Option<String>,
}

/// Whether an unread drop-in could have decided a key the deciding file
/// `source` was credited with.
///
/// The comparison is on FILENAMES, because that is what both appliers sort on
/// (`sysctl.d(5)` and `sysctl(8) --system`, both read on 2026-08-09), and it is
/// `>=` rather than `>` on purpose: equality cannot arise today, since
/// `chosen` holds exactly one path per name and that path is either read or
/// unreadable, never both. Should that invariant ever break, `>=` blocks and
/// `>` would not, and blocking is the direction this module fails in.
///
/// `None` for `source` is the silence case, where no file was credited at all
/// and any unread name could be the one naming it.
pub(super) fn decided_after(unreadable_last_name: Option<&str>, source: Option<&str>) -> bool {
    let Some(unread) = unreadable_last_name else {
        return false;
    };
    let Some(source) = source else {
        return true;
    };
    let deciding = Path::new(source)
        .file_name()
        .and_then(|name| name.to_str())
        // A credited source with no filename is not something this module
        // produces, and guessing which way it sorts would be inventing the
        // answer. Blocked, like every other question it cannot settle.
        .unwrap_or("");
    unread >= deciding
}

/// What the boot sequence leaves each managed key at, and what stopped this
/// reader from saying so where it could not.
pub(super) async fn effective_boot_values(ctx: &Context, scope: DropinScope) -> EffectiveBoot {
    let DropinSweep {
        files: dropins_read,
        unchecked,
        unreadable_last_name,
        dir_unlisted,
    } = dropins(ctx, scope).await;
    let (ufw, ufw_unchecked) = ufw_applied_file(ctx).await;
    // ufw last, for the reason `boot_persistence` gives: its unit is ordered
    // after systemd-sysctl, so it lands after every drop-in.
    let ordered: Vec<LaterFile> = dropins_read.into_iter().chain(ufw).collect();

    let mut values = BTreeMap::new();
    let mut sources = BTreeMap::new();
    for (key, (file, value)) in merge_effective(&ordered) {
        values.insert(key.clone(), value);
        sources.insert(key, file.path.clone());
    }

    let mut unresolved: Vec<String> = ordered
        .iter()
        .filter(|file| !file.values.glob_patterns.is_empty())
        .map(|file| {
            format!(
                "{} assigns sysctls through glob patterns, which this scan does not resolve",
                file.path
            )
        })
        .collect();
    // A directory nobody could list, or a ufw file nobody could read, blocks
    // every parameter: the first hides an unknown set of names, and the second
    // is chained last whatever it is called, because ufw's unit is ordered
    // after systemd-sysctl. An unreadable drop-in FILE is no longer in here,
    // because its name says which keys it could reach (#145).
    let blocks_all = dir_unlisted || !ufw_unchecked.is_empty();
    unresolved.extend(
        unchecked
            .iter()
            .chain(ufw_unchecked.iter())
            .map(|u| u.unchecked_reason.clone()),
    );
    let glob_patterns: Vec<String> = ordered
        .iter()
        .flat_map(|file| file.values.glob_patterns.iter().cloned())
        .collect();

    EffectiveBoot {
        values,
        sources,
        unresolved,
        glob_patterns,
        blocks_all,
        unreadable_last_name,
    }
}

/// The file `procps sysctl --system` reads that `systemd-sysctl` does not.
const LEGACY_SYSCTL_CONF: &str = "/etc/sysctl.conf";

/// The applier this probe recognises. Its presence is the capability the
/// rollback sentence depends on, and it is probed rather than assumed from
/// the host being a systemd one.
const SYSTEMD_SYSCTL: &str = "/usr/lib/systemd/systemd-sysctl";

/// What `/etc/sysctl.conf` assigns, for the one caller that needs it.
///
/// An absent file gives every field empty, which is the honest reading: the
/// file names nothing because it is not there. A file that exists and could
/// not be read fills `unreadable` instead, because a read that failed is not
/// an absence and must not be folded into one.
#[derive(Default)]
pub(super) struct LegacyConf {
    /// Explicit assignments keyed by [`procfs_key`].
    pub(super) values: BTreeMap<String, String>,
    /// Glob patterns keyed the same way, unresolved, for
    /// [`glob_could_match`].
    pub(super) glob_patterns: Vec<String>,
    /// Set when the file exists and could not be read, carrying the reason.
    pub(super) unreadable: Option<String>,
}

/// Whether the applier that runs at boot reads [`LEGACY_SYSCTL_CONF`].
///
/// There is deliberately no `Reads` variant. Nothing measured produces one:
/// `procps.service` on Debian 13 is systemd's own unit under a compatibility
/// name (`ExecStart=/usr/lib/systemd/systemd-sysctl`), and no tested
/// distribution ships a unit that runs `sysctl --system` at boot. A variant no
/// code path can construct would be a claim about the world with no evidence
/// behind it. If a real second applier is ever found, it is named here the way
/// ufw is named in [`ufw_applied_file`], never inferred.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Reach {
    /// The boot applier does not read this file **by that path**, and no
    /// `sysctl --system` runs at boot, so nothing at boot applies the file
    /// because it is `/etc/sysctl.conf`.
    ///
    /// What this does NOT settle is whether the file's content reaches the
    /// boot sequence by another name: a host can link
    /// `/etc/sysctl.d/99-sysctl.conf` at the same inode, and the drop-in
    /// reader then applies that content under the drop-in's name. A caller
    /// wording a sentence on this answer says what does not run at boot, or
    /// which file decides among the ones that do, unless it has established
    /// that a linked file could not have reached the branch it is wording:
    /// only then may it say the boot applier ignores the legacy file's
    /// content, and the caller in `divergence.rs` marks which of its arms has
    /// established that and which has not.
    DoesNotRead,
    /// No applier this probe recognises, so the question was not answered.
    Unknown,
}

/// Reads `/etc/sysctl.conf`, which the rollback's own `sysctl --system` reload
/// applies and the boot applier does not.
///
/// The scan must never call this. Its question is which file overrides this
/// tool's own, and a file the boot applier does not read cannot override
/// anything at boot.
pub(super) async fn legacy_sysctl_conf(ctx: &Context) -> LegacyConf {
    match read_boot_file(ctx, LEGACY_SYSCTL_CONF).await {
        FileRead::Content(content) => {
            let parsed = parse_sysctl(&content);
            LegacyConf {
                values: parsed.values,
                glob_patterns: parsed.glob_patterns,
                unreadable: None,
            }
        }
        FileRead::Absent => LegacyConf::default(),
        FileRead::Unreadable { reason, .. } => LegacyConf {
            unreadable: Some(reason),
            ..LegacyConf::default()
        },
    }
}

/// Which applier runs at boot, as a capability rather than a host label.
pub(super) async fn boot_reads_legacy_conf(ctx: &Context) -> Reach {
    match ctx.executor().path_exists(Path::new(SYSTEMD_SYSCTL)).await {
        Ok(true) => Reach::DoesNotRead,
        // A probe that answered "absent" and a probe that errored are the same
        // answer here: no applier was identified, so nothing is claimed.
        _ => Reach::Unknown,
    }
}

#[cfg(test)]
mod tests;
