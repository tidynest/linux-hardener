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
//! This is report-only. Editing another package's configuration file is not
//! something this tool does, and the precedent is the vendor-layer reporting in
//! `crate::permissions`: the finding names the file, the parameter, the value
//! that file sets and the target it undercuts, so an operator can act without a
//! second investigation, and the apply writes nothing new.

use super::{KERNEL_PARAMS, KernelParameter, SYSCTL_HARDENER_CONF, resolved_target};
use hardener_common::{error::is_permission_denied, types::FindingCategory};
use hardener_core::{
    PluginConfig,
    context::Context,
    plugin::{Finding, UncheckedCheck},
};
use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
};

/// The drop-in directories `systemd-sysctl` merges, **highest precedence
/// first**, as `sysctl.d(5)` lists them in its SYNOPSIS. These four are also
/// the only paths `/usr/lib/systemd/systemd-sysctl` names, read off the binary
/// 2026-07-31; `/etc/sysctl.conf` is not among them, and a distribution that
/// still wants it applied reaches it through a `/etc/sysctl.d/99-sysctl.conf`
/// symlink, which is a file in one of these directories and needs no special
/// case here.
const SYSCTL_DROPIN_DIRS: &[&str] = &[
    // The one this tool writes into is named once, in the parent module.
    super::SYSCTL_DROPIN_DIR,
    "/run/sysctl.d",
    "/usr/local/lib/sysctl.d",
    "/usr/lib/sysctl.d",
];

/// ufw's enablement flag, and the file that carries it.
const UFW_CONF: &str = "/etc/ufw/ufw.conf";
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
    /// Whether the file also assigns through a glob pattern. Those are not
    /// resolved here: the pattern language carries exclusions and an
    /// explicit-key precedence rule, and a half-implemented matcher is how a
    /// false finding gets built. Reported as unchecked instead, so a file this
    /// reader cannot fully resolve is not mistaken for a file that agrees.
    globbed: bool,
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
            parsed.globbed = true;
            continue;
        }
        parsed
            .values
            .insert(procfs_key(key), value.trim().to_string());
    }
    parsed
}

/// The last value `key` is assigned in a shell-sourced configuration file.
///
/// `/etc/default/ufw` and `/etc/ufw/ufw.conf` are both `.`-sourced by
/// `ufw-init-functions`, so the last assignment wins and a commented-out line
/// is not an assignment at all.
fn shell_value(content: &str, key: &str) -> Option<String> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let line = line.strip_prefix("export ").unwrap_or(line);
            let (name, value) = line.split_once('=')?;
            (name.trim() == key).then(|| value.trim().trim_matches(['"', '\'']).to_string())
        })
        .next_back()
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
    UncheckedCheck {
        unchecked_check_id: persistence_check_id(path),
        unchecked_title: "Kernel parameters survive a reboot".to_string(),
        unchecked_category: FindingCategory::Kernel,
        unchecked_reason: reason,
        unchecked_needs_privilege: needs_privilege,
        unchecked_compliance: super::coverage(),
    }
}

/// Every `sysctl.d` drop-in that sorts after this tool's file, in the order
/// `systemd-sysctl` applies them.
async fn later_dropins(ctx: &Context) -> (Vec<LaterFile>, Vec<UncheckedCheck>) {
    // An empty name here would sort before every drop-in on the host and turn
    // the whole of `sysctl.d` into findings, so this is asserted rather than
    // defaulted: it is this tool's own constant.
    let ours = Path::new(SYSCTL_HARDENER_CONF)
        .file_name()
        .and_then(|name| name.to_str())
        .expect("this tool's own drop-in path must end in a filename");
    let mut unchecked = Vec::new();
    // Keyed by filename, which is both the precedence order systemd-sysctl
    // sorts by and the identity a higher-precedence directory replaces on.
    let mut chosen: BTreeMap<String, String> = BTreeMap::new();

    for dir in SYSCTL_DROPIN_DIRS {
        let entries = match ctx.executor().read_dir(Path::new(dir)).await {
            Ok(entries) => entries,
            Err(e) => {
                unchecked.push(unchecked_persistence(
                    dir,
                    format!(
                        "{dir} could not be listed, so a drop-in overriding \
                         {SYSCTL_HARDENER_CONF} cannot be ruled out: {e}"
                    ),
                    is_permission_denied(&e),
                ));
                continue;
            }
        };
        for entry in entries {
            let Some(name) = entry.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            // Only `.conf` is read, and only a name sorting strictly after this
            // tool's own beats it.
            if !name.ends_with(".conf") || name <= ours {
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
            } => unchecked.push(unchecked_persistence(
                &path,
                format!("{reason}, and {name} sorts after {ours}"),
                needs_privilege,
            )),
        }
    }
    (files, unchecked)
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
        finding_policy_exception: config
            .matching_exception(name, value)
            .map(|e| e.to_finding_exception()),
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
    let (dropins, mut unchecked) = later_dropins(ctx).await;
    let (ufw, ufw_unchecked) = ufw_applied_file(ctx).await;
    unchecked.extend(ufw_unchecked);

    // ufw last: it runs from a unit ordered after systemd-sysctl, so it lands
    // after every drop-in whatever those are called. Folding the two mechanisms
    // into one ordered application is what stops a drop-in being reported for a
    // value ufw then sets back, which the host would never actually run.
    let mut effective: HashMap<String, (&LaterFile, String)> = HashMap::new();
    let ordered: Vec<LaterFile> = dropins.into_iter().chain(ufw).collect();
    for file in &ordered {
        for (key, value) in &file.values.values {
            effective.insert(key.clone(), (file, value.clone()));
        }
    }

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
            .filter(|file| file.values.globbed)
            .map(unchecked_glob),
    );
    (findings, unchecked)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two spellings `sysctl` accepts, reduced to one. Without this the
    /// tool's dotted table and ufw's procfs paths never meet, and a comparison
    /// that matches nothing reports nothing, which is the pass condition.
    #[test]
    fn both_separators_reduce_to_the_procfs_spelling() {
        assert_eq!(
            procfs_key("net.ipv4.conf.all.log_martians"),
            "net/ipv4/conf/all/log_martians"
        );
        assert_eq!(
            procfs_key("net/ipv4/conf/all/log_martians"),
            "net/ipv4/conf/all/log_martians"
        );
        assert_eq!(
            procfs_key("kernel.randomize_va_space"),
            "kernel/randomize_va_space"
        );
    }

    /// An interface name may itself contain a dot, which is the whole reason
    /// the rule is "the first separator decides" rather than "replace dots".
    #[test]
    fn the_first_separator_decides_how_the_rest_is_read() {
        // First separator a slash: dots later in the name are part of it.
        assert_eq!(
            procfs_key("net/ipv4/conf/enp3s0.200/forwarding"),
            "net/ipv4/conf/enp3s0.200/forwarding"
        );
        // First separator a dot: the two are interchanged, so the embedded
        // slash becomes the dot in the interface name.
        assert_eq!(
            procfs_key("net.ipv4.conf.enp3s0/200.forwarding"),
            "net/ipv4/conf/enp3s0.200/forwarding"
        );
    }

    #[test]
    fn a_sysctl_file_is_read_in_either_spelling_and_comments_are_not_settings() {
        let parsed = parse_sysctl(
            "# a comment\n; another\n\nnet/ipv4/conf/all/log_martians=0\n\
             net.ipv4.conf.default.rp_filter = 2\n-fs.suid_dumpable = 1\n",
        );
        assert_eq!(
            parsed.values.get("net/ipv4/conf/all/log_martians"),
            Some(&"0".to_string())
        );
        assert_eq!(
            parsed.values.get("net/ipv4/conf/default/rp_filter"),
            Some(&"2".to_string())
        );
        // A leading `-` only makes the assignment failure-tolerant.
        assert_eq!(
            parsed.values.get("fs/suid_dumpable"),
            Some(&"1".to_string())
        );
        assert!(!parsed.globbed, "no pattern appears in this file");
    }

    /// The last assignment wins, which is what `sysctl` does with the file.
    #[test]
    fn a_later_line_wins_over_an_earlier_one() {
        let parsed =
            parse_sysctl("net.ipv4.conf.all.rp_filter = 0\nnet.ipv4.conf.all.rp_filter = 1\n");
        assert_eq!(
            parsed.values.get("net/ipv4/conf/all/rp_filter"),
            Some(&"1".to_string())
        );
    }

    /// A pattern is recorded as unresolved rather than skipped in silence.
    #[test]
    fn a_glob_pattern_is_not_quietly_dropped() {
        let parsed = parse_sysctl("net.ipv4.conf.*.rp_filter = 2\n-net.ipv4.conf.all.rp_filter\n");
        assert!(parsed.globbed, "the pattern must be reported as unresolved");
        assert!(
            parsed.values.is_empty(),
            "an exclusion line assigns nothing and a pattern is not resolved here"
        );
    }

    /// Shell semantics: the last assignment is the one in force, a commented
    /// line is not an assignment, and quotes are not part of the value.
    #[test]
    fn a_shell_value_is_the_last_uncommented_assignment() {
        // Three assignments of the same name: one commented out, which is not
        // an assignment at all, then two live ones, so "the last wins" is
        // pinned rather than being satisfied by there only being one.
        let content = "#IPT_SYSCTL=/etc/ufw/off.conf\nIPV6=yes\n\
                       IPT_SYSCTL=/etc/ufw/superseded.conf\n\
                       IPT_SYSCTL=\"/etc/ufw/sysctl.conf\"\nexport ENABLED=yes\n";
        assert_eq!(
            shell_value(content, "IPT_SYSCTL").as_deref(),
            Some("/etc/ufw/sysctl.conf")
        );
        assert_eq!(shell_value(content, "ENABLED").as_deref(), Some("yes"));
        assert_eq!(shell_value(content, "MISSING"), None);
    }
}
