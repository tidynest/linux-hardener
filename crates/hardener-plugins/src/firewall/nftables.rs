//! Nftables firewall backend implementation.
//!
//! This backend manages firewall rules on modern Linux systems using nftables.
//! Nftables is the modern replacement for iptables and is used on Fedora, Debian 10+,
//! Ubuntu 20.04+, Arch Linux, and other distributions.

use crate::firewall::{FirewallBackend, Rule, get_baseline_rules};
use async_trait::async_trait;
use hardener_common::error::{HardeningError, Result};
use hardener_core::{Change, ChangeType, context::Context};
use std::net::IpAddr;
use std::path::Path;
use tracing::{info, warn};

/// The persistent ruleset `nftables.service` loads at boot on Arch and
/// Debian, and only there: Fedora and RHEL load
/// `/etc/sysconfig/nftables.conf`, and openSUSE loads
/// `/etc/nftables/rules/main.nft`. [`boot_ruleset`] probes the unit itself to
/// tell the three apart, so this constant is no longer the path a checkpoint
/// captures, a rollback restores, or a reload feeds to `nft` in general; it is
/// one distribution's boot path, kept as a named literal because two things
/// still read it as exactly that: the over-inclusive, `Context`-free match in
/// `reloads_for_path` (firewall/mod.rs), which cannot run the probe and so
/// names every shipped unit's file instead, and this file's own Arch/Debian
/// test fixtures.
pub(super) const NFTABLES_CONFIG_PATH: &str = "/etc/nftables.conf";

/// Where a rendered ruleset is parked so `nft --check` can judge it before the
/// boot path is touched.
///
/// `/run` rather than `/etc`, deliberately. It is root-owned and tmpfs, so an
/// unprivileged user cannot swap the file between the write and the check, and
/// anything left behind by an interrupted apply is gone at the next boot. It is
/// also outside every path this plugin checkpoints, so a scratch file can never
/// be mistaken for configuration to restore or delete.
pub(super) const NFTABLES_CHECK_PATH: &str = "/run/linux-hardener-nftables-check.nft";

/// The `inet` table this plugin owns, creates, replaces and is the only writer
/// of. Named once here so the table the ruleset defines and the table the diff
/// reads back cannot drift apart.
///
/// Deliberately **not** `inet filter`. That is the conventional default name,
/// not a name that belongs to anybody, and this machine's own package-shipped
/// `/etc/nftables.conf` uses it. Replacing a table outright is only honest
/// against one we created, and nothing distinguishes an `inet filter` we made
/// from an `inet filter` the administrator made: measured in a network
/// namespace, an administrator's own rules survived the old incremental path
/// and were destroyed by a `delete table inet filter` in the rendered one.
/// Owning a distinctly named table is what makes the replacement safe, and it
/// is why no `delete` in this file may ever name a table this plugin did not
/// create.
///
/// **The consequence to state plainly:** this plugin no longer merges into the
/// administrator's chain, so an accept of theirs no longer keeps a port open.
/// Both tables hook `input`, and a `drop` verdict in either ends the packet's
/// journey, so this table's `policy drop` governs whatever its own rules do
/// not accept. A port an operator wants open has to be expressed as a
/// directive to this tool. That is the same posture the plugin always
/// intended; what changes is that the `nft` load reaching it destroys nothing.
///
/// **The load. Not the whole apply.** This plugin now owns the file its
/// ruleset lives in as well as the table: the rendered ruleset is written to
/// [`HARDENER_RULESET_PATH`], a fragment nothing else writes, and the apply
/// appends a single glob include line, [`HARDENER_INCLUDE_LINE`], to whatever
/// file the boot unit loads instead of overwriting it. On a distribution
/// shipping a packaged ruleset in that file, Arch and Debian included, the
/// administrator's own `inet filter` table is untouched by the apply, so
/// there is no longer a file write for it to survive in the running kernel
/// and then lose at the next boot. That whole-file overwrite is what issue
/// #98 closed.
pub(super) const NFTABLES_TABLE: &str = "linux_hardener";

/// The directory this plugin owns for the nftables fragments it writes.
///
/// Deliberately not `/etc/nftables/`. Fedora and RHEL ship `main.nft`,
/// `nat.nft` and `router.nft` there, none of which their boot file loads (its
/// only `include` is commented out), so a glob over that directory would switch
/// three sample rulesets on for every host of that family.
pub(super) const HARDENER_RULESET_DIR: &str = "/etc/linux-hardener/nftables";

/// The rendered ruleset. Written whole on every apply, and the only nftables
/// file whose entire content belongs to this plugin.
pub(super) const HARDENER_RULESET_PATH: &str = "/etc/linux-hardener/nftables/50-linux-hardener.nft";

/// The one line appended to whatever file the boot unit loads.
///
/// A **glob**, and that is not cosmetic. Measured against nft 1.1.6 in a
/// network namespace: a glob include matching no file loads at exit 0, while a
/// literal include of a missing file is a parse error that exits 1. A rollback
/// removes [`HARDENER_RULESET_PATH`], so with a literal include the boot path
/// would refuse to parse and the host would come up unfiltered. The glob is
/// what makes the undo survivable in either order.
pub(super) const HARDENER_INCLUDE_LINE: &str = "include \"/etc/linux-hardener/nftables/*.nft\"";

/// What `systemctl show` said about the unit that loads a ruleset at boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BootRuleset {
    /// The file the unit loads, or the reason we could not tell.
    ///
    /// Three outcomes rather than two, and the `Err` carries its reason so an
    /// operator reads what failed instead of a shrug. A single value standing
    /// for several distinct outcomes is the defect family this plugin has
    /// already closed four times.
    pub(super) loads: std::result::Result<String, String>,
    /// True when the unit declares `ConditionPathExists` on the same file it
    /// loads, so systemd already treats that file's absence as "do not run".
    pub(super) condition_guards_it: bool,
}

/// Reads the unit's own `ExecStart` and returns the ruleset file it names.
///
/// Asked of the target through the executor rather than inferred from a
/// distribution table. `hardener_distro::Distribution::detect` reads
/// `/etc/os-release` with `std::fs`, which is the controller's file, so a table
/// keyed on it would be silently wrong for every `--ssh` host.
///
/// `-p` twice without `--value`, deliberately. `--value` prints values with no
/// names, and systemd omits a property the unit does not declare even under
/// `--all`, so with two properties and one missing there is no way to tell
/// which value survived. Named lines are unambiguous.
pub(super) async fn boot_ruleset(ctx: &Context) -> BootRuleset {
    let output = ctx
        .executor()
        .execute_command(
            "systemctl",
            &[
                "show",
                "nftables.service",
                "-p",
                "ExecStart",
                "-p",
                "ConditionPathExists",
            ],
        )
        .await;

    let shown = match output {
        Ok(output) if output.success() => output.stdout,
        Ok(output) => {
            return BootRuleset {
                loads: Err(format!(
                    "systemctl could not describe nftables.service: {}",
                    output.stderr.trim()
                )),
                condition_guards_it: false,
            };
        }
        Err(e) => {
            return BootRuleset {
                loads: Err(format!("systemctl could not be run: {e}")),
                condition_guards_it: false,
            };
        }
    };

    parse_boot_ruleset(
        &property(&shown, "ExecStart"),
        &property(&shown, "ConditionPathExists"),
    )
}

/// One `Name=value` line's value, or an empty string when the unit did not
/// declare that property. systemd omits an undeclared property entirely, so
/// absence and emptiness are the same answer here and both mean "not stated".
///
/// Only reachable through [`boot_ruleset`].
fn property(shown: &str, name: &str) -> String {
    shown
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .unwrap_or_default()
        .to_string()
}

/// The pure half, so every distribution's real string is a cheap test.
pub(super) fn parse_boot_ruleset(exec_start: &str, condition_path_exists: &str) -> BootRuleset {
    let loads = parse_exec_start(exec_start);
    let condition_guards_it = match &loads {
        Ok(path) => condition_path_exists
            .split_whitespace()
            .any(|declared| declared == path),
        Err(_) => false,
    };
    BootRuleset {
        loads,
        condition_guards_it,
    }
}

/// The ruleset file an `ExecStart` property names, in either form the shipped
/// units use.
///
/// Two forms because the images carry two, which was measured and not assumed:
/// Arch, Debian, Fedora and RHEL pass `-f <path>`, while openSUSE runs an
/// inline program, `nft 'flush ruleset; include "..."'`, with no `-f` anywhere.
/// A parser reading only `-f` returns "cannot tell" for every openSUSE and SLES
/// host, which would leave that family permanently unpersisted while reporting
/// nothing wrong.
///
/// Only reachable through [`parse_boot_ruleset`].
fn parse_exec_start(exec_start: &str) -> std::result::Result<String, String> {
    let trimmed = exec_start.trim();
    if trimmed.is_empty() {
        return Err(
            "systemctl reported no ExecStart for nftables.service, which is also what it \
             reports for a unit that does not exist, and it exits 0 either way"
                .to_string(),
        );
    }

    let Some((_, after)) = trimmed.split_once("argv[]=") else {
        return Err(format!(
            "the ExecStart property carries no argv[]: {trimmed:?}"
        ));
    };
    let argv = after.split(" ; ").next().unwrap_or(after);

    let mut tokens = argv.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "-f" || token == "--file" {
            return match tokens.next() {
                Some(path) => Ok(path.to_string()),
                None => Err(format!("{token} in the ExecStart names no file: {argv:?}")),
            };
        }
    }

    if let Some((_, after_include)) = argv.split_once("include \"")
        && let Some((path, _)) = after_include.split_once('"')
        && !path.is_empty()
    {
        return Ok(path.to_string());
    }

    Err(format!(
        "the ExecStart argv names no ruleset file, by -f and by include: {argv:?}"
    ))
}

/// The directory holding `path`, or `/` when it names no parent.
fn parent_of(path: &str) -> String {
    Path::new(path)
        .parent()
        .and_then(Path::to_str)
        .unwrap_or("/")
        .to_string()
}

/// Puts [`HARDENER_INCLUDE_LINE`] in `boot_path` exactly once.
///
/// Reads first and appends only when the line is absent, so a repeated apply
/// does not stack includes. An absent boot file is an ordinary outcome, not a
/// failure: openSUSE ships a unit gated on a `main.nft` a stock host does not
/// have, so creating it is what persistence means there.
///
/// A read that fails for any reason other than absence refuses, rather than
/// treating the file as empty and replacing it with one line. That conflation
/// is precisely the PAM defect this project has already fixed once.
async fn ensure_include_line(ctx: &Context, boot_path: &str) -> Result<()> {
    let path = Path::new(boot_path);
    let existing = match ctx.executor().path_exists(path).await {
        Ok(false) => String::new(),
        _ => ctx.executor().read_file(path).await.map_err(|e| {
            HardeningError::Plugin(format!(
                "Refusing to append to {boot_path}, which could not be read: {e}. \
                 Replacing a file whose content is unknown is how an administrator's \
                 ruleset gets lost."
            ))
        })?,
    };

    if existing
        .lines()
        .any(|line| line.trim() == HARDENER_INCLUDE_LINE)
    {
        return Ok(());
    }

    let separator = match existing.is_empty() || existing.ends_with('\n') {
        true => "",
        false => "\n",
    };
    let appended = format!("{existing}{separator}{HARDENER_INCLUDE_LINE}\n");
    ctx.executor()
        .write_file(path, &appended)
        .await
        .map_err(|e| HardeningError::Plugin(format!("Failed to append to {boot_path}: {e}")))
}

/// Nftables firewall backend for modern Linux systems.
///
/// Nftables uses a hierarchical structure:
/// - Tables (e.g., "inet filter") contain chains
/// - Chains (e.g., "input", "output") contain rules
/// - Rules define what to do with packets
pub struct NftablesBackend;

impl NftablesBackend {
    /// Creates a new nftables backend instance.
    pub fn new() -> NftablesBackend {
        NftablesBackend
    }

    /// Executes an nft command and returns the output.
    ///
    /// # Arguments
    /// * `ctx` - The context containing the executor.
    /// * `args` - Command arguments to pass to nft.
    ///
    /// # Returns
    /// The command output as a string, or an error if execution fails.
    async fn execute_nft(&self, ctx: &Context, args: &[&str]) -> Result<String> {
        let output = ctx
            .executor()
            .execute_command("nft", args)
            .await
            .map_err(|e| HardeningError::Plugin(format!("Failed to execute nft command: {}", e)))?;

        if !output.success() {
            return Err(HardeningError::Plugin(format!(
                "nft command failed: {}",
                output.stderr
            )));
        }

        Ok(output.stdout)
    }

    /// Loads `ruleset` live without leaving a persistent file behind.
    ///
    /// For the branch where the boot path could not be determined: nothing
    /// may be written anywhere, [`HARDENER_RULESET_PATH`] included, or an
    /// unreachable fragment would go live the moment somebody repairs the
    /// unit. The host still has to be filtered now, so the ruleset is parked
    /// in [`NFTABLES_CHECK_PATH`], the same `/run` scratch file
    /// [`Self::refuse_a_ruleset_nft_will_not_parse`] uses, loaded from there,
    /// and removed, rather than writing a second copy of that dance.
    async fn execute_nft_from_string(&self, ctx: &Context, ruleset: &str) -> Result<()> {
        ctx.executor()
            .write_file(Path::new(NFTABLES_CHECK_PATH), ruleset)
            .await
            .map_err(|e| {
                HardeningError::Plugin(format!("Could not write {NFTABLES_CHECK_PATH}: {e}"))
            })?;

        let loaded = self.execute_nft(ctx, &["-f", NFTABLES_CHECK_PATH]).await;
        if let Err(e) = ctx
            .executor()
            .execute_command("rm", &["-f", NFTABLES_CHECK_PATH])
            .await
        {
            warn!("Could not remove {NFTABLES_CHECK_PATH} after loading the ruleset live: {e}");
        }
        loaded.map(|_| ())
    }

    /// Build nftables command arguments from a Rule.
    ///
    /// Converts backend-agnostic Rule into nft command syntax:
    /// e.g., `nft add rule inet linux_hardener input tcp dport 22 accept`
    ///
    /// No caller runs this argv any more: the whole ruleset is rendered and
    /// loaded in one transaction, so the five leading elements survive only as
    /// the address the statement would be added at. They are kept, and kept
    /// correct, because both consumers slice from index 5 and a shortened
    /// prefix would silently move what `args[5..]` means.
    pub(crate) fn build_nft_rule_args(&self, rule: &Rule) -> Vec<String> {
        let mut args = vec![
            "add".to_string(),
            "rule".to_string(),
            "inet".to_string(),
            NFTABLES_TABLE.to_string(),
            "input".to_string(),
        ];

        // Handle special cases first
        if rule.rule_description.contains("loopback") {
            // Allow loopback: iif lo accept
            args.push("iif".to_string());
            args.push("lo".to_string());
            args.push("accept".to_string());
            return args;
        }

        if rule.rule_description.contains("established and related") {
            // Allow established/related: ct state established,related accept
            args.push("ct".to_string());
            args.push("state".to_string());
            args.push("established,related".to_string());
            args.push("accept".to_string());
            return args;
        }

        // Source address filter. `ip` and `ip6` are different match
        // expressions and nft infers neither, so the family comes from the
        // address itself. A value that does not parse renders as `ip` here and
        // is refused outright by `render_ruleset` before it can reach a file.
        if rule.rule_source != "any" {
            args.push(saddr_family(&rule.rule_source).to_string());
            args.push("saddr".to_string());
            args.push(rule.rule_source.clone());
        }

        // Protocol and port
        if rule.rule_protocol != "all" && rule.rule_protocol != "any" {
            args.push(rule.rule_protocol.clone());

            if rule.rule_port != "any" {
                args.push("dport".to_string());
                args.push(rule.rule_port.clone());
            }
        }

        // Action
        args.push(rule.rule_action.clone());

        args
    }

    /// Reads the current `input` chain and returns the canonical token list of
    /// each rule already present, used to skip rules that are already there.
    ///
    /// Fails CLOSED: if the chain cannot be read, an empty list is returned so
    /// every baseline rule is reported as newly added rather than skipped. That
    /// over-counts what an apply changed and can never hide a rule that
    /// genuinely needed adding, which is the direction to fail in. It cannot
    /// produce a duplicate: the table is replaced outright by the load, so this
    /// read decides the REPORT and not the ruleset.
    ///
    /// Reads [`NFTABLES_TABLE`] rather than `inet filter` because that is the
    /// table [`render_ruleset`] writes. Reading the other one would compare
    /// this apply against a chain no apply of ours maintains, so every baseline
    /// rule would report as newly added on a host that already had them all.
    async fn existing_input_rules(&self, ctx: &Context) -> Vec<Vec<String>> {
        match self
            .execute_nft(ctx, &["list", "chain", "inet", NFTABLES_TABLE, "input"])
            .await
        {
            Ok(output) => parse_input_chain_rules(&output),
            Err(e) => {
                warn!(
                    "Could not read nftables input chain ({e}); treating it as empty so \
                     baseline rules are re-added rather than skipped"
                );
                Vec::new()
            }
        }
    }

    /// Refuses a rendered ruleset `nft` will not parse, before the boot path
    /// is touched.
    ///
    /// `render_ruleset` already refuses a `source` it cannot read, and that
    /// check is worth keeping because it is pure and costs no host access. It
    /// is also, on its own, an enumeration of the fields somebody thought of.
    /// A `port` reached the file as the operator's own string until it was
    /// renotated for #99, and the same shape can return with any field this
    /// plugin later renders. Asking `nft` itself ends the class rather than the
    /// instance: the parser that would refuse the file at load time is the one
    /// that judges it here.
    ///
    /// The ordering is the entire point. `apply_rules` writes the ruleset and
    /// then loads it, so a file that renders cleanly and fails at `nft` has
    /// already replaced the ruleset `nftables.service` reads at boot, on a unit
    /// the same apply enabled. Parking the candidate in [`NFTABLES_CHECK_PATH`]
    /// and running `nft --check` against it moves that failure to a scratch
    /// file and leaves the boot path exactly as it was.
    ///
    /// Fails CLOSED in every direction: a write that fails, an `nft` that
    /// cannot be run, and a check that reports a problem all refuse the apply.
    /// The scratch file is removed whether the check passed or failed, and its
    /// removal is deliberately not allowed to mask the check's own verdict.
    async fn refuse_a_ruleset_nft_will_not_parse(
        &self,
        ctx: &Context,
        ruleset: &str,
    ) -> Result<()> {
        ctx.executor()
            .write_file(Path::new(NFTABLES_CHECK_PATH), ruleset)
            .await
            .map_err(|e| {
                HardeningError::Plugin(format!(
                    "Could not write {NFTABLES_CHECK_PATH} to check the ruleset before \
                     installing it: {e}. The boot path is untouched."
                ))
            })?;

        let checked = ctx
            .executor()
            .execute_command("nft", &["--check", "--file", NFTABLES_CHECK_PATH])
            .await;

        // Runs before the verdict is read, so the scratch file goes whichever
        // way the check went and a cleanup failure never becomes the answer.
        if let Err(e) = ctx
            .executor()
            .execute_command("rm", &["-f", NFTABLES_CHECK_PATH])
            .await
        {
            warn!("Could not remove {NFTABLES_CHECK_PATH} after checking the ruleset: {e}");
        }

        let output = checked.map_err(|e| {
            HardeningError::Plugin(format!(
                "Could not ask nft to check the ruleset before installing it: {e}. \
                 The boot path is untouched."
            ))
        })?;

        if !output.success() {
            return Err(HardeningError::Plugin(format!(
                "Refusing to install a ruleset nft will not parse: {}. \
                 The boot path is untouched.",
                output.stderr.trim()
            )));
        }
        Ok(())
    }

    /// Issue #97. An apply enables `nftables.service` and creates the file it
    /// loads; a rollback removes that file and, without this, leaves the unit
    /// enabled, so a `Type=oneshot` unit running `nft` against a missing file
    /// exits 1, enters `failed`, and the host boots unfiltered. Only reached
    /// once [`Self::reload`] has already confirmed the loaded file is absent.
    ///
    /// **Two conditions, not one.** The first attempt at this guard used only
    /// "the file is absent, therefore the unit is broken", which is false
    /// wherever the unit loads a different file: on Fedora and RHEL it names
    /// `/etc/sysconfig/nftables.conf`, so that version disabled a working
    /// firewall on exactly the family it existed for, and it was reviewed and
    /// withdrawn. `condition_guards_it` is the second condition, and the one
    /// that closes that gap: openSUSE declares `ConditionPathExists` on the
    /// very file it loads, so systemd already treats that file's absence as
    /// "do not run" rather than as a failure. There is no failing unit to
    /// prevent there, and disabling it would leave it off for an
    /// administrator who later creates the file themselves.
    ///
    /// Best effort by design: a rollback that restored every file is not a
    /// failure because a `systemctl disable` did not take.
    async fn disable_a_unit_with_nothing_to_load(
        &self,
        ctx: &Context,
        condition_guards_it: bool,
    ) -> Result<()> {
        if condition_guards_it {
            info!(
                "nftables.service is gated on the file it loads, so systemd already treats its \
                 absence as 'do not run'; leaving the unit enabled"
            );
            return Ok(());
        }

        info!("Disabling nftables.service, which is enabled with no ruleset left to load");
        if let Err(e) = ctx
            .executor()
            .execute_command("systemctl", &["disable", self.systemd_unit()])
            .await
        {
            warn!("Could not disable {}: {e}", self.systemd_unit());
        }
        Ok(())
    }

    /// Tells a `destroy` that failed because the table was never there from
    /// one that failed with the table still live. Called from [`Self::reload`]
    /// once a `destroy` has already failed and been warned about.
    ///
    /// A failed `destroy` is ambiguous by itself: an nft older than 1.0.6
    /// refuses the subcommand outright, whether the table exists or not, and
    /// an nft new enough to run it can still fail for some other reason with
    /// the table genuinely still there. `nft list table` tells the two apart:
    /// it fails when the table is absent, which is the harmless reading the
    /// caller's warning already covers, and it succeeds when the table is
    /// still live, which this refuses to let the rollback report past. A
    /// rollback that says it succeeded while `table inet linux_hardener`
    /// still carries `policy drop` is the exact defect this exists to close.
    async fn fail_if_table_survived_a_failed_destroy(
        &self,
        ctx: &Context,
        destroy_error: HardeningError,
    ) -> Result<()> {
        let still_present = self
            .execute_nft(ctx, &["list", "table", "inet", NFTABLES_TABLE])
            .await
            .is_ok();
        if !still_present {
            return Ok(());
        }

        Err(HardeningError::Plugin(format!(
            "the {NFTABLES_TABLE} table is still present after the failed destroy \
             above, so this rollback cannot report success: {destroy_error}"
        )))
    }
}

/// Reads a rule's `source` as an address, with an optional prefix length that
/// has to fit the family the address is in.
///
/// The breadth clamp that guards a `source` directive deliberately measures the
/// prefix and never the address, and says so at `field_breadth`: what a
/// malformed address does is the backend's answer to give. This is that answer.
/// `std::net` is the parser rather than a hand-rolled one, so every form nft
/// itself accepts (dotted quad, compressed IPv6, IPv4-mapped) is read the way
/// nft reads it, and the family is taken from what parsed rather than guessed
/// from the punctuation.
fn parse_source(source: &str) -> std::result::Result<IpAddr, String> {
    let (address, prefix) = match source.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (source, None),
    };
    let address: IpAddr = address
        .parse()
        .map_err(|_| format!("{address:?} is not an IPv4 or IPv6 address"))?;

    if let Some(prefix) = prefix {
        let family_bits = if address.is_ipv6() { 128 } else { 32 };
        let bits: u8 = prefix
            .parse()
            .map_err(|_| format!("{prefix:?} is not a prefix length"))?;
        if bits > family_bits {
            return Err(format!(
                "a /{bits} prefix does not fit {address}, whose family has \
                 {family_bits} bits"
            ));
        }
    }
    Ok(address)
}

/// The `nft` keyword matching a source address of `source`'s family.
///
/// Defaults to `ip` for a value that does not parse, which is never rendered
/// into a file: [`render_ruleset`] refuses such a rule before writing anything.
fn saddr_family(source: &str) -> &'static str {
    match parse_source(source) {
        Ok(address) if address.is_ipv6() => "ip6",
        _ => "ip",
    }
}

/// Canonicalises an nftables rule statement into comparable tokens.
///
/// A rule this plugin renders into its own table's `input` chain must compare
/// equal to the same rule as printed back by `nft list chain`, but nft
/// rewrites its output: a bare interface name gains quotes (`iif lo` becomes
/// `iif "lo"`) and, with handles enabled, a trailing `# handle N` comment is
/// appended. Neither changes the rule's identity, so surrounding double quotes
/// are stripped and any trailing comment dropped before comparison. Matching
/// deliberately fails CLOSED: if a present rule fails to canonicalise to the
/// same tokens, it is treated as absent and re-added.
fn canonical_rule_tokens<'a>(tokens: impl Iterator<Item = &'a str>) -> Vec<String> {
    tokens
        .take_while(|token| !token.starts_with('#'))
        .map(|token| token.trim_matches('"').to_string())
        .collect()
}

/// Extracts the canonical token list of every actual rule line in an
/// `nft list chain inet <table> input` body, skipping the structural lines
/// (table/chain headers, the base-chain `type ... hook ...` spec, braces and
/// comments). The result feeds the presence check in [`apply_rules`].
fn parse_input_chain_rules(chain_output: &str) -> Vec<Vec<String>> {
    chain_output
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with('#')
                && !line.starts_with("table")
                && !line.starts_with("chain")
                && !line.starts_with("type")
                && !line.starts_with('{')
                && !line.starts_with('}')
        })
        .map(|line| canonical_rule_tokens(line.split_whitespace()))
        .collect()
}

impl Default for NftablesBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// The complete nftables script for `rules`, loaded in one `nft -f`.
///
/// One transaction is the whole point. `enable` used to create the input chain
/// with `policy drop` and no rules, before `apply_rules` added the accepts, so
/// a remote apply severed the SSH connection carrying the rest of itself and
/// the baseline rule named "Allow SSH to prevent lockout" was never installed.
/// nftables applies a file or none of it, so here the policy is never live
/// without the accepts beside it.
///
/// `policy drop` is kept rather than traded for `accept` plus the baseline's
/// final drop rule: within the transaction it costs nothing, and it means a
/// host whose load fails outright stays closed rather than open.
///
/// Replaces [`NFTABLES_TABLE`] and nothing else, atomically, leaving every
/// other table on the host alone. Two drafts of this file were rejected before
/// this one, in the same direction and for the same reason.
///
/// A whole-ruleset `flush ruleset` came first: Docker, libvirt, and
/// iptables-nft all create their own nftables tables on a host that also runs
/// this plugin (this backend's own `is_enabled` already documents that), and
/// flushing would tear all of them down on every apply, taking container and
/// VM networking with it. Scoping the same three statements to `inet filter`
/// came second, and was narrower without being correct: `inet filter` is the
/// conventional default name rather than an owned one, so
/// `delete table inet filter` destroyed an administrator's own rules on any
/// host using it, which was measured rather than argued. Only a distinctly
/// named table can be replaced outright in good conscience, which is what
/// [`NFTABLES_TABLE`] is for and what its doc comment records.
///
/// The bare `table inet <name>` first creates the table if it is absent, so
/// the following `delete` cannot fail on a host that never had one; the final
/// definition then rebuilds it with the baseline rules. All three statements
/// land in the one `nft -f`, so the ordering guarantee below is unaffected:
/// nothing this plugin does not own is ever touched, and the table it does own
/// is replaced outright rather than merged into, which is what stops a
/// repeated apply from stacking duplicate rules.
///
/// Statements come from [`NftablesBackend::build_nft_rule_args`], sliced from
/// index 5 exactly as `apply_rules` slices it, so the file and the diff cannot
/// come to disagree about what a rule means.
///
/// Fallible for one reason, and it is the transaction's own doing. A source
/// nft cannot read costs one refused `nft add rule` under a per-rule path,
/// leaving the other baseline rules in force; under one transaction it costs
/// the entire load, so **no** baseline rule lands, drop-all included. The write
/// happens before the load, so the host would be left holding a ruleset
/// `nftables.service` cannot parse at the path it loads at boot, on a unit
/// `enable` marked to start there earlier in the same apply. Refusing here is
/// what keeps that file from ever being written.
///
/// Two things it does NOT mean. The apply has already taken its checkpoint and
/// already enabled the unit by the time this runs, so an `Err` here leaves an
/// enabled unit with no ruleset to load, which is issue #97's state reached by
/// a route no rollback covers. And this refuses a **source** alone: a `port`
/// reaches the rendered file as the operator's own string, so `"+22"` renders,
/// is written, and is refused by `nft` at load, while `"022"` renders, loads,
/// and means port 18 because `nft` reads a leading zero as octal where the
/// validator read it as decimal.
pub(super) fn render_ruleset(rules: &[Rule]) -> Result<String> {
    let backend = NftablesBackend::new();
    let mut statements = Vec::with_capacity(rules.len());

    for rule in rules {
        let args = backend.build_nft_rule_args(rule);

        // Checked against what this rule RENDERS, not against what it carries.
        // Reading `rule_source` directly refused an apply over a source that
        // could never reach `nft`: `build_nft_rule_args` returns early for the
        // loopback and established rules and emits no `saddr` for either, and
        // the breadth clamp admits junk in a `source` because it measures
        // prefix width alone. Locating the `saddr` this rule actually emits
        // keeps the check and the statement describing one thing.
        if let Some(index) = args.iter().position(|token| token == "saddr") {
            let source = &args[index + 1];
            parse_source(source).map_err(|reason| {
                HardeningError::Plugin(format!(
                    "Refusing to render the nftables ruleset: the rule {:?} \
                     matches on the source {source:?}, which cannot be matched \
                     on, because {reason}. Nothing has been written or loaded.",
                    rule.rule_description
                ))
            })?;
        }

        statements.push(format!("        {}", args[5..].join(" ")));
    }

    Ok(format!(
        "table inet {NFTABLES_TABLE}\n\
         delete table inet {NFTABLES_TABLE}\n\
         table inet {NFTABLES_TABLE} {{\n\
         \x20   chain input {{\n\
         \x20       type filter hook input priority 0; policy drop;\n\
         {}\n\
         \x20   }}\n\
         \x20   chain forward {{\n\
         \x20       type filter hook forward priority 0; policy drop;\n\
         \x20   }}\n\
         \x20   chain output {{\n\
         \x20       type filter hook output priority 0; policy accept;\n\
         \x20   }}\n\
         }}\n",
        statements.join("\n")
    ))
}

#[async_trait]
impl FirewallBackend for NftablesBackend {
    fn backend_name(&self) -> &str {
        "nftables"
    }

    /// The file this host boots from, plus the fragment this plugin writes.
    ///
    /// The boot file is probed rather than assumed: Fedora and RHEL load
    /// `/etc/sysconfig/nftables.conf` and openSUSE loads
    /// `/etc/nftables/rules/main.nft`, so a constant would checkpoint a file
    /// those hosts never read while leaving the one they do read undeclared.
    ///
    /// A probe that cannot answer still yields `Ok`, carrying only our own
    /// fragment, [`HARDENER_RULESET_PATH`]. This call sits before the enable
    /// and the live load in `apply` (`firewall/mod.rs`), so an `Err` here used
    /// to abort both and leave the host with no firewall at all merely because
    /// the boot path could not be named, which is a worse outcome than the
    /// unreadable probe itself. The apply must go on so the host is filtered
    /// now, even though persistence across a reboot is not achieved on that
    /// host.
    ///
    /// An empty list was rejected too. A checkpoint is an assertion about the
    /// world at the moment it is taken; if a later apply succeeds and writes
    /// the fragment, rolling back to a checkpoint that named nothing would
    /// leave that fragment in place instead of removing it. Declaring a path
    /// this particular apply may not manage to write is ordinarily dangerous,
    /// because a checkpoint row recorded absent is an instruction to delete,
    /// and a file that arrives afterwards from a package or an administrator
    /// would then be deleted on rollback. That danger does not apply to
    /// [`HARDENER_RULESET_PATH`]: nothing but this plugin ever writes it.
    async fn checkpoint_paths(&self, ctx: &Context) -> Result<Vec<String>> {
        let probed = boot_ruleset(ctx).await;
        match probed.loads {
            Ok(boot_path) => Ok(vec![boot_path, HARDENER_RULESET_PATH.to_string()]),
            Err(why) => {
                warn!(
                    "Cannot determine which file nftables.service loads at boot, so only our \
                     own fragment is checkpointed and boot persistence will not be achieved: \
                     {why}"
                );
                Ok(vec![HARDENER_RULESET_PATH.to_string()])
            }
        }
    }

    fn systemd_unit(&self) -> &'static str {
        "nftables"
    }

    async fn detect(&self, ctx: &Context) -> Result<bool> {
        // Check if nft command exists using executor.
        ctx.executor()
            .command_exists("nft")
            .await
            .map_err(|e| HardeningError::Plugin(e.to_string()))
    }

    async fn is_enabled(&self, ctx: &Context) -> Result<()> {
        // Check if nftables is acting as a packet-filtering firewall.
        //
        // A bare `table` in the ruleset is not sufficient evidence: Docker,
        // libvirt, and iptables-nft all create their own nftables tables
        // (NAT/routing, not filtering) on hosts whose admin intends a
        // different backend such as ufw or firewalld. Counting those would
        // wrongly select nftables here, suppressing the "firewall disabled"
        // finding and writing rules alongside tables owned by another
        // subsystem. A packet-filtering firewall is only "active" if some
        // chain actually hooks input, so require that instead.
        let output = self.execute_nft(ctx, &["list", "ruleset"]).await?;

        if output.contains("hook input") {
            Ok(())
        } else {
            Err(HardeningError::Plugin(
                "Nftables has no active input-hook chain".to_string(),
            ))
        }
    }

    async fn enable(&self, ctx: &Context) -> Result<()> {
        info!("Enabling nftables firewall");

        // Only the boot-persistence symlink lives here now; the managed table
        // and chains are no longer built in this step. This function used to
        // create an `inet filter` table with an input chain carrying `policy
        // drop` and not one rule in it, running before `apply_rules` had
        // written a single accept. Over SSH that drop policy went live and
        // severed the very connection the rest of the apply was arriving on,
        // which was issue #92. `apply_rules` now writes the whole ruleset,
        // baseline accepts included, and loads it as one `nft -f` transaction,
        // so the table and chains come into being together with the rules
        // that make `policy drop` survivable.
        //
        // Deliberately `enable`, not `enable --now` or a separate `start`:
        // `apply_rules` runs after this and loads the ruleset itself, so the
        // firewall is already live by the time this function's caller moves
        // on. All that is missing without this call is persistence across a
        // reboot, which `systemctl enable` alone provides. Starting the unit
        // here as well would be redundant at best, and if it ran before
        // `apply_rules` had ever written the boot path, it would ask the
        // unit to load a file that does not exist yet.
        let output = ctx
            .executor()
            .execute_command("systemctl", &["enable", self.systemd_unit()])
            .await
            .map_err(|e| HardeningError::Plugin(format!("Failed to enable nftables: {e}")))?;

        if !output.success() {
            return Err(HardeningError::Plugin(format!(
                "Failed to enable nftables: {}",
                output.stderr
            )));
        }

        info!("Nftables firewall enabled successfully");
        Ok(())
    }

    /// Undoes what [`Self::apply_rules`] did: removes the table it installed,
    /// then feeds the file this host actually boots from back to `nft`.
    ///
    /// **The table, first and unconditionally.** Restoring the pre-apply boot
    /// file and loading it does not remove `inet linux_hardener`, because
    /// that file never mentioned it: without this, a rollback reports success
    /// while the host stays hardened until its next reboot. `nft destroy
    /// table` does not fail on a table that is not there, but only on an nft
    /// new enough to know the subcommand at all: `destroy` landed in nftables
    /// 1.0.6 (January 2023), and README.md commits this project to RHEL 9 and
    /// later, whose 9.0 ships 1.0.1, where `destroy` is a parse error and
    /// exits 1 whatever the table holds. A failed destroy is therefore not by
    /// itself proof the table survived; [`Self::reload`] asks `nft list
    /// table` to tell the two cases apart before it decides whether the
    /// failure was harmless. It runs even when the boot path below cannot be
    /// determined, because removing the applied table is the whole of what
    /// the rollback is for.
    ///
    /// [`Self::enable`] is not a substitute for the reload that follows: it
    /// only marks the systemd unit to start at the next boot and never reads
    /// the restored file at all, so a rollback that called it instead would
    /// leave the applied posture live - a host whose firewall was inactive
    /// before the apply would come out of the undo still filtering traffic.
    ///
    /// **The probed path, not [`NFTABLES_CONFIG_PATH`].** [`boot_ruleset`]
    /// asks the target which file `nftables.service` actually loads, because
    /// Fedora and RHEL load `/etc/sysconfig/nftables.conf` and openSUSE loads
    /// `/etc/nftables/rules/main.nft`; reloading the constant would silently
    /// reload nothing on those hosts while the file they boot from went
    /// stale. What the loaded file does on load is the file's own business:
    /// every distribution's shipped `nftables.conf` opens with
    /// `flush ruleset`, so loading it replaces the live ruleset outright, and
    /// one that does not will merge instead, which is the behaviour that
    /// host's own boot gives it.
    ///
    /// Guarded on the probed file's presence, through the executor so the
    /// answer is the target's and not the controller's. Absence confirmed is
    /// the only case that skips the load: `nft -f` on a file that is not
    /// there exits 1, and running it anyway would turn a rollback that had
    /// done everything possible into a reported failure. Anything else,
    /// including a probe that could not tell which file to load, still
    /// attempts the load so a genuine refusal is surfaced.
    ///
    /// **The #97 guard.** Once the load is skipped for confirmed absence, see
    /// [`Self::disable_a_unit_with_nothing_to_load`] for what happens to the
    /// unit itself.
    async fn reload(&self, ctx: &Context) -> Result<()> {
        // Removed before anything is loaded: the restored boot file below
        // never mentions this table, so nothing else in this function could
        // remove it.
        if let Err(e) = self
            .execute_nft(ctx, &["destroy", "table", "inet", NFTABLES_TABLE])
            .await
        {
            warn!("Could not remove the {NFTABLES_TABLE} table during rollback: {e}");
            self.fail_if_table_survived_a_failed_destroy(ctx, e).await?;
        }

        // Destructured rather than matched on `probed.loads` directly:
        // `condition_guards_it` is still needed below, in the branch that
        // skips the load, and a `let Ok(boot_path) = probed.loads else {..}`
        // would move `loads` out of `probed` and leave nothing later able to
        // borrow the struct whole.
        let BootRuleset {
            loads,
            condition_guards_it,
        } = boot_ruleset(ctx).await;
        let Ok(boot_path) = loads else {
            warn!(
                "Cannot tell which file nftables.service loads, so nothing was reloaded: {}",
                loads.unwrap_err()
            );
            return Ok(());
        };

        if matches!(
            ctx.executor().path_exists(Path::new(&boot_path)).await,
            Ok(false)
        ) {
            info!("{boot_path} is absent on this host, so there is nothing for nft to reload");
            return self
                .disable_a_unit_with_nothing_to_load(ctx, condition_guards_it)
                .await;
        }

        info!("Reloading the nftables ruleset from {boot_path}");
        self.execute_nft(ctx, &["-f", &boot_path]).await?;
        Ok(())
    }

    async fn apply_rules(&self, ctx: &Context, rules: &[Rule]) -> Result<Vec<Change>> {
        // The diff runs BEFORE the write and load rather than per rule as the
        // load happens: the whole ruleset lands in one `nft -f` transaction
        // (see `render_ruleset`), so there is no longer a per-rule `nft add
        // rule` call left to report Skipped or FirewallRule against as it
        // runs. `ApplyResult::applied_change_count()` and `Change::is_skipped`
        // still have to mean what they meant before this change, so the diff
        // below classifies each rule exactly as the old per-rule path did:
        // present -> Skipped, absent -> FirewallRule.
        //
        // `existing_input_rules` fails CLOSED: an unreadable chain, including
        // one that does not exist yet on a host with no managed chain, reads
        // as empty. Under this diff-first flow that means every baseline rule
        // is reported FirewallRule rather than Skipped, and never the other
        // way round, so a read failure over-counts what changed; it can never
        // hide a rule that genuinely needed adding.
        //
        // Rendered first, before the host is touched at all. `render_ruleset`
        // refuses a rule whose source it cannot express, and a refusal has to
        // land while nothing has happened yet: the write precedes the load, so
        // a ruleset rendered and then refused by `nft` would already be sitting
        // at the boot path.
        let ruleset = render_ruleset(rules)?;
        self.refuse_a_ruleset_nft_will_not_parse(ctx, &ruleset)
            .await?;
        let existing = self.existing_input_rules(ctx).await;
        let mut changes = Vec::with_capacity(rules.len());

        for rule in rules {
            let nft_args = self.build_nft_rule_args(rule);
            // The rule statement is everything after `add rule <family> <table> <chain>`.
            let wanted = canonical_rule_tokens(nft_args[5..].iter().map(String::as_str));

            changes.push(if existing.contains(&wanted) {
                info!("nftables rule already present: {}", rule.rule_description);
                Change {
                    change_description: format!(
                        "Firewall rule already present: {}",
                        rule.rule_description
                    ),
                    change_type: ChangeType::Skipped,
                    change_success: true,
                    change_error: None,
                }
            } else {
                Change {
                    change_description: format!("Added firewall rule: {}", rule.rule_description),
                    change_type: ChangeType::FirewallRule,
                    change_success: true,
                    change_error: None,
                }
            });
        }

        // Probed before anything is written. A boot path that cannot be
        // determined is not a reason to guess: the ruleset still loads, so the
        // host is filtered now, and the operator is told persistence did not
        // happen rather than left believing it did.
        let probed = boot_ruleset(ctx).await;
        let Ok(boot_path) = probed.loads else {
            let why = probed.loads.unwrap_err();
            warn!("nftables ruleset will not persist across a reboot: {why}");
            self.execute_nft_from_string(ctx, &ruleset).await?;
            changes.push(Change {
                change_description: format!(
                    "Firewall rules are live but will not persist across a reboot: {why}"
                ),
                change_type: ChangeType::Skipped,
                change_success: true,
                change_error: None,
            });
            return Ok(changes);
        };

        // Our own fragment, written whole. write_file cannot create a missing
        // parent, and neither directory is guaranteed: /etc/linux-hardener
        // exists only where a signing key was created, and openSUSE's
        // /etc/nftables/rules does not exist at all on a stock host.
        for directory in [HARDENER_RULESET_DIR, parent_of(&boot_path).as_str()] {
            ctx.executor()
                .execute_command("mkdir", &["-p", directory])
                .await
                .map_err(|e| {
                    HardeningError::Plugin(format!("Failed to create {directory}: {e}"))
                })?;
        }

        ctx.executor()
            .write_file(Path::new(HARDENER_RULESET_PATH), &ruleset)
            .await
            .map_err(|e| {
                HardeningError::Plugin(format!("Failed to write {HARDENER_RULESET_PATH}: {e}"))
            })?;

        // One appended line, never a rewrite. The administrator's own table is
        // defined in this file on Arch and Debian, and issue #98 is what
        // replacing it wholesale cost them.
        ensure_include_line(ctx, &boot_path).await?;

        // Only our own fragment is loaded, not the boot file. Our file is
        // self-contained (table, delete table, table { ... }), so the live
        // effect matches the old whole-file write, while the administrator's
        // live table is never re-loaded underneath them. Boot composes the two
        // through the include.
        self.execute_nft(ctx, &["-f", HARDENER_RULESET_PATH])
            .await?;

        Ok(changes)
    }

    fn get_default_rules(&self) -> Vec<Rule> {
        // Use the shared baseline, backend-agnostic rules.
        get_baseline_rules()
    }
}
