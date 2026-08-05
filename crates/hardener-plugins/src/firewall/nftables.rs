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

/// The persistent ruleset `nftables.service` loads at boot on the distributions
/// that read this path, which is not all of them: Fedora and RHEL ship
/// `/etc/sysconfig/nftables.conf` instead, and that is issue #52.
///
/// It is also the only nftables file this plugin checkpoints. Named once here
/// so the path the checkpoint captures, the path the rollback reloads for, and
/// the path the reload actually feeds to `nft` cannot drift apart.
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
/// **The load. Not the whole apply.** The rendered ruleset is written to
/// [`NFTABLES_CONFIG_PATH`], and that write replaces the file entire. On a
/// distribution shipping a packaged ruleset there, Arch and Debian included,
/// that file is where the administrator's own `inet filter` table is defined,
/// so their table survives the apply in the running kernel and is gone at the
/// next boot. Issue #98. Owning a separate table fixed what `nft` destroys and
/// not what the write does.
pub(super) const NFTABLES_TABLE: &str = "linux_hardener";

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

    /// Refuses a rendered ruleset `nft` will not parse, before
    /// [`NFTABLES_CONFIG_PATH`] is touched.
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
                     installing it: {e}. {NFTABLES_CONFIG_PATH} is untouched."
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
                 {NFTABLES_CONFIG_PATH} is untouched."
            ))
        })?;

        if !output.success() {
            return Err(HardeningError::Plugin(format!(
                "Refusing to install a ruleset nft will not parse: {}. \
                 {NFTABLES_CONFIG_PATH} is untouched.",
                output.stderr.trim()
            )));
        }
        Ok(())
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

    /// The rendered ruleset, which [`Self::apply_rules`] writes and this
    /// backend alone ever creates.
    fn config_paths(&self) -> &'static [&'static str] {
        &[NFTABLES_CONFIG_PATH]
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
        // `apply_rules` had ever written `NFTABLES_CONFIG_PATH`, it would ask
        // the unit to load a file that does not exist yet.
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

    /// Feeds the restored [`NFTABLES_CONFIG_PATH`] back to `nft`, which is the
    /// whole of what a rollback of an nftables configuration has to do.
    ///
    /// [`Self::enable`] is not a substitute: it only marks the systemd unit to
    /// start at the next boot and never reads the restored file at all, so a
    /// rollback that called it instead would leave the applied posture live -
    /// a host whose firewall was inactive before the apply would come out of
    /// the undo still filtering traffic.
    ///
    /// What the file does on load is the file's business. Every distribution's
    /// shipped `nftables.conf` opens with `flush ruleset`, so loading it
    /// replaces the live ruleset outright; one that does not will merge
    /// instead, which is the behaviour that host's own boot gives it.
    ///
    /// Guarded on the file's presence, through the executor so the answer is
    /// the target's and not the controller's. Fedora and RHEL ship
    /// `/etc/sysconfig/nftables.conf` instead of this path, so a host where
    /// nftables wins backend detection can genuinely never have had
    /// [`NFTABLES_CONFIG_PATH`] before its first apply; the checkpoint then
    /// records it absent, and because that path is deliberately deletable the
    /// restore removes the ruleset the apply rendered there rather than leaving
    /// it for the next boot. Either way this guard finds nothing left to load.
    /// `nft -f` on a file that is not there exits
    /// 1, and this used to run it anyway, turning a rollback that had done
    /// everything possible into a reported failure. Absence confirmed is the
    /// only case this skips: anything else, including a probe that could not
    /// tell, still attempts the load so a genuine refusal is still surfaced.
    async fn reload(&self, ctx: &Context) -> Result<()> {
        if matches!(
            ctx.executor()
                .path_exists(Path::new(NFTABLES_CONFIG_PATH))
                .await,
            Ok(false)
        ) {
            info!(
                "{NFTABLES_CONFIG_PATH} is absent on this host, so there is nothing for nft to \
                 reload"
            );
            return Ok(());
        }
        info!("Reloading the nftables ruleset from {NFTABLES_CONFIG_PATH}");
        self.execute_nft(ctx, &["-f", NFTABLES_CONFIG_PATH]).await?;
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

        // One transaction for the whole ruleset: see `render_ruleset`'s doc
        // comment for why. A failure here means nothing in `changes` above
        // actually happened, so it is propagated with `?` rather than folded
        // into a per-rule failed `Change` the way the old per-rule loop did;
        // the caller in `mod.rs` already treats an `Err` from this function as
        // a whole-backend failure.
        ctx.executor()
            .write_file(Path::new(NFTABLES_CONFIG_PATH), &ruleset)
            .await
            .map_err(|e| {
                HardeningError::Plugin(format!("Failed to write {NFTABLES_CONFIG_PATH}: {e}"))
            })?;
        self.execute_nft(ctx, &["-f", NFTABLES_CONFIG_PATH]).await?;

        Ok(changes)
    }

    fn get_default_rules(&self) -> Vec<Rule> {
        // Use the shared baseline, backend-agnostic rules.
        get_baseline_rules()
    }
}
