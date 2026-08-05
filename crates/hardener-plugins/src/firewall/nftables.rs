//! Nftables firewall backend implementation.
//!
//! This backend manages firewall rules on modern Linux systems using nftables.
//! Nftables is the modern replacement for iptables and is used on Fedora, Debian 10+,
//! Ubuntu 20.04+, Arch Linux, and other distributions.

use crate::firewall::{FirewallBackend, Rule, get_baseline_rules};
use async_trait::async_trait;
use hardener_common::error::{HardeningError, Result};
use hardener_core::{Change, ChangeType, context::Context};
use std::path::Path;
use tracing::{info, warn};

/// The persistent ruleset every distribution's `nftables.service` loads at
/// boot, and the only nftables file this plugin checkpoints. Named once here
/// so the path the checkpoint captures, the path the rollback reloads for, and
/// the path the reload actually feeds to `nft` cannot drift apart.
pub(super) const NFTABLES_CONFIG_PATH: &str = "/etc/nftables.conf";

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
    /// e.g., `nft add rule inet filter input tcp dport 22 accept`
    pub(crate) fn build_nft_rule_args(&self, rule: &Rule) -> Vec<String> {
        let mut args = vec![
            "add".to_string(),
            "rule".to_string(),
            "inet".to_string(),
            "filter".to_string(),
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

        // Source address filter
        if rule.rule_source != "any" {
            args.push("ip".to_string());
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

    /// Idempotently ensures the managed `inet filter` table and its base
    /// `input` chain exist before any rule is added.
    ///
    /// `nft add table` / `nft add chain` are no-ops when the object already
    /// exists (unlike `create`, which errors), so this runs unconditionally at
    /// the start of every apply. It fixes the ENOENT seen when a foreign
    /// `hook input` chain (docker, or another address family) made the
    /// scan-time `is_enabled` heuristic believe a filter was already active:
    /// the plugin then skipped `enable()` and every `add rule` failed against
    /// a chain that did not exist. Scoped to exactly the objects `apply_rules`
    /// writes into, so it stays safe to call when the chain is already
    /// populated.
    async fn ensure_managed_chain(&self, ctx: &Context) -> Result<()> {
        self.execute_nft(ctx, &["add", "table", "inet", "filter"])
            .await?;
        self.execute_nft(
            ctx,
            &[
                "add", "chain", "inet", "filter", "input", "{", "type", "filter", "hook", "input",
                "priority", "0", ";", "policy", "drop", ";", "}",
            ],
        )
        .await?;
        Ok(())
    }

    /// Reads the current `input` chain and returns the canonical token list of
    /// each rule already present, used to skip rules that are already there.
    ///
    /// Fails CLOSED: if the chain cannot be read, an empty list is returned so
    /// every baseline rule is treated as absent and (re-)added. A duplicate is
    /// harmless; a silently-missing baseline rule (e.g. the default drop) is a
    /// real security gap.
    async fn existing_input_rules(&self, ctx: &Context) -> Vec<Vec<String>> {
        match self
            .execute_nft(ctx, &["list", "chain", "inet", "filter", "input"])
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
}

/// Canonicalises an nftables rule statement into comparable tokens.
///
/// A rule we pass to `nft add rule inet filter input <statement>` must compare
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
/// `nft list chain inet filter input` body, skipping the structural lines
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
/// Opens with `flush ruleset` because the file is also what the unit loads at
/// boot, and because a load that merged would stack a duplicate of every
/// baseline rule on each apply.
///
/// Statements come from [`NftablesBackend::build_nft_rule_args`], sliced from
/// index 5 exactly as `apply_rules` slices it, so the file and the incremental
/// path cannot come to disagree about what a rule means.
pub(super) fn render_ruleset(rules: &[Rule]) -> String {
    let backend = NftablesBackend::new();
    let statements: Vec<String> = rules
        .iter()
        .map(|rule| {
            let args = backend.build_nft_rule_args(rule);
            format!("        {}", args[5..].join(" "))
        })
        .collect();

    format!(
        "flush ruleset\n\
         table inet filter {{\n\
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
    )
}

#[async_trait]
impl FirewallBackend for NftablesBackend {
    fn backend_name(&self) -> &str {
        "nftables"
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

        // Create a basic inet filter table with input/output/forward chains
        // This is the foundation for the firewall rules

        // Step 1: Create the table
        self.execute_nft(ctx, &["add", "table", "inet", "filter"])
            .await?;

        // Step 2: Create input chain (with drop policy for security)
        self.execute_nft(
            ctx,
            &[
                "add", "chain", "inet", "filter", "input", "{", "type", "filter", "hook", "input",
                "priority", "0", ";", "policy", "drop", ";", "}",
            ],
        )
        .await?;

        // Step 3: Create forward chain
        self.execute_nft(
            ctx,
            &[
                "add", "chain", "inet", "filter", "forward", "{", "type", "filter", "hook",
                "forward", "priority", "0", ";", "policy", "drop", ";", "}",
            ],
        )
        .await?;

        // Step 4: Create output chain (allow all outbound by default)
        self.execute_nft(
            ctx,
            &[
                "add", "chain", "inet", "filter", "output", "{", "type", "filter", "hook",
                "output", "priority", "0", ";", "policy", "accept", ";", "}",
            ],
        )
        .await?;

        info!("Nftables firewall enabled successfully");
        Ok(())
    }

    /// Feeds the restored [`NFTABLES_CONFIG_PATH`] back to `nft`, which is the
    /// whole of what a rollback of an nftables configuration has to do.
    ///
    /// [`Self::enable`] is not a substitute and was actively harmful here: it
    /// builds an `inet filter` table whose input chain carries a `drop` policy
    /// and never reads the restored file at all, so the applied posture stayed
    /// live and a host whose firewall was inactive before the apply came out
    /// of the undo filtering traffic.
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
    /// [`NFTABLES_CONFIG_PATH`]; the checkpoint then records it absent and the
    /// restore is a correct no-op. `nft -f` on a file that is not there exits
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
        let mut changes = Vec::new();

        // Ensure the managed table + input chain exist first, unconditionally
        // and idempotently (see `ensure_managed_chain`).
        self.ensure_managed_chain(ctx).await?;

        // Read the chain once so only genuinely-absent rules are added:
        // `nft add rule` always appends a fresh handle, so without this check
        // every apply stacks another duplicate of every baseline rule.
        let existing = self.existing_input_rules(ctx).await;

        for rule in rules {
            let nft_args = self.build_nft_rule_args(rule);
            // The rule statement is everything after `add rule inet filter input`.
            let wanted = canonical_rule_tokens(nft_args[5..].iter().map(String::as_str));

            if existing.contains(&wanted) {
                info!("nftables rule already present: {}", rule.rule_description);
                changes.push(Change {
                    change_description: format!(
                        "Firewall rule already present: {}",
                        rule.rule_description
                    ),
                    change_type: ChangeType::Skipped,
                    change_success: true,
                    change_error: None,
                });
                continue;
            }

            let args_refs: Vec<&str> = nft_args.iter().map(|s| s.as_str()).collect();
            match self.execute_nft(ctx, &args_refs).await {
                Ok(_) => {
                    info!("Applied nftables rule: {}", rule.rule_description);
                    changes.push(Change {
                        change_description: format!(
                            "Added firewall rule: {}",
                            rule.rule_description
                        ),
                        change_type: ChangeType::FirewallRule,
                        change_success: true,
                        change_error: None,
                    });
                }
                Err(e) => {
                    warn!("Failed to apply rule '{}': {}", rule.rule_description, e);
                    changes.push(Change {
                        change_description: format!(
                            "Failed to add firewall rule: {}",
                            rule.rule_description
                        ),
                        change_type: ChangeType::FirewallRule,
                        change_success: false,
                        change_error: Some(e.to_string()),
                    });
                }
            }
        }

        Ok(changes)
    }

    fn get_default_rules(&self) -> Vec<Rule> {
        // Use the shared baseline, backend-agnostic rules.
        get_baseline_rules()
    }
}
