//! Nftables firewall backend implementation.
//!
//! This backend manages firewall rules on modern Linux systems using nftables.
//! Nftables is the modern replacement for iptables and is used on Fedora, Debian 10+,
//! Ubuntu 20.04+, Arch Linux, and other distributions.

use crate::firewall::{FirewallBackend, Rule, get_baseline_rules};
use async_trait::async_trait;
use hardener_common::error::{HardeningError, Result};
use hardener_core::{Change, ChangeType, context::Context};
use tracing::{info, warn};

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

    /// Parses a single nftables rule line into a Rule.
    ///
    /// Example formats:
    /// - "tcp dport 22 accept"
    /// - "ip addr 192.168.1.0/24 tcp dport 80 accept"
    /// - "ct state established,related accept"
    fn parse_nft_rule_line(&self, line: &str) -> Option<Rule> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.is_empty() {
            return None;
        }

        let mut protocol = "all".to_string();
        let mut port = "any".to_string();
        let mut source = "any".to_string();
        let mut action = "drop".to_string();

        // Parse action (last element is usually accept/drop/reject)
        if let Some(last) = parts.last() {
            action = match *last {
                "accept" => "accept".to_string(),
                "drop" => "drop".to_string(),
                "reject" => "reject".to_string(),
                _ => action,
            };
        }

        // Parse protocol and port
        for i in 0..parts.len() {
            if parts[i] == "tcp" || parts[i] == "udp" {
                protocol = parts[i].to_string();
            }

            if parts[i] == "dport" && i + 1 < parts.len() {
                port = parts[i + 1].to_string();
            }

            if parts[i] == "saddr" && i + 1 < parts.len() {
                source = parts[i + 1].to_string();
            }
        }

        Some(Rule {
            rule_description: format!("{} {} from {}", action, port, source),
            rule_protocol: protocol,
            rule_port: port,
            rule_source: source,
            rule_action: action,
        })
    }

    /// Build nftables command arguments from a Rule.
    ///
    /// Converts backend-agnostic Rule into nft command syntax:
    /// e.g., `nft add rule inet filter input tcp dport 22 accept`
    fn build_nft_rule_args(&self, rule: &Rule) -> Vec<String> {
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

    async fn list_rules(&self, ctx: &Context) -> Result<Vec<Rule>> {
        let output = self.execute_nft(ctx, &["list", "ruleset"]).await?;
        let mut rules = Vec::new();

        // Parse nftables output format:
        // table inet filter {
        //     chain input {
        //         tcp dport 22 accept
        //         ip addr 192.168.1.0/24 tcp dport 80 accept
        //     }
        // }
        for line in output.lines() {
            let trimmed = line.trim();

            // Skip empty lines, comments, and structural lines
            if trimmed.is_empty()
                || trimmed.starts_with('#')
                || trimmed.starts_with("table")
                || trimmed.starts_with("chain")
                || trimmed.starts_with('{')
                || trimmed.starts_with('}')
            {
                continue;
            }

            // Parse rule line (simplified parsing for common cases)
            if let Some(rule) = self.parse_nft_rule_line(trimmed) {
                rules.push(rule);
            }
        }

        Ok(rules)
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
