//! Nftables firewall backend implementation.
//!
//! This backend manages firewall rules on modern Linux systems using nftables.
//! Nftables is the modern replacement for iptables and is used on Fedora, Debian 10+,
//! Ubuntu 20.04+, Arch Linux, and other distributions.

use crate::firewall::{FirewallBackend, Rule, get_baseline_rules};
use hardener_common::error::{HardeningError, Result};
use hardener_core::{Change, ChangeType};
use std::process::Command;

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
    /// * `args` - Command arguments to pass to nft.
    ///
    /// # Returns
    /// The command output as a string, or an error if execution fails.
    fn execute_nft(&self, args: &[&str]) -> Result<String> {
        let output = Command::new("nft")
            .args(args)
            .output()
            .map_err(|e| HardeningError::Plugin(format!("Failed to execute nft command: {}", e)))?;

        if !output.status.success() {
            return Err(HardeningError::Plugin(format!(
                "nft command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
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
            args.push("established".to_string());
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
}

impl Default for NftablesBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl FirewallBackend for NftablesBackend {
    fn backend_name(&self) -> &str {
        "nftables"
    }

    fn detect(&self) -> Result<bool> {
        // Check if nft command exists by trying to run it.
        match Command::new("which").arg("nft").output() {
            Ok(output) => Ok(output.status.success()),
            Err(_) => Ok(false),
        }
    }

    fn is_enabled(&self) -> Result<()> {
        // Check if nftables has any active ruleset.
        // An empty ruleset means nftables is installed but not configured.
        let output = self.execute_nft(&["list", "ruleset"])?;

        // If there are tables defined, nftables is considered "enabled"
        if output.contains("table") {
            Ok(())
        } else {
            Err(HardeningError::Plugin(
                "Nftables has no active ruleset".to_string(),
            ))
        }
    }

    fn enable(&self) -> Result<()> {
        tracing::info!("Enabling nftables firewall");

        // Create a basic inet filter table with input/output/forward chains
        // This is the foundation for the firewall rules

        // Step 1: Create the table
        self.execute_nft(&["add", "table", "inet", "filter"])?;

        // Step 2: Create input chain (with drop policy for security
        self.execute_nft(&[
            "add", "chain", "inet", "filter", "input", "{", "type", "filter", "hook", "input",
            "priority", "0", ";", "policy", "drop", ";", "}",
        ])?;

        // Step 3: Create forward chain
        self.execute_nft(&[
            "add", "chain", "inet", "filter", "forward", "{", "type", "filter", "hook", "forward",
            "priority", "0", ";", "policy", "drop", ";", "}",
        ])?;

        // Step 4: Create output chain (allow all outbound by default)
        self.execute_nft(&[
            "add", "chain", "inet", "filter", "output", "{", "type", "filter", "hook", "output",
            "priority", "0", ";", "policy", "accept", ";", "}",
        ])?;

        tracing::info!("Nftables firewall enabled successfully");
        Ok(())
    }

    fn list_rules(&self) -> Result<Vec<Rule>> {
        let output = self.execute_nft(&["list", "ruleset"])?;
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

    fn apply_rules(&self, rules: &[Rule]) -> Result<Vec<Change>> {
        let mut changes = Vec::new();

        for rule in rules {
            let nft_args = self.build_nft_rule_args(rule);

            let args_refs: Vec<&str> = nft_args.iter().map(|s| s.as_str()).collect();
            match self.execute_nft(&args_refs) {
                Ok(_) => {
                    tracing::info!("Applied nftables rule: {}", rule.rule_description);
                    changes.push(Change {
                        description: format!("Added firewall rule: {}", rule.rule_description),
                        change_type: ChangeType::FirewallRule,
                        success: true,
                        error: None,
                    });
                }
                Err(e) => {
                    tracing::warn!("Failed to apply rule '{}': {}", rule.rule_description, e);
                    changes.push(Change {
                        description: format!(
                            "Failed to add firewall rule: {}",
                            rule.rule_description
                        ),
                        change_type: ChangeType::FirewallRule,
                        success: false,
                        error: Some(e.to_string()),
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
