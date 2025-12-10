//! UFW (Uncomplicated Firewall) backend implementation.
//!
//! This backend manages firewall rules on Ubuntu/Debian systems using ufw.

use crate::firewall::{FirewallBackend, Rule, get_baseline_rules};
use async_trait::async_trait;
use hardener_common::error::{HardeningError, Result};
use hardener_core::{Change, ChangeType, context::Context};
use tracing::{info, warn};

/// UFW firewall backend for Ubuntu/Debian systems.
pub struct UfwBackend;

impl UfwBackend {
    /// Creates a new UFW backend instance.
    pub fn new() -> UfwBackend {
        UfwBackend
    }

    /// Executes a ufw command and returns the output.
    ///
    /// # Arguments
    /// * `ctx` - The context containing the executor.
    /// * `args` - Command arguments to pass to ufw.
    ///
    /// # Returns
    /// The command output as a string, or an error if execution fails.
    async fn execute_ufw(&self, ctx: &Context, args: &[&str]) -> Result<String> {
        let output = ctx
            .executor()
            .execute_command("ufw", args)
            .await
            .map_err(|e| HardeningError::Plugin(format!("Failed to execute ufw command: {}", e)))?;

        if !output.success() {
            return Err(HardeningError::Plugin(format!(
                "ufw command failed: {}",
                output.stderr
            )));
        }
        Ok(output.stdout)
    }

    /// Parses a single UFW status line into a Rule.
    ///
    /// UFW format: "22/tcp     Allow     Anywhere"
    fn parse_ufw_rule_line(&self, line: &str) -> Option<Rule> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() < 3 {
            return None;
        }

        // First part is port/protocol (e.g., "22/tcp" or "80").
        let (port, protocol) = if parts[0].contains('/') {
            let split: Vec<&str> = parts[0].split('/').collect();
            (split[0].to_string(), split[1].to_string())
        } else {
            (parts[0].to_string(), "any".to_string())
        };

        // Second part is action (ALLOW, DENY, REJECT).
        let action = match parts[1].to_uppercase().as_str() {
            "ALLOW" => "accept",
            "DENY" => "drop",
            "REJECT" => "reject",
            _ => "drop",
        }
        .to_string();

        // Third part is source (Anywhere = any).
        let source = if parts[2] == "Anywhere" {
            "any".to_string()
        } else {
            parts[2].to_string()
        };

        Some(Rule {
            rule_description: format!("{} {} from {}", action, port, source,),
            rule_protocol: protocol,
            rule_port: port,
            rule_source: source,
            rule_action: action,
        })
    }

    /// Build UFW command arguments from a Rule.
    ///
    /// Converts backend-agnostic Rule into UFW command syntax:
    /// e.g., `ufw allow from 192.168.1.0/24 to any port 22 proto tcp`
    fn build_ufw_rule_args(&self, rule: &Rule) -> Vec<String> {
        let mut args = Vec::new();

        // Action: allow, deny, reject.
        let ufw_action = match rule.rule_description.as_str() {
            "accept" => "allow",
            "drop" => "deny",
            "reject" => "reject",
            _ => "deny",
        };
        args.push(ufw_action.to_string());

        // Source
        if rule.rule_source != "any" {
            args.push("from".to_string());
            args.push(rule.rule_source.clone());
        }

        // Port and protocol
        if rule.rule_port != "any" {
            args.push("to".to_string());
            args.push("any".to_string());
            args.push("port".to_string());
            args.push(rule.rule_port.clone());

            if rule.rule_protocol != "all" && rule.rule_protocol != "any" {
                args.push("proto".to_string());
                args.push(rule.rule_protocol.clone());
            }
        }

        args
    }
}

impl Default for UfwBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FirewallBackend for UfwBackend {
    fn backend_name(&self) -> &str {
        "ufw"
    }

    async fn detect(&self, ctx: &Context) -> Result<bool> {
        // Check if ufw command exists using executor.
        ctx.executor()
            .command_exists("ufw")
            .await
            .map_err(|e| HardeningError::Plugin(e.to_string()))
    }

    async fn is_enabled(&self, ctx: &Context) -> Result<()> {
        // Try systemctl first - doesn't require root privileges.
        // This prevents false positives when running as non-root user.
        let systemctl_result = ctx
            .executor()
            .execute_command("systemctl", &["is-active", "ufw"])
            .await;

        if let Ok(output) = systemctl_result {
            if output.stdout.trim() == "active" {
                return Ok(());
            }
            // systemctl says inactive - firewall is genuinely disabled
            if output.stdout.trim() == "inactive" {
                return Err(HardeningError::Plugin("UFW is not enabled".to_string()));
            }
        }

        // Fall back to ufw status (may fail without root).
        match self.execute_ufw(ctx, &["status"]).await {
            Ok(output) => {
                if output.contains("Status: active") {
                    Ok(())
                } else {
                    Err(HardeningError::Plugin("UFW is not enabled".to_string()))
                }
            }
            Err(_) => {
                // Cannot determine status - likely permission denied.
                // Return error but don't claim it's disabled.
                Err(HardeningError::Plugin(
                    "Unable to determine UFW status (permission denied)".to_string(),
                ))
            }
        }
    }

    async fn enable(&self, ctx: &Context) -> Result<()> {
        // Enable UFW firewall
        info!("Enabling UFW firewall");

        let output = self.execute_ufw(ctx, &["--force", "enable"]).await?;

        if output.contains("Firewall is active") || output.contains("enabled") {
            info!("UFW firewall enabled successfully");
            Ok(())
        } else {
            Err(HardeningError::Plugin(
                "Failed to enable UFW firewall".to_string(),
            ))
        }
    }

    async fn list_rules(&self, ctx: &Context) -> Result<Vec<Rule>> {
        let output = self.execute_ufw(ctx, &["status"]).await?;
        let mut rules = Vec::new();

        // Skip header, parse rule line.
        let mut in_rules_section = false;

        for line in output.lines() {
            // Rules start after the "---" separator line.
            if line.starts_with("--") {
                in_rules_section = true;
                continue;
            }

            if !in_rules_section || line.trim().is_empty() {
                continue;
            }

            // Parse rule line: "22/tcp     Allow     Anywhere"
            if let Some(rule) = self.parse_ufw_rule_line(line) {
                rules.push(rule);
            }
        }

        Ok(rules)
    }

    async fn apply_rules(&self, ctx: &Context, rules: &[Rule]) -> Result<Vec<Change>> {
        let mut changes = Vec::new();

        for rule in rules {
            let ufw_args = self.build_ufw_rule_args(rule);

            let args_refs: Vec<&str> = ufw_args.iter().map(|s| s.as_str()).collect();
            match self.execute_ufw(ctx, &args_refs).await {
                Ok(_) => {
                    info!("Applied UFW rule: {}", rule.rule_description);
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
