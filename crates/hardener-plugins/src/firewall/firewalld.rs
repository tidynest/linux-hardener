//! Firewalld backend implementation
//!
//! This backend manages firewall rules on RHEL/Fedora/CentOS systems using firewalld.
//! Firewalld uses a zone-based configuration model and distinguishes between runtime
//! and permanent configurations.

use crate::firewall::{FirewallBackend, Rule, get_baseline_rules};
use async_trait::async_trait;
use hardener_common::error::{HardeningError, Result};
use hardener_core::{Change, ChangeType, context::Context};
use tracing::{debug, error, info, warn};

/// Firewalld backend for RHEL/Fedora/CentOS systems.
///
/// Firewalld uses zones (e.g., "public", "trusted") to organise rules.
/// Changes can be runtime-only or permanent (persistent across reboots).
pub struct FirewalldBackend;

impl FirewalldBackend {
    /// Creates a new firewalld backend instance.
    pub fn new() -> FirewalldBackend {
        FirewalldBackend
    }

    async fn execute_firewall_cmd(&self, ctx: &Context, args: &[&str]) -> Result<String> {
        let output = ctx
            .executor()
            .execute_command("firewall-cmd", args)
            .await
            .map_err(|e| {
                HardeningError::Plugin(format!("Failed to execute firewall-cmd: {}", e))
            })?;

        if !output.success() {
            return Err(HardeningError::Plugin(format!(
                "firewall-cmd failed: {}",
                output.stderr
            )));
        }

        Ok(output.stdout)
    }

    /// Gets the default zone used by firewalld.
    ///
    /// This is typically "public" but can be customised by the user.
    async fn get_default_zone(&self, ctx: &Context) -> Result<String> {
        let output = self
            .execute_firewall_cmd(ctx, &["--get-default-zone"])
            .await?;
        Ok(output.trim().to_string())
    }
}

impl Default for FirewalldBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FirewallBackend for FirewalldBackend {
    fn backend_name(&self) -> &str {
        "firewalld"
    }

    async fn detect(&self, ctx: &Context) -> Result<bool> {
        // Check if firewall-cmd command exists using executor
        ctx.executor()
            .command_exists("firewall-cmd")
            .await
            .map_err(|e| HardeningError::Plugin(e.to_string()))
    }

    async fn is_enabled(&self, ctx: &Context) -> Result<()> {
        // Check if firewalld is running
        let output = self.execute_firewall_cmd(ctx, &["--state"]).await?;

        if output.trim() == "running" {
            Ok(())
        } else {
            Err(HardeningError::Plugin(
                "Firewalld is not running".to_string(),
            ))
        }
    }

    async fn enable(&self, ctx: &Context) -> Result<()> {
        info!("Enabling firewalld service");

        // Start firewalld service
        let start_output = ctx
            .executor()
            .execute_command("systemctl", &["start", "firewalld"])
            .await
            .map_err(|e| HardeningError::Plugin(format!("Failed to start firewalld: {}", e)))?;

        if !start_output.success() {
            return Err(HardeningError::Plugin(format!(
                "Failed to start firewalld: {}",
                start_output.stderr
            )));
        }

        // Enable firewalld to start on boot
        let enable_output = ctx
            .executor()
            .execute_command("systemctl", &["enable", "firewalld"])
            .await
            .map_err(|e| HardeningError::Plugin(format!("Failed to enable firewalld: {}", e)))?;

        if !enable_output.success() {
            return Err(HardeningError::Plugin(format!(
                "Failed to enable firewalld: {}",
                enable_output.stderr
            )));
        }

        info!("Firewalld enabled successfully");
        Ok(())
    }

    async fn list_rules(&self, ctx: &Context) -> Result<Vec<Rule>> {
        let zone = self.get_default_zone(ctx).await?;
        let mut rules = Vec::new();

        // List services allowed in the zone
        let service_output = self
            .execute_firewall_cmd(ctx, &["--zone", &zone, "--list-services"])
            .await?;

        for service in service_output.split_whitespace() {
            rules.push(Rule {
                rule_description: format!("Allow {} service", service),
                rule_protocol: "tcp".to_string(), // Services typically use TCP
                rule_port: service.to_string(),
                rule_source: "any".to_string(),
                rule_action: "accept".to_string(),
            });
        }

        // List ports allowed in the zone
        let ports_output = self
            .execute_firewall_cmd(ctx, &["--zone", &zone, "--list-ports"])
            .await?;

        for port in ports_output.split_whitespace() {
            let parts: Vec<&str> = port.split('/').collect();
            if parts.len() == 2 {
                rules.push(Rule {
                    rule_description: format!("Allow port {}", port,),
                    rule_protocol: parts[1].to_string(),
                    rule_port: parts[0].to_string(),
                    rule_source: "any".to_string(),
                    rule_action: "accept".to_string(),
                });
            }
        }

        Ok(rules)
    }

    async fn apply_rules(&self, ctx: &Context, rules: &[Rule]) -> Result<Vec<Change>> {
        let zone = self.get_default_zone(ctx).await?;
        let mut changes = Vec::new();

        info!("Applying {} firewalld rules to zone {}", rules.len(), zone);

        for rule in rules {
            if rule.rule_description.contains("loopback") {
                debug!("Skipping loopback rule (handled by firewalld automatically)");
                continue;
            }

            if rule.rule_description.contains("established") {
                debug!("Skipping established/related rule (handled by firewalld automatically)");
                continue;
            }

            // Handle drop/default deny rules (set zone target)
            if rule.rule_action == "drop" && rule.rule_port == "any" {
                match self
                    .execute_firewall_cmd(
                        ctx,
                        &["--permanent", "--zone", &zone, "--set-target=DROP"],
                    )
                    .await
                {
                    Ok(_) => {
                        changes.push(Change {
                            change_type: ChangeType::FirewallRule,
                            change_description: format!(
                                "Set zone '{}' default target to DROP",
                                zone,
                            ),
                            change_success: true,
                            change_error: None,
                        });
                    }
                    Err(e) => {
                        changes.push(Change {
                            change_type: ChangeType::FirewallRule,
                            change_description: format!(
                                "Set zone '{}' default target to DROP",
                                zone,
                            ),
                            change_success: false,
                            change_error: Some(e.to_string()),
                        });
                    }
                }
                continue;
            }

            // For accept rules, add port or service
            if rule.rule_action == "accept" {
                let port_spec = format!("{}/{}", rule.rule_port, rule.rule_protocol);

                match self
                    .execute_firewall_cmd(
                        ctx,
                        &["--permanent", "--zone", &zone, "--add-port", &port_spec],
                    )
                    .await
                {
                    Ok(_) => {
                        changes.push(Change {
                            change_type: ChangeType::FirewallRule,
                            change_description: format!(
                                "Added port {} to zone '{}'",
                                port_spec, zone
                            ),
                            change_success: true,
                            change_error: None,
                        });
                    }
                    Err(e) => {
                        warn!("Failed to add port {}: {}", port_spec, e);
                        changes.push(Change {
                            change_type: ChangeType::FirewallRule,
                            change_description: format!(
                                "Failed to add port {} to zone '{}'",
                                port_spec, zone
                            ),
                            change_success: false,
                            change_error: Some(e.to_string()),
                        });
                    }
                }
            }
        }

        // Reload firewalld to activate permanent changes
        match self.execute_firewall_cmd(ctx, &["--reload"]).await {
            Ok(_) => {
                info!("Reloaded firewalld configuration");
                changes.push(Change {
                    change_type: ChangeType::FirewallRule,
                    change_description: "Reloaded firewalld to activate changes".to_string(),
                    change_success: true,
                    change_error: None,
                });
            }
            Err(e) => {
                error!("Failed to reload firewalld: {}", e);
                changes.push(Change {
                    change_type: ChangeType::FirewallRule,
                    change_description: "Reloaded firewalld to activate changes".to_string(),
                    change_success: false,
                    change_error: Some(e.to_string()),
                });
            }
        }

        Ok(changes)
    }

    fn get_default_rules(&self) -> Vec<Rule> {
        get_baseline_rules()
    }
}
