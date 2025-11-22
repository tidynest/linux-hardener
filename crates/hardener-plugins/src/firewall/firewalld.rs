//! Firewalld backend implementation
//!
//! This backend manages firewall rules on RHEL/Fedora/CentOS systems using firewalld.
//! Firewalld uses a zone-based configuration model and distinguishes between runtime
//! and permanent configurations.

use crate::firewall::{
    FirewallBackend,
    get_baseline_rules,
    Rule,
};
use hardener_common::error::{
    HardeningError,
    Result,
};
use hardener_core::{
    Change,
    ChangeType,
};
use std::process::Command;

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

    fn execute_firewall_cmd(
        &self,
        args: &[&str],
    ) -> Result<String> {
        let output = Command::new("firewall-cmd")
            .args(args)
            .output()
            .map_err(|e| {
                HardeningError::Plugin(format!(
                    "Failed to execute firewall-cmd: {}", e
                ))
            })?;

        if !output.status.success() {
            return Err(HardeningError::Plugin(format!(
                "firewall-cmd failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Gets the default zone used by firewalld.
    ///
    /// This is typically "public" but can be customised by the user.
    fn get_default_zone(&self) -> Result<String> {
        let output = self.execute_firewall_cmd(&["--get-default-zone"])?;
        Ok(output.trim().to_string())
    }
}

impl FirewallBackend for FirewalldBackend {
    fn backend_name(&self) -> &str {
        "firewalld"
    }

    fn detect(&self) -> Result<bool> {
        // Check if firewall-cmd command exists
        match Command::new("firewall-cmd").arg("--version").output() {
            Ok(output) => Ok(output.status.success()),
            Err(_)     => Ok(false),
        }
    }

    fn is_enabled(&self) -> Result<()> {
        // Check if firewalld is running
        let output = self.execute_firewall_cmd(&["--state"])?;

        if output.trim() == "running" {
            Ok(())
        } else {
            Err(HardeningError::Plugin(
                "Firewalld is not running".to_string(),
            ))
        }
    }

    fn enable(&self) -> Result<()> {
        tracing::info!("Enabling firewalld service");

        // Start firewalld service
        let start_output = Command::new("systemctl")
            .args(&["start", "firewalld"])
            .output()
            .map_err(|e| {
                HardeningError::Plugin(format!(
                    "Failed to start firewalld: {}", e
                ))
            })?;

        if !start_output.status.success() {
            return Err(HardeningError::Plugin(format!(
                "Failed to start firewalld: {}",
                String::from_utf8_lossy(&start_output.stderr)
            )));
        }

        // Enable firewalld to start on boot
        let enable_output = Command::new("systemctl")
            .args(&["enable", "firewalld"])
            .output()
            .map_err(|e| {
                HardeningError::Plugin(format!(
                    "Failed to enable firewalld: {}", e
                ))
            })?;

        if !enable_output.status.success() {
            return Err(HardeningError::Plugin(format!(
                "Failed to enable firewalld: {}",
                String::from_utf8_lossy(&enable_output.stderr)
            )));
        }

        tracing::info!("Firewalld enabled successfully");
        Ok(())
    }

    fn get_default_rules(&self) -> Vec<Rule> {
        get_baseline_rules()
    }

    fn list_rules(&self) -> Result<Vec<Rule>> {
        let zone = self.get_default_zone()?;
        let mut rules = Vec::new();

        // List services allowed in the zone
        let service_output = self.execute_firewall_cmd(&[
            "--zone",
            &zone,
            "--list-services",
        ])?;

        for service in service_output.split_whitespace() {
            rules.push(Rule {
                rule_description: format!(
                    "Allow {} service",
                    service
                ),
                rule_protocol:    "tcp".to_string(),  // Services typically use TCP
                rule_port:        service.to_string(),
                rule_source:      "any".to_string(),
                rule_action:      "accept".to_string(),
            });
        }

        // List ports allowed in the zone
        let ports_output = self.execute_firewall_cmd(&[
            "--zone",
            &zone,
            "--list-ports",
        ])?;

        for port in ports_output.split_whitespace() {
            let parts: Vec<&str> = port.split('/').collect();
            if parts.len() == 2 {
                rules.push(Rule {
                    rule_description: format!(
                        "Allow port {}",
                        port,
                    ),
                    rule_protocol:    parts[1].to_string(),
                    rule_port:        parts[0].to_string(),
                    rule_source:      "any".to_string(),
                    rule_action:      "accept".to_string(),
                });
            }
        }

        Ok(rules)
    }

    fn apply_rules(
        &self,
        rules: &[Rule]
    ) -> Result<Vec<Change>> {
        let zone = self.get_default_zone()?;
        let mut changes = Vec::new();

        tracing::info!(
            "Applying {} firewalld rules to zone {}",
            rules.len(),
            zone
        );

        for rule in rules {
            if rule.rule_description.contains("loopback") {
                tracing::debug!("Skipping loopback rule (handled by firewalld automatically)");
                continue;
            }

            if rule.rule_description.contains("established") {
                tracing::debug!("Skipping established/related rule (handled by firewalld automatically)");
                continue;
            }

            // Handle drop/default deny rules (set zone target)
            if rule.rule_action == "drop" && rule.rule_port == "any"
            {
                match self.execute_firewall_cmd(&[
                    "--permanent",
                    "--zone", &zone,
                    "--set-target=DROP",
                ]) {
                    Ok(_) => {
                        changes.push(Change {
                            change_type: ChangeType::FirewallRule,
                            description: format!(
                                "Set zone '{}' default target to DROP",
                                zone,
                            ),
                            success:     true,
                            error:       None,
                        });
                    }
                    Err(e) => {
                        changes.push(Change {
                            change_type: ChangeType::FirewallRule,
                            description: format!(
                                "Set zone '{}' default target to DROP",
                                zone,
                            ),
                            success:     false,
                            error:       Some(e.to_string()),
                        });
                    }
                }
                continue;
            }

            // For accept rules, add port or service
            if rule.rule_action == "accept" {
                let port_spec = format!("{}/{}", rule.rule_port,
                                        rule.rule_protocol);

                match self.execute_firewall_cmd(&[
                    "--permanent",
                    "--zone", &zone,
                    "--add-port", &port_spec,
                ]) {
                    Ok(_) => {
                        changes.push(Change {
                            change_type: ChangeType::FirewallRule,
                            description: format!(
                                "Added port {} to zone '{}'",
                                port_spec,
                                zone
                            ),
                            success:     true,
                            error:       None,
                        });
                    }
                    Err(e) => {
                        tracing::warn!("Failed to add port {}: {}", port_spec, e);
                        changes.push(Change {
                            change_type: ChangeType::FirewallRule,
                            description: format!(
                                "Added port {} to zone '{}'",
                                port_spec,
                                zone
                            ),
                            success:     false,
                            error:       Some(e.to_string()),
                        });
                    }
                }
            }
        }

        // Reload firewalld to activate permanent changes
        match self.execute_firewall_cmd(&["--reload"]) {
            Ok(_) => {
                tracing::info!("Reloaded firewalld configuration");
                changes.push(Change {
                    change_type: ChangeType::FirewallRule,
                    description: "Reloaded firewalld to activate changes".to_string(),
                    success:     true,
                    error:       None,
                });
            }
            Err(e) => {
                tracing::error!("Failed to reload firewalld: {}", e);
                changes.push(Change {
                    change_type: ChangeType::FirewallRule,
                    description: "Reloaded firewalld to activate changes".to_string(),
                    success:     false,
                    error:       Some(e.to_string()),
                });
            }
        }

        Ok(changes)
    }
}


