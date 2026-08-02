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

/// Validates that a firewalld zone name contains only safe characters.
pub fn validate_zone_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        return Err(HardeningError::Config("Invalid zone name length".into()));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(HardeningError::Config(format!(
            "Zone name contains invalid characters: {name}"
        )));
    }
    if name.starts_with('-') {
        return Err(HardeningError::Config(
            "Zone name must not start with a dash".into(),
        ));
    }
    Ok(())
}

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
        let zone = output.trim().to_string();
        validate_zone_name(&zone)?;
        Ok(zone)
    }

    /// The ports already allowed in the zone's **permanent** configuration.
    ///
    /// The permanent layer is the one [`FirewalldBackend::apply_rules`] writes
    /// into, so it is the only layer that can say whether an `--add-port`
    /// would change anything. Omitting `--permanent` here would read the
    /// runtime layer instead, which disagrees with the permanent one for as
    /// long as a change is pending a reload.
    ///
    /// A read that fails is treated as an empty list, so the port is added and
    /// reported rather than skipped. Doing the work is the safe direction when
    /// the state cannot be determined, and it is the fallback the nftables
    /// backend already takes for the same reason.
    async fn permanent_ports(&self, ctx: &Context, zone: &str) -> Vec<String> {
        match self
            .execute_firewall_cmd(ctx, &["--permanent", "--zone", zone, "--list-ports"])
            .await
        {
            Ok(output) => output.split_whitespace().map(str::to_string).collect(),
            Err(e) => {
                warn!(
                    "Could not read the permanent port list for zone '{zone}' ({e}); \
                     treating it as empty so baseline ports are added rather than skipped"
                );
                Vec::new()
            }
        }
    }

    /// Whether the zone's **permanent** target is already `DROP`.
    ///
    /// Same layer and same fallback direction as
    /// [`FirewalldBackend::permanent_ports`]: a target that cannot be read is
    /// reported as not `DROP`, so the apply sets it.
    async fn permanent_target_is_drop(&self, ctx: &Context, zone: &str) -> bool {
        match self
            .execute_firewall_cmd(ctx, &["--permanent", "--zone", zone, "--get-target"])
            .await
        {
            Ok(output) => output.trim() == "DROP",
            Err(e) => {
                warn!(
                    "Could not read the permanent target for zone '{zone}' ({e}); \
                     treating it as not DROP so the apply sets it"
                );
                false
            }
        }
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

    fn systemd_unit(&self) -> &'static str {
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

    /// `firewall-cmd --reload` is the only thing that makes a running
    /// firewalld re-read `/etc/firewalld`. Its permanent configuration lives
    /// in those XML files and its runtime configuration is a separate copy
    /// held in the daemon, so a rollback that restores the files and stops
    /// there changes nothing a packet ever meets. `systemctl start firewalld`
    /// cannot stand in: it exits zero without doing anything on a host where
    /// firewalld is already running, which is every host that has a firewalld
    /// configuration worth rolling back.
    async fn reload(&self, ctx: &Context) -> Result<()> {
        info!("Reloading firewalld configuration");
        self.execute_firewall_cmd(ctx, &["--reload"]).await?;
        Ok(())
    }

    async fn apply_rules(&self, ctx: &Context, rules: &[Rule]) -> Result<Vec<Change>> {
        let zone = self.get_default_zone(ctx).await?;
        let mut changes = Vec::new();

        info!("Applying {} firewalld rules to zone {}", rules.len(), zone);

        // Read the permanent zone state once, before writing anything.
        // `firewall-cmd` exits 0 for a port that is already allowed, printing
        // ALREADY_ENABLED, and for a target that is already set, so its exit
        // status cannot tell an addition from a no-op and every apply used to
        // report both as changes. Measured on the fedora container
        // 2026-07-30: a second apply printed the same three changes as the
        // first, on a zone the first apply had already hardened.
        let existing_ports = self.permanent_ports(ctx, &zone).await;
        let target_already_drop = self.permanent_target_is_drop(ctx, &zone).await;

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
            let sets_default_target = rule.rule_action == "drop" && rule.rule_port == "any";

            if sets_default_target && target_already_drop {
                info!("Zone '{}' default target is already DROP", zone);
                changes.push(Change {
                    change_type: ChangeType::Skipped,
                    change_description: format!("Zone '{}' default target is already DROP", zone),
                    change_success: true,
                    change_error: None,
                });
                continue;
            }

            if sets_default_target {
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
            let port_spec = format!("{}/{}", rule.rule_port, rule.rule_protocol);
            let adds_port = rule.rule_action == "accept";

            if adds_port && existing_ports.iter().any(|port| port == &port_spec) {
                info!("Port {} is already allowed in zone '{}'", port_spec, zone);
                changes.push(Change {
                    change_type: ChangeType::Skipped,
                    change_description: format!(
                        "Port {} is already allowed in zone '{}'",
                        port_spec, zone
                    ),
                    change_success: true,
                    change_error: None,
                });
                continue;
            }

            if adds_port {
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

        // A reload only activates permanent changes that are pending, so on a
        // zone where every rule was already in force there is nothing to
        // activate. Reloading anyway and recording it as a change is what kept
        // an already-hardened host from ever reading "no changes needed".
        if !changes
            .iter()
            .any(|change| !change.is_skipped() && change.change_success)
        {
            info!("No permanent firewalld change was written; skipping the reload");
            changes.push(Change {
                change_type: ChangeType::Skipped,
                change_description: "Firewalld reload not needed: no permanent change was written"
                    .to_string(),
                change_success: true,
                change_error: None,
            });
            return Ok(changes);
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
