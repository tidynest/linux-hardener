//! UFW (Uncomplicated Firewall) backend implementation.
//!
//! This backend manages firewall rules on Ubuntu/Debian systems using ufw.

use crate::firewall::{FirewallBackend, Rule, get_baseline_rules};
use async_trait::async_trait;
use hardener_common::error::{HardeningError, Result};
use hardener_core::{Change, ChangeType, context::Context};
use tracing::{info, warn};

/// The baseline rule that maps to ufw's default-policy switch rather than to
/// an `ufw allow`-style rule.
const DEFAULT_INBOUND_RULE: &str = "Drop all other inbound traffic by default";

/// What ufw prints, while exiting 0, when asked to add a rule it already has.
///
/// The exit status is the same either way, so this string is the only thing
/// that distinguishes an addition from a no-op, and reading it is what lets
/// apply report an already-hardened host as needing no changes.
const RULE_ALREADY_PRESENT: &str = "Skipping adding existing rule";

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

    /// Whether ufw's default incoming policy is already `deny`.
    ///
    /// This one rule has to be asked about beforehand, unlike the others.
    /// `ufw default deny incoming` prints "Default incoming policy changed to
    /// 'deny'" whether or not the policy moved, so its output cannot say
    /// whether it changed anything. `ufw status verbose` states the policy in
    /// one line: `Default: deny (incoming), allow (outgoing), disabled
    /// (routed)`.
    ///
    /// A line that is absent, unparseable or unreadable all yield `false`, so
    /// the policy is set and reported rather than skipped on a host whose
    /// state cannot be seen. Doing the work is the safe direction here, and it
    /// is the same fallback the firewalld and nftables backends take.
    async fn default_incoming_is_deny(&self, ctx: &Context) -> bool {
        match self.execute_ufw(ctx, &["status", "verbose"]).await {
            Ok(output) => output
                .lines()
                .find_map(|line| line.trim().strip_prefix("Default:"))
                .and_then(|policies| {
                    policies
                        .split(',')
                        .find(|policy| policy.contains("(incoming)"))
                })
                .is_some_and(|policy| policy.trim().starts_with("deny")),
            Err(e) => {
                warn!(
                    "Could not read ufw's default policies ({e}); treating the \
                     incoming policy as not deny so the apply sets it"
                );
                false
            }
        }
    }

    /// Build UFW command arguments from a Rule.
    ///
    /// Converts backend-agnostic Rule into UFW command syntax:
    /// e.g., `ufw allow from 192.168.1.0/24 to any port 22 proto tcp`
    ///
    /// The baseline's "drop all other inbound by default" rule is not a
    /// `ufw add`-style rule; ufw's own default-policy switch is
    /// `ufw default deny incoming`.
    fn build_ufw_rule_args(&self, rule: &Rule) -> Vec<String> {
        if rule.rule_description == DEFAULT_INBOUND_RULE {
            return vec![
                "default".to_string(),
                "deny".to_string(),
                "incoming".to_string(),
            ];
        }

        let mut args = Vec::new();

        // Action: allow, deny, reject.
        let ufw_action = match rule.rule_action.as_str() {
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

    fn systemd_unit(&self) -> &'static str {
        "ufw"
    }

    async fn detect(&self, ctx: &Context) -> Result<bool> {
        // Check if ufw command exists using executor.
        ctx.executor()
            .command_exists("ufw")
            .await
            .map_err(|e| HardeningError::Plugin(e.to_string()))
    }

    /// Whether ufw is actually enforcing, asked of ufw and of nothing else.
    ///
    /// **The systemd unit's state is deliberately not consulted here.** It
    /// answers a different question, and this method taking it as proof left a
    /// Debian host with no firewall while the tool reported one: Debian ships
    /// `ENABLED=no` in `/etc/ufw/ufw.conf`, its `ufw` unit is a oneshot that
    /// reports `active` having loaded no rules, and
    /// [`super::backend_activity`] read this method's `Ok` as `Verified`. Apply
    /// then skipped [`Self::enable`], `ufw allow` wrote ufw's own rule files and
    /// succeeded, and three changes were reported against a kernel holding an
    /// empty filter table and a default-ACCEPT policy. Measured 2026-07-30 by
    /// the differential suite's firewall oracle, on its first run.
    ///
    /// The unit hint is not lost, it is applied where it belongs.
    /// [`super::backend_activity`] already degrades a permission-denied probe to
    /// `UnitActiveUnverified` by asking systemd there, which is the layer that
    /// can express "the unit is up but the ruleset is unverifiable" without
    /// claiming the backend's own probe confirmed anything.
    async fn is_enabled(&self, ctx: &Context) -> Result<()> {
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

    async fn apply_rules(&self, ctx: &Context, rules: &[Rule]) -> Result<Vec<Change>> {
        let mut changes = Vec::new();

        // Read the default incoming policy once, before writing anything.
        // Every other rule reports its own outcome (see `RULE_ALREADY_PRESENT`)
        // and this one does not, so it is the only state this backend has to
        // ask for. Measured on the debian container 2026-07-30: a second apply
        // printed the same three changes as the first, on a host the first had
        // already hardened.
        let default_already_deny = self.default_incoming_is_deny(ctx).await;

        for rule in rules {
            // ufw is stateful by default: it tracks connection state
            // implicitly, so there is no ufw command for "allow established
            // and related connections" at all. Recording it as a normal
            // FirewallRule change previously ran `ufw allow` with no
            // criteria, which ufw rejects as invalid syntax.
            if rule.rule_description == "Allow established and related connections" {
                info!(
                    "Skipping ufw rule '{}': ufw tracks connection state implicitly",
                    rule.rule_description
                );
                changes.push(Change {
                    change_description: format!(
                        "{}: not applicable to ufw (ufw tracks connection state implicitly)",
                        rule.rule_description
                    ),
                    change_type: ChangeType::Skipped,
                    change_success: true,
                    change_error: None,
                });
                continue;
            }

            // The default-policy switch is the one rule whose own output
            // cannot say whether it changed anything, so it is asked about
            // beforehand. See `default_incoming_is_deny`.
            if rule.rule_description == DEFAULT_INBOUND_RULE && default_already_deny {
                info!("ufw's default incoming policy is already deny");
                changes.push(Change {
                    change_description: format!(
                        "{}: already in force (ufw's default incoming policy is deny)",
                        rule.rule_description
                    ),
                    change_type: ChangeType::Skipped,
                    change_success: true,
                    change_error: None,
                });
                continue;
            }

            let ufw_args = self.build_ufw_rule_args(rule);

            let args_refs: Vec<&str> = ufw_args.iter().map(|s| s.as_str()).collect();
            match self.execute_ufw(ctx, &args_refs).await {
                Ok(output) if output.contains(RULE_ALREADY_PRESENT) => {
                    info!("ufw rule already present: {}", rule.rule_description);
                    changes.push(Change {
                        change_description: format!(
                            "Firewall rule already present: {}",
                            rule.rule_description
                        ),
                        change_type: ChangeType::Skipped,
                        change_success: true,
                        change_error: None,
                    });
                }
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
