//! What a firewall rollback left enforcing that its restored files do not ask
//! for.
//!
//! `reload_after_rollback` re-reads the restored configuration and never
//! starts or stops a unit, in either direction, because undoing a hardening
//! run must not leave a host less protected than it was found. That decision
//! stands. What was missing is the telling (#139).

use super::{FirewallHardeningPlugin, UFW_CONF};
use crate::shell_config::shell_value;
use hardener_core::Context;
use hardener_types::{DivergenceState, RollbackDivergence};
use std::path::Path;

/// The plugin id every row here carries.
const PLUGIN_ID: &str = "firewall-hardening";

fn row(state: DivergenceState, detail: String) -> RollbackDivergence {
    RollbackDivergence {
        divergence_plugin_id: PLUGIN_ID.to_string(),
        divergence_subject: "ufw".to_string(),
        divergence_state: state,
        divergence_detail: detail,
    }
}

/// What reading `ufw status` produced, classified three ways rather than two.
///
/// `UfwBackend::is_enabled` (`ufw.rs`) collapses "ufw says inactive" and "the
/// status command could not be run at all" into the same `Err`, because the
/// callers it serves, apply and scan, both want "assume not enforcing and act
/// safely" for either case. This probe wants the opposite: it must never
/// assert a divergence it did not measure, so a failed command and a genuine
/// `inactive` line have to stay distinguishable here even though they are not
/// distinguishable through the trait method.
enum LiveEnforcement {
    Enforcing,
    NotEnforcing,
    Unverifiable(String),
}

/// Reads `ufw status` directly through the executor, deliberately bypassing
/// `UfwBackend::is_enabled`, and classifies the result.
///
/// **Exact matching, not `contains`.** `Status: inactive` contains the
/// substring `active`, so a `contains("active")` check reads a stopped
/// firewall as a running one. The line is matched only after trimming, and
/// only against the two lines ufw actually prints; anything else, including a
/// line ufw might print in some future version, is unverifiable rather than
/// guessed at.
async fn read_live_enforcement(ctx: &Context) -> LiveEnforcement {
    match ctx.executor().execute_command("ufw", &["status"]).await {
        Ok(output) if output.success() => match output.stdout.trim() {
            "Status: active" => LiveEnforcement::Enforcing,
            "Status: inactive" => LiveEnforcement::NotEnforcing,
            other => LiveEnforcement::Unverifiable(format!(
                "ufw status printed neither 'Status: active' nor 'Status: inactive': {other:?}"
            )),
        },
        Ok(output) => LiveEnforcement::Unverifiable(format!(
            "ufw status exited with a failure: {}",
            output.stderr
        )),
        Err(e) => LiveEnforcement::Unverifiable(format!("ufw status could not be run: {e}")),
    }
}

/// Whether the running firewall and the restored configuration agree.
///
/// ufw only, and deliberately. firewalld restores a configuration directory
/// its daemon re-reads, so the reload converges it; nftables is #97, closed by
/// #106, which reads the unit's own `ExecStart`. ufw is the one backend whose
/// enablement is a flag inside a restored file while the running state is a
/// separate thing.
pub(super) async fn firewall_divergences(ctx: &Context) -> Vec<RollbackDivergence> {
    let plugin = FirewallHardeningPlugin::new();
    let Ok(backend) = plugin.detect_backend(ctx).await else {
        // No backend detected is not a divergence: there is no configuration
        // to disagree with.
        return Vec::new();
    };
    if backend.backend_name() != "ufw" {
        return Vec::new();
    }

    let live = read_live_enforcement(ctx).await;

    let configured_enabled = match ctx.executor().read_file(Path::new(UFW_CONF)).await {
        Ok(content) => {
            // The two spellings ufw's own test accepts, and no others.
            let enabled = shell_value(&content, "ENABLED").unwrap_or_default();
            enabled == "yes" || enabled == "YES"
        }
        Err(e) => {
            return vec![row(
                DivergenceState::Unverifiable,
                format!(
                    "{UFW_CONF} could not be read, so whether ufw's restored configuration \
                     matches what it is running is unknown: {e}"
                ),
            )];
        }
    };

    let live_enforcing = match live {
        LiveEnforcement::Enforcing => true,
        LiveEnforcement::NotEnforcing => false,
        LiveEnforcement::Unverifiable(detail) => {
            return vec![row(
                DivergenceState::Unverifiable,
                format!(
                    "ufw's running state could not be read, so whether it matches the \
                     restored {UFW_CONF} (ENABLED={}) is unknown: {detail}",
                    if configured_enabled { "yes" } else { "no" }
                ),
            )];
        }
    };

    match (live_enforcing, configured_enabled) {
        (true, false) => vec![row(
            DivergenceState::Diverged,
            format!(
                "ufw is enforcing while {UFW_CONF} says ENABLED=no, so the next reboot changes \
                 this host's firewall posture. A rollback restores configuration and never stops \
                 a running firewall, because stopping one would leave the host less protected \
                 than the rollback found it"
            ),
        )],
        (false, true) => vec![row(
            DivergenceState::Diverged,
            format!(
                "ufw is not enforcing while {UFW_CONF} says ENABLED=yes, so this host is weaker \
                 than its own configuration describes and the next reboot changes its posture"
            ),
        )],
        _ => Vec::new(),
    }
}

mod tests;
