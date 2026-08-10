//! What a service-minimisation rollback left running that its restored unit
//! files do not name (#142).
//!
//! `reload_after_rollback` (`services/mod.rs`) runs `systemctl daemon-reload`
//! whenever a rollback restores anything under [`ADMIN_UNIT_DIR`](super::ADMIN_UNIT_DIR),
//! which makes systemd re-read the restored unit files. It never starts,
//! stops, or restarts anything: a unit `apply` had stopped stays stopped, and
//! the reverse.
//!
//! Booted arch container, 2026-08-10:
//!   bluetooth.service state before the apply: enabled=disabled active=inactive
//!   bluetooth.service active state after the forcing step: failed
//!   forced: attempted to start bluetooth.service while its unit files say
//!           disabled, but it did not take (state after starting: failed)
//!   reported: (nothing)
//!
//! So: no container this project can build was able to force this
//! divergence, because `bluetooth.service` cannot start in one at all. This
//! probe is therefore built from the plugin's own semantics and has never
//! fired against a real divergence. The reading itself is available on any
//! booted host, which is why a probe is worth writing rather than an
//! always-Unverifiable row.

use super::{UNNECESSARY_SERVICES, is_service_active, is_service_enabled, is_service_exists};
use hardener_core::Context;
use hardener_types::{DivergenceState, RollbackDivergence};

/// The plugin id every row here carries.
const PLUGIN_ID: &str = "service-minimisation";

fn row(subject: &str, state: DivergenceState, detail: String) -> RollbackDivergence {
    RollbackDivergence {
        divergence_plugin_id: PLUGIN_ID.to_string(),
        divergence_subject: subject.to_string(),
        divergence_state: state,
        divergence_detail: detail,
    }
}

/// Whether the restored unit files leave a unit enabled, classified three
/// ways rather than two. `systemctl is-enabled` exits non-zero both for a
/// unit that is genuinely disabled (or masked) and for an invocation that
/// could not run at all, and this probe must never turn the second case into
/// a claim about the first: that is the `.unwrap_or(false)` every existing
/// caller in `services/mod.rs` takes, and the one this probe must not repeat.
enum Enablement {
    Enabled,
    NotEnabled,
    Unverifiable(String),
}

async fn read_enablement(ctx: &Context, service_name: &str) -> Enablement {
    match is_service_enabled(ctx, service_name).await {
        Ok(true) => Enablement::Enabled,
        Ok(false) => Enablement::NotEnabled,
        Err(e) => Enablement::Unverifiable(format!(
            "systemctl is-enabled {service_name} could not be run: {e}"
        )),
    }
}

/// Whether the unit is currently running, classified the same three ways as
/// [`Enablement`], for the same reason: `systemctl is-active` exits non-zero
/// both for a unit that is genuinely not running and for an invocation that
/// could not run at all.
enum Activity {
    Active,
    NotActive,
    Unverifiable(String),
}

async fn read_activity(ctx: &Context, service_name: &str) -> Activity {
    match is_service_active(ctx, service_name).await {
        Ok(true) => Activity::Active,
        Ok(false) => Activity::NotActive,
        Err(e) => Activity::Unverifiable(format!(
            "systemctl is-active {service_name} could not be run: {e}"
        )),
    }
}

/// Every managed unit this rollback left disagreeing with the service
/// manager, and every one this probe could not decide.
///
/// A unit not installed on this host has nothing a rollback could have
/// restored, so there is nothing here for a running process to disagree
/// with: it is skipped rather than read at all.
///
/// Reporting only: none of the readings below start, stop, enable, disable,
/// mask or unmask anything.
pub(super) async fn service_divergences(ctx: &Context) -> Vec<RollbackDivergence> {
    let mut rows = Vec::new();

    for directive in UNNECESSARY_SERVICES {
        let name = directive.service_name;

        match is_service_exists(ctx, name).await {
            Ok(true) => {}
            Ok(false) => continue,
            Err(e) => {
                rows.push(row(
                    name,
                    DivergenceState::Unverifiable,
                    format!(
                        "whether {name} is installed could not be read, so whether its \
                         restored unit files disagree with the running service is unknown: {e}"
                    ),
                ));
                continue;
            }
        }

        let enablement = read_enablement(ctx, name).await;
        let activity = read_activity(ctx, name).await;

        match (enablement, activity) {
            (Enablement::Unverifiable(detail), _) => rows.push(row(
                name,
                DivergenceState::Unverifiable,
                format!(
                    "whether {name}'s restored unit files leave it enabled could not be read, \
                     so whether it disagrees with the running service is unknown: {detail}"
                ),
            )),
            (_, Activity::Unverifiable(detail)) => rows.push(row(
                name,
                DivergenceState::Unverifiable,
                format!(
                    "whether {name} is currently running could not be read, so whether it \
                     disagrees with its restored unit files is unknown: {detail}"
                ),
            )),
            // The restored files say disabled, but the service manager reports
            // it running anyway: whatever the rollback undid on disk, it did
            // not reach the running process.
            (Enablement::NotEnabled, Activity::Active) => rows.push(row(
                name,
                DivergenceState::Diverged,
                format!(
                    "{name}'s restored unit files leave it disabled, but the service manager \
                     reports it running"
                ),
            )),
            // The restored files say enabled, but the service manager reports
            // it stopped: reload_after_rollback only reloads the unit files,
            // it never starts anything, so a unit apply had stopped stays
            // stopped even once the files that governed it are put back.
            (Enablement::Enabled, Activity::NotActive) => rows.push(row(
                name,
                DivergenceState::Diverged,
                format!(
                    "{name}'s restored unit files leave it enabled, but the service manager \
                     reports it not running"
                ),
            )),
            // Enabled and running, or disabled and stopped: the restored
            // files and the service manager agree, and this probe makes no
            // claim.
            (Enablement::Enabled, Activity::Active)
            | (Enablement::NotEnabled, Activity::NotActive) => {}
        }
    }

    rows
}

mod tests;
