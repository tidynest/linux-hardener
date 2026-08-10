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

use super::{UNNECESSARY_SERVICES, is_service_exists};
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
/// ways rather than two. `systemctl is-enabled` exits zero for `enabled` but
/// also for `static`, `indirect`, `enabled-runtime`, `generated` and `alias`
/// (`ENABLED_STATES` in `services/mod.rs` spells out all seven), and it exits
/// non-zero both for a unit that is genuinely `disabled`/`masked` and for an
/// invocation that could not run at all. The exit status therefore cannot
/// carry this probe's answer, unlike [`is_service_enabled`](super::is_service_enabled),
/// whose exit-status reading is deliberately correct for the apply path that
/// calls it. This probe reads the printed word directly through the
/// executor instead, the way `ssh/divergence.rs`'s `read_enablement` does.
///
/// Five words are interpreted and the rest are not. `enabled` and
/// `enabled-runtime` count as enabled; `disabled`, `masked` and
/// `masked-runtime` count as not enabled. The two `-runtime` words say the
/// state holds for this boot only, which is still an unambiguous answer to
/// what this probe asks, because it only ever asks about now: a rollback
/// either restored the unit to the enablement the checkpoint recorded or it
/// did not, and neither question reaches past the current boot.
///
/// Every other word is unverifiable rather than guessed, which is a statement
/// about that word and not about the probe's reach. `static`, `indirect`,
/// `alias`, `generated` and `transient` are not refusals to read: each is a
/// unit whose enablement is not a settable property to begin with, so there is
/// no value a rollback could have restored and nothing for this probe to
/// compare. Adding them to either bucket would manufacture an answer rather
/// than sharpen one.
/// Each interpreted variant carries the word it was built from, because the
/// bucket is not specific enough for the sentence a reader gets. Three words
/// reach `NotEnabled`, and calling a `masked` unit "disabled" is true in
/// effect and wrong in fact: masking symlinks the unit to `/dev/null` and
/// refuses starts, disabling drops the `[Install]` symlinks and leaves it
/// startable by hand or as a dependency, and the two are undone by different
/// commands.
enum Enablement {
    Enabled(String),
    NotEnabled(String),
    Unverifiable(String),
}

/// Reads `systemctl is-enabled` for `service_name` and classifies the printed
/// word, never the exit status.
async fn read_enablement(ctx: &Context, service_name: &str) -> Enablement {
    match ctx
        .executor()
        .execute_command("systemctl", &["is-enabled", service_name])
        .await
    {
        Ok(output) => match output.stdout.trim() {
            word @ ("enabled" | "enabled-runtime") => Enablement::Enabled(word.to_string()),
            word @ ("disabled" | "masked" | "masked-runtime") => {
                Enablement::NotEnabled(word.to_string())
            }
            other => Enablement::Unverifiable(format!(
                "systemctl is-enabled {service_name} printed none of 'enabled', \
                 'enabled-runtime', 'disabled', 'masked' or 'masked-runtime': {other:?}"
            )),
        },
        Err(e) => Enablement::Unverifiable(format!(
            "systemctl is-enabled {service_name} could not be run: {e}"
        )),
    }
}

/// Whether the unit is currently running, classified the same three ways as
/// [`Enablement`] and read the same way: the printed word, not
/// [`is_service_active`](super::is_service_active)'s exit status. `systemctl
/// is-active` exits non-zero both for a unit that is genuinely not running
/// and for an invocation that could not run at all, so only the word tells
/// the two apart.
enum Activity {
    Active,
    NotActive,
    Unverifiable(String),
}

/// Reads `systemctl is-active` for `service_name` and classifies the printed
/// word, never the exit status.
///
/// Every word other than `active`, `inactive` and `failed` falls to
/// `Unverifiable`, which includes the transitional `reloading`, `activating`
/// and `deactivating`. That is deliberate, and it deliberately disagrees with
/// [`ServiceStates::active`](super::ServiceStates::active), in this same
/// plugin, which counts `reloading` as active.
///
/// The two answer different questions. That one asks whether an unnecessary
/// service is running, where a unit mid-reload is running and dropping the
/// finding would hide a real one. This one asks whether a rollback restored a
/// settled state, and a unit mid-reload has not settled, so there is no
/// answer to compare against the checkpoint. Calling it `NotActive` would
/// claim the rollback took when nothing was read; calling it `Active` would
/// claim it did not. `Unverifiable` is the only one of the three that is true.
async fn read_activity(ctx: &Context, service_name: &str) -> Activity {
    match ctx
        .executor()
        .execute_command("systemctl", &["is-active", service_name])
        .await
    {
        Ok(output) => match output.stdout.trim() {
            "active" => Activity::Active,
            "inactive" | "failed" => Activity::NotActive,
            other => Activity::Unverifiable(format!(
                "systemctl is-active {service_name} printed neither 'active', 'inactive' \
                 nor 'failed': {other:?}"
            )),
        },
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
            // Not enabled, but the service manager reports it running anyway:
            // whatever the rollback undid on disk, it did not reach the
            // running process.
            //
            // Both sentences below report the word that was read rather than
            // asserting where the state came from. The previous wording said
            // "restored unit files leave it ...", which named the wrong source
            // for two of the five words: `enabled-runtime` and
            // `masked-runtime` live in `/run`, not in the unit files a
            // rollback restores.
            (Enablement::NotEnabled(word), Activity::Active) => rows.push(row(
                name,
                DivergenceState::Diverged,
                format!(
                    "{name} reads {word} after the rollback, but the service manager reports \
                     it running"
                ),
            )),
            // Enabled, but the service manager reports it stopped:
            // reload_after_rollback only reloads the unit files, it never
            // starts anything, so a unit apply had stopped stays stopped even
            // once the files that governed it are put back.
            (Enablement::Enabled(word), Activity::NotActive) => rows.push(row(
                name,
                DivergenceState::Diverged,
                format!(
                    "{name} reads {word} after the rollback, but the service manager reports \
                     it not running"
                ),
            )),
            // Enabled and running, or not enabled and stopped: the enablement
            // and the service manager agree, and this probe makes no claim.
            (Enablement::Enabled(_), Activity::Active)
            | (Enablement::NotEnabled(_), Activity::NotActive) => {}
        }
    }

    rows
}

mod tests;
