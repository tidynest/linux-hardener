//! What an sshd rollback left running against a configuration it could not
//! reload onto (#142).
//!
//! `reload_after_rollback` (`ssh/mod.rs`) restarts sshd unconditionally
//! whenever a rollback restores anything under `/etc/ssh`, and reports a
//! failed restart upward as an `Err` from that method, never through this
//! file: the reload and this probe run independently (`lib.rs`'s
//! `reconcile_plugins_after_rollback`), so a restart that could not take
//! leaves nothing here to read directly.
//!
//! Measured 2026-08-10 in a booted arch container
//! (`scripts/test/verify-rollback.sh` TEST 10): masking `sshd.service`
//! before a rollback left it reporting `active` both immediately before the
//! mask and again after the rollback's restart attempt. Masking a unit
//! refuses future start and restart commands; it does not stop a unit
//! already running. So the restart `reload_after_rollback` attempted could
//! not have taken, sshd carried on serving the pre-rollback configuration,
//! and `divergences_after_rollback` reported nothing. That silence is the
//! gap this closes.
//!
//! **Running alone proves nothing.** A restart that succeeded also leaves
//! sshd running, so "is it running" cannot be the whole test: a probe that
//! reported a divergence on every running sshd would fire on every healthy
//! host, which is a false alarm rather than a missed one. What proves the
//! restart could not have taken is the unit being masked, which
//! `systemctl restart` refuses outright regardless of what was running
//! beforehand. The divergence this probe reports is specifically "running
//! and masked": a masked and STOPPED sshd is serving nothing, and there is
//! nothing there to disagree with the restored file.

use hardener_core::Context;
use hardener_types::{DivergenceState, RollbackDivergence};

/// The plugin id every row here carries.
const PLUGIN_ID: &str = "ssh-hardening";

/// The unit name `restart_ssh_service`'s primary, systemctl-based path
/// restarts (`ssh/mod.rs`: `systemctl restart sshd`). Asking about any other
/// name would measure a unit the reload never tried to touch.
const SSHD_UNIT: &str = "sshd";

fn row(state: DivergenceState, detail: String) -> RollbackDivergence {
    RollbackDivergence {
        divergence_plugin_id: PLUGIN_ID.to_string(),
        divergence_subject: SSHD_UNIT.to_string(),
        divergence_state: state,
        divergence_detail: detail,
    }
}

/// Whether the unit is currently running, classified three ways rather than
/// two. `systemctl is-active` exits non-zero both for a unit that is
/// genuinely not running and for a systemctl invocation that could not run
/// at all, and this probe must never turn the second case into a claim about
/// the first.
enum Activity {
    Running,
    NotRunning,
    Unverifiable(String),
}

/// Reads `systemctl is-active` for [`SSHD_UNIT`] and classifies the result.
///
/// Matched against the exact words systemd prints for the states this probe
/// cares about, never `contains`, for the same reason `firewall/divergence`
/// matches `ufw status`'s status line exactly: substring matching against
/// "active" would read "inactive" as running.
async fn read_activity(ctx: &Context) -> Activity {
    match ctx
        .executor()
        .execute_command("systemctl", &["is-active", SSHD_UNIT])
        .await
    {
        Ok(output) => match output.stdout.trim() {
            "active" => Activity::Running,
            "inactive" | "failed" => Activity::NotRunning,
            other => Activity::Unverifiable(format!(
                "systemctl is-active {SSHD_UNIT} printed neither 'active', 'inactive' \
                 nor 'failed': {other:?}"
            )),
        },
        Err(e) => Activity::Unverifiable(format!(
            "systemctl is-active {SSHD_UNIT} could not be run: {e}"
        )),
    }
}

/// Whether the unit is masked, classified the same three ways as
/// [`Activity`]. `systemctl is-enabled` exits non-zero both for a masked
/// unit and for a merely disabled one, so the exit code alone cannot tell
/// them apart; the printed word is what carries the answer, and printing
/// nothing is evidence of neither state.
enum Enablement {
    Masked,
    NotMasked,
    Unverifiable(String),
}

/// Reads `systemctl is-enabled` for [`SSHD_UNIT`] and classifies the result.
async fn read_enablement(ctx: &Context) -> Enablement {
    match ctx
        .executor()
        .execute_command("systemctl", &["is-enabled", SSHD_UNIT])
        .await
    {
        Ok(output) => match output.stdout.trim() {
            "masked" => Enablement::Masked,
            "" => Enablement::Unverifiable(format!(
                "systemctl is-enabled {SSHD_UNIT} printed no output"
            )),
            _ => Enablement::NotMasked,
        },
        Err(e) => Enablement::Unverifiable(format!(
            "systemctl is-enabled {SSHD_UNIT} could not be run: {e}"
        )),
    }
}

/// Whether sshd is still serving the pre-rollback configuration because a
/// restart onto the restored one could not take.
///
/// Reporting only: neither reading here starts, stops, restarts or unmasks
/// anything.
pub(super) async fn sshd_divergences(ctx: &Context) -> Vec<RollbackDivergence> {
    match read_activity(ctx).await {
        // Nothing is being served, so there is nothing to disagree with the
        // restored file. Whether the unit happens to be masked too is
        // irrelevant here: a stopped unit is not a divergence regardless.
        Activity::NotRunning => Vec::new(),
        Activity::Unverifiable(detail) => vec![row(
            DivergenceState::Unverifiable,
            format!(
                "whether {SSHD_UNIT} is running could not be read, so whether it is serving \
                 the restored configuration is unknown: {detail}"
            ),
        )],
        Activity::Running => match read_enablement(ctx).await {
            // Running and masked: the restart reload_after_rollback attempted
            // was refused outright, so whatever is running is whatever was
            // running before the rollback, not the restored configuration.
            Enablement::Masked => vec![row(
                DivergenceState::Diverged,
                format!(
                    "{SSHD_UNIT} is running and masked, so the restart reload_after_rollback \
                     attempted could not have applied the restored configuration; masking \
                     refuses future starts but does not stop a unit already running"
                ),
            )],
            // Running and not masked: nothing here contradicts a restart
            // having succeeded, so this probe makes no claim.
            Enablement::NotMasked => Vec::new(),
            Enablement::Unverifiable(detail) => vec![row(
                DivergenceState::Unverifiable,
                format!(
                    "{SSHD_UNIT} is running, but whether it is masked, and so whether its \
                     restart onto the restored configuration could have taken, could not be \
                     read: {detail}"
                ),
            )],
        },
    }
}

mod tests;
