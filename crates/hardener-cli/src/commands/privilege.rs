//! Shared privilege probe for commands that mutate system state.
//!
//! Every command in this crate can run against either a local executor or a
//! remote `--ssh` session, so the privilege gate must ask the *executor*
//! whether its session is privileged rather than inspecting the local
//! process euid, which only reflects the CLI's own invocation.

use hardener_core::{SystemExecutor, session_is_root};

/// True if the executor's session is root (uid 0) or has passwordless sudo.
///
/// The uid half is [`session_is_root`], which the ssh plugin's remote-root
/// guard and the unchecked entries' blocker both need as well; this gate is
/// the only one of the three that also accepts an available elevation, because
/// it is asking whether a mutation can be performed rather than whether one
/// has already been tried.
///
/// Fails closed: any error from `id -u` or `sudo -n true` is treated as
/// "not privileged", never as privileged. The privilege gate must never
/// pass on ambiguity.
pub(crate) async fn is_privileged(executor: &dyn SystemExecutor) -> bool {
    session_is_root(executor).await
        || matches!(
            executor.execute_command("sudo", &["-n", "true"]).await,
            Ok(o) if o.success()
        )
}

#[cfg(test)]
mod tests;
