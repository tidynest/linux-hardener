//! Shared privilege probe for commands that mutate system state.
//!
//! Every command in this crate can run against either a local executor or a
//! remote `--ssh` session, so the privilege gate must ask the *executor*
//! whether its session is privileged rather than inspecting the local
//! process euid, which only reflects the CLI's own invocation.

use hardener_core::SystemExecutor;

/// True if the executor's session is root (uid 0) or has passwordless sudo.
///
/// Fails closed: any error from `id -u` or `sudo -n true` is treated as
/// "not privileged", never as privileged. The privilege gate must never
/// pass on ambiguity.
pub(crate) async fn is_privileged(executor: &dyn SystemExecutor) -> bool {
    if let Ok(out) = executor.execute_command("id", &["-u"]).await
        && out.success()
        && out.stdout.trim() == "0"
    {
        return true;
    }
    matches!(
        executor.execute_command("sudo", &["-n", "true"]).await,
        Ok(o) if o.success()
    )
}

#[cfg(test)]
mod tests;
