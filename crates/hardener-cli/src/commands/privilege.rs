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
mod tests {
    use super::*;
    use hardener_common::executor::{CommandOutput, MockExecutor};

    #[tokio::test]
    async fn is_privileged_via_uid_and_sudo() {
        let ok = |stdout: &str| CommandOutput {
            stdout: stdout.into(),
            stderr: String::new(),
            exit_code: 0,
        };
        let fail = CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 1,
        };

        // uid 0 -> privileged; sudo is not even consulted
        let root = MockExecutor::new().with_command("id", &["-u"], ok("0\n"));
        assert!(is_privileged(&root).await);

        // non-root but passwordless sudo -> privileged
        let sudoer = MockExecutor::new()
            .with_command("id", &["-u"], ok("1000\n"))
            .with_command("sudo", &["-n", "true"], ok(""));
        assert!(is_privileged(&sudoer).await);

        // non-root, sudo denied -> not privileged
        let nope = MockExecutor::new()
            .with_command("id", &["-u"], ok("1000\n"))
            .with_command("sudo", &["-n", "true"], fail);
        assert!(!is_privileged(&nope).await);

        // id -u errors (transport/IO) and sudo also unavailable -> fail closed
        let broken = MockExecutor::new();
        assert!(
            !is_privileged(&broken).await,
            "errors from both probes must fail closed"
        );
    }
}
