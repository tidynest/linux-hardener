//! What a MAC rollback left enforcing that its restored files do not ask for,
//! on a host where that can be read at all.
//!
//! Loading an LSM policy is host-global, so no container on the development
//! machine can be given MAC enforcement: the kernel there exposes
//! `capability,landlock,lockdown,yama,bpf` and nothing else. This probe is
//! therefore written to be honest about what it cannot read rather than to
//! measure something unreachable, and it is #18 that turns it into a
//! measurement on a real VM.

use super::{MacDetection, MacHardeningPlugin, MacSystem};
use hardener_core::Context;
use hardener_types::{DivergenceState, RollbackDivergence};

/// The plugin id every row here carries.
const PLUGIN_ID: &str = "mac-hardening";

fn row(subject: &str, state: DivergenceState, detail: String) -> RollbackDivergence {
    RollbackDivergence {
        divergence_plugin_id: PLUGIN_ID.to_string(),
        divergence_subject: subject.to_string(),
        divergence_state: state,
        divergence_detail: detail,
    }
}

/// One row, always. A restored MAC configuration and the policy the kernel is
/// actually enforcing are separate things, and this probe can currently
/// establish the second on no host the suite can build.
///
/// **`Unverifiable`, never an empty vector.** An empty vector has a defined
/// meaning here: everything checkable came back. That is a claim about the
/// running system, and this probe has not earned it.
pub(super) async fn mac_divergences(
    plugin: &MacHardeningPlugin,
    ctx: &Context,
) -> Vec<RollbackDivergence> {
    let (subject, reason) = match plugin.detect_mac_system(ctx).await {
        MacDetection::Found(MacSystem::SELinux) => (
            "selinux",
            "the policy the kernel is enforcing cannot be compared against the restored \
             configuration: reading it back needs a host where a policy can be loaded"
                .to_string(),
        ),
        MacDetection::Found(MacSystem::AppArmor) => (
            "apparmor",
            "the profile set the kernel is enforcing cannot be compared against the restored \
             configuration: reading it back needs a host where a profile can be loaded"
                .to_string(),
        ),
        MacDetection::Absent => (
            "mac",
            "no MAC system was detected, so nothing can be read back to compare against the \
             restored configuration"
                .to_string(),
        ),
        // Kept apart from `Absent` on purpose. "No MAC here" and "the probe
        // could not tell" are different sentences, and the detection carries
        // its own reason precisely so the second one can be passed on.
        MacDetection::Indeterminate(reason) => (
            "mac",
            format!("the host could not be probed for a MAC system: {reason}"),
        ),
    };

    vec![row(
        subject,
        DivergenceState::Unverifiable,
        format!("{reason}. See #18."),
    )]
}

mod tests;
