//! What a MAC rollback left enforcing that its restored files do not ask for,
//! on a host where that can be read at all.
//!
//! Loading an LSM policy is host-global, so no container on the development
//! machine can be given MAC enforcement: the kernel there exposes
//! `capability,landlock,lockdown,yama,bpf` and nothing else. This probe is
//! therefore written to be honest about what it cannot read rather than to
//! measure something unreachable, and it is #18 that turns it into a
//! measurement on a real VM.
//!
//! A host with no MAC system detected at all is a different case from either
//! of those, and reported differently: there is no restored MAC configuration
//! and no policy the kernel could be enforcing instead, so there is nothing
//! for a divergence to be between. `firewall/divergence.rs` treats the
//! matching situation, no backend installed, the same way and for the same
//! reason: genuinely nothing installed is not a divergence.

use super::{MacDetection, MacHardeningPlugin, MacSystem};
use hardener_core::Context;
use hardener_types::{DivergenceState, RollbackDivergence};

/// The plugin id every row here carries.
const PLUGIN_ID: &str = "mac-hardening";

fn row(
    subject: &str,
    state: DivergenceState,
    detail: String,
    expected: Option<String>,
) -> RollbackDivergence {
    RollbackDivergence {
        divergence_plugin_id: PLUGIN_ID.to_string(),
        divergence_subject: subject.to_string(),
        divergence_state: state,
        divergence_detail: detail,
        divergence_expected: expected,
    }
}

/// One row for a detected MAC system whose enforcement cannot be read back,
/// none for a host with no MAC system at all.
///
/// **`Unverifiable`, never an empty vector, for `Found` and `Indeterminate`.**
/// An empty vector has a defined meaning here: everything checkable came
/// back. That is a claim about the running system, and this probe has not
/// earned it on those two arms. `Absent` is the exception: a host with
/// nothing installed has no restored configuration and no enforced policy
/// for either to disagree with, so an empty vector there is not a dodge, it
/// is the correct answer, the same one `firewall/divergence.rs` gives for a
/// host with no firewall backend installed.
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
        // Genuinely nothing installed is not a divergence: there is no
        // configuration to disagree with, and no policy enforcing anything
        // else either.
        MacDetection::Absent => return Vec::new(),
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
        Some(
            "a stated ceiling rather than a probe that failed: loading an LSM policy is \
             host-global, so no container this project can build can be given MAC \
             enforcement to disagree about. #18 turns this into a measurement"
                .to_string(),
        ),
    )]
}

mod tests;
