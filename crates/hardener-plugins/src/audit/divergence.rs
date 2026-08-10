//! What an audit rollback left the kernel's loaded rule set disagreeing with,
//! on a host where that can be read at all (#142).
//!
//! Loading a kernel audit rule set is host-global in the same way an LSM
//! policy is, so no container this project can build can run `auditctl`.
//! Measured twice on 2026-08-10, booted and unbooted, in an arch container:
//! `auditctl -w /etc/hardener-divergence-probe -k hardener_probe` failed
//! before it got as far as attempting to load the rule, so the scenario this
//! probe would ideally measure (a restored rules file against a live kernel
//! disagreement) never became reachable. This probe is therefore written to
//! be honest about what it cannot compare rather than to measure something
//! unreachable, and it is #18 that turns it into a measurement on a real VM.

use hardener_core::Context;
use hardener_types::{DivergenceState, RollbackDivergence};

use super::{AuditRulesResult, read_current_audit_rules};

/// The plugin id every row here carries.
const PLUGIN_ID: &str = "audit-hardening";

/// The subject every row here carries: this probe reports on the kernel's
/// loaded rule set as a whole, never on one rule at a time.
const SUBJECT: &str = "audit-rules";

fn row(state: DivergenceState, detail: String, expected: Option<String>) -> RollbackDivergence {
    RollbackDivergence {
        divergence_plugin_id: PLUGIN_ID.to_string(),
        divergence_subject: SUBJECT.to_string(),
        divergence_state: state,
        divergence_detail: detail,
        divergence_expected: expected,
    }
}

/// One row, always, whenever this is asked at all. The kernel's loaded rule
/// set and the rules file a rollback restored are separate things, and this
/// probe can currently establish the first on no host the suite can build,
/// and would still need a comparison this crate does not implement even on a
/// host where it could.
///
/// **`Unverifiable`, never an empty vector.** An empty vector has a defined
/// meaning here: everything checkable came back. That is a claim about the
/// running system, and this probe has not earned it. It is also never
/// `Diverged`: nothing read here has been compared against the restored
/// file, so nothing here can say the two disagree.
///
/// Reporting only: `read_current_audit_rules` shells out to `auditctl -l`,
/// which lists the loaded rule set; nothing this probe calls loads, deletes
/// or alters a rule.
pub(super) async fn audit_divergences(ctx: &Context) -> Vec<RollbackDivergence> {
    // The ceiling reason for `ProbeFailed` and `PermissionDenied`: both are
    // the measured, stated ceiling this project has already named an issue
    // for (auditctl cannot run in any container this project builds, booted
    // or not).
    const UNRUNNABLE_CEILING_REASON: &str = "a stated ceiling rather than a probe that failed: auditctl cannot run in any \
         container this project builds, measured booted and unbooted. #18 turns this \
         into a measurement";

    let (reason, expected) = match read_current_audit_rules(ctx).await {
        // The rule set was read, so the limitation is not access but
        // comparison: nothing here checks a read-back rule set against the
        // file a rollback restored, because that comparison is not
        // implemented. Still expected, but the reason has to describe the
        // comparison this crate does not implement, not the "auditctl cannot
        // run" ceiling that arm never reached: auditctl plainly ran here.
        AuditRulesResult::Rules(rules) => (
            format!(
                "auditctl read {} loaded audit rule(s) from the kernel, but comparing them \
                 against the restored audit rules file is not implemented",
                rules.len()
            ),
            Some(
                "a stated ceiling rather than a probe that failed: comparing a read-back \
                 rule set against the restored audit rules file is not implemented in this \
                 crate. #18 turns this into a measurement"
                    .to_string(),
            ),
        ),
        // `auditctl` ran and refused for lack of privilege: distinct from
        // the binary being unrunnable, because the fix is different (a
        // privilege the caller lacks, not a package that is missing).
        AuditRulesResult::PermissionDenied => (
            "auditctl refused to list the kernel's loaded audit rules for lack of privilege, \
             so the kernel rule set cannot be read back here"
                .to_string(),
            Some(UNRUNNABLE_CEILING_REASON.to_string()),
        ),
        // `auditctl` could not be run at all, carrying the reason
        // `read_current_audit_rules` recorded (most commonly: the audit
        // package is not installed, which no privilege fixes).
        AuditRulesResult::ProbeFailed(cause) => (
            format!(
                "auditctl could not be run, so the kernel's loaded audit rules cannot be read \
                 back here: {cause}"
            ),
            Some(UNRUNNABLE_CEILING_REASON.to_string()),
        ),
        // `auditctl -l` ran and exited non-zero for a reason that is neither
        // a recognised permission refusal nor an unspawnable binary. Scan
        // and validate fold this back to Rules(Vec::new()), the conservative
        // choice this used to collapse into silently; apply never calls
        // read_current_audit_rules at all, so it is untouched either way.
        // This probe folds neither, because "auditctl read 0 loaded audit
        // rule(s) from the kernel" is a positive claim about the kernel that
        // a failed, unrecognised command answered nothing to support. Not
        // expected: this is exactly the unrecognised case the design's risk
        // section says must not inherit the demotion the other arms carry.
        AuditRulesResult::UnrecognisedFailure(cause) => (
            format!(
                "auditctl failed for a reason this project does not recognise as a permission \
                 refusal, so the kernel's loaded audit rules cannot be read back here: {cause}"
            ),
            None,
        ),
    };

    vec![row(
        DivergenceState::Unverifiable,
        format!("{reason}. See #18."),
        expected,
    )]
}

#[cfg(test)]
mod tests;
