//! What a kernel rollback left running that its restored files do not name.
//!
//! A rollback restores files and then runs `sysctl --system`. It never writes
//! `/proc/sys`. A parameter that no surviving file names therefore keeps
//! whatever the apply gave it, and the rollback reports success (#138).

use super::persistence::{self, DropinScope};
use super::{KERNEL_PARAMS, KernelHardeningPlugin};
use hardener_core::Context;
use hardener_types::{DivergenceState, RollbackDivergence};

/// The plugin id every row here carries.
const PLUGIN_ID: &str = "kernel-hardening";

fn row(subject: &str, state: DivergenceState, detail: String) -> RollbackDivergence {
    RollbackDivergence {
        divergence_plugin_id: PLUGIN_ID.to_string(),
        divergence_subject: subject.to_string(),
        divergence_state: state,
        divergence_detail: detail,
    }
}

/// Every managed parameter the running kernel and the surviving configuration
/// disagree about, and every one this probe could not decide.
///
/// **The unnamed case is judged by strictness, not by equality.** A value no
/// file names is reported when it is at least as strict as this tool's own
/// baseline, which catches an operator's raised target as well as the
/// baseline itself and needs no config to be plumbed through the rollback
/// path. It misses only a target an operator deliberately loosened below the
/// baseline, where there is little left to have been undone.
///
/// The sentence states the measurement and draws no conclusion about the
/// rollback: on a host whose kernel default already matches, the value is
/// correct and the sentence is still true.
///
/// **An unresolved source turns that same case into `Unverifiable`, not
/// `Diverged`, but only where it could actually be the reason.**
/// [`persistence::effective_boot_values`] never inserts a glob-matched key, so
/// a parameter no *explicit* assignment names looks identical whether nothing
/// names it or a glob this scan could not resolve does. Claiming `Diverged`
/// there would be exactly the confident claim this probe exists to refuse.
/// A file this scan could not read or list blocks every parameter, because an
/// unreadable file could name anything; a glob pattern this scan chose not to
/// resolve blocks only the parameters [`persistence::glob_could_match`] says
/// it could reach, because `net.ipv4.conf.*` cannot name `kernel.kptr_restrict`
/// and claiming otherwise is not caution, it is a wrong answer with caution's
/// wording.
///
/// **Every unresolved source also gets a row of its own,** independent of how
/// the parameter loop below classifies anything. Consulting `effective.unresolved`
/// only from inside that loop was tried once already: if every managed
/// parameter happens to land somewhere else (an explicit assignment that
/// agrees, a runtime read that errors, a value looser than the baseline), the
/// unresolved source produces no row anywhere, and the operator learns
/// nothing went unchecked. A row here, naming the file, is what the invariant
/// this module states in its own comment requires: silence never stands for
/// "nobody looked".
pub(super) async fn sysctl_divergences(ctx: &Context) -> Vec<RollbackDivergence> {
    let plugin = KernelHardeningPlugin::new();
    let effective = persistence::effective_boot_values(ctx, DropinScope::All).await;
    let mut rows: Vec<RollbackDivergence> = effective
        .unresolved
        .iter()
        .map(|reason| {
            row(
                "kernel parameters",
                DivergenceState::Unverifiable,
                format!("{reason}, so whether the restored configuration names them is unknown"),
            )
        })
        .collect();

    // The clause a blocked per-parameter row adds to its own sentence. With
    // exactly one unresolved source, naming it here is more actionable than
    // sending the operator to cross-reference the generic rows above; with
    // several, naming just one would read as though that one were the cause,
    // which is not known, so the sentence stays generic and the rows above
    // remain where every path is named.
    let unresolved_clause = match effective.unresolved.as_slice() {
        [reason] => format!(", but {reason}, so whether it names it is unknown"),
        _ => ", but this scan could not resolve every configuration source, so whether an \
              unresolved one names it is unknown"
            .to_string(),
    };

    for parameter in KERNEL_PARAMS {
        let name = parameter.kernel_parameter_name;
        let runtime = match plugin.read_sysctl(name, ctx).await {
            Ok(value) => value,
            Err(e) => {
                rows.push(row(
                    name,
                    DivergenceState::Unverifiable,
                    format!("/proc/sys could not be read for {name}, so whether it came back is unknown: {e}"),
                ));
                continue;
            }
        };

        let key = persistence::procfs_key(name);
        match effective.values.get(&key) {
            Some(configured) if configured != &runtime => rows.push(row(
                name,
                DivergenceState::Diverged,
                format!(
                    "the running kernel reads {runtime} while the restored configuration says \
                     {configured}, so this host is not running what its own files describe"
                ),
            )),
            Some(_) => {}
            // No explicit assignment names it. Reported only where the running
            // value is at least as strict as this tool's baseline, which is
            // what the apply would have left behind.
            None if !parameter
                .kernel_compare
                .violated_by(parameter.kernel_secure_value, Some(&runtime)) =>
            {
                let matched_pattern = effective
                    .glob_patterns
                    .iter()
                    .find(|pattern| persistence::glob_could_match(pattern, &key));
                let (state, detail) = if effective.blocks_all {
                    (
                        DivergenceState::Unverifiable,
                        format!(
                            "{name} reads {runtime} in the running kernel and no explicit \
                             assignment names it{unresolved_clause}"
                        ),
                    )
                } else if matched_pattern.is_some() {
                    (
                        DivergenceState::Unverifiable,
                        format!(
                            "{name} reads {runtime} in the running kernel and no explicit \
                             assignment names it, but a glob pattern in the surviving \
                             configuration could name it, so whether it does is unknown"
                        ),
                    )
                } else {
                    (
                        DivergenceState::Diverged,
                        format!(
                            "{name} reads {runtime} in the running kernel and no configuration \
                             file names it. A rollback restores files and reloads them; it does \
                             not write /proc/sys, so this value did not come from the restored \
                             configuration and will not survive a reboot unless the kernel \
                             default matches it"
                        ),
                    )
                };
                rows.push(row(name, state, detail));
            }
            None => {}
        }
    }

    rows
}

mod tests;
