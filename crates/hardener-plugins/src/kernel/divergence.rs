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

        match effective.values.get(&persistence::procfs_key(name)) {
            Some(configured) if configured != &runtime => rows.push(row(
                name,
                DivergenceState::Diverged,
                format!(
                    "the running kernel reads {runtime} while the restored configuration says \
                     {configured}, so this host is not running what its own files describe"
                ),
            )),
            Some(_) => {}
            // Nothing names it. Reported only where the running value is at
            // least as strict as this tool's baseline, which is what the apply
            // would have left behind.
            None if !parameter
                .kernel_compare
                .violated_by(parameter.kernel_secure_value, Some(&runtime)) =>
            {
                rows.push(row(
                    name,
                    DivergenceState::Diverged,
                    format!(
                        "{name} reads {runtime} in the running kernel and no configuration file \
                         names it. A rollback restores files and reloads them; it does not write \
                         /proc/sys, so this value did not come from the restored configuration \
                         and will not survive a reboot unless the kernel default matches it"
                    ),
                ));
            }
            None => {}
        }
    }

    rows
}

mod tests;
