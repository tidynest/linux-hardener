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
///
/// **`/etc/sysctl.conf` is a third case, and it splits the sentence in two.**
/// The rollback's reload is `procps sysctl --system`, which reads that file;
/// the next boot is `systemd-sysctl`, which does not. A parameter named only
/// there therefore DID come from the restored configuration and still will not
/// survive a reboot, so the row stays `Diverged` and says the second thing
/// rather than the first. Where no applier is recognised the row is
/// `Unverifiable` instead: see [`persistence::boot_reads_legacy_conf`].
///
/// **That precedence also decides a disagreement, not only a silence.**
/// `man sysctl` reads `/etc/sysctl.conf` last, so it replaces anything a
/// drop-in set. A host whose drop-in says one value, whose `/etc/sysctl.conf`
/// says another, and whose kernel is running the second is running exactly
/// what its own files describe, and must not be told otherwise. The row stays
/// `Diverged` because the next boot hands the parameter back to the drop-in,
/// and it says that instead.
pub(super) async fn sysctl_divergences(ctx: &Context) -> Vec<RollbackDivergence> {
    let plugin = KernelHardeningPlugin::new();
    let effective = persistence::effective_boot_values(ctx, DropinScope::All).await;
    // `/etc/sysctl.conf` is read here and not through `effective_boot_values`
    // because only this caller may see it: the scan's question is which file
    // overrides this tool's own, and a file the boot applier does not read
    // overrides nothing at boot. Read once, outside the loop, because the
    // answer is the same for every parameter.
    let legacy = persistence::legacy_sysctl_conf(ctx).await;
    let reach = persistence::boot_reads_legacy_conf(ctx).await;
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

    // The same invariant the drop-in sources carry: silence never stands for
    // "nobody looked". A file that exists and could not be read is a question
    // left open, and the row names it so an operator can go and settle it.
    if let Some(reason) = &legacy.unreadable {
        rows.push(row(
            "kernel parameters",
            DivergenceState::Unverifiable,
            format!("{reason}, so whether it names a parameter this rollback restored is unknown"),
        ));
    }

    // The clause a blocked per-parameter row adds to its own sentence. Both
    // kinds of open question feed it, because both block the same attribution:
    // a drop-in source this scan could not resolve, and an `/etc/sysctl.conf`
    // nobody could read. With exactly one of them open, naming it here is more
    // actionable than sending the operator to cross-reference the generic rows
    // above; with several, naming just one would read as though that one were
    // the cause, which is not known, so the sentence stays generic and the rows
    // above remain where every path is named.
    let open_questions: Vec<&String> = effective
        .unresolved
        .iter()
        .chain(legacy.unreadable.iter())
        .collect();
    let unresolved_clause = match open_questions.as_slice() {
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
            Some(configured) if configured != &runtime => {
                // `man sysctl`, SYSTEM FILE PRECEDENCE: `/etc/sysctl.conf` is
                // read last and replaces whatever a drop-in set. So when that
                // file names this parameter with the value the kernel is
                // running, the rollback's own `sysctl --system` is exactly why
                // the kernel is running it, and the host IS running what its
                // own files describe. The divergence is a future one: the boot
                // applier never reads that file, so the next boot hands the
                // parameter back to the drop-in's value.
                let (state, detail) = if let Some(legacy_value) = legacy.values.get(&key)
                    && legacy_value == &runtime
                {
                    match reach {
                        persistence::Reach::DoesNotRead => (
                            DivergenceState::Diverged,
                            format!(
                                "the running kernel reads {runtime} because /etc/sysctl.conf \
                                 assigns it and is read last, ahead of the restored sysctl.d \
                                 drop-in configuration saying {configured}. The applier that \
                                 runs at boot does not read /etc/sysctl.conf at all, so the next \
                                 boot switches {name} to {configured}"
                            ),
                        ),
                        persistence::Reach::Unknown => (
                            DivergenceState::Unverifiable,
                            format!(
                                "the running kernel reads {runtime} because /etc/sysctl.conf \
                                 assigns it and is read last, ahead of the restored sysctl.d \
                                 drop-in configuration saying {configured}. Which applier runs \
                                 at boot on this host was not established, so whether the next \
                                 boot switches {name} to {configured} is unknown"
                            ),
                        ),
                    }
                } else {
                    (
                        DivergenceState::Diverged,
                        format!(
                            "the running kernel reads {runtime} while the restored configuration \
                             says {configured}, so this host is not running what its own files \
                             describe"
                        ),
                    )
                };
                rows.push(row(name, state, detail));
            }
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
                    .chain(legacy.glob_patterns.iter())
                    .find(|pattern| persistence::glob_could_match(pattern, &key));
                // Only what `/etc/sysctl.conf` explicitly assigns is read at
                // this statement: the same file's glob patterns went into
                // `matched_pattern` just above, and whether it could be read at
                // all is one of the two not-knowing cases tested below. Those
                // two come first because an unresolved source could name this
                // parameter in a file the boot applier DOES read, which would
                // make the reboot claim wrong.
                let named_by_legacy = legacy.values.get(&key);
                // Both not-knowing sentences say "no drop-in assignment", not
                // "no explicit assignment": `/etc/sysctl.conf` can carry an
                // explicit assignment for this key and still be reached here,
                // through a blocked drop-in source or a drop-in glob, and the
                // wider claim would then be false.
                let (state, detail) = if effective.blocks_all || legacy.unreadable.is_some() {
                    (
                        DivergenceState::Unverifiable,
                        format!(
                            "{name} reads {runtime} in the running kernel and no drop-in \
                             assignment names it{unresolved_clause}"
                        ),
                    )
                } else if matched_pattern.is_some() {
                    (
                        DivergenceState::Unverifiable,
                        format!(
                            "{name} reads {runtime} in the running kernel and no drop-in \
                             assignment names it, but a glob pattern in the surviving \
                             configuration could name it, so whether it does is unknown"
                        ),
                    )
                } else if let Some(configured) = named_by_legacy {
                    match reach {
                        // The file names it and the rollback's own `sysctl
                        // --system` applied it, so the running value did come
                        // from the restored configuration. What does not
                        // follow is the reboot: the boot applier does not read
                        // this file, so the value is lost at the next one.
                        persistence::Reach::DoesNotRead => (
                            DivergenceState::Diverged,
                            format!(
                                "{name} reads {runtime} in the running kernel and the only file \
                                 naming it is /etc/sysctl.conf, which says {configured}. The \
                                 rollback's own `sysctl --system` reads that file, but the \
                                 applier that runs at boot does not, so this value is lost at \
                                 the next reboot unless the kernel default matches it"
                            ),
                        ),
                        persistence::Reach::Unknown => (
                            DivergenceState::Unverifiable,
                            format!(
                                "{name} reads {runtime} in the running kernel and the only file \
                                 naming it is /etc/sysctl.conf, which says {configured}. Which \
                                 applier runs at boot on this host was not established, so \
                                 whether the value survives a reboot is unknown"
                            ),
                        ),
                    }
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
