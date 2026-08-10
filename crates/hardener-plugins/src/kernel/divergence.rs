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
/// "nobody looked". `/etc/sysctl.conf` is held to exactly that rule too: a
/// copy of it nobody could read, and a glob in a copy anybody could, each earn
/// a row naming the file, whether or not the parameter loop below ever reaches
/// a key either of them could explain.
///
/// **`/etc/sysctl.conf` is a third case, and it splits the sentence in two.**
/// The rollback's reload is `procps sysctl --system`, which reads that file;
/// the next boot is `systemd-sysctl`, which does not. A parameter named only
/// there at the running value therefore DID come from the restored
/// configuration and still will not survive a reboot, so the row stays
/// `Diverged` and says the second thing rather than the first. Where no applier
/// is recognised the row is `Unverifiable` instead: see
/// [`persistence::boot_reads_legacy_conf`].
///
/// **A silence is judged on that file's value, never on the fact that it names
/// the key.** Where `/etc/sysctl.conf` names the parameter at some OTHER value,
/// the reload did not take: the only file naming the parameter says one thing
/// and the kernel reads another, which is a present-tense divergence and is
/// what the row says. Nothing exotic reaches it. `reload_after_rollback`
/// deliberately tolerates a non-zero exit from its own `sysctl --system`,
/// because a read-only parameter under a container runtime makes that exit
/// non-zero on an otherwise unremarkable host, so every key the reload failed
/// to write lands here with the value the apply left behind.
///
/// **No DISAGREEMENT row claims what the boot applier does with
/// `/etc/sysctl.conf`.** [`persistence::Reach::DoesNotRead`] is measured from
/// the applier on disk and settles that no `sysctl --system` runs at boot. It
/// does not settle that the file's content stays out of the boot sequence: a
/// host can reach the same inode through an `/etc/sysctl.d/99-sysctl.conf`
/// symlink, and there the drop-in reader has already applied that content under
/// the drop-in's name. So the disagreement rows predict the next boot from the
/// file that decides among the ones the boot sequence does apply, which holds
/// either way, rather than from a claim that the boot applier ignores the
/// legacy file, which does not.
///
/// The silence row below DOES make that stronger claim, and is entitled to:
/// it is reached only where no drop-in names the parameter, and a symlinked
/// `/etc/sysctl.conf` puts the key in `effective.values` under the drop-in's
/// name, so a linked file cannot reach that arm at all. The row is true by
/// unreachability rather than by wording, which is why the two arms are worded
/// differently and why this paragraph names which is which.
///
/// **That precedence also decides a disagreement, not only a silence.**
/// `man sysctl` reads `/etc/sysctl.conf` last, so it replaces anything a
/// drop-in set. A host whose drop-in says one value, whose `/etc/sysctl.conf`
/// says another, and whose kernel is running the second is running exactly
/// what its own files describe, and must not be told otherwise. The row stays
/// `Diverged` because the next boot hands the parameter to whichever file
/// decides among the ones the boot sequence applies, and it says that instead.
/// Where the two files name a third value between them the accusation does
/// stand, but the value a reload restores is the legacy file's, so that is the
/// value the row reports and the file it names: an operator sent to the
/// deciding file instead would edit it, reload, and still not get what it says.
/// That claim is qualified to the reload, because the file deciding the reload
/// need not be the file deciding the boot: [`persistence::effective_boot_values`]
/// chains `/etc/ufw/sysctl.conf` last, ufw applies it from a unit ordered after
/// `systemd-sysctl`, and `sysctl --system` never reads it at all.
///
/// **The same not-knowing cases block a disagreement as block a silence.**
/// An `/etc/sysctl.conf` nobody could read, a glob in it
/// [`persistence::glob_could_match`] says could name the parameter, a drop-in
/// source this scan could not resolve, and a drop-in glob that could name the
/// parameter each leave a file that decides the value unread for that key. A
/// `Diverged` row there would accuse a host of ignoring its own files, and name
/// the value the next boot brings, on the strength of every file but the ones
/// nobody read: the winner among the drop-ins this scan could read is not the
/// winner among all of them. So all four downgrade to `Unverifiable`, exactly
/// as they already do where no drop-in names the parameter at all. The two
/// globs keep their per-key narrowing in both places, because
/// `net.ipv4.conf.*` still cannot name `kernel.kptr_restrict` and blocking it
/// on that pattern would be a wrong answer in caution's wording.
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
                None,
            )
        })
        .collect();

    // A glob in `/etc/sysctl.conf` is the same kind of open question a glob in
    // a drop-in is, and it is worded the same way so the two read alike. It is
    // built once here because it is a property of the file, not of any one
    // parameter: which keys it could reach is decided per parameter below, by
    // `glob_could_match`.
    let legacy_glob_reason = (!legacy.glob_patterns.is_empty()).then(|| {
        "/etc/sysctl.conf assigns sysctls through glob patterns, which this scan does not resolve"
            .to_string()
    });

    // The same invariant the drop-in sources carry: silence never stands for
    // "nobody looked". A file that exists and could not be read, or one that
    // assigns through a pattern this scan will not resolve, is a question left
    // open, and the row names it so an operator can go and settle it. Without
    // a row here a legacy glob that reaches no managed parameter, or one whose
    // keys all land in some other branch, would leave the file unmentioned
    // anywhere on the host.
    rows.extend(
        legacy
            .unreadable
            .iter()
            .chain(legacy_glob_reason.iter())
            .map(|reason| {
                row(
                    "kernel parameters",
                    DivergenceState::Unverifiable,
                    format!(
                        "{reason}, so whether it names a parameter this rollback restored is \
                         unknown"
                    ),
                    None,
                )
            }),
    );

    // The clause a blocked per-parameter row adds to its own sentence. Every
    // kind of open question feeds it, because they block the same attribution:
    // a drop-in source this scan could not resolve, an `/etc/sysctl.conf`
    // nobody could read, and a glob in that same file. With exactly one of them
    // open, naming it here is more actionable than sending the operator to
    // cross-reference the generic rows above; with several, naming just one
    // would read as though that one were the cause, which is not known, so the
    // sentence stays generic and the rows above remain where every path is
    // named.
    let open_questions: Vec<&String> = effective
        .unresolved
        .iter()
        .chain(legacy.unreadable.iter())
        .chain(legacy_glob_reason.iter())
        .collect();
    let unresolved_clause = match open_questions.as_slice() {
        // "an unresolved source names this parameter" rather than "it names
        // it": the reason may end in a DIRECTORY, as `/etc/sysctl.d could not
        // be listed` does, and a directory names no parameter. Neither pronoun
        // had an antecedent the sentence supplied, which is #146. The parameter
        // cannot be named here because one clause serves every row, and the
        // sentence this is appended to has already named it.
        [reason] => format!(
            ", but {reason}, so whether an unresolved source names this parameter is unknown"
        ),
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
                    None,
                ));
                continue;
            }
        };

        let key = persistence::procfs_key(name);
        match effective.values.get(&key) {
            Some(configured) if configured != &runtime => {
                // The file the winning drop-in value came from, which is what
                // an operator has to go and edit. `sources` is filled from the
                // same merge as `values`, so the fallback is unreachable; it
                // exists so a broken invariant degrades to a vaguer sentence
                // rather than to a named file that was never measured. It is
                // not always a sysctl.d drop-in: `effective_boot_values` chains
                // `/etc/ufw/sysctl.conf` onto the drop-ins, so the fallback
                // wording has to be true of any restored configuration file.
                let deciding_file = effective
                    .sources
                    .get(&key)
                    .map_or("a restored configuration file", String::as_str);
                // Every blocked sentence opens on the same measurement, so it
                // is built once and each branch adds only what it could not
                // settle.
                let measured = format!(
                    "the running kernel reads {runtime} while {deciding_file} says {configured}"
                );
                // Four not-knowing cases come before any verdict, and for one
                // reason between them: the value in hand is the winner among
                // the files this scan could read, which is not the winner among
                // all of them.
                //
                // `man sysctl`, SYSTEM FILE PRECEDENCE: `/etc/sysctl.conf` is
                // read last and replaces whatever a drop-in set, so it, and not
                // the drop-in, decides what a reload leaves running. A copy
                // nobody could read, or a glob nobody resolved, could therefore
                // be the whole explanation for the running value.
                //
                // A drop-in source this scan could not resolve, and a drop-in
                // glob that could name this key, block just as much: either
                // could assign the running value, in which case the host IS
                // running what its files describe, and either could outrank the
                // drop-in named above, in which case the value the next boot
                // brings is not the one measured here.
                let (state, detail) = if let Some(reason) = &legacy.unreadable {
                    (
                        DivergenceState::Unverifiable,
                        format!(
                            "{measured}, but {reason}, and if that file is there a reload reads \
                             it after every drop-in, so whether it is what assigns {name} the \
                             running value is unknown"
                        ),
                    )
                } else if legacy
                    .glob_patterns
                    .iter()
                    .any(|pattern| persistence::glob_could_match(pattern, &key))
                {
                    (
                        DivergenceState::Unverifiable,
                        format!(
                            "{measured}, but a glob pattern in /etc/sysctl.conf could name \
                             {name}, and a reload reads that file after every drop-in, so \
                             whether it is what assigns {name} the running value is unknown"
                        ),
                    )
                } else if effective.blocks_all
                    || persistence::decided_after(
                        effective.unreadable_last_name.as_deref(),
                        effective.sources.get(&key).map(String::as_str),
                    )
                {
                    // Two questions, not one, and only the second is new.
                    // `blocks_all` is a directory nobody could list or a ufw
                    // file nobody could read, neither of which a name can
                    // narrow. `decided_after` is an unread drop-in FILE, and
                    // there the name settles it: under last-one-wins an unread
                    // file sorting before the file that decided this key
                    // cannot have decided it, so it blocks nothing here (#145).
                    // It still earns its own row above, so nothing is hidden;
                    // what it stops doing is downgrading every other
                    // parameter's verdict along with its own.
                    (
                        DivergenceState::Unverifiable,
                        format!(
                            "{measured}, but this scan could not resolve every configuration \
                             source, so whether an unresolved one assigns {name} the running \
                             value, and what the next boot leaves it at, are unknown"
                        ),
                    )
                } else if effective
                    .glob_patterns
                    .iter()
                    .any(|pattern| persistence::glob_could_match(pattern, &key))
                {
                    (
                        DivergenceState::Unverifiable,
                        format!(
                            "{measured}, but a glob pattern in the surviving configuration could \
                             name {name}, so whether it assigns {name} the running value, and \
                             what the next boot leaves it at, are unknown"
                        ),
                    )
                } else {
                    match legacy.values.get(&key) {
                        // The legacy file names the running value, so the
                        // rollback's own `sysctl --system` is exactly why the
                        // kernel is running it and the host IS running what
                        // its own files describe. The divergence is a future
                        // one: no reload runs at boot, and among the files the
                        // boot sequence does apply, the one named here decides.
                        Some(legacy_value) if legacy_value == &runtime => match reach {
                            // Stays divergence_expected: None. The criterion is not that the
                            // rollback always applies this, but whether it leaves the host
                            // stronger than its restored configuration asks. Here the host is
                            // correct now (the rollback applied it) but weaker after the next
                            // reboot, since the boot applier does not read /etc/sysctl.conf.
                            persistence::Reach::DoesNotRead => (
                                DivergenceState::Diverged,
                                format!(
                                    "the running kernel reads {runtime} because /etc/sysctl.conf \
                                     assigns it and a reload reads that file last, ahead of \
                                     {deciding_file}, which says {configured}. No such reload \
                                     runs at boot, and {deciding_file} is what decides {name} \
                                     among the files the boot sequence does apply, so the next \
                                     boot switches {name} to {configured}"
                                ),
                            ),
                            persistence::Reach::Unknown => (
                                DivergenceState::Unverifiable,
                                format!(
                                    "the running kernel reads {runtime} because /etc/sysctl.conf \
                                     assigns it and a reload reads that file last, ahead of \
                                     {deciding_file}, which says {configured}. Which applier \
                                     runs at boot on this host was not established, so whether \
                                     the next boot switches {name} to {configured} is unknown"
                                ),
                            ),
                        },
                        // A third value. The host really is running something
                        // no file names, so the accusation stands, but the
                        // value a reload would restore is the legacy file's
                        // and not the drop-in's: an operator who edits the
                        // drop-in reloads and still does not get what it says.
                        // The claim is qualified to the reload, because the
                        // boot is a different question with a different answer
                        // where `deciding_file` is ufw's: ufw applies its file
                        // after `systemd-sysctl`, and nothing at boot reads
                        // /etc/sysctl.conf.
                        Some(legacy_value) => (
                            DivergenceState::Diverged,
                            format!(
                                "the running kernel reads {runtime} while a reload restores \
                                 {legacy_value}, which /etc/sysctl.conf assigns and a reload \
                                 reads last, ahead of {deciding_file}, which says {configured}. \
                                 So this host is not running what its own files describe, and \
                                 the value a reload leaves behind is the one in /etc/sysctl.conf"
                            ),
                        ),
                        None => (
                            DivergenceState::Diverged,
                            format!(
                                "the running kernel reads {runtime} while the restored \
                                 configuration says {configured}, so this host is not running \
                                 what its own files describe"
                            ),
                        ),
                    }
                };
                rows.push(row(name, state, detail, None));
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
                //
                // Blocked is also not the same as knowing nothing. Where the
                // legacy file was read and does name the parameter, that is the
                // most actionable fact on the row and the only one measured, so
                // it is said rather than left for the operator to rediscover.
                // Both blocked branches carry the clause, for the same reason: a
                // glob that stops attribution does not stop an explicit
                // assignment from having been read, and `sysctl` would prefer
                // that assignment over the pattern anyway.
                let legacy_clause = match named_by_legacy {
                    Some(configured) => format!(
                        ". What was read says /etc/sysctl.conf assigns {name} {configured}, and \
                         a reload reads that file after every drop-in"
                    ),
                    None => String::new(),
                };
                // The same predicate the disagreement arm uses, and it answers
                // differently here for a reason rather than by accident: this
                // arm is reached when NO file was credited with the key, so
                // `sources` has no entry, `decided_after` gets `None` and every
                // unread name blocks. There is nothing for a name to sort
                // against when nothing named the parameter (#145).
                let unread_could_name = persistence::decided_after(
                    effective.unreadable_last_name.as_deref(),
                    effective.sources.get(&key).map(String::as_str),
                );
                let (state, detail, expected) = if effective.blocks_all
                    || unread_could_name
                    || legacy.unreadable.is_some()
                {
                    (
                        DivergenceState::Unverifiable,
                        format!(
                            "{name} reads {runtime} in the running kernel and no drop-in \
                             assignment names it{unresolved_clause}{legacy_clause}"
                        ),
                        None,
                    )
                } else if matched_pattern.is_some() {
                    (
                        DivergenceState::Unverifiable,
                        format!(
                            "{name} reads {runtime} in the running kernel and no drop-in \
                             assignment names it, but a glob pattern in the surviving \
                             configuration could name it, so whether it does is \
                             unknown{legacy_clause}"
                        ),
                        None,
                    )
                } else if let Some(configured) = named_by_legacy
                    && configured != &runtime
                {
                    // The one file naming the parameter says something the
                    // kernel is not running, so the reload did not take. The
                    // sentence says that and makes no claim about a later boot:
                    // what the kernel reads now did not come from any surviving
                    // file, whichever applier runs next.
                    (
                        DivergenceState::Diverged,
                        format!(
                            "{name} reads {runtime} in the running kernel while the only file \
                             naming it, /etc/sysctl.conf, says {configured}. A rollback reloads \
                             with `sysctl --system`, which reads that file after every drop-in, \
                             so the reload did not take and this host is not running what its \
                             own files describe"
                        ),
                        None,
                    )
                } else if let Some(configured) = named_by_legacy {
                    match reach {
                        // The file names the running value and the rollback's
                        // own `sysctl --system` applied it, so the running
                        // value did come from the restored configuration. What
                        // does not follow is the reboot: the boot applier does
                        // not read this file, so the value is lost at the next
                        // one. The symlink case the disagreement rows have to
                        // word around cannot arise here: a legacy file reached
                        // through `/etc/sysctl.d/99-sysctl.conf` is read by the
                        // drop-in reader, which puts the key in
                        // `effective.values` and this arm never runs.
                        // Stays divergence_expected: None. Same principle: the host will be
                        // weaker after the next reboot, not stronger, so it must not be demoted.
                        persistence::Reach::DoesNotRead => (
                            DivergenceState::Diverged,
                            format!(
                                "{name} reads {runtime} in the running kernel and the only file \
                                 naming it is /etc/sysctl.conf, which says {configured}. The \
                                 rollback's own `sysctl --system` reads that file, but the \
                                 applier that runs at boot does not, so this value is lost at \
                                 the next reboot unless the kernel default matches it"
                            ),
                            None,
                        ),
                        persistence::Reach::Unknown => (
                            DivergenceState::Unverifiable,
                            format!(
                                "{name} reads {runtime} in the running kernel and the only file \
                                 naming it is /etc/sysctl.conf, which says {configured}. Which \
                                 applier runs at boot on this host was not established, so \
                                 whether the value survives a reboot is unknown"
                            ),
                            None,
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
                        Some(
                            "a rollback restores files and reloads them and never writes \
                             /proc/sys, so a parameter no surviving file names keeps whatever \
                             the apply gave it until the next reboot"
                                .to_string(),
                        ),
                    )
                };
                rows.push(row(name, state, detail, expected));
            }
            None => {}
        }
    }

    rows
}

mod tests;
