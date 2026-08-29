//! The apply half of the SSH plugin: the body of `SshHardeningPlugin::apply`.
//!
//! Locks the config path the layered reader resolved, checkpoints it, backs
//! it up, writes the managed directives (to the drop-in where the main file
//! cannot win), passes the candidate through `sshd -t` before anything is
//! committed, and restarts the service only after that check passed. The
//! trait method in `mod.rs` delegates here.

use super::{
    MainConfig, PERMIT_ROOT_LOGIN, REMOTE_ROOT_SAFE_VALUE, SSH_CRYPTO_DIRECTIVES, SSH_DIRECTIVES,
    SSHD_ADMIN_CONFIG_PATH, SshHardeningPlugin, backup_prefix, crypto_value_is_secure, dropin,
    include, is_remote_root_session, keep_value_the_fragment_holds, lock_config_path,
    observed_value, resolved_target, select_algorithms, supported_algorithms, validate_sshd_config,
    verify_dropin_precedence,
};

use chrono::Utc;
use hardener_common::{
    error::{HardeningError, Result},
    file_utils::{
        ConfigFormat, Duplicates, global_scope, parse_config_value, set_config_directive,
    },
    types::PluginId,
    vendor_config::{ConfigLayer, LayeredRead, read_layered},
};
use hardener_core::{ApplyResult, Change, ChangeType, PluginConfig, context::Context};
use std::path::Path;
use tracing::{error, info, warn};

pub(super) async fn apply(ctx: &mut Context, config: &PluginConfig) -> Result<ApplyResult> {
    let plugin_id = PluginId::new("ssh-hardening");

    // Step 1: Find the config actually in force, then lock it. openSUSE
    // ships no /etc/ssh/sshd_config and keeps the vendor one under
    // /usr/etc, so a lock opening the admin path directly died there
    // before anything else ran. Locking the resolved path serialises
    // concurrent runs just as well, because they resolve the same file.
    let main = match read_layered(ctx.executor().as_ref(), SSHD_ADMIN_CONFIG_PATH).await {
        LayeredRead::Found {
            path,
            layer,
            content,
        } => MainConfig {
            path,
            layer,
            content,
        },
        LayeredRead::Absent => {
            return Err(HardeningError::Plugin(format!(
                "Failed to read {SSHD_ADMIN_CONFIG_PATH}: no sshd_config exists there or at \
                     its /usr/etc counterpart"
            )));
        }
        LayeredRead::Unreadable { path, reason, .. } => {
            return Err(HardeningError::Plugin(format!(
                "Failed to read {path}: {reason}"
            )));
        }
    };
    let config_path = main.path.as_str();
    // The vendor file is never written. Where it is the one in force, every
    // managed directive goes to the drop-in instead, because creating
    // /etc/ssh/sshd_config would make sshd stop reading the vendor config
    // and discard its Include lines with it.
    let writing_main = matches!(main.layer, ConfigLayer::Admin);

    // flock needs a local file descriptor and means nothing against a
    // remote target, so it is taken only for a local executor, matching
    // what the permissions plugin does at permissions/mod.rs:845.
    let _lock = (!ctx.executor().is_remote()).then(|| lock_config_path(config_path));

    // Pruned here as well as beside the copy, and this is the call that
    // reaches a compliant host at all. The copy-side prune runs only when
    // the config drifts, and the guard below returns before any of that,
    // so a host with nothing to rewrite keeps every backup it has ever
    // accumulated: 17 in /etc/ssh on the development host on 2026-08-11,
    // against a dry run reporting "0 change(s) to apply".
    //
    // Unlike audit's and pam's, this call sits above no checkpoint, because
    // a no-op here creates none. That changes nothing about what it may
    // remove: in all three plugins the prune runs before the capture, so
    // the copies it removes are absent from that apply's checkpoint either
    // way. Older checkpoints still hold them.
    //
    // Above the no-op guard rather than inside it, so the retention is one
    // rule rather than two: every apply prunes, whether or not it goes on
    // to write anything.
    crate::prune_timestamped_backups(ctx, &backup_prefix(config_path), crate::BACKUPS_KEPT).await;

    let original_content = main.content.clone();

    // Step 2: Compute the hardened config from the current content.
    // Directive changes accumulate in `changes`, but nothing is committed
    // to disk until the no-op guard below confirms the config actually
    // differs. Probe the session once up front: on a remote root session
    // the PermitRootLogin target is downgraded so the apply cannot sever
    // its own access.
    let mut config_content = original_content.clone();
    let mut changes = Vec::new();
    // Directives that cannot take effect by editing the main file, either
    // because a drop-in outranks it or because it is the vendor's and must
    // not be touched. These go to the fragment this tool owns.
    let mut to_dropin: Vec<dropin::Directive> = Vec::new();
    let remote_root_session = is_remote_root_session(ctx.executor().as_ref()).await;

    // Which directives a drop-in already answers. sshd reads the Include
    // above everything written here, and uses the first value it obtains,
    // so writing this file cannot change those. Refusing to resolve is
    // fail-closed: without the included files there is no way to tell
    // whether a write would take effect.
    let resolved = include::resolve(ctx, config_path, &original_content).await?;

    for directive in SSH_DIRECTIVES {
        // The exception is honoured only when it documents the value the
        // host actually has, so a stale exception cannot stop hardening.
        // Read from the resolved configuration, so this agrees with scan
        // and with the preview about which host an exception applies to;
        // see `observed_value` for what reading the main file alone cost.
        let observed = observed_value(resolved.effective(directive.ssh_directive_name).as_ref());
        if let Some(exception) = config.matching_exception(directive.ssh_directive_name, &observed)
        {
            info!(
                "Skipping {} (exception: {})",
                directive.ssh_directive_name, exception.reason
            );
            changes.push(Change {
                change_description: format!(
                    "{}: skipped (exception: {})",
                    directive.ssh_directive_name, exception.reason
                ),
                change_type: ChangeType::Skipped,
                change_success: true,
                change_error: None,
            });
            continue;
        }

        let target_value = resolved_target(directive, config);

        // The remote-root lockout guard binds wherever the directive is
        // written. Routing PermitRootLogin to the drop-in with the strict
        // 'no' would sever the very session performing the apply exactly as
        // writing it to the main file would, so the flag is computed before
        // the destination is chosen rather than after.
        let guard_active = remote_root_session
            && directive.ssh_directive_name == PERMIT_ROOT_LOGIN
            && target_value == "no";

        // What the host obeys today, from whichever file supplies it. The
        // lockout guard compares against this rather than the main file's
        // own line, because on a vendor-layer host that line is not the one
        // in force and on an overridden directive it is inert.
        let effective_now = resolved.effective(directive.ssh_directive_name);
        // That value may be in force only because this tool's own fragment
        // supplies it. Wherever the guard below concludes no write is
        // needed, the conclusion rewrites the fragment without this
        // directive, so a value only the fragment holds has to be carried
        // into that rewrite rather than left to a file about to lose it.
        let held_by_our_fragment = effective_now
            .as_ref()
            .filter(|effective| effective.source == dropin::DROPIN_PATH)
            .map(|effective| effective.value.clone());
        let (dropin_target, dropin_note) = if guard_active {
            (
                REMOTE_ROOT_SAFE_VALUE.to_string(),
                " (downgraded from 'no': applying 'no' over this root SSH session \
                     would sever access; set 'no' from a console)",
            )
        } else {
            (target_value.clone(), "")
        };
        // The fragment is read before every other file, so whatever it
        // holds is what the host obeys. Writing the bare target into it
        // would therefore overwrite a stricter value elsewhere with a
        // looser one, which is the same defect as writing the main file
        // would be. Clamping rather than skipping keeps the fragment
        // present, which is what holds a vendor-layer host to this target
        // after a package update replaces the file underneath.
        let dropin_target = directive.ssh_compare.clamp_target(
            &dropin_target,
            effective_now
                .as_ref()
                .map(|effective| effective.value.as_str()),
        );
        // Never loosen: a value already at least as strict as the safe
        // fallback stays as it is. That includes a case variant of the
        // target and the legacy spelling of the fallback, both of which
        // the directive's own ranking already treats as what they are.
        let already_safe_enough = guard_active
            && effective_now.as_ref().is_some_and(|effective| {
                !directive
                    .ssh_compare
                    .violated_by(REMOTE_ROOT_SAFE_VALUE, Some(&effective.value))
            });

        // A drop-in read before this file already answers this directive,
        // so writing here cannot change what sshd uses. One that already
        // holds the target leaves the host compliant and is reported as
        // skipped; reporting that as a failure would be a false alarm.
        // Where it holds the wrong value the directive is routed to the
        // fragment this tool owns, which sorts first and therefore wins.
        //
        // A directive our own fragment already answers is not an override
        // to route around: it is this tool's own previous write, and the
        // rewrite below refreshes it. What matters is therefore what would
        // win if the fragment were not there, because that is what decides
        // whether writing the main file can take effect. Discarding the
        // fragment and reading the empty result as "nobody overrides this"
        // instead would hand a second apply the main file as its target
        // while the vendor fragment underneath still outranks it, and prune
        // the fragment that was holding the host.
        let overridden = resolved
            .effective_without(directive.ssh_directive_name, dropin::DROPIN_PATH)
            .filter(|effective| effective.source != config_path);
        if let Some(effective) = overridden {
            // At least as strict as the target, not equal to it: a file
            // underneath holding `MaxAuthTries 2` leaves the host
            // compliant without this tool's fragment just as surely as one
            // holding 3 does, so the fragment is unnecessary either way.
            // Asking for equality here left behind a fragment restating a
            // value the host already had.
            let file_underneath_is_strict_enough = !directive
                .ssh_compare
                .violated_by(&target_value, Some(&effective.value));
            if file_underneath_is_strict_enough || already_safe_enough {
                changes.push(Change {
                    change_description: format!(
                        "{}: already '{}' via {}, which sshd reads before {}",
                        directive.ssh_directive_name,
                        effective.value,
                        effective.source,
                        config_path,
                    ),
                    change_type: ChangeType::Skipped,
                    change_success: true,
                    change_error: None,
                });
                // Dropping the directive is right where the file underneath
                // is already strict enough, because the fragment is then
                // genuinely unnecessary. It is wrong where the only reason
                // the host counts as safe is the fragment itself: that file
                // underneath still says otherwise, so leaving the directive
                // out of the rewrite hands the host straight back to it.
                if !file_underneath_is_strict_enough {
                    keep_value_the_fragment_holds(
                        &mut to_dropin,
                        directive.ssh_directive_name,
                        held_by_our_fragment,
                    );
                }
                continue;
            }
            to_dropin.push(dropin::Directive {
                keyword: directive.ssh_directive_name,
                value: dropin_target,
                note: dropin_note,
            });
            continue;
        }

        // The vendor file is never edited, so every managed directive goes
        // to the drop-in on a host that keeps its sshd_config under
        // /usr/etc. Being already compliant is not a reason to skip: the
        // vendor value can change under a package update, and the fragment
        // is what holds the host to this tool's target afterwards.
        if !writing_main {
            if already_safe_enough {
                changes.push(Change {
                    change_description: format!(
                        "PermitRootLogin: kept at '{}' (already the strongest value safely \
                             settable over this root SSH session; set 'no' from a console)",
                        effective_now
                            .map(|effective| effective.value)
                            .unwrap_or_default()
                    ),
                    change_type: ChangeType::Skipped,
                    change_success: true,
                    change_error: None,
                });
                // The vendor file is never edited, so the fragment is the
                // only file this tool may write here. Leaving the directive
                // out of the rewrite is therefore what removes the value
                // being reported as kept.
                keep_value_the_fragment_holds(
                    &mut to_dropin,
                    directive.ssh_directive_name,
                    held_by_our_fragment,
                );
                continue;
            }
            to_dropin.push(dropin::Directive {
                keyword: directive.ssh_directive_name,
                value: dropin_target,
                note: dropin_note,
            });
            continue;
        }

        let original_value = parse_config_value(
            global_scope(&config_content),
            directive.ssh_directive_name,
            ConfigFormat::SpaceSeparated,
            false,
        );

        // Compared against the strict target first, so an existing `no`
        // is "already compliant" and the guard below can never loosen it.
        // The comparison is the directive's own, so a value stricter than
        // the target needs no change either, and a case variant of the
        // target is already the target as far as sshd is concerned. That
        // last point used to need a branch of its own here, guarding
        // against the downgrade below "normalising" a `No` into
        // prohibit-password; a ranked comparison cannot reach it.
        let needs_change = directive
            .ssh_compare
            .violated_by(&target_value, original_value.as_deref());

        // Lockout guard: on a remote root session, never write the
        // session-severing `no`. A current value already at least as
        // strict as the safe fallback is left untouched (never loosen);
        // anything weaker gets the fallback with an honest explanation.
        if guard_active
            && needs_change
            && let Some(current) = original_value.as_deref()
            && !directive
                .ssh_compare
                .violated_by(REMOTE_ROOT_SAFE_VALUE, Some(current))
        {
            info!(
                "PermitRootLogin left at '{}' on remote root session (never loosen)",
                current
            );
            changes.push(Change {
                change_description: format!(
                    "PermitRootLogin: kept at '{}' (already the strongest value safely \
                         settable over this root SSH session; set 'no' from a console)",
                    current
                ),
                change_type: ChangeType::Skipped,
                change_success: true,
                change_error: None,
            });
            continue;
        }

        let (target_value, guard_note) = if guard_active && needs_change {
            (
                REMOTE_ROOT_SAFE_VALUE,
                " (downgraded from 'no': applying 'no' over this root SSH session \
                     would sever access; set 'no' from a console)",
            )
        } else {
            (target_value.as_str(), "")
        };

        if needs_change {
            config_content = set_config_directive(
                &config_content,
                directive.ssh_directive_name,
                target_value,
                ConfigFormat::SpaceSeparated,
                false,
                Duplicates::Keep,
            );

            changes.push(Change {
                change_description: format!(
                    "{}: {} -> {}{}",
                    directive.ssh_directive_name,
                    original_value.unwrap_or_else(|| "not set".to_string()),
                    target_value,
                    guard_note
                ),
                change_type: ChangeType::ConfigFile,
                change_success: true,
                change_error: None,
            });

            info!(
                "Applied SSH directive: {} = {}",
                directive.ssh_directive_name, target_value
            );
        }
    }

    // Step 5b: Apply cryptographic directives via host-capability intersection.
    // For each crypto directive, query what the local sshd supports and emit
    // only (desired strong ∩ supported). This can never produce a weak algo
    // (subset of the hardcoded allow-list) nor one the host cannot parse.
    for crypto in SSH_CRYPTO_DIRECTIVES {
        // As above: the crypto allow-list intersection deliberately has no
        // directive override, but the exception itself still only applies
        // when it documents the value actually on the host, read the way
        // scan and the preview read it.
        let observed = observed_value(resolved.effective(crypto.crypto_directive_name).as_ref());
        if let Some(exception) = config.matching_exception(crypto.crypto_directive_name, &observed)
        {
            info!(
                "Skipping {} (exception: {})",
                crypto.crypto_directive_name, exception.reason
            );
            changes.push(Change {
                change_description: format!(
                    "{}: skipped (exception: {})",
                    crypto.crypto_directive_name, exception.reason
                ),
                change_type: ChangeType::Skipped,
                change_success: true,
                change_error: None,
            });
            continue;
        }

        let supported =
            supported_algorithms(ctx.executor().as_ref(), crypto.crypto_query_arg).await;
        let selected = select_algorithms(crypto.crypto_desired, &supported);

        // Empty intersection: the host supports none of our strong choices.
        // Leave the host default untouched rather than writing an invalid
        // (empty) value that sshd would reject.
        if selected.is_empty() {
            warn!(
                "No supported strong algorithms for {}; leaving host default",
                crypto.crypto_directive_name
            );
            changes.push(Change {
                change_description: format!(
                    "{}: skipped (no strong algorithm supported by host)",
                    crypto.crypto_directive_name
                ),
                change_type: ChangeType::Skipped,
                change_success: true,
                change_error: None,
            });
            continue;
        }

        let target_value = selected.join(",");

        // Where this directive belongs, by the same question the directive
        // loop above asks: what would win if this tool's own fragment were
        // not there. Writing the main file cannot change what sshd
        // negotiates when a file it reads first answers the keyword, and on
        // RHEL, Fedora and openSUSE that file is crypto-policies'
        // 50-redhat.conf, which answers all three of these. The apply
        // reported "Ciphers: x -> y" and sshd went on using the drop-in's
        // list. The maintainer's decision is that this tool overrides that
        // fragment rather than deferring to it, so an overridden directive
        // is routed to the fragment this tool owns, which sorts first.
        //
        // Routed rather than written here, deliberately: a directive in
        // `to_dropin` goes through `verify_dropin_precedence`, which reads
        // the configuration back and reports a failed change naming the
        // file still answering the keyword. That 00- sorts before 50- is a
        // claim about filenames nobody controls, and it is checked rather
        // than assumed for these directives exactly as for the others.
        let overridden = resolved
            .effective_without(crypto.crypto_directive_name, dropin::DROPIN_PATH)
            .filter(|effective| effective.source != config_path);
        if let Some(effective) = overridden {
            // Secure rather than equal to the target: a file underneath
            // offering a subset of the allow-list leaves the host with no
            // weak algorithm on offer, which is the same question scan
            // asks, so the two agree about that host and no fragment is
            // needed. Asking for equality would leave a fragment restating
            // a list the host already obeys.
            if crypto_value_is_secure(Some(&effective.value), crypto.crypto_desired) {
                changes.push(Change {
                    change_description: format!(
                        "{}: already strong via {}, which sshd reads before {}",
                        crypto.crypto_directive_name, effective.source, config_path,
                    ),
                    change_type: ChangeType::Skipped,
                    change_success: true,
                    change_error: None,
                });
                continue;
            }
            to_dropin.push(dropin::Directive {
                keyword: crypto.crypto_directive_name,
                value: target_value,
                note: "",
            });
            continue;
        }

        // The vendor file is never edited, so on a host keeping its
        // sshd_config under /usr/etc every managed directive goes to the
        // fragment, crypto included.
        if !writing_main {
            to_dropin.push(dropin::Directive {
                keyword: crypto.crypto_directive_name,
                value: target_value,
                note: "",
            });
            continue;
        }

        let original_value = parse_config_value(
            global_scope(&config_content),
            crypto.crypto_directive_name,
            ConfigFormat::SpaceSeparated,
            false,
        );

        if original_value.as_deref() != Some(target_value.as_str()) {
            config_content = set_config_directive(
                &config_content,
                crypto.crypto_directive_name,
                &target_value,
                ConfigFormat::SpaceSeparated,
                false,
                Duplicates::Keep,
            );
            changes.push(Change {
                change_description: format!(
                    "{}: {} -> {}",
                    crypto.crypto_directive_name,
                    original_value.unwrap_or_else(|| "not set".to_string()),
                    target_value
                ),
                change_type: ChangeType::ConfigFile,
                change_success: true,
                change_error: None,
            });
            info!(
                "Applied SSH crypto directive: {} = {}",
                crypto.crypto_directive_name, target_value
            );
        }
    }

    // Step 3: No-op guard. If the hardened config is byte-identical to what
    // was read, the host is already compliant: skip the checkpoint, the
    // backup, the write and - critically - the sshd restart, which is the
    // one operation that can drop the admin's own session. Emit a single
    // Skipped change so the caller still sees the plugin ran.
    //
    // The fragment counts as part of the config here. On a vendor-layer
    // host every directive goes there and the main file is never touched,
    // so comparing the main file alone would report "already compliant" on
    // a host nothing had been written to yet.
    let desired_dropin = (!to_dropin.is_empty()).then(|| dropin::render(&to_dropin));
    // A drop-in that cannot be read counts as changed, which is why the
    // failure is folded into None rather than distinguished: the cost of
    // being wrong is one needless rewrite of a file this tool owns and
    // stamps as managed, and the direction is toward hardening.
    let current_dropin = ctx
        .executor()
        .read_file(Path::new(dropin::DROPIN_PATH))
        .await
        .ok();
    let dropin_changed = desired_dropin.as_deref() != current_dropin.as_deref();

    if config_content == original_content && !dropin_changed {
        changes.push(Change {
            change_description:
                "sshd_config already compliant - not rewritten, service not restarted".to_string(),
            change_type: ChangeType::Skipped,
            change_success: true,
            change_error: None,
        });
        info!("sshd_config already compliant; skipped backup, rewrite and restart");
        return Ok(ApplyResult {
            apply_plugin_id: plugin_id,
            apply_success: true,
            apply_changes: changes,
            apply_checkpoint_id: None,
            apply_error: None,
        });
    }

    // Step 4: The config drifts, so commit the change. Create the
    // checkpoint and the legacy backup now (never on a no-op); they lead
    // the committed change list, ahead of the directive changes.
    let mut committed = Vec::new();

    // The fragment joins the checkpoint so a rollback removes it. It is
    // deliberately absent from UNDELETABLE_ROLLBACK_PATHS: a checkpoint
    // taken before this apply records it as truthfully absent, so deleting
    // it is what the operator asked for, and protecting it would leave the
    // hardening in place after a rollback. Same precedent as the kernel
    // plugin's sysctl.d drop-in.
    // A checkpoint captures what a rollback can put back, which here is
    // what this apply can write. The vendor file is neither: `edit_target`
    // sends every managed directive to the drop-in where the vendor copy is
    // the one in force, and `DEFAULT_ROLLBACK_PREFIXES` covers `/etc` alone.
    // Capturing `/usr/etc/ssh/sshd_config` therefore recorded a restore
    // obligation the rollback refuses by design, and on openSUSE that made
    // every ssh rollback exit 1 reporting files it had not restored, having
    // restored everything that was ever changed. Five distributions keep it
    // under /etc and showed nothing. The legacy backup below already skips
    // the vendor file for the same reason; this is that rule, applied to
    // the capture it was missing from.
    // One expression, both arms visible: `writing_main` is the same
    // predicate that guards the write of `config_path` below, so the file is
    // captured exactly when it can be written, and never otherwise.
    let capture_paths: Vec<&Path> = if writing_main {
        vec![Path::new(config_path), Path::new(dropin::DROPIN_PATH)]
    } else {
        vec![Path::new(dropin::DROPIN_PATH)]
    };
    let checkpoint_id =
        crate::create_checkpoint_for_apply(ctx, "ssh-hardening-pre-apply", &capture_paths).await?;
    committed.extend(crate::checkpoint_change(&checkpoint_id));

    // The legacy backup sits beside the file it copies, so it is taken only
    // when that file is the administrator's. Copying the vendor config
    // would drop a hardener-named file into /usr/etc, which is the
    // distribution's to own, and there is nothing to back up in any case
    // because the vendor file is never edited.
    let main_write_needed = writing_main && config_content != original_content;
    if main_write_needed {
        let backup_path = format!(
            "{}{}",
            backup_prefix(config_path),
            Utc::now().format("%Y%m%d_%H%M%S")
        );
        // `-p` was here from the start and `--no-dereference` was not, the
        // reverse of the audit plugin's copy; the two flags answer separate
        // questions and a backup needs both. `-p` preserves mode, ownership
        // and timestamps, so a restored copy is the file rather than one
        // wearing the umask's mode. `--no-dereference` copies a symlink as
        // a symlink, which matters here more than at the other two sites: a
        // host whose sshd_config is a link into a configuration-management
        // checkout would otherwise have its managed file copied and the
        // object this apply is about to overwrite left with no backup at
        // all. `cp -p` exits non-zero when it cannot preserve ownership, as
        // an unprivileged copy of a root-owned file cannot; that is caught
        // by the failure arms below, which is the right direction, and
        // apply runs as root so it should not arise.
        match ctx
            .executor()
            .execute_command("cp", &["-p", "--no-dereference", config_path, &backup_path])
            .await
        {
            Ok(output) if output.success() => {
                committed.push(Change {
                    change_description: format!("Created backup: {}", backup_path),
                    change_type: ChangeType::ConfigFile,
                    change_success: true,
                    change_error: None,
                });
                info!("SSH config backup created: {}", backup_path);
                // The copy exists, so the directory holds one more backup
                // than it did. Pruned here rather than at the end of apply
                // so the creation and the retention sit together, and only
                // on the path that made one: a compliant host takes no
                // backup and has nothing to prune.
                crate::prune_timestamped_backups(
                    ctx,
                    &backup_prefix(config_path),
                    crate::BACKUPS_KEPT,
                )
                .await;
            }
            Ok(output) => {
                return Ok(ApplyResult {
                    apply_plugin_id: plugin_id,
                    apply_success: false,
                    apply_changes: committed,
                    apply_checkpoint_id: checkpoint_id,
                    apply_error: Some(format!("Failed to create backup: {}", output.stderr)),
                });
            }
            Err(e) => {
                return Ok(ApplyResult {
                    apply_plugin_id: plugin_id,
                    apply_success: false,
                    apply_changes: committed,
                    apply_checkpoint_id: checkpoint_id,
                    apply_error: Some(format!("Failed to create backup: {}", e)),
                });
            }
        }
    }

    // Step 5: Validate the candidate config with `sshd -t` BEFORE touching
    // the live file. If sshd would refuse to start, abort here: no write, no
    // restart; the running daemon and its config are left fully intact, so
    // there is no lockout path.
    //
    // The candidate is the fragment's body ahead of the main file, because
    // that is the order sshd resolves in and the first value wins. On a
    // vendor-layer host the main file is unchanged, so validating it alone
    // would check nothing this apply is about to write.
    let candidate = match &desired_dropin {
        Some(body) => format!("{body}\n{config_content}"),
        None => config_content.clone(),
    };
    if let Err(e) = validate_sshd_config(ctx.executor().as_ref(), &candidate).await {
        error!("Candidate sshd_config failed validation, aborting apply: {e}");
        // Staged, never written. These edits were moved into `committed`
        // above this gate and so were counted as applied on every host
        // where sshd refused the candidate: the debian and ubuntu fixtures
        // have no /run/sshd, and `apply` there announced "11 of 12
        // change(s) applied" having written no bytes, with the scan
        // immediately after still raising all ten SSH findings. Skipped is
        // what they are, and it keeps them out of both the applied and the
        // failed counts, because neither happened; the descriptions stay
        // listed so the operator can still read what would have changed.
        for change in &mut changes {
            change.change_type = ChangeType::Skipped;
        }
        committed.append(&mut changes);
        committed.push(Change {
            change_description: "Candidate sshd_config rejected by `sshd -t`; \
                    no changes written, service not restarted"
                .to_string(),
            change_type: ChangeType::ConfigFile,
            change_success: false,
            change_error: Some(e.to_string()),
        });
        return Ok(ApplyResult {
            apply_plugin_id: plugin_id,
            apply_success: false,
            apply_changes: committed,
            apply_checkpoint_id: checkpoint_id,
            apply_error: Some(format!("sshd config validation failed: {e}")),
        });
    }

    // Past the gate, so the candidate is one sshd will accept and these
    // edits are about to be written. Appended here rather than before the
    // gate, which is the only difference between a change this apply made
    // and one it merely planned.
    committed.append(&mut changes);

    // Step 6: Write modified configuration using executor. The vendor file
    // is never a write target: creating /etc/ssh/sshd_config to hold these
    // directives would make sshd stop reading the vendor config entirely,
    // discarding its Include lines and every setting it makes.
    if main_write_needed {
        match ctx
            .executor()
            .write_file(Path::new(config_path), &config_content)
            .await
        {
            Ok(_) => {
                committed.push(Change {
                    change_description: format!("Updated {}", config_path),
                    change_type: ChangeType::ConfigFile,
                    change_success: true,
                    change_error: None,
                });
                info!("SSH configuration updated successfully");
            }
            Err(e) => {
                committed.push(Change {
                    change_description: format!("Failed to write {}", config_path),
                    change_type: ChangeType::ConfigFile,
                    change_success: false,
                    change_error: Some(e.to_string()),
                });
                error!("Failed to write SSH config: {}", e);
            }
        }
    }

    // Step 6b: Write the fragment, then ask the resolver whether it
    // actually won. That 00- sorts first is a claim about filenames nobody
    // controls, so it is checked rather than trusted: a directive still
    // answered by another file is a failed change naming that file, never a
    // success.
    if dropin_changed {
        match dropin::write_dropin(ctx, &to_dropin).await {
            Ok(()) => committed.extend(
                verify_dropin_precedence(ctx, config_path, &to_dropin, &config_content).await,
            ),
            Err(e) => {
                committed.push(Change {
                    change_description: format!("Failed to write {}", dropin::DROPIN_PATH),
                    change_type: ChangeType::ConfigFile,
                    change_success: false,
                    change_error: Some(e.to_string()),
                });
                error!("Failed to write the sshd drop-in: {e}");
            }
        }
    }

    // Step 7: Restart SSH service to apply changes. Only reached after the
    // candidate config passed `sshd -t`, so a restart cannot lock us out.
    match SshHardeningPlugin::restart_ssh_service(ctx).await {
        Ok(_) => {
            committed.push(Change {
                change_description: "Restarted SSH service".to_string(),
                change_type: ChangeType::Service,
                change_success: true,
                change_error: None,
            });
            info!("SSH service restarted successfully");
        }
        Err(e) => {
            committed.push(Change {
                change_description: "Failed to restart SSH service".to_string(),
                change_type: ChangeType::Service,
                change_success: false,
                change_error: Some(e.to_string()),
            });
            error!("Failed to restart SSH service: {}", e);
        }
    }

    let success = committed.iter().all(|c| c.change_success);
    Ok(ApplyResult {
        apply_plugin_id: plugin_id,
        apply_success: success,
        apply_changes: committed,
        apply_checkpoint_id: checkpoint_id,
        apply_error: None,
    })
}
