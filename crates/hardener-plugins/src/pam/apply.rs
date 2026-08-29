//! The apply half of the PAM plugin: the body of `PamHardeningPlugin::apply`.
//!
//! Checkpoints the five managed paths, rewrites pwquality.conf and
//! login.defs through the backup-and-write path, creates or edits the two
//! `/etc/security` conffiles, and refuses to edit the PAM stack itself: an
//! inline override there is reported as a manual action, never written.
//! The trait method in `mod.rs` delegates here.

use super::{
    ConfRead, InlineRead, ModulePresence, PAM_BACKED_UP_FILES, PAM_DIRECTIVES, PamConfigFile,
    PamHardeningPlugin, apply_exact_directive, backup_and_write, clamped_baseline,
    conf_is_writable, module_not_loaded_message, module_presence_by_file, observed_pam_value,
    pam_backup_prefix, read_conf_classified, read_pamd_inline, write_changed_conf,
};

use hardener_common::error::Result;
use hardener_common::file_utils::{Duplicates, set_config_directive};
use hardener_core::{
    Change, ChangeType, Context, PluginConfig,
    plugin::{ApplyResult, HardeningPlugin},
};
use std::path::Path;
use std::time::Instant;
use tracing::{debug, info, warn};

pub(super) async fn apply(ctx: &mut Context, config: &PluginConfig) -> Result<ApplyResult> {
    let start = Instant::now();
    info!("Starting PAM authentication hardening apply");

    let mut changes = Vec::new();
    let mut all_success = true;

    // Create checkpoint before changes
    let pam_paths: Vec<&Path> = vec![
        Path::new("/etc/security/pwquality.conf"),
        Path::new("/etc/login.defs"),
        Path::new("/etc/pam.d"),
        Path::new("/etc/security/faillock.conf"),
        Path::new("/etc/security/pwhistory.conf"),
    ];
    // Pruned here as well as beside the copy, and this is the call that
    // does the work on a host that is already compliant. The copy-side
    // prune runs only when a copy is taken, so an apply that rewrites
    // nothing pruned nothing, while the capture above still copied every
    // dead backup in /etc/security into a fresh checkpoint for a rollback
    // to restore. Sixteen had accumulated on the development host by
    // 2026-08-11.
    //
    // Above the capture rather than below it, which the copy-side call
    // cannot be: that is what stops the checkpoint holding them, and why a
    // rollback no longer resurrects what a prune removed.
    for path in PAM_BACKED_UP_FILES {
        crate::prune_timestamped_backups(ctx, &pam_backup_prefix(path), crate::BACKUPS_KEPT).await;
    }

    let checkpoint_id =
        crate::create_checkpoint_for_apply(ctx, "pam-hardening-pre-apply", &pam_paths).await?;

    changes.extend(crate::checkpoint_change(&checkpoint_id));

    // Step 1: Read current configuration files. Backups are created later,
    // and only for a file that will actually be rewritten, so a compliant
    // host accumulates no backup churn in /etc.
    let pwquality_read = read_conf_classified(ctx, "/etc/security/pwquality.conf").await;
    let pwquality_write = conf_is_writable(
        ctx,
        "/etc/security/pwquality.conf",
        &pwquality_read,
        &mut changes,
        &mut all_success,
    )
    .await;
    let mut pwquality_content = match &pwquality_read {
        ConfRead::Content(content, _) => content.clone(),
        _ => String::new(),
    };
    let mut pwquality_changed = false;

    let login_defs_read = read_conf_classified(ctx, "/etc/login.defs").await;
    let login_defs_write = conf_is_writable(
        ctx,
        "/etc/login.defs",
        &login_defs_read,
        &mut changes,
        &mut all_success,
    )
    .await;
    let mut login_defs_content = match &login_defs_read {
        ConfRead::Content(content, _) => content.clone(),
        _ => String::new(),
    };
    let mut login_defs_changed = false;

    // A file no module reads is still written: the value will be right the
    // moment the module is added, and refusing would leave the operator
    // with neither. What must not happen is reporting that as hardening
    // done. Recorded once per file, and it fails the run, because this
    // plugin already refuses to edit /etc/pam.d itself, so the remaining
    // step is the operator's and a run that hardened nothing has not
    // earned a clean result.
    // `Indeterminate` continues here alongside `InStack`, and that is a
    // decision rather than the two being conflated by accident. It has two
    // flavours and neither is reachable in an apply on any distribution this
    // project supports. A candidate that could not be read cannot get this
    // far: /etc/pam.d is in `pam_paths` above and
    // `create_checkpoint_for_apply` propagates a capture failure with `?`,
    // so the apply has already aborted. A distribution whose stack this
    // table does not name is not one of the five: the candidates cover
    // system-auth and password-auth for the RHEL family, and
    // common-password and common-auth for the Debian family and openSUSE.
    //
    // What remains is latent rather than live, and it is worth naming
    // because a sweep for "which apply outcomes are silent" lands here and
    // cannot otherwise tell this from an oversight. Were a sixth
    // distribution added whose stack sits outside the table, this loop would
    // say nothing while the apply reported success for files nothing reads.
    // Scan is not blind to that case, which is why nothing is changed here
    // today: it reports the same reading as unchecked, and an unchecked
    // control renders as ManualReview rather than as a pass.
    for (path, presence) in module_presence_by_file(ctx).await {
        let ModulePresence::NotInStack { module } = presence else {
            continue;
        };
        warn!(
            "Nothing on this host reads {}: {} is not loaded",
            path, module
        );
        all_success = false;
        changes.push(Change {
            change_type: ChangeType::ConfigFile,
            change_description: module_not_loaded_message(path, module),
            change_success: false,
            change_error: Some(format!("{module} is not loaded by the PAM stack")),
        });
    }

    // Pre-apply snapshots for the exception check below. Taken once, here,
    // before any directive can mutate `pwquality_content`/`login_defs_content`,
    // or write a `SecurityConf` file: the exception decision must be judged
    // against the host's actual pre-apply state, never against a buffer or
    // file this same loop has already rewritten. Resolving every directive's
    // observed value in this one pass, before any write happens, makes that
    // guarantee hold structurally, so it stays true even if a future
    // directive's `SecurityConf` path happens to collide with an earlier
    // one's, rather than relying on today's `PAM_DIRECTIVES` entries
    // pointing at distinct files.
    let pwquality_observed = pwquality_read;
    let login_defs_observed = login_defs_read;
    let mut observed_values = Vec::with_capacity(PAM_DIRECTIVES.len());
    for directive in PAM_DIRECTIVES {
        observed_values.push(
            observed_pam_value(
                ctx,
                directive,
                &pwquality_observed,
                &login_defs_observed,
                &[],
            )
            .await,
        );
    }

    // Step 2: Apply each directive (state-aware: already-correct values
    // record a Skipped no-op and never trigger a rewrite)
    for (directive, observed) in PAM_DIRECTIVES.iter().zip(observed_values.iter()) {
        // Honour an exception only when it documents the value the host
        // actually has. An unset value and an unreadable one both render
        // "not set", matching scan's rendering and what an operator
        // writes in the config, so an exception documenting value =
        // "not set" is honoured even when the file could not be read: a
        // narrow, deliberate gap in the fail-closed rule.

        // Check for a valid exception: skip this directive if exempted
        if let Some(exception) =
            config.matching_exception(directive.pam_directive_name, observed.value_or_not_set())
        {
            info!(
                "Skipping {} (exception: {})",
                directive.pam_directive_name, exception.reason
            );
            changes.push(Change {
                change_type: ChangeType::Skipped,
                change_description: format!(
                    "{}: skipped (exception: {})",
                    directive.pam_directive_name, exception.reason
                ),
                change_success: true,
                change_error: None,
            });
            continue;
        }

        // The target, clamped twice through one definition: an operator
        // override can only tighten the baseline, and then the write can
        // only tighten what the host already holds.
        //
        // Clamping the write rather than skipping it is deliberate.
        // `apply_exact_directive` exists partly to repair a duplicate or a
        // line an older release wrote in a syntax the file does not parse,
        // and its own comment says skipping on the value leaves that repair
        // undone so the file never converges. Writing the stricter of the
        // two keeps the repair and keeps the host's setting.
        let target = clamped_baseline(directive, config);
        let target_value = directive
            .pam_compare
            .clamp_target(&target, Some(observed.value_or_not_set()));

        // A file whose current contents could not be read is never
        // rewritten, and that refusal was already recorded once, at read
        // time. Skip its directives outright so none of them records a
        // change for a write that cannot happen. "N change(s) applied" is
        // not always N hardening successes: a separator repaired on an
        // already-correct value counts as a change too, because the tool
        // cannot tell a cosmetic repair from a load-bearing one without
        // modelling each consumer's parser, and over-reporting is the
        // safe direction, since under-reporting was the defect this
        // branch fixed. The `SecurityConf` arm classifies its own read
        // and refuses per directive below, which is the same rule applied
        // at its own read site.
        let file_writable = match directive.pam_config_file {
            PamConfigFile::PwQuality => pwquality_write.allowed,
            PamConfigFile::LoginDefs => login_defs_write.allowed,
            _ => true,
        };
        if !file_writable {
            continue;
        }

        match directive.pam_config_file {
            PamConfigFile::PwQuality => apply_exact_directive(
                &mut pwquality_content,
                &mut pwquality_changed,
                &mut changes,
                directive.pam_directive_name,
                &target_value,
                directive.pam_config_file.config_format(),
                "pwquality.conf",
            ),
            PamConfigFile::LoginDefs => apply_exact_directive(
                &mut login_defs_content,
                &mut login_defs_changed,
                &mut changes,
                directive.pam_directive_name,
                &target_value,
                directive.pam_config_file.config_format(),
                "login.defs",
            ),
            PamConfigFile::PamAuth => {
                // Skip PAM module for now
                debug!(
                    "Skipping PAM module directive: {}",
                    directive.pam_directive_name
                );
                continue;
            }
            PamConfigFile::SecurityConf(path) => {
                // `target` is the hoisted, override-clamped baseline. This
                // arm does not use the host-clamped `target_value`: it
                // gates on the comparison below and skips outright
                // when the host is already stricter, so it never writes a
                // looser value in the first place.

                // Read directly (rather than reusing `observed`, which already
                // read this via `read_effective_threshold`) because the refuse-
                // to-auto-edit message below needs to know specifically whether
                // the value came from an inline pam.d override, a distinction
                // `PamObserved` deliberately does not carry.
                let inline = read_pamd_inline(ctx, path, directive.pam_directive_name).await;

                // No-loosen contract: only act when the effective value
                // breaches the (clamped) target. A stricter value is already
                // compliant, so touching it could only loosen it. `observed`
                // (computed above via the shared helper) already resolved
                // inline-vs-conf-file precedence; "not set" fails to parse as
                // an integer just like a genuinely missing value, so reusing
                // it here is equivalent to reading afresh.
                if !directive
                    .pam_compare
                    .violated_by(&target, Some(observed.value_or_not_set()))
                {
                    changes.push(Change {
                        change_type: ChangeType::Skipped,
                        change_description: format!(
                            "{} already meets threshold in {}",
                            directive.pam_directive_name, path,
                        ),
                        change_success: true,
                        change_error: None,
                    });
                    continue;
                }

                // An inline pam.d arg overrides the .conf, so writing the
                // .conf would be a silent no-op. Never auto-edit the auth
                // stack (a malformed edit can lock users out); report the
                // manual action and mark the run unsuccessful.
                if let InlineRead::Value(value) = &inline {
                    warn!(
                        "{} is set inline ({}={}) in the PAM stack; refusing to auto-edit it",
                        directive.pam_directive_name, directive.pam_directive_name, value,
                    );
                    all_success = false;
                    changes.push(Change {
                        change_type: ChangeType::ConfigFile,
                        change_description: format!(
                            "{name}={value} is set inline in the PAM stack and overrides {path}; \
                                 edit the PAM stack manually to set {name} to {target}",
                            name = directive.pam_directive_name,
                        ),
                        change_success: false,
                        change_error: Some("inline pam.d override present".to_string()),
                    });
                    continue;
                }

                // A stack that could not be read may hold an inline
                // argument, and one would override this file: writing it
                // would then succeed, be recorded as applied, and leave the
                // host enforcing a value the run never saw. Refusing is the
                // same answer as for an override actually seen, because
                // both mean this file is not where the value lives.
                if let InlineRead::Unreadable {
                    path: stack,
                    permission_denied,
                } = &inline
                {
                    warn!(
                        "{} may be set inline in {}, which could not be read; refusing to write {}",
                        directive.pam_directive_name, stack, path,
                    );
                    all_success = false;
                    let advice = if *permission_denied {
                        "re-run with sudo, or edit the PAM stack manually"
                    } else {
                        "repair the file, or edit the PAM stack manually"
                    };
                    changes.push(Change {
                        change_type: ChangeType::ConfigFile,
                        change_description: format!(
                            "{stack} could not be read and may set {name} inline, which would \
                                 override {path}; {advice} to set {name} to {target}",
                            name = directive.pam_directive_name,
                        ),
                        change_success: false,
                        change_error: Some(format!("PAM stack {stack} unreadable")),
                    });
                    continue;
                }

                let read = read_conf_classified(ctx, path).await;
                let write =
                    conf_is_writable(ctx, path, &read, &mut changes, &mut all_success).await;
                if !write.allowed {
                    continue;
                }
                // Reachable only for a confirmed absence with no vendor
                // file behind it, which is the case where creating the
                // file is correct.
                let current = match read {
                    ConfRead::Content(content, _) => content,
                    _ => String::new(),
                };

                let target_str = target.to_string();
                let updated = set_config_directive(
                    &current,
                    directive.pam_directive_name,
                    &target_str,
                    directive.pam_config_file.config_format(),
                    true,
                    Duplicates::Remove,
                );

                if backup_and_write(ctx, path, path, &updated, write.create_mode, &mut changes)
                    .await
                {
                    changes.push(Change {
                        change_type: ChangeType::ConfigFile,
                        change_description: format!(
                            "Set {} = {} in {}",
                            directive.pam_directive_name, target_str, path,
                        ),
                        change_success: true,
                        change_error: None,
                    });
                } else {
                    all_success = false;
                }
            }
        }
    }

    // Step 3: Back up and rewrite only the files that actually changed.
    // As before, a failed backup blocks the write for that file.
    //
    // The `_writable` half of each guard is deliberate belt and braces, not
    // load bearing: Step 2 skips every directive belonging to a file that
    // could not be read, so nothing can set `_changed` for one. It stays
    // because the write it guards destroys the host's settings if it ever
    // runs on contents that were never read, and a second, local check
    // costs nothing.
    if pwquality_changed
        && pwquality_write.allowed
        && !write_changed_conf(
            ctx,
            "/etc/security/pwquality.conf",
            "pwquality.conf",
            &pwquality_content,
            pwquality_write.create_mode,
            &mut changes,
        )
        .await
    {
        all_success = false;
    }

    if login_defs_changed
        && login_defs_write.allowed
        && !write_changed_conf(
            ctx,
            "/etc/login.defs",
            "login.defs",
            &login_defs_content,
            login_defs_write.create_mode,
            &mut changes,
        )
        .await
    {
        all_success = false;
    }

    let duration_ms = start.elapsed().as_millis() as u64;

    info!(
        "PAM apply completed: {} changes, success={} in {} ms",
        changes.len(),
        all_success,
        duration_ms
    );

    Ok(ApplyResult {
        apply_plugin_id: PamHardeningPlugin::new().metadata().plugin_id,
        apply_success: all_success,
        apply_changes: changes,
        apply_checkpoint_id: checkpoint_id,
        apply_error: None,
    })
}
