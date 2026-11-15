//! The validate half of the SSH plugin: the body of
//! `SshHardeningPlugin::validate`.
//!
//! The dry-run preview. Reads through the same layered reader scan and
//! apply use, so a preview cannot disagree with either about which file is
//! in force, and names what an apply would change, the drop-in fragment
//! included. The trait method in `mod.rs` delegates here.

use super::{
    SSH_CRYPTO_DIRECTIVES, SSH_DIRECTIVES, SSHD_ADMIN_CONFIG_PATH, auth_methods,
    crypto_value_is_secure, dropin, include, is_second_factor_only, observed_value,
    resolved_target, second_factor, second_factor_switched_off_ahead, select_algorithms,
    supported_algorithms,
};

use hardener_common::{
    error::Result,
    types::{PluginId, Severity},
    vendor_config::{ConfigLayer, LayeredRead, read_layered},
};
use hardener_core::{PluginConfig, ValidationIssue, ValidationReport, context::Context};
use std::path::Path;

pub(super) async fn validate(ctx: &Context, config: &PluginConfig) -> Result<ValidationReport> {
    let mut issues = Vec::new();
    let plugin_id = PluginId::new("ssh-hardening");
    // Validate whichever sshd_config is in force. Where neither layer has
    // one, the admin path is the right file to name: it is where an
    // operator would look, and where a working host would keep it.
    let main = read_layered(ctx.executor().as_ref(), SSHD_ADMIN_CONFIG_PATH).await;
    let resolved_path = match &main {
        LayeredRead::Found { path, .. } => path.clone(),
        LayeredRead::Absent | LayeredRead::Unreadable { .. } => SSHD_ADMIN_CONFIG_PATH.to_string(),
    };
    let config_path = Path::new(&resolved_path);

    // Check if SSH config file exists and is readable using executor.
    match ctx.executor().file_metadata(config_path).await {
        Ok(metadata) => {
            // Check if it is a regular file.
            if !metadata.is_file {
                issues.push(ValidationIssue {
                    validation_issue_severity: Severity::Critical,
                    validation_issue_message: format!(
                        "{} is not a regular file",
                        config_path.display()
                    ),
                    validation_issue_config_key: None,
                });
            }
        }
        Err(e) => {
            issues.push(ValidationIssue {
                validation_issue_severity: Severity::Critical,
                validation_issue_message: format!("Cannot access {}: {}", config_path.display(), e),
                validation_issue_config_key: None,
            });
        }
    }

    // Try to read the configuration and check which directives need changing.
    let mut estimated_changes = Vec::new();
    // Excepted directives are recorded rather than dropped: the preview
    // must not show "0 changes" over an empty panel on a host where a
    // deviation is deliberate and documented.
    let mut exceptions = Vec::new();

    // The content already came back from the layered read above; reading it
    // a second time would be a second round trip against a remote host.
    // Whether the apply this previews will write the fragment, which is a
    // file appearing in /etc that the preview said nothing about until the
    // kernel plugin was caught doing the same with 99-hardener.conf.
    let mut writes_fragment = false;

    match &main {
        LayeredRead::Found { content, layer, .. } => {
            // The apply edits the main file only where it is the
            // administrator's; the vendor copy is never written.
            let writes_main = matches!(layer, ConfigLayer::Admin);
            // Resolved first, because a preview reading a different
            // configuration from the apply it precedes is not a preview.
            // This parsed the main file alone while scan and apply both
            // resolved the Include, so on the layout RHEL, Fedora and
            // openSUSE ship, a main file already holding the target
            // previewed no change while the apply went on to write a
            // fragment beating the drop-in. Failing to resolve is a
            // blocking issue rather than a fallback to the main file: the
            // fallback is precisely the reading that was wrong.
            let resolved = match include::resolve(ctx, &resolved_path, content).await {
                Ok(resolved) => resolved,
                Err(e) => {
                    issues.push(ValidationIssue {
                        validation_issue_severity: Severity::Critical,
                        validation_issue_message: format!(
                            "Cannot resolve sshd_config Include directives: {e}"
                        ),
                        validation_issue_config_key: None,
                    });
                    return Ok(ValidationReport {
                        validation_report_plugin_id: plugin_id,
                        validation_report_is_valid: false,
                        validation_report_issues: issues,
                        validation_report_estimated_changes: estimated_changes,
                        validation_report_compliant_count: 0,
                        validation_report_exceptions: exceptions,
                    });
                }
            };

            // The second factor as the apply will plan it, so the preview
            // judges keyboard-interactive against the same lists the apply
            // does. An exception documenting what the host does instead
            // leaves it out here as it does there.
            let second_factor_plan = second_factor::requested(config)
                .map(|policy| second_factor::plan(policy, &resolved))
                .filter(|plan| {
                    let excepted = plan.shortfall.as_ref().and_then(|observed| {
                        config
                            .matching_exception(auth_methods::AUTHENTICATION_METHODS, observed)
                            .map(|exception| (observed, exception))
                    });
                    if let Some((observed, exception)) = excepted {
                        exceptions.push(hardener_common::types::exception_preview_line(
                            auth_methods::AUTHENTICATION_METHODS,
                            observed,
                            &exception.reason,
                        ));
                    }
                    excepted.is_none()
                });
            let auth_lists = second_factor::planned_lists(second_factor_plan.as_ref(), &resolved);

            // Check each directive to see if it needs updating.
            for directive in SSH_DIRECTIVES {
                // Left on by the apply, so absent from its preview, except
                // where a main-file line above the drop-in Include switches
                // it off, which the apply switches on.
                if is_second_factor_only(directive, auth_lists.as_deref()) {
                    if writes_main
                        && let Some(line) =
                            second_factor_switched_off_ahead(directive, content, &resolved_path)
                    {
                        estimated_changes.push(format!(
                            "{}: {} → yes in {} (read before the drop-ins)",
                            line.keyword, line.value, resolved_path
                        ));
                    }
                    continue;
                }

                // Resolve the target the way apply and scan do, through the
                // one function all three call.
                let target = resolved_target(directive, config);

                // The value sshd obeys, from whichever file supplies it.
                let effective = resolved.effective(directive.ssh_directive_name);
                let current_value = effective.as_ref().map(|e| e.value.clone());
                // A directive another file answers first is one the apply
                // routes to the fragment, whatever the main file says.
                let overridden = effective
                    .as_ref()
                    .is_some_and(|e| e.source != resolved_path);

                // The exception is honoured only when it documents the
                // value the host actually has. Scan, this preview and
                // apply all read that value through `observed_value`, so a
                // preview cannot report an exception honoured for a host
                // whose apply would overwrite it.
                let observed = observed_value(effective.as_ref());
                if let Some(exception) =
                    config.matching_exception(directive.ssh_directive_name, &observed)
                {
                    exceptions.push(hardener_common::types::exception_preview_line(
                        directive.ssh_directive_name,
                        &observed,
                        &exception.reason,
                    ));
                    continue;
                }

                match current_value {
                    Some(value) if !directive.ssh_compare.violated_by(&target, Some(&value)) => {
                        // Already set to the target value - no change needed.
                    }
                    Some(value) if overridden => {
                        writes_fragment = true;
                        estimated_changes.push(format!(
                            "{}: {} → {}",
                            directive.ssh_directive_name, value, target
                        ));
                    }
                    Some(value) => {
                        // Value exists but does not match the target.
                        estimated_changes.push(format!(
                            "{}: {} → {}",
                            directive.ssh_directive_name, value, target
                        ));
                    }
                    None => {
                        // Directive not set - will add it.
                        estimated_changes.push(format!(
                            "{}: (not set) → {}",
                            directive.ssh_directive_name, target
                        ));
                    }
                }
            }

            // The second factor's settings, which the apply always writes to
            // the fragment. Its guards need a staged candidate and `sshd -T`,
            // which a preview does not stage, so only what can be answered
            // from here is raised. A PAM stack that cannot ask for the
            // password refuses on every host, which makes the apply fail, so
            // that is a blocking issue. Over SSH the apply refuses only where
            // no Match block keeps this session's account on its key, which
            // the preview cannot tell, so that is a note and does not fail
            // the dry run.
            if let Some(plan) = &second_factor_plan
                && plan.shortfall.is_some()
            {
                for (directive, now) in second_factor::pending(plan, &resolved) {
                    writes_fragment = true;
                    estimated_changes.push(format!(
                        "{}: {} → {}",
                        directive.keyword,
                        now.unwrap_or_else(|| "(not set)".to_string()),
                        directive.value
                    ));
                }
                // The global `PAMServiceName` the files set, which this plugin
                // never writes; the apply reads it from `sshd -T` instead,
                // per account as well.
                let service = resolved
                    .effective(second_factor::PAM_SERVICE_NAME)
                    .map_or_else(
                        || second_factor::DEFAULT_PAM_SERVICE.to_string(),
                        |effective| effective.value,
                    );
                if let Some(reason) =
                    second_factor::pam_answers_with_password(ctx.executor().as_ref(), &service)
                        .await
                        .refusal()
                {
                    issues.push(ValidationIssue {
                        validation_issue_severity: Severity::Critical,
                        validation_issue_message: format!(
                            "The second factor will not be applied: {reason} (PAM service \
                             {service})"
                        ),
                        validation_issue_config_key: Some(
                            auth_methods::AUTHENTICATION_METHODS.to_string(),
                        ),
                    });
                }
                // Two more refusals the files alone can show: a Match block
                // the switched-on keyboard-interactive would turn into a
                // password-only login, and logins no key file lists. The
                // apply reads the second from `sshd -T`; the files say the
                // same thing wherever no Match block changes it.
                if let Some(reason) = second_factor::match_refusal(&resolved) {
                    issues.push(ValidationIssue {
                        validation_issue_severity: Severity::Critical,
                        validation_issue_message: format!(
                            "The second factor will not be applied: {reason}"
                        ),
                        validation_issue_config_key: Some(
                            auth_methods::AUTHENTICATION_METHODS.to_string(),
                        ),
                    });
                }
                let unlisted =
                    second_factor::unlisted_logins_in_files(ctx.executor().as_ref(), &resolved)
                        .await;
                if !unlisted.is_empty() {
                    let named = unlisted.join(",");
                    if config
                        .matching_exception(second_factor::UNLISTED_KEYS_EXCEPTION_KEY, &named)
                        .is_none()
                    {
                        issues.push(ValidationIssue {
                            validation_issue_severity: Severity::Critical,
                            validation_issue_message: format!(
                                "The second factor will not be applied: {named} lets accounts \
                                 log in without a key file the apply's check can read. Accept \
                                 that with [ssh.exceptions.\"{}\"] value = \"{named}\"",
                                second_factor::UNLISTED_KEYS_EXCEPTION_KEY
                            ),
                            validation_issue_config_key: Some(
                                auth_methods::AUTHENTICATION_METHODS.to_string(),
                            ),
                        });
                    }
                }
                if ctx.executor().is_remote() {
                    issues.push(ValidationIssue {
                        validation_issue_severity: Severity::Medium,
                        validation_issue_message: "This apply runs over SSH, and this tool's \
                             remote mode cannot answer a password prompt. Before writing, the \
                             apply checks that this session's account keeps a way in on its \
                             key alone (a Match block for it, see the configuration \
                             reference), and leaves the second factor out if not"
                            .to_string(),
                        validation_issue_config_key: Some(
                            auth_methods::AUTHENTICATION_METHODS.to_string(),
                        ),
                    });
                }
            }

            // The crypto directives were previewed by nothing at all
            // until now: an apply writing three cryptographic lists
            // announced none of them. The target is the intersection of
            // this tool's allow-list with what the host supports, so the
            // preview asks `ssh -Q` exactly as the apply does; a host that
            // cannot answer yields an empty intersection, which the apply
            // skips and the preview therefore omits, so the two agree.
            for crypto in SSH_CRYPTO_DIRECTIVES {
                let effective = resolved.effective(crypto.crypto_directive_name);
                let current_value = effective.as_ref().map(|e| e.value.clone());
                let observed = observed_value(effective.as_ref());
                if let Some(exception) =
                    config.matching_exception(crypto.crypto_directive_name, &observed)
                {
                    exceptions.push(hardener_common::types::exception_preview_line(
                        crypto.crypto_directive_name,
                        &observed,
                        &exception.reason,
                    ));
                    continue;
                }
                if crypto_value_is_secure(current_value.as_deref(), crypto.crypto_desired) {
                    continue;
                }
                let supported =
                    supported_algorithms(ctx.executor().as_ref(), crypto.crypto_query_arg).await;
                let selected = select_algorithms(crypto.crypto_desired, &supported);
                if selected.is_empty() {
                    continue;
                }
                if effective
                    .as_ref()
                    .is_some_and(|e| e.source != resolved_path)
                {
                    writes_fragment = true;
                }
                estimated_changes.push(format!(
                    "{}: {} → {}",
                    crypto.crypto_directive_name,
                    observed,
                    selected.join(",")
                ));
            }
        }
        LayeredRead::Absent => {
            issues.push(ValidationIssue {
                validation_issue_severity: Severity::Critical,
                validation_issue_message: format!(
                    "Cannot read {}: no sshd_config exists there or at its /usr/etc \
                         counterpart",
                    config_path.display()
                ),
                validation_issue_config_key: None,
            });
        }
        LayeredRead::Unreadable { path, reason, .. } => {
            issues.push(ValidationIssue {
                validation_issue_severity: Severity::Critical,
                validation_issue_message: format!("Cannot read {path}: {reason}"),
                validation_issue_config_key: None,
            });
        }
    }

    // Named once rather than per directive: the fragment is one file, and
    // an operator approving this run should know a file will appear in /etc
    // that no line above mentions.
    if writes_fragment {
        estimated_changes.push(format!(
            "{} will be written so the settings above are the ones sshd reads first",
            dropin::DROPIN_PATH
        ));
    }

    let valid = issues.is_empty();
    Ok(ValidationReport {
        validation_report_plugin_id: plugin_id,
        validation_report_is_valid: valid,
        validation_report_issues: issues,
        validation_report_estimated_changes: estimated_changes,
        validation_report_compliant_count: 0,
        validation_report_exceptions: exceptions,
    })
}
