//! The validate half of the SSH plugin: the body of
//! `SshHardeningPlugin::validate`.
//!
//! The dry-run preview. Reads through the same layered reader scan and
//! apply use, so a preview cannot disagree with either about which file is
//! in force, and names what an apply would change, the drop-in fragment
//! included. The trait method in `mod.rs` delegates here.

use super::{
    SSH_CRYPTO_DIRECTIVES, SSH_DIRECTIVES, SSHD_ADMIN_CONFIG_PATH, crypto_value_is_secure, dropin,
    include, observed_value, resolved_target, select_algorithms, supported_algorithms,
};

use hardener_common::{
    error::Result,
    types::{PluginId, Severity},
    vendor_config::{LayeredRead, read_layered},
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
        LayeredRead::Found { content, .. } => {
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

            // Check each directive to see if it needs updating.
            for directive in SSH_DIRECTIVES {
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
