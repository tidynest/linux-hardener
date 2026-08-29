//! The scan half of the SSH plugin: the body of `SshHardeningPlugin::scan`.
//!
//! The trait impl stays whole in `mod.rs`, because a trait impl cannot span
//! files; its method bodies outgrew that file and now live one per module,
//! each with the trait method delegating to it. This one reads whichever
//! sshd_config layer is in force, resolves includes the way sshd does, and
//! reports the directives whose effective values violate the baseline.

use super::{
    MainConfig, SSH_CRYPTO_DIRECTIVES, SSH_DIRECTIVES, SSHD_ADMIN_CONFIG_PATH,
    crypto_value_is_secure, get_ssh_compliance_mappings, include, observed_value, resolved_target,
    unchecked_ssh_checks,
};

use hardener_common::{
    error::Result,
    types::{FindingCategory, PluginId},
    vendor_config::{LayeredRead, read_layered},
};
use hardener_core::{
    PluginConfig,
    context::Context,
    plugin::{Finding, ScanResult, UncheckedBlocker},
};
use std::time::Instant;

pub(super) async fn scan(ctx: &Context, config: &PluginConfig) -> Result<ScanResult> {
    let start_time = Instant::now();
    let mut findings = Vec::new();
    let plugin_id = PluginId::new("ssh-hardening");

    // Read whichever sshd_config is in force, which is not always the one
    // under /etc: openSUSE keeps the vendor copy at /usr/etc and the scan
    // used to report it could not read /etc/ssh/sshd_config and assess
    // nothing at all.
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
        // A root-only sshd_config must not read as "every directive
        // missing": that would falsely flag a hardened host. Surface the
        // privilege failure as unchecked entries instead, naming the file
        // that could not be read rather than assuming it was the /etc one.
        LayeredRead::Unreadable {
            path,
            reason,
            permission_denied,
        } => {
            let duration_us = start_time.elapsed().as_micros() as u64;
            if permission_denied {
                return Ok(ScanResult {
                    scan_plugin_id: plugin_id,
                    scan_success: true,
                    scan_findings: vec![],
                    scan_unchecked: unchecked_ssh_checks(
                        &format!("reading {path} requires root"),
                        crate::refusal_blocker(ctx).await,
                    ),
                    scan_duration_us: duration_us,
                    scan_error: None,
                });
            }
            // Not a refusal, but not a clean host either: the read failed
            // and the existence probe could not confirm absence. Silence
            // here passed the whole SSH catalogue for the same reason the
            // `Absent` arm below did. `Unknown` as the blocker because the
            // plugin has established only that privilege was not the
            // cause, which is not enough to claim sudo would not help.
            return Ok(ScanResult {
                scan_plugin_id: plugin_id,
                scan_success: false,
                scan_findings: vec![],
                scan_unchecked: unchecked_ssh_checks(
                    &format!("{path} could not be read: {reason}"),
                    UncheckedBlocker::Unknown,
                ),
                scan_duration_us: duration_us,
                scan_error: Some(format!("Failed to read {path}: {reason}")),
            });
        }
        // The error alone is not enough. `coverage()` declares every SSH
        // control assessed, and the compliance generator cannot see
        // `scan_success`: a control that is assessed, carries no finding
        // and is recorded unchecked by nothing passes. Returning empty
        // vectors here therefore passed the whole SSH catalogue on a host
        // with no SSH configuration at all, which is #159 and #166 in a
        // fifth plugin. Environment rather than Privilege as the blocker:
        // a file that is not installed stays not installed under sudo.
        LayeredRead::Absent => {
            let duration_us = start_time.elapsed().as_micros() as u64;
            let reason = format!(
                "no sshd_config exists at {SSHD_ADMIN_CONFIG_PATH} or at its /usr/etc \
                     counterpart, so no SSH setting on this host can be read"
            );
            return Ok(ScanResult {
                scan_plugin_id: plugin_id,
                scan_success: false,
                scan_findings: vec![],
                scan_unchecked: unchecked_ssh_checks(&reason, UncheckedBlocker::Environment),
                scan_duration_us: duration_us,
                scan_error: Some(format!("Failed to read {SSHD_ADMIN_CONFIG_PATH}: {reason}")),
            });
        }
    };
    let config_content = main.content.clone();

    // sshd uses the first value it obtains, and the shipped config
    // Includes /etc/ssh/sshd_config.d/*.conf above everything this tool
    // writes, so a drop-in silently wins. Reading only the main file
    // reported the value we wrote while sshd enforced the drop-in's.
    let resolved = match include::resolve(ctx, &main.path, &config_content).await {
        Ok(resolved) => resolved,
        Err(e) => {
            // Without the included files the effective configuration is
            // unknown, and guessing from the main file alone is the false
            // pass this replaces.
            let duration_us = start_time.elapsed().as_micros() as u64;
            return Ok(ScanResult {
                scan_plugin_id: plugin_id,
                scan_success: false,
                scan_findings: vec![],
                scan_unchecked: unchecked_ssh_checks(
                    &format!(
                        "{} was read, but the Include directives it carries \
                             could not be resolved, so the effective configuration \
                             is unknown: {e}",
                        main.path
                    ),
                    // `include::resolve` fails on nesting past its depth
                    // limit, a directory it cannot list, an included file it
                    // cannot read, and a pattern naming no directory. Only
                    // one of those is a refusal root would lift, and nothing
                    // here knows which happened.
                    UncheckedBlocker::Unknown,
                ),
                scan_duration_us: duration_us,
                scan_error: Some(format!(
                    "Cannot resolve sshd_config Include directives: {e}"
                )),
            });
        }
    };

    // Check each SSH directive
    for directive in SSH_DIRECTIVES {
        let effective = resolved.effective(directive.ssh_directive_name);
        let current_value = effective.as_ref().map(|e| e.value.clone());

        let target = resolved_target(directive, config);

        // Threshold, not equality: a host stricter than the baseline is
        // already compliant. Comparing for equality flagged
        // `MaxAuthTries 2` against a baseline of 3, and apply then wrote
        // the 3 over it. An absent directive violates every direction,
        // since nothing is enforcing it.
        let is_insecure = directive
            .ssh_compare
            .violated_by(&target, current_value.as_deref());

        if is_insecure {
            // An exception is honoured only when it documents the value the
            // host actually has, so a config cannot pass a control by
            // describing a deviation that is not there.
            let current_display = observed_value(effective.as_ref());
            let policy_exception =
                config.exception_outcome(directive.ssh_directive_name, &current_display);
            findings.push(Finding {
                finding_category: FindingCategory::Network,
                finding_current_value: current_display.clone(),
                finding_description: directive.ssh_description.to_string(),
                finding_explanation: match effective.as_ref() {
                    // Naming the file matters when it is not the one this
                    // tool edits: editing sshd_config would not change what
                    // sshd uses, because the drop-in is read first.
                    Some(e) if e.source != main.path => format!(
                        "The SSH directive '{}' is not configured securely. {} \
                             The value in force comes from {}, which sshd reads before \
                             {}, so it overrides anything set there.",
                        directive.ssh_directive_name,
                        directive.ssh_description,
                        e.source,
                        main.path,
                    ),
                    _ => format!(
                        "The SSH directive '{}' is not configured securely. {}",
                        directive.ssh_directive_name, directive.ssh_description,
                    ),
                },
                finding_id: format!("ssh-{}", directive.ssh_directive_name.to_lowercase()),
                finding_impact: "May allow unauthorised access or weaken SSH security".to_string(),
                finding_recommended_value: target.to_string(),
                finding_remediation_steps: vec![
                    format!(
                        "Edit {} and set: {} {}",
                        main.edit_target(),
                        directive.ssh_directive_name,
                        target,
                    ),
                    "Restart SSH service: systemctl restart sshd".to_string(),
                ],
                finding_severity: directive.ssh_severity,
                finding_title: format!("Insecure SSH setting: {}", directive.ssh_directive_name,),
                finding_compliance: get_ssh_compliance_mappings(directive.ssh_directive_name),
                finding_exception: policy_exception,
                finding_exception_key: Some(directive.ssh_directive_name.to_string()),
            });
        }
    }

    // Check cryptographic directives. These are insecure if unset OR if they
    // contain any algorithm outside the strong allow-list (i.e. a weak/legacy
    // cipher, KEX or MAC is enabled).
    for crypto in SSH_CRYPTO_DIRECTIVES {
        // From the resolved configuration, exactly as the loop above reads
        // its own directives. This read the main file alone until an
        // openSUSE, Fedora or RHEL host made the cost plain: crypto-policies
        // supplies Ciphers, MACs and KexAlgorithms from
        // /etc/ssh/sshd_config.d, the Include sits above everything this
        // tool writes, and sshd takes the first value it obtains. The strong
        // list this tool put in the main file was read back and reported
        // while sshd negotiated the drop-in's, and since these three
        // directives are in `coverage()`, the absent finding rendered their
        // controls as Pass. The mirror was just as wrong: a drop-in already
        // holding a strong list read as "not set" and was reported.
        let effective = resolved.effective(crypto.crypto_directive_name);
        let current_value = effective.as_ref().map(|e| e.value.clone());

        if !crypto_value_is_secure(current_value.as_deref(), crypto.crypto_desired) {
            let current_display = observed_value(effective.as_ref());
            let policy_exception =
                config.exception_outcome(crypto.crypto_directive_name, &current_display);
            findings.push(Finding {
                finding_category: FindingCategory::Network,
                finding_current_value: current_display.clone(),
                finding_description: crypto.crypto_description.to_string(),
                finding_explanation: match effective.as_ref() {
                    // Naming the file matters for the same reason it does
                    // above: editing sshd_config would not change what sshd
                    // negotiates, because the drop-in is read first.
                    Some(e) if e.source != main.path => format!(
                        "The SSH directive '{}' is unset or permits weak algorithms. {} \
                             The value in force comes from {}, which sshd reads before \
                             {}, so it overrides anything set there.",
                        crypto.crypto_directive_name,
                        crypto.crypto_description,
                        e.source,
                        main.path,
                    ),
                    _ => format!(
                        "The SSH directive '{}' is unset or permits weak algorithms. {}",
                        crypto.crypto_directive_name, crypto.crypto_description,
                    ),
                },
                finding_id: format!("ssh-{}", crypto.crypto_directive_name.to_lowercase()),
                finding_impact:
                    "Weak SSH cryptography can allow session decryption or downgrade attacks"
                        .to_string(),
                finding_recommended_value: crypto.crypto_desired.join(","),
                finding_remediation_steps: vec![
                    format!(
                        "Restrict {} to strong algorithms supported by the host",
                        crypto.crypto_directive_name,
                    ),
                    "Validate with: sshd -t".to_string(),
                    "Restart SSH service: systemctl restart sshd".to_string(),
                ],
                finding_severity: crypto.crypto_severity,
                finding_title: format!(
                    "Weak or unset SSH cryptography: {}",
                    crypto.crypto_directive_name,
                ),
                finding_compliance: get_ssh_compliance_mappings(crypto.crypto_directive_name),
                finding_exception: policy_exception,
                finding_exception_key: Some(crypto.crypto_directive_name.to_string()),
            });
        }
    }

    let duration_us = start_time.elapsed().as_micros() as u64;
    Ok(ScanResult {
        scan_plugin_id: plugin_id,
        scan_success: true,
        scan_findings: findings,
        scan_unchecked: vec![],
        scan_duration_us: duration_us,
        scan_error: None,
    })
}
