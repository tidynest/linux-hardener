//! The validate half of the PAM plugin: the body of
//! `PamHardeningPlugin::validate`.
//!
//! The dry-run preview. Asks the same module-presence, drift and classified
//! readers scan and apply use, so a dry run cannot promise hardening the
//! apply it previews would report as incomplete. The trait method in
//! `mod.rs` delegates here.

use super::{
    ConfRead, FAILLOCK_CONF, ModulePresence, PAM_DIRECTIVES, PWHISTORY_CONF, PamConfigFile,
    PamHardeningPlugin, PamObserved, clamped_baseline, dictcheck_lockout_message,
    dictcheck_locks_out_password_changes, layer_drift_findings, module_not_loaded_message,
    module_presence_by_file, observed_pam_value, read_conf_classified, unreadable_issue,
};

use hardener_common::file_utils::{ConfigFormat, parse_config_value};
use hardener_common::{error::Result, types::Severity};
use hardener_core::{
    Context, PluginConfig,
    plugin::{HardeningPlugin, ValidationIssue, ValidationReport},
};
use tracing::info;

pub(super) async fn validate(ctx: &Context, config: &PluginConfig) -> Result<ValidationReport> {
    info!("Validating PAM configuration files");

    let mut issues = Vec::new();

    // Deliberately no metadata probe of the two configuration files here.
    //
    // There was one, and it asked `file_metadata(..).is_file` alone. That
    // field is false for a file which is not there as well as for a
    // directory standing where a file should, because a positively-confirmed
    // absence is `Ok(FileMetadata { exists: false, is_file: false, .. })`, so
    // both states were reported as "exists but is not a regular file" at
    // High and failed the dry run. On three of the five test distributions
    // `/etc/security/pwquality.conf` is not under `/etc` at all, and openSUSE
    // keeps `/etc/login.defs` under `/usr/etc` too, so the run called a file
    // malformed on every host that merely kept it somewhere else.
    //
    // Nothing is lost by dropping it. `read_conf_classified` below answers
    // the same question with three outcomes instead of one bit, across both
    // configuration layers: `Absent` is previewed as "currently not set" and
    // created by apply, and anything that exists but cannot be read reaches
    // `unreadable_issue`, which says which file failed and why.

    // Whether anything reads the files about to be previewed, asked through
    // the same function scan and apply use, so a dry run cannot promise
    // hardening the apply it previews will report as incomplete.
    //
    // High, so the dry run fails. That is the same answer the real apply
    // gives: it records the missing module as a failed change, because the
    // remaining step is a /etc/pam.d edit this plugin refuses to make. A
    // dry run exiting 0 where the apply exits non-zero is the divergence
    // `ValidationReport::has_blocking_issue` exists to prevent.
    let presence = module_presence_by_file(ctx).await;
    for (path, found) in &presence {
        let ModulePresence::NotInStack { module } = found else {
            continue;
        };
        issues.push(ValidationIssue {
            validation_issue_config_key: None,
            validation_issue_message: module_not_loaded_message(path, module),
            validation_issue_severity: Severity::High,
        });
    }

    // Drift between the layers, asked here through the same function scan
    // uses so the two cannot come to disagree about one host.
    //
    // An issue rather than an estimated change, deliberately. Estimated
    // changes are what apply would do, and their count is read as the real
    // change count; apply does not import keys an existing /etc file omits,
    // because that file is the host's own and this tool cannot tell a key
    // the operator dropped on purpose from one an older release dropped for
    // them. Listing drift there would inflate the count and promise a write
    // that never happens. The message says so outright, so the preview
    // cannot be read as an undertaking to fix it.
    // Read here rather than below, where they used to sit, so the drift
    // walk can be handed them instead of reading the same two files a
    // second time and warning a second time about the same failure.
    //
    // Classified reads so a root-only file yields honest requires-root
    // wording, never a false "(currently not set)" claim. Both feed the
    // state-aware change estimate further down, which lists only directives
    // that would actually change; already-compliant directives are tallied
    // in compliant_count rather than listed, so estimated_changes holds
    // only real pending changes.
    let pwquality = read_conf_classified(ctx, "/etc/security/pwquality.conf").await;
    let login_defs = read_conf_classified(ctx, "/etc/login.defs").await;
    let faillock = read_conf_classified(ctx, FAILLOCK_CONF).await;
    let pwhistory = read_conf_classified(ctx, PWHISTORY_CONF).await;

    let already_read: [(&str, &ConfRead); 4] = [
        ("/etc/security/pwquality.conf", &pwquality),
        ("/etc/login.defs", &login_defs),
        (FAILLOCK_CONF, &faillock),
        (PWHISTORY_CONF, &pwhistory),
    ];

    issues.extend(
        layer_drift_findings(ctx, &already_read)
            .await
            .into_iter()
            .map(|finding| ValidationIssue {
                validation_issue_config_key: None,
                validation_issue_message: format!(
                    "{}; apply will not import them, so restoring them is a manual step",
                    finding.finding_description
                ),
                validation_issue_severity: finding.finding_severity,
            }),
    );

    // Medium, and not High, on purpose. High blocks the dry run
    // (`has_blocking_issue`), and this is a pre-existing condition of the
    // host that this plugin neither caused nor will fix: refusing to
    // preview an otherwise sound hardening run because a package is missing
    // would be the wrong lever. The operator is told, and the run proceeds.
    if dictcheck_locks_out_password_changes(ctx, &presence, &pwquality).await {
        issues.push(ValidationIssue {
            validation_issue_config_key: Some("dictcheck".to_string()),
            validation_issue_message: dictcheck_lockout_message(),
            validation_issue_severity: Severity::Medium,
        });
    }

    let mut estimated_changes = Vec::new();
    // Excepted settings are recorded rather than dropped: a preview that
    // omits them shows a documented deviation as nothing at all.
    let mut exceptions: Vec<String> = Vec::new();
    let mut compliant_count = 0usize;

    for d in PAM_DIRECTIVES {
        if d.pam_config_file == PamConfigFile::PamAuth {
            continue;
        }

        // Honour an exception only when it documents the value the host
        // actually has, matching apply's rendering of an absent or
        // unreadable directive as "not set" so neither trusts an
        // exception on faith.
        let observed = observed_pam_value(ctx, d, &pwquality, &login_defs, &already_read).await;
        if let Some(exception) =
            config.matching_exception(d.pam_directive_name, observed.value_or_not_set())
        {
            exceptions.push(hardener_common::types::exception_preview_line(
                d.pam_directive_name,
                observed.value_or_not_set(),
                &exception.reason,
            ));
            continue;
        }

        match &d.pam_config_file {
            PamConfigFile::PwQuality | PamConfigFile::LoginDefs => {
                let read = if d.pam_config_file == PamConfigFile::PwQuality {
                    &pwquality
                } else {
                    &login_defs
                };
                // The same override-clamped target scan and apply use, so
                // the preview cannot judge the host by a rule the apply it
                // previews does not apply.
                let target_value = clamped_baseline(d, config);
                let target_value = target_value.as_str();
                // Absent reads as empty content, same as a confirmed-missing
                // file always has: parsing finds nothing and the directive
                // is honestly reported "(currently not set)" below. Only an
                // Unreadable file (existing but blocked by privilege) must
                // avoid that claim, since it is not a fact this scan can see.
                let content = match read {
                    ConfRead::Content(c, _) => c.as_str(),
                    ConfRead::Absent => "",
                    ConfRead::Unreadable {
                        path,
                        permission_denied,
                        ..
                    } => {
                        // Never claim "not set" for a value this run could
                        // not see, and never offer the write either:
                        // `conf_is_writable` refuses this whole file and
                        // every directive in it is skipped.
                        issues.push(unreadable_issue(
                            d.pam_directive_name,
                            target_value,
                            path,
                            *permission_denied,
                        ));
                        continue;
                    }
                };
                match parse_config_value(content, d.pam_directive_name, ConfigFormat::Auto, true) {
                    // Threshold, not equality: a host stricter than the
                    // baseline is compliant and has no pending change.
                    Some(current) if !d.pam_compare.violated_by(target_value, Some(&current)) => {
                        compliant_count += 1
                    }
                    Some(current) => estimated_changes.push(format!(
                        "{} will change: {} -> {}",
                        d.pam_directive_name, current, target_value
                    )),
                    None => estimated_changes.push(format!(
                        "Set {} = {} (currently not set)",
                        d.pam_directive_name, target_value
                    )),
                }
            }
            PamConfigFile::SecurityConf(_) => {
                // Same clamped target and effective-value resolution as
                // apply. Reuses `observed` (computed above, the source of
                // which is this exact `read_effective_threshold` call)
                // instead of reading again: unlike login.defs, a
                // `SecurityConf` directive has no lenient/classified
                // split between the exception check and this estimate,
                // so there is no wording that reusing it could degrade.
                let target = clamped_baseline(d, config);
                match &observed {
                    PamObserved::Value(v) if !d.pam_compare.violated_by(&target, Some(v)) => {
                        compliant_count += 1
                    }
                    PamObserved::Value(v) => estimated_changes.push(format!(
                        "{} will change: {} -> {}",
                        d.pam_directive_name, v, target
                    )),
                    PamObserved::NotSet => estimated_changes.push(format!(
                        "Set {} = {} (currently not set)",
                        d.pam_directive_name, target
                    )),
                    // Apply refuses outright here, whether what could not be
                    // read is this directive's own conf or a PAM stack file
                    // that would override it, so the same shared wording as
                    // the arm above applies.
                    PamObserved::Unreadable {
                        path,
                        permission_denied,
                    } => issues.push(unreadable_issue(
                        d.pam_directive_name,
                        target,
                        path,
                        *permission_denied,
                    )),
                }
            }
            PamConfigFile::PamAuth => {}
        }
    }

    let is_valid = issues.is_empty();

    Ok(ValidationReport {
        validation_report_plugin_id: PamHardeningPlugin::new().metadata().plugin_id,
        validation_report_is_valid: is_valid,
        validation_report_issues: issues,
        validation_report_estimated_changes: estimated_changes,
        validation_report_compliant_count: compliant_count,
        validation_report_exceptions: exceptions,
    })
}
