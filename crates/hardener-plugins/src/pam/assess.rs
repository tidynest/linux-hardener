//! The scan half of the PAM plugin: the body of `PamHardeningPlugin::scan`.
//!
//! The trait impl stays whole in `mod.rs`, because a trait impl cannot span
//! files; its method bodies outgrew that file and now live one per module,
//! each with the trait method delegating to it. This one reads every
//! configuration file the plugin manages (classified, and through the
//! vendor layer where `/etc` holds nothing), reports the directives that
//! violate the baseline, and carries the layer drift and module-presence
//! findings beside them.

use super::{
    ConfRead, FAILLOCK_CONF, MIN_DAYS_DIRECTIVE, ModulePresence, PAM_DIRECTIVES, PWHISTORY_CONF,
    PamConfigFile, PamHardeningPlugin, PamObserved, clamped_baseline, get_pam_compliance_mappings,
    layer_drift_findings, min_days_enforceable, min_days_unenforceable_finding,
    module_absent_finding, module_presence_by_file, observed_pam_value, pam_violates, presence_for,
    read_conf_classified, unchecked_pam_directive, unreadable_reason,
};

use hardener_common::{error::Result, types::FindingCategory};
use hardener_core::{
    Context, PluginConfig,
    plugin::{Finding, HardeningPlugin, ScanResult},
};
use std::time::Instant;
use tracing::{debug, info};

pub(super) async fn scan(ctx: &Context, config: &PluginConfig) -> Result<ScanResult> {
    let start = Instant::now();
    info!("Starting PAM authentication hardening scan");

    let mut findings = Vec::new();
    let mut unchecked = Vec::new();

    // Read configuration files.
    let pwquality = read_conf_classified(ctx, "/etc/security/pwquality.conf").await;

    // Classified, and layered, like every other file this plugin reads. It
    // used to go through a second reader that folded any failure into an
    // empty string, so a root-only /etc/login.defs reported every directive
    // it sets as unset and a hardened host collected findings for settings
    // it already had.
    let login_defs_read = read_conf_classified(ctx, "/etc/login.defs").await;

    // The other two files the drift table names. Hoisted here for the same
    // reason as the two above: the drift walk and the directive loop both
    // want them, and whichever reads second reads a file this run already
    // read and warns a second time about the same failure (#170).
    let faillock = read_conf_classified(ctx, FAILLOCK_CONF).await;
    let pwhistory = read_conf_classified(ctx, PWHISTORY_CONF).await;

    // Drift between the layers, for every file the table names rather than
    // for login.defs alone. The files already read above are handed over so
    // they are not read, and warned about, a second time.
    let already_read: [(&str, &ConfRead); 4] = [
        ("/etc/security/pwquality.conf", &pwquality),
        ("/etc/login.defs", &login_defs_read),
        (FAILLOCK_CONF, &faillock),
        (PWHISTORY_CONF, &pwhistory),
    ];
    findings.extend(layer_drift_findings(ctx, &already_read).await);

    // Whether each file's consuming module is loaded, read once per file
    // rather than once per directive: six pwquality keys share one module,
    // and over SSH a per-directive read is six round trips for one answer.
    let presence = module_presence_by_file(ctx).await;

    // Check each PAM directive.
    for directive in PAM_DIRECTIVES {
        if directive.pam_config_file == PamConfigFile::PamAuth {
            debug!(
                "Skipping PAM module directive: {}",
                directive.pam_directive_name
            );
            continue;
        }

        // A file no module reads makes its own value irrelevant, so this
        // comes before the value is read at all. Judging the value first
        // and this second would report a directive both compliant and
        // unenforced, which is one host described two ways.
        match presence_for(&presence, directive) {
            ModulePresence::NotInStack { module } => {
                let conf_path = directive
                    .pam_config_file
                    .conf_path()
                    .expect("a directive with a module has a file");
                findings.push(module_absent_finding(directive, module, conf_path));
                continue;
            }
            ModulePresence::Indeterminate {
                reason,
                needs_privilege,
            } => {
                unchecked.push(unchecked_pam_directive(
                    directive,
                    reason.clone(),
                    *needs_privilege,
                ));
                continue;
            }
            ModulePresence::InStack | ModulePresence::NoModule => {}
        }

        // A correct value in a file no consumer reads is not compliance.
        // Asked before the value is compared, because on an affected host
        // the comparison would pass: apply writes the target, the file
        // holds it, and no account ever receives it. See issue #69.
        //
        // Only a positive "this build has no such field" diverts. An
        // undetermined probe falls through to the ordinary comparison,
        // because the value can still be read and a wrong one is still
        // worth reporting: suppressing it would trade a rare false pass for
        // losing the check on every host whose chage could not be run.
        if directive.pam_directive_name == MIN_DAYS_DIRECTIVE
            && min_days_enforceable(ctx).await == Some(false)
        {
            findings.push(min_days_unenforceable_finding(directive));
            continue;
        }

        let current_value =
            match observed_pam_value(ctx, directive, &pwquality, &login_defs_read, &already_read)
                .await
            {
                PamObserved::Value(v) => Some(v),
                PamObserved::NotSet => None,
                PamObserved::Unreadable {
                    path,
                    permission_denied,
                } => {
                    unchecked.push(unchecked_pam_directive(
                        directive,
                        unreadable_reason(path, permission_denied),
                        permission_denied,
                    ));
                    continue;
                }
            };

        // Resolve the effective target the same way apply and validate do,
        // through the one function all three call: a directive override
        // wins over the hardcoded baseline only where it tightens it. The
        // shared call is what keeps the three in step, rather than a note
        // pointing at the line numbers of the other two.
        let target = clamped_baseline(directive, config);

        // Check if current value satisfies the directive's comparison
        // against the resolved (overridden + clamped) target.
        let is_secure = !pam_violates(directive, &target, current_value.as_deref());

        if !is_secure {
            let current_display = current_value.unwrap_or_else(|| "not set".to_string());
            let policy_exception =
                config.exception_outcome(directive.pam_directive_name, &current_display);

            findings.push(Finding {
                    finding_id: format!(
                        "pam-{}",
                        directive.pam_directive_name
                    ),
                    finding_category: FindingCategory::Authentication,
                    finding_current_value: current_display.clone(),
                    finding_description: format!(
                        "PAM directive '{}' is currently '{}' but should be '{}'",
                        directive.pam_directive_name,
                        current_display,
                        target,
                    ),
                    finding_explanation: directive.pam_description.to_string(),
                    finding_impact: "Weak authentication settings can allow easier password guessing and brute-force attacks".to_string(),
                    finding_recommended_value: target.clone(),
                    finding_remediation_steps: vec![
                        format!(
                            "Set {} = {} in the appropriate configuration file",
                            directive.pam_directive_name,
                            target,
                        ),
                    ],
                    finding_severity: directive.pam_severity,
                    finding_title: format!(
                        "Insecure PAM setting: {}",
                        directive.pam_directive_name
                    ),
                    finding_compliance: get_pam_compliance_mappings(directive.pam_directive_name),
                    finding_exception: policy_exception,
                    finding_exception_key: Some(directive.pam_directive_name.to_string()),
                });
        }
    }

    let duration_us = start.elapsed().as_micros() as u64;

    info!(
        "PAM scan completed: {} findings in {}µs",
        findings.len(),
        duration_us,
    );

    Ok(ScanResult {
        scan_plugin_id: PamHardeningPlugin::new().metadata().plugin_id,
        scan_success: true,
        scan_findings: findings,
        scan_unchecked: unchecked,
        scan_duration_us: duration_us,
        scan_error: None,
        scan_skipped: None,
    })
}
