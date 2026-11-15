//! The scan half of the PAM plugin: the body of `PamHardeningPlugin::scan`.
//!
//! The trait impl stays whole in `mod.rs`, because a trait impl cannot span
//! files; its method bodies outgrew that file and now live one per module,
//! each with the trait method delegating to it. This one reads every
//! configuration file the plugin manages (classified, and through the
//! vendor layer where `/etc` holds nothing), reports the directives that
//! violate the baseline, and carries the layer drift and module-presence
//! findings beside them.

use super::policy::{
    PolicyDirective, departure_finding, ignored_override, policy_directives, rule_mappings,
};
use super::{
    ConfRead, FAILLOCK_CONF, MIN_DAYS_DIRECTIVE, ModulePresence, PWHISTORY_CONF, PamConfigFile,
    PamHardeningPlugin, PamObserved, clamped_baseline, layer_drift_findings, min_days_enforceable,
    min_days_unenforceable_finding, module_absent_finding, module_presence_by_file,
    observed_pam_value, pam_violates, presence_for, read_conf_classified, unchecked_pam_directive,
    unreadable_reason,
};

use hardener_common::{error::Result, types::FindingCategory};
use hardener_core::{
    Context, PasswordPolicy, PluginConfig,
    plugin::{Finding, HardeningPlugin, ScanResult},
};
use std::time::Instant;
use tracing::{debug, info, warn};

pub(super) async fn scan(ctx: &Context, config: &PluginConfig) -> Result<ScanResult> {
    let start = Instant::now();
    let policy = config.password_policy();
    info!(
        "Starting PAM authentication hardening scan ({} password policy)",
        policy.id()
    );

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

    // Check each PAM directive, as the selected password policy states it.
    for policy_directive in policy_directives(policy) {
        let directive = &policy_directive.rule;
        if let Some(note) = ignored_override(policy, &policy_directive, config) {
            warn!("{note}");
        }
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
        let current_display = current_value
            .clone()
            .unwrap_or_else(|| "not set".to_string());

        if !is_secure {
            findings.push(rule_finding(
                policy,
                &policy_directive,
                &target,
                &current_display,
                config,
            ));
        }

        // A rule the selected policy drops is still judged against the
        // benchmark, so the frameworks that require it fail rather than pass
        // on a host that does not meet it. See `policy` for why the two
        // findings carry different controls.
        if let Some(departure) = &policy_directive.departure {
            let benchmark_target = clamped_baseline(departure.benchmark, config);
            if pam_violates(
                departure.benchmark,
                &benchmark_target,
                current_value.as_deref(),
            ) {
                findings.push(departure_finding(
                    policy,
                    departure,
                    &benchmark_target,
                    &current_display,
                    config,
                ));
            }
        }
    }

    // Password hashing (#191): judged across login.defs and the pam_unix
    // lines that override it, so it has its own reader rather than a row in
    // the loop above. Handed the login.defs read this scan already took.
    let hashing = super::hashing::scan(ctx, config, &login_defs_read).await;
    findings.extend(hashing.findings);
    unchecked.extend(hashing.unchecked);

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

/// The finding for a host that breaks the selected policy's own rule for a
/// directive.
///
/// Under the benchmark policy this is byte for byte the finding every earlier
/// release produced, so an operator who changed nothing sees nothing change.
/// Under the NIST policy it names the policy, and a rule that drops a benchmark
/// requirement is described as the host not having adopted the policy yet
/// rather than as an insecure setting, because by that policy's reasoning the
/// value it replaces is the weaker one.
fn rule_finding(
    policy: PasswordPolicy,
    policy_directive: &PolicyDirective,
    target: &str,
    current_display: &str,
    config: &PluginConfig,
) -> Finding {
    let directive = &policy_directive.rule;
    let name = directive.pam_directive_name;
    let policy_note = match policy {
        PasswordPolicy::Benchmark => String::new(),
        PasswordPolicy::Nist80063b => format!(" under the {} password policy", policy.id()),
    };
    let (title, impact) = match &policy_directive.departure {
        Some(_) => (
            format!(
                "PAM setting differs from the {} password policy: {name}",
                policy.id()
            ),
            format!(
                "Character-class rules and forced periodic change push people towards \
                 predictable patterns and written-down passwords, and reject long passphrases \
                 made of words. The {} policy drops them and relies on length, the dictionary \
                 check, lockout and password history instead",
                policy.id()
            ),
        ),
        None => (
            format!("Insecure PAM setting: {name}"),
            "Weak authentication settings can allow easier password guessing and brute-force \
             attacks"
                .to_string(),
        ),
    };
    Finding {
        finding_id: format!("pam-{name}"),
        finding_category: FindingCategory::Authentication,
        finding_current_value: current_display.to_string(),
        finding_description: format!(
            "PAM directive '{name}' is currently '{current_display}' but should be \
             '{target}'{policy_note}",
        ),
        finding_explanation: directive.pam_description.to_string(),
        finding_impact: impact,
        finding_recommended_value: target.to_string(),
        finding_remediation_steps: vec![format!(
            "Set {name} = {target} in the appropriate configuration file"
        )],
        finding_severity: directive.pam_severity,
        finding_title: title,
        finding_compliance: rule_mappings(policy_directive),
        finding_exception: config.exception_outcome(name, current_display),
        finding_exception_key: Some(name.to_string()),
    }
}
