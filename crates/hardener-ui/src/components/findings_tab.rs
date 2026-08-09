//! Findings tab content for the Analysis page.
//!
//! Renders findings as a severity-grouped hairline list with expand-in-place
//! detail and a severity filter. A finding the configuration documents as an
//! accepted deviation is not a violation, so it sits in its own group below the
//! severity groups rather than inflating a severity count, and it is never
//! hidden: the documented deviation is itself the evidence.

use super::icons::IconChevron;
use super::{ExceptionDraft, ExceptionModal};
use crate::state::{AppState, unchecked_tally};
use crate::tauri_bindings::{
    invoke_add_policy_exception, invoke_deep_scan, invoke_generate_report,
    invoke_remove_policy_exception,
};
use crate::types::{ExceptionOutcome, Finding, Severity};
use crate::utils::{
    PluginFinding, apply_written_exception, clear_exception, group_findings_by_severity,
    is_auth_cancelled, severity_class, severity_label, split_policy_excepted,
    unchecked_honesty_line,
};
use leptos::prelude::*;
use leptos_router::components::A;

/// Maps a severity level to a numeric rank for comparison.
fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

/// Parses a dropdown value string into an Option<Severity>.
fn parse_severity(value: &str) -> Option<Severity> {
    match value {
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

/// Findings tab content displaying the scanner results.
///
/// Contains a severity filter in the header, and the findings themselves as a
/// severity-grouped list where each row expands in place. The filter is
/// client-side: all findings remain in memory and the dropdown instantly
/// adjusts which are visible.
#[component]
pub fn FindingsTab() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // All findings flattened from scan results, paired with the plugin that
    // produced each one: the exception a row writes is keyed per plugin, and
    // this is the only place that still has both on hand once the results are
    // flattened.
    let all_findings = move || {
        app_state
            .scan_results
            .get()
            .iter()
            .flat_map(|r| {
                let plugin_id = r.scan_plugin_id.as_str().to_string();
                r.scan_findings
                    .clone()
                    .into_iter()
                    .map(move |f| (plugin_id.clone(), f))
            })
            .collect::<Vec<_>>()
    };

    // Filtered findings based on the severity threshold. Policy-excepted
    // findings are never filtered out here: they are separated at render time
    // so they stay visible as evidence instead of being silently dropped.
    let filtered_findings = Signal::derive(move || {
        let mut findings = all_findings();

        if let Some(min) = app_state.severity_filter.get() {
            let threshold = severity_rank(min);
            findings.retain(|(_, f)| severity_rank(f.finding_severity) >= threshold);
        }

        findings
    });

    let total_count = move || all_findings().len();
    let filtered_count = move || filtered_findings.get().len();
    let has_findings = move || !all_findings().is_empty();
    let is_filtered = move || app_state.severity_filter.get().is_some();

    let on_severity_change = move |ev: leptos::ev::Event| {
        let value = event_target_value(&ev);
        app_state.severity_filter.set(parse_severity(&value));
    };

    // Which finding is expanded in place (by finding_id). None = all collapsed.
    let expanded = RwSignal::new(Option::<String>::None);

    // Folded honesty footer: privileged deep scan (mirrors the Dashboard hero).
    let deep_running = app_state.deep_scan_running;
    let on_deep_scan = move |_| {
        deep_running.set(true);
        leptos::task::spawn_local(async move {
            match invoke_deep_scan(vec![], app_state.config_path.get_untracked()).await {
                Ok(results) => {
                    app_state.scan_results.set(results);
                    let frameworks = hardener_types::ComplianceFramework::ALL
                        .iter()
                        .map(|f| f.id().to_string())
                        .collect();
                    if let Ok(reports) = invoke_generate_report(frameworks).await {
                        app_state.compliance_reports.set(reports);
                    }
                }
                Err(e) if is_auth_cancelled(&e) => {}
                Err(e) => app_state
                    .error_message
                    .set(Some(format!("Deep scan failed: {e}"))),
            }
            deep_running.set(false);
        });
    };

    // Raw unchecked counts for the honesty footer (undeduplicated, honest),
    // split by whether a privileged re-run would reach them.
    let tally = move || unchecked_tally(&app_state.scan_results.get());

    view! {
        <div class="findings-tab">
            <Show
                when=has_findings
                fallback=|| view! {
                    <div class="empty-state">
                        <p class="empty-state-title">"No findings yet"</p>
                        <p class="empty-state-hint">
                            "Run a Security Scan above to analyse your system. Findings are grouped by severity."
                        </p>
                    </div>
                }
            >
                <div class="findings-controls">
                    <span class="findings-count">
                        {move || if is_filtered() {
                            format!("{} of {} findings", filtered_count(), total_count())
                        } else {
                            let total = total_count();
                            format!(
                                "{} finding{} detected",
                                total,
                                if total == 1 { "" } else { "s" },
                            )
                        }}
                    </span>
                    <div class="findings-filters">
                        <select id="severity-select" on:change=on_severity_change aria-label="Minimum severity">
                            <option value="" selected=true>"Min severity: All"</option>
                            <option value="low">"Low and above"</option>
                            <option value="medium">"Medium and above"</option>
                            <option value="high">"High and above"</option>
                            <option value="critical">"Critical only"</option>
                        </select>
                    </div>
                </div>

                <ol class="findings-groups">
                    {move || {
                        let (live, excepted) = split_policy_excepted(&filtered_findings.get());
                        let mut groups: Vec<_> = group_findings_by_severity(&live)
                            .into_iter()
                            .map(|(sev, group)| {
                                finding_group(severity_class(sev), severity_label(sev), group, expanded)
                            })
                            .collect();
                        // Documented deviations last, so the severity groups
                        // above them count real problems only.
                        if !excepted.is_empty() {
                            groups.push(finding_group(
                                "severity_exception",
                                "Policy Exceptions",
                                excepted,
                                expanded,
                            ));
                        }
                        groups
                    }}
                </ol>

                <Show when=move || tally().total != 0>
                    <p class="findings-unchecked">
                        {move || unchecked_honesty_line(tally())}
                        <Show when=move || tally().privilege_would_help()>
                            <button class="link-button" on:click=on_deep_scan disabled=move || deep_running.get()>
                                {move || if deep_running.get() { "Scanning..." } else { "Run with sudo" }}
                            </button>
                        </Show>
                    </p>
                </Show>
            </Show>
        </div>
    }
}

/// One group of findings: a head carrying a dot, a name and a count, then the
/// rows. Shared by the severity groups and the policy-exception group so the
/// latter cannot drift from the former.
fn finding_group(
    dot_class: &'static str,
    name: &'static str,
    findings: Vec<PluginFinding>,
    expanded: RwSignal<Option<String>>,
) -> impl IntoView {
    let count = findings.len();
    view! {
        <li class="finding-group">
            <div class="finding-group-head">
                <span class=format!("finding-dot {dot_class}")></span>
                <span class="finding-group-name">{name}</span>
                <span class="finding-group-count">{count}</span>
            </div>
            <ul class="finding-rows">
                {findings.into_iter().map(|(plugin_id, f)| finding_row(plugin_id, f, expanded)).collect::<Vec<_>>()}
            </ul>
        </li>
    }
}

/// One finding row: a head that toggles the detail open in place.
///
/// `plugin_id` names the plugin the finding came from. It is not part of the
/// `Finding` itself: an exception is keyed per plugin (two plugins can key on
/// the same word), so accepting or removing one needs both `plugin_id` and
/// `finding_exception_key` to name the right row.
fn finding_row(plugin_id: String, f: Finding, expanded: RwSignal<Option<String>>) -> impl IntoView {
    let app_state = expect_context::<AppState>();
    let id = f.finding_id.clone();
    let id_for_toggle = id.clone();
    let id_for_key = id.clone();
    // Copy Signal so `is_open` can be read at all three sites
    // (row class, detail Show, chevron) without moving `id`.
    let is_open = Signal::derive(move || expanded.with(|e| e.as_deref() == Some(id.as_str())));
    let category = f.finding_category.to_string();
    let current = f.finding_current_value.clone();
    let recommended = f.finding_recommended_value.clone();
    let steps = f.finding_remediation_steps.clone();
    let title = f.finding_title.clone();
    // A finding with no exception key renders no accept/remove control at all,
    // rather than one that fails the moment it is pressed.
    let key = f.finding_exception_key.clone();
    // The reason the deviation was accepted is the evidence that makes this a
    // documented exception rather than an unexplained gap, so the detail
    // carries it. The rest of the approval metadata stays out until someone
    // asks for it.
    let exception_reason = match &f.finding_exception {
        ExceptionOutcome::Applied(e) => Some(e.exception_reason.clone()),
        ExceptionOutcome::NotConfigured | ExceptionOutcome::Declined(_) => None,
    }
    .filter(|r| !r.is_empty());
    // An exception that did not apply leaves the finding live, so the row keeps
    // its real severity and merely gains this line, rather than the label
    // branch above that replaces severity for an applied one. The sentence
    // comes from the formatter the CLI renders, so the two surfaces cannot word
    // the same outcome differently.
    let exception_declined = match &f.finding_exception {
        ExceptionOutcome::Declined(d) => Some(hardener_types::exception_declined_line(d)),
        ExceptionOutcome::NotConfigured | ExceptionOutcome::Applied(_) => None,
    };

    // Construction-time snapshot, same as `exception_reason` and
    // `exception_declined` above: the row is rebuilt fresh whenever
    // `AppState::scan_results` changes (the unkeyed list in `FindingsTab`
    // reconstructs every row from the patched `Finding` on that same
    // update), so this is the one source of truth for the Accept/Remove
    // control rather than a second signal that shadows it.
    let is_not_configured = matches!(f.finding_exception, ExceptionOutcome::NotConfigured);
    let modal_open = RwSignal::new(false);
    // A write failure renders inside the modal (see `ExceptionModal`'s `error`
    // prop) rather than through `app_state.error_message`: that banner sits in
    // normal document flow behind the modal backdrop's `z-index: 50`, so it
    // would render half-dimmed with an unreachable dismiss button, and a click
    // aimed at it would land on the backdrop and discard the reason the
    // operator just typed. Cleared whenever the modal (re)opens, so a stale
    // failure from a previous attempt cannot outlive it.
    let modal_error = RwSignal::new(Option::<String>::None);

    let submit_plugin_id = plugin_id.clone();
    let submit_key = key.clone();
    let on_submit = Callback::new(move |draft: ExceptionDraft| {
        let Some(exception_key) = submit_key.clone() else {
            return;
        };
        let plugin_id = submit_plugin_id.clone();
        leptos::task::spawn_local(async move {
            match invoke_add_policy_exception(
                plugin_id.clone(),
                exception_key.clone(),
                draft.reason,
                draft.approved_by,
                draft.ticket,
                draft.expires,
            )
            .await
            {
                Ok(written) => {
                    app_state.scan_results.update(|results| {
                        apply_written_exception(results, &plugin_id, &exception_key, &written);
                    });
                    modal_open.set(false);
                }
                // A cancelled pkexec prompt is not a failure to report, and
                // leaves nothing typed that is worth preserving, so the modal
                // still closes exactly as before.
                Err(e) if is_auth_cancelled(&e) => {
                    modal_open.set(false);
                }
                // A real failure leaves the modal open so the typed reason,
                // approver, ticket and expiry survive for a retry.
                Err(e) => modal_error.set(Some(format!("Accept finding failed: {e}"))),
            }
        });
    });

    let remove_plugin_id = plugin_id.clone();
    let remove_key = key.clone();
    let remove_now = Callback::new(move |()| {
        let Some(exception_key) = remove_key.clone() else {
            return;
        };
        let plugin_id = remove_plugin_id.clone();
        leptos::task::spawn_local(async move {
            match invoke_remove_policy_exception(plugin_id.clone(), exception_key.clone()).await {
                Ok(()) => {
                    app_state.scan_results.update(|results| {
                        clear_exception(results, &plugin_id, &exception_key);
                    });
                }
                Err(e) if is_auth_cancelled(&e) => {}
                Err(e) => app_state
                    .error_message
                    .set(Some(format!("Remove exception failed: {e}"))),
            }
        });
    });

    view! {
        <li class="finding-row" class:open=move || is_open.get()>
            <div
                class="finding-row-head"
                role="button"
                tabindex="0"
                aria-expanded=move || is_open.get().to_string()
                on:click=move |_| expanded.update(|e| {
                    let cur = id_for_toggle.clone();
                    *e = if e.as_deref() == Some(cur.as_str()) { None } else { Some(cur) };
                })
                on:keydown=move |ev: leptos::ev::KeyboardEvent| {
                    if ev.key() == "Enter" || ev.key() == " " {
                        ev.prevent_default();
                        let cur = id_for_key.clone();
                        expanded.update(|e| {
                            *e = if e.as_deref() == Some(cur.as_str()) { None } else { Some(cur) };
                        });
                    }
                }
            >
                <span class="finding-title">{f.finding_title.clone()}</span>
                <span class="finding-tag">{category}</span>
                <IconChevron class="finding-chevron"/>
            </div>
            <Show when=move || is_open.get()>
                <div class="finding-detail">
                    <p class="finding-desc">{f.finding_description.clone()}</p>
                    <p class="finding-explain">{f.finding_explanation.clone()}</p>
                    {exception_reason.clone().map(|reason| view! {
                        <p class="finding-exception-reason">
                            <span class="finding-exception-label">
                                {hardener_types::POLICY_EXCEPTION_LABEL}
                            </span>
                            {reason}
                        </p>
                    })}
                    {exception_declined.clone().map(|line| view! {
                        <p class="finding-exception-declined">{line}</p>
                    })}
                    {key.clone().map(|_k| view! {
                        <div class="finding-exception-actions">
                            <Show
                                when=move || is_not_configured
                                fallback=move || view! {
                                    <button
                                        class="btn btn-secondary finding-exception-remove"
                                        on:click=move |_| remove_now.run(())
                                    >"Remove Exception"</button>
                                }
                            >
                                <button
                                    class="btn btn-secondary finding-exception-accept"
                                    on:click=move |_| {
                                        modal_error.set(None);
                                        modal_open.set(true);
                                    }
                                >"Accept This Finding"</button>
                            </Show>
                        </div>
                    })}
                    <div class="finding-values">
                        <span class="value-current">{current.clone()}</span>
                        <span class="value-arrow" aria-hidden="true">"->"</span>
                        <span class="value-recommended">{recommended.clone()}</span>
                    </div>
                    {(!steps.is_empty()).then(|| view! {
                        <p class="finding-remediation-label">"Remediation"</p>
                        <ol class="finding-remediation">
                            {steps.clone().into_iter().map(|s| view! { <li>{s}</li> }).collect::<Vec<_>>()}
                        </ol>
                    })}
                    <A href="/hardening" attr:class="finding-bridge">"Configure Fix in Hardening"</A>
                </div>
            </Show>
            <Show when=move || modal_open.get()>
                <ExceptionModal
                    finding_title=title.clone()
                    on_submit=on_submit
                    on_dismiss=Callback::new(move |()| modal_open.set(false))
                    error=Signal::derive(move || modal_error.get())
                />
            </Show>
        </li>
    }
}
