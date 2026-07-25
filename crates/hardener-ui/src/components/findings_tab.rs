//! Findings tab content for the Analysis page.
//!
//! Renders findings as a severity-grouped hairline list with expand-in-place
//! detail, plus severity and view-mode filtering. View modes: All
//! (audit-style, default), Compliance (hides policy-excepted findings to
//! show only real violations).

use crate::state::{AppState, total_unchecked};
use crate::tauri_bindings::{invoke_deep_scan, invoke_generate_report};
use crate::types::Severity;
use crate::utils::{group_findings_by_severity, is_auth_cancelled, severity_class, severity_label};
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

/// View mode for findings display.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ViewMode {
    /// Show all findings (audit-style, full assessment).
    All,
    /// Show only findings without policy exceptions (compliance violations).
    Compliance,
}

/// Findings tab content displaying the scanner results.
///
/// Contains severity and view-mode filters in the header, and the findings
/// themselves as a severity-grouped list where each row expands in place.
/// Both filters are client-side: all findings remain in memory and the
/// dropdowns instantly adjust which are visible.
#[component]
pub fn FindingsTab() -> impl IntoView {
    let app_state = expect_context::<AppState>();
    let view_mode = RwSignal::new(ViewMode::All);

    // All findings flattened from scan results
    let all_findings = move || {
        app_state
            .scan_results
            .get()
            .iter()
            .flat_map(|r| r.scan_findings.clone())
            .collect::<Vec<_>>()
    };

    // Filtered findings based on severity threshold and view mode
    let filtered_findings = Signal::derive(move || {
        let mut findings = all_findings();

        // Apply view mode filter
        if view_mode.get() == ViewMode::Compliance {
            findings.retain(|f| f.finding_policy_exception.is_none());
        }

        // Apply severity filter
        if let Some(min) = app_state.severity_filter.get() {
            let threshold = severity_rank(min);
            findings.retain(|f| severity_rank(f.finding_severity) >= threshold);
        }

        findings
    });

    let total_count = move || all_findings().len();
    let filtered_count = move || filtered_findings.get().len();
    let has_findings = move || !all_findings().is_empty();
    let is_filtered =
        move || app_state.severity_filter.get().is_some() || view_mode.get() != ViewMode::All;

    let on_severity_change = move |ev: leptos::ev::Event| {
        let value = event_target_value(&ev);
        app_state.severity_filter.set(parse_severity(&value));
    };

    let on_view_mode_change = move |ev: leptos::ev::Event| {
        let value = event_target_value(&ev);
        view_mode.set(match value.as_str() {
            "compliance" => ViewMode::Compliance,
            _ => ViewMode::All,
        });
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

    // Raw unchecked count for the honesty footer (undeduplicated, honest).
    let unchecked_count = move || total_unchecked(&app_state.scan_results.get());

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
                        <select id="view-mode-select" on:change=on_view_mode_change aria-label="View mode">
                            <option value="all" selected=true>"All (Audit)"</option>
                            <option value="compliance">"Compliance Only"</option>
                        </select>
                    </div>
                </div>

                <ol class="findings-groups">
                    {move || group_findings_by_severity(&filtered_findings.get())
                        .into_iter()
                        .map(|(sev, group)| {
                            let count = group.len();
                            view! {
                                <li class="finding-group">
                                    <div class="finding-group-head">
                                        <span class=format!("finding-dot {}", severity_class(sev))></span>
                                        <span class="finding-group-name">{severity_label(sev)}</span>
                                        <span class="finding-group-count">{count}</span>
                                    </div>
                                    <ul class="finding-rows">
                                        {group.into_iter().map(|f| {
                                            let id = f.finding_id.clone();
                                            let id_for_toggle = id.clone();
                                            let id_for_key = id.clone();
                                            // Copy Signal so `is_open` can be read at all three sites
                                            // (row class, detail Show, chevron) without moving `id`.
                                            let is_open = Signal::derive(move || {
                                                expanded.with(|e| e.as_deref() == Some(id.as_str()))
                                            });
                                            let category = f.finding_category.to_string();
                                            let current = f.finding_current_value.clone();
                                            let recommended = f.finding_recommended_value.clone();
                                            let steps = f.finding_remediation_steps.clone();
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
                                                        <span class="finding-chevron" aria-hidden="true">
                                                            {move || if is_open.get() { "v" } else { ">" }}
                                                        </span>
                                                    </div>
                                                    <Show when=move || is_open.get()>
                                                        <div class="finding-detail">
                                                            <p class="finding-desc">{f.finding_description.clone()}</p>
                                                            <p class="finding-explain">{f.finding_explanation.clone()}</p>
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
                                                </li>
                                            }
                                        }).collect::<Vec<_>>()}
                                    </ul>
                                </li>
                            }
                        })
                        .collect::<Vec<_>>()}
                </ol>

                <Show when=move || unchecked_count() != 0>
                    <p class="findings-unchecked">
                        {move || {
                            let count = unchecked_count();
                            format!(
                                "{} check{} not verifiable without privileges. ",
                                count,
                                if count == 1 { "" } else { "s" },
                            )
                        }}
                        <button class="link-button" on:click=on_deep_scan disabled=move || deep_running.get()>
                            {move || if deep_running.get() { "Scanning..." } else { "Run with sudo" }}
                        </button>
                    </p>
                </Show>
            </Show>
        </div>
    }
}
