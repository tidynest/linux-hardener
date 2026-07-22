//! Compliance tab content for the Analysis page.
//!
//! A framework chip picker over the ten supported frameworks, then one report
//! section per generated framework: a score-band bar, a compact status-count
//! row, and hairline control rows. A bottom-right Export/Generate footer stays
//! visible so a report can be generated from the empty state. Presentation-only
//! over the frozen report bindings.

use crate::state::AppState;
use crate::tauri_bindings::{invoke_export_report, invoke_generate_report};
use crate::types::ControlStatus;
use crate::utils::{score_band, score_band_class};
use leptos::prelude::*;

/// The existing `.status-*` colour class for a control status pill. Manual
/// review maps to the amber `.status-manual` (honesty bucket), never red.
fn control_status_class(status: &ControlStatus) -> &'static str {
    match status {
        ControlStatus::Pass => "status-pass",
        ControlStatus::Fail => "status-fail",
        ControlStatus::ManualReview => "status-manual",
        ControlStatus::NotApplicable => "status-na",
    }
}

/// Compliance tab: framework chip picker, per-framework reports, and a
/// persistent Export/Generate footer.
#[component]
pub fn ComplianceTab() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // The ten frameworks as (id, full name), from the shared enum so the
    // picker cannot drift when a framework is added.
    let frameworks: Vec<(&'static str, &'static str)> = hardener_types::ComplianceFramework::ALL
        .iter()
        .map(|f| (f.id(), f.full_name()))
        .collect();

    let selected = RwSignal::new(vec!["cis".to_string()]);
    let export_format = RwSignal::new("text".to_string());
    let is_exporting = RwSignal::new(false);
    let status_message = RwSignal::new(Option::<(String, bool)>::None);

    let toggle = move |id: String| {
        selected.update(|s| {
            if s.contains(&id) {
                s.retain(|f| f != &id);
            } else {
                s.push(id);
            }
        });
    };

    let on_generate = move |_| {
        let frameworks = selected.get();
        if frameworks.is_empty() {
            return;
        }
        app_state.is_generating_report.set(true);
        status_message.set(None);
        leptos::task::spawn_local(async move {
            match invoke_generate_report(frameworks).await {
                Ok(reports) => app_state.compliance_reports.set(reports),
                Err(e) => status_message.set(Some((format!("Failed: {e}"), false))),
            }
            app_state.is_generating_report.set(false);
        });
    };

    let on_export = move |_| {
        let frameworks = selected.get();
        if frameworks.is_empty() {
            return;
        }
        let format = export_format.get();
        is_exporting.set(true);
        status_message.set(None);
        leptos::task::spawn_local(async move {
            match invoke_export_report(frameworks, format, None).await {
                Ok(path) => status_message.set(Some((format!("Exported to {path}"), true))),
                Err(e) => status_message.set(Some((format!("Export failed: {e}"), false))),
            }
            is_exporting.set(false);
        });
    };

    view! {
        <div class="compliance-tab">
            <div class="compliance-frameworks" role="group" aria-label="Compliance frameworks">
                {frameworks.into_iter().map(|(id, label)| {
                    let id_str = id.to_string();
                    let id_check = id_str.clone();
                    let id_click = id_str.clone();
                    // Copy Signal so `is_sel` reads at both the class and aria sites.
                    let is_sel = Signal::derive(move || selected.get().iter().any(|f| f == &id_check));
                    view! {
                        <button
                            type="button"
                            class="framework-chip"
                            class:selected=move || is_sel.get()
                            aria-pressed=move || is_sel.get().to_string()
                            on:click=move |_| toggle(id_click.clone())
                        >
                            {label}
                        </button>
                    }
                }).collect::<Vec<_>>()}
            </div>

            <Show
                when=move || !app_state.compliance_reports.get().is_empty()
                fallback=|| view! {
                    <div class="empty-state">
                        <p class="empty-state-title">"No reports generated yet"</p>
                        <p class="empty-state-hint">
                            "Select frameworks and generate a report to see per-control compliance."
                        </p>
                    </div>
                }
            >
                {move || app_state.compliance_reports.get().into_iter().map(|report| {
                    let name = report.report_framework.full_name();
                    let summary = report.report_summary.clone();
                    let score = summary.summary_score_percentage;
                    let band_cls = score_band_class(score_band(score.round() as i32));
                    let total = summary.summary_total_controls;
                    let pass = summary.summary_passing;
                    let fail = summary.summary_failing;
                    let manual = summary.summary_manual_review;
                    let na = summary.summary_not_applicable;
                    let controls = report.report_controls.clone();
                    view! {
                        <section class=format!("compliance-report {band_cls}")>
                            <div class="compliance-report-head">
                                <h3 class="compliance-report-name">{name}</h3>
                                <span class="compliance-report-assessed">
                                    {format!("{total} controls assessed")}
                                </span>
                            </div>
                            <div class="score-bar">
                                <div
                                    class="score-bar-fill"
                                    style=format!("width: {}%", score.clamp(0.0, 100.0))
                                ></div>
                            </div>
                            <div class="compliance-counts">
                                <span class="compliance-count">
                                    <span class="count-num status-pass">{pass}</span>" Pass"
                                </span>
                                <span class="compliance-count">
                                    <span class="count-num status-fail">{fail}</span>" Fail"
                                </span>
                                <span class="compliance-count">
                                    <span class="count-num status-manual">{manual}</span>" Manual review"
                                </span>
                                <span class="compliance-count">
                                    <span class="count-num status-na">{na}</span>" N/A"
                                </span>
                            </div>
                            <ul class="compliance-controls-list">
                                {controls.into_iter().map(|c| {
                                    let sc = control_status_class(&c.control_status);
                                    view! {
                                        <li class="control-row">
                                            <span class="control-id">{c.control_id}</span>
                                            <span class="control-title">{c.control_title}</span>
                                            <span class=format!("control-status {sc}")>
                                                {c.control_status.to_string()}
                                            </span>
                                        </li>
                                    }
                                }).collect::<Vec<_>>()}
                            </ul>
                        </section>
                    }
                }).collect::<Vec<_>>()}
            </Show>

            <div class="compliance-actions">
                {move || status_message.get().map(|(msg, ok)| {
                    let cls = if ok { "status-success" } else { "status-error" };
                    view! { <span class=format!("status-message {cls}")>{msg}</span> }
                })}
                <select
                    class="format-select"
                    on:change=move |ev| export_format.set(event_target_value(&ev))
                >
                    <option value="text" selected=true>"Text"</option>
                    <option value="json">"JSON"</option>
                    <option value="csv">"CSV"</option>
                    <option value="html">"HTML"</option>
                    <option value="pdf">"PDF"</option>
                </select>
                <button
                    class="btn btn-secondary"
                    on:click=on_export
                    disabled=move || selected.get().is_empty() || is_exporting.get()
                >
                    {move || if is_exporting.get() { "Exporting..." } else { "Export" }}
                </button>
                <button
                    class="btn btn-primary"
                    on:click=on_generate
                    disabled=move || selected.get().is_empty() || app_state.is_generating_report.get()
                >
                    {move || if app_state.is_generating_report.get() { "Generating..." } else { "Generate Report" }}
                </button>
            </div>
        </div>
    }
}
