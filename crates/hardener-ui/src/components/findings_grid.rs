//! Findings table with keyboard navigation.
//!
//! Its only consumer is FleetTable, which is orphaned once `/fleet` routes to
//! the merged HostsPage (Task 4), so this component is transitionally dead.
//! Removed with fleet_page.rs/fleet_table.rs in Task 5.
#![allow(dead_code)]

use crate::components::SeverityBadge;
use crate::state::AppState;
use crate::types::Finding;
use leptos::prelude::*;
use wasm_bindgen::JsCast;

/// Displays a table of security findings with keyboard navigation.
///
/// Receives a pre-filtered list of findings from the parent component.
/// Supports: click to select, ArrowUp/Down to navigate, Enter/Space to open detail.
#[component]
pub fn FindingsGrid(
    /// Findings to display, already filtered by the parent.
    findings: Signal<Vec<Finding>>,
) -> impl IntoView {
    let app_state = expect_context::<AppState>();

    let select_finding = move |finding: Finding| {
        app_state.selected_finding.set(Some(finding));
    };

    view! {
        <section class="findings-grid">
            {move || {
                let findings = findings.get();
                if findings.is_empty() {
                    view! {
                        <p class="empty-state">
                            "No security findings to display. Run a scan to see results."
                        </p>
                    }.into_any()
                } else {
                    view! {
                        <table class="findings-table" role="grid">
                            <thead>
                                <tr role="row">
                                    <th role="columnheader">"Severity"</th>
                                    <th role="columnheader">"Category"</th>
                                    <th role="columnheader">"Title"</th>
                                    <th role="columnheader">"Current Value"</th>
                                    <th role="columnheader">"Recommended Value"</th>
                                </tr>
                            </thead>
                            <tbody>
                                {findings.into_iter().enumerate().map(|(idx, finding)| {
                                    let finding_for_click = finding.clone();
                                    let finding_for_key = finding.clone();
                                    let title_for_class = finding.finding_title.clone();
                                    let title_for_aria = finding.finding_title.clone();
                                    let is_selected = move || {
                                        app_state.selected_finding.get()
                                            .as_ref()
                                            .is_some_and(|f| f.finding_title == title_for_class)
                                    };
                                    let is_selected_aria = move || {
                                        app_state.selected_finding.get()
                                            .as_ref()
                                            .is_some_and(|f| f.finding_title == title_for_aria)
                                    };

                                    // Keyboard handler: ArrowUp/Down to navigate, Enter/Space to select
                                    let on_keydown = move |ev: web_sys::KeyboardEvent| {
                                        match ev.key().as_str() {
                                            "Enter" | " " => {
                                                ev.prevent_default();
                                                select_finding(finding_for_key.clone());
                                            }
                                            "ArrowDown" => {
                                                ev.prevent_default();
                                                focus_sibling_row(&ev, false);
                                            }
                                            "ArrowUp" => {
                                                ev.prevent_default();
                                                focus_sibling_row(&ev, true);
                                            }
                                            _ => {}
                                        }
                                    };

                                    view! {
                                        <tr
                                            class="finding-row"
                                            class:finding-row-selected=is_selected
                                            role="row"
                                            tabindex=move || if idx == 0 { "0" } else { "-1" }
                                            aria-selected=move || is_selected_aria().to_string()
                                            on:click=move |_| select_finding(finding_for_click.clone())
                                            on:keydown=on_keydown
                                        >
                                            <td role="gridcell"><SeverityBadge severity=finding.finding_severity/></td>
                                            <td role="gridcell">{format!("{:?}", finding.finding_category)}</td>
                                            <td role="gridcell">{finding.finding_title.clone()}</td>
                                            <td role="gridcell" class="value-cell">{finding.finding_current_value.clone()}</td>
                                            <td role="gridcell" class="value-cell">{finding.finding_recommended_value.clone()}</td>
                                        </tr>
                                    }
                                }).collect::<Vec<_>>()}
                            </tbody>
                        </table>
                    }.into_any()
                }
            }}
        </section>
    }
}

/// Move focus to the previous (up=true) or next (up=false) sibling `<tr>`.
fn focus_sibling_row(ev: &web_sys::KeyboardEvent, up: bool) {
    let Some(target) = ev.target() else { return };
    let Some(row) = target.dyn_ref::<web_sys::HtmlElement>() else {
        return;
    };

    let sibling = if up {
        row.previous_element_sibling()
    } else {
        row.next_element_sibling()
    };

    if let Some(el) = sibling
        && let Ok(html) = el.dyn_into::<web_sys::HtmlElement>()
    {
        let _ = html.focus();
    }
}
