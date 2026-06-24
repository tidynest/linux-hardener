//! Fleet scan results table — one row per host, expandable to its findings.

use crate::components::FindingsGrid;
use crate::types::{
    ComplianceFramework, Finding, FleetFrameworkPosture, FleetHostScan, FleetHostStatus,
};
use leptos::prelude::*;
use std::sync::Arc;

/// Toggles which host row is expanded (accordion: one open at a time).
fn toggle_expanded(expanded: RwSignal<Option<String>>, host: &str) {
    expanded.update(|cur| {
        *cur = if cur.as_deref() == Some(host) {
            None
        } else {
            Some(host.to_string())
        };
    });
}

/// CIS score cell for a host row: `(formatted percent, colour class)`, or `None`
/// to render an em dash when the host has no CIS posture (e.g. it failed).
/// ponytail: thresholds mirror `mini_security_score` (71/41) on the same 0-100
/// scale — kept inline for the one call site rather than shared.
fn cis_cell(compliance: &[FleetFrameworkPosture]) -> Option<(String, &'static str)> {
    let cis = compliance
        .iter()
        .find(|s| s.framework == ComplianceFramework::CIS)?;
    let percentage = cis.summary.summary_score_percentage;
    let class = if percentage >= 71.0 {
        "score-good"
    } else if percentage >= 41.0 {
        "score-warning"
    } else {
        "score-critical"
    };
    Some((format!("{percentage:.0}%"), class))
}

/// Renders fleet scan results: a row per host with severity tallies, expandable
/// to that host's findings (reusing `FindingsGrid`). Failed hosts show the error.
#[component]
pub fn FleetTable(#[prop(into)] scans: Signal<Vec<FleetHostScan>>) -> impl IntoView {
    let expanded = RwSignal::new(None::<String>);

    view! {
        <section class="fleet-table">
            {move || {
                let scans = scans.get();
                if scans.is_empty() {
                    return view! {
                        <p class="empty-state">"No fleet scan yet. Select hosts and scan."</p>
                    }
                    .into_any();
                }
                view! {
                    <table class="findings-table" role="grid">
                        <thead>
                            <tr role="row">
                                <th role="columnheader">"Host"</th>
                                <th role="columnheader">"Status"</th>
                                <th role="columnheader">"CIS %"</th>
                                <th role="columnheader">"Critical"</th>
                                <th role="columnheader">"High"</th>
                                <th role="columnheader">"Medium"</th>
                                <th role="columnheader">"Low"</th>
                                <th role="columnheader">"Info"</th>
                            </tr>
                        </thead>
                        <tbody>
                            {scans
                                .into_iter()
                                .map(|scan| {
                                    let host = scan.host_name.clone();
                                    let findings: Arc<Vec<Finding>> = Arc::new(
                                        scan.scan_results
                                            .iter()
                                            .flat_map(|r| r.scan_findings.iter().cloned())
                                            .collect(),
                                    );
                                    let compliance = scan.compliance.clone();
                                    let cis = cis_cell(&compliance);
                                    let (status_text, status_class, failed) = match &scan.status {
                                        FleetHostStatus::Ok => ("OK".to_string(), "fleet-ok", false),
                                        FleetHostStatus::Failed(e) => {
                                            (format!("Failed: {e}"), "fleet-failed", true)
                                        }
                                    };
                                    let t = scan.tallies;
                                    let host_expanded = host.clone();
                                    let is_expanded =
                                        move || expanded.get().as_deref() == Some(host_expanded.as_str());
                                    let host_click = host.clone();
                                    let host_key = host.clone();
                                    // Keyboard handler: Enter/Space to toggle expansion.
                                    let on_keydown = move |ev: web_sys::KeyboardEvent| {
                                        if failed {
                                            return;
                                        }
                                        match ev.key().as_str() {
                                            "Enter" | " " => {
                                                ev.prevent_default();
                                                toggle_expanded(expanded, &host_key);
                                            }
                                            _ => {}
                                        }
                                    };
                                    view! {
                                        <tr
                                            role="row"
                                            class="fleet-row"
                                            class:fleet-row-expandable=move || !failed
                                            tabindex=if failed { "-1" } else { "0" }
                                            on:click=move |_| {
                                                if !failed {
                                                    toggle_expanded(expanded, &host_click);
                                                }
                                            }
                                            on:keydown=on_keydown
                                        >
                                            <td>{host.clone()}</td>
                                            <td class={status_class}>{status_text}</td>
                                            {match cis {
                                                Some((text, class)) => {
                                                    view! { <td class={class}>{text}</td> }.into_any()
                                                }
                                                None => view! { <td>{"—"}</td> }.into_any(),
                                            }}
                                            <td>{t.critical}</td>
                                            <td>{t.high}</td>
                                            <td>{t.medium}</td>
                                            <td>{t.low}</td>
                                            <td>{t.info}</td>
                                        </tr>
                                        <Show when=move || is_expanded() && !failed>
                                            {
                                                let findings = Arc::clone(&findings);
                                                let compliance = compliance.clone();
                                                view! {
                                                    <tr class="fleet-detail-row">
                                                        <td colspan="8">
                                                            <table class="findings-table fleet-compliance-summary">
                                                                <thead>
                                                                    <tr>
                                                                        <th>"Framework"</th>
                                                                        <th>"Score"</th>
                                                                        <th>"Pass"</th>
                                                                        <th>"Fail"</th>
                                                                        <th>"Manual"</th>
                                                                        <th>"N/A"</th>
                                                                    </tr>
                                                                </thead>
                                                                <tbody>
                                                                    {compliance
                                                                        .iter()
                                                                        .map(|s| {
                                                                            let sm = &s.summary;
                                                                            view! {
                                                                                <tr>
                                                                                    <td>{s.framework.to_string()}</td>
                                                                                    <td>
                                                                                        {format!(
                                                                                            "{:.0}%",
                                                                                            sm.summary_score_percentage,
                                                                                        )}
                                                                                    </td>
                                                                                    <td>{sm.summary_passing}</td>
                                                                                    <td>{sm.summary_failing}</td>
                                                                                    <td>{sm.summary_manual_review}</td>
                                                                                    <td>{sm.summary_not_applicable}</td>
                                                                                </tr>
                                                                            }
                                                                        })
                                                                        .collect::<Vec<_>>()}
                                                                </tbody>
                                                            </table>
                                                            <FindingsGrid findings=Signal::derive(move || {
                                                                (*findings).clone()
                                                            }) />
                                                        </td>
                                                    </tr>
                                                }
                                            }
                                        </Show>
                                    }
                                })
                                .collect::<Vec<_>>()}
                        </tbody>
                    </table>
                }
                .into_any()
            }}
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ComplianceSummary;

    fn posture(framework: ComplianceFramework, percentage: f64) -> FleetFrameworkPosture {
        FleetFrameworkPosture {
            framework,
            summary: ComplianceSummary {
                summary_total_controls: 0,
                summary_passing: 0,
                summary_failing: 0,
                summary_manual_review: 0,
                summary_not_applicable: 0,
                summary_score_percentage: percentage,
            },
        }
    }

    #[test]
    fn cis_cell_picks_cis_and_classes_by_threshold() {
        assert_eq!(cis_cell(&[]), None);
        assert_eq!(cis_cell(&[posture(ComplianceFramework::STIG, 90.0)]), None);
        assert_eq!(
            cis_cell(&[posture(ComplianceFramework::CIS, 80.0)]),
            Some(("80%".to_string(), "score-good"))
        );
        assert_eq!(
            cis_cell(&[posture(ComplianceFramework::CIS, 50.0)]),
            Some(("50%".to_string(), "score-warning"))
        );
        assert_eq!(
            cis_cell(&[posture(ComplianceFramework::CIS, 10.0)]),
            Some(("10%".to_string(), "score-critical"))
        );
        // Exact threshold seams: the class uses the raw value, not the rounded
        // display, so 70.9 stays warning even though it renders as "71%".
        assert_eq!(
            cis_cell(&[posture(ComplianceFramework::CIS, 71.0)]),
            Some(("71%".to_string(), "score-good"))
        );
        assert_eq!(
            cis_cell(&[posture(ComplianceFramework::CIS, 70.9)]),
            Some(("71%".to_string(), "score-warning"))
        );
        assert_eq!(
            cis_cell(&[posture(ComplianceFramework::CIS, 41.0)]),
            Some(("41%".to_string(), "score-warning"))
        );
        assert_eq!(
            cis_cell(&[posture(ComplianceFramework::CIS, 40.9)]),
            Some(("41%".to_string(), "score-critical"))
        );
    }
}
