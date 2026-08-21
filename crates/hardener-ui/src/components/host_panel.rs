//! Expanded per-host panel: connection strip, collapsible Compliance detail,
//! collapsible Findings (severity subgroups, then a policy-exception subgroup),
//! and the per-host scan-history timeline. Rendered only when a `HostRow` is
//! expanded.

use crate::components::ConfirmDeleteButton;
use crate::tauri_bindings::invoke_get_host_history;
use crate::types::{Finding, FleetHostScan};
use crate::utils::{
    checkpoint_time, control_status_class, framework_short_label, group_findings_by_severity,
    profile_badge_label, score_band, score_band_class, severity_class, severity_label,
    split_policy_excepted,
};
use hardener_types::remote::{HostSessionInfo, RemoteHostProfile};
use leptos::prelude::*;

/// One collapsible findings subgroup in a host panel: a severity, or the
/// policy-exception group that sits below them. Shared so the exception
/// subgroup cannot drift from the severity ones it sits with.
fn host_finding_subgroup(
    class: &'static str,
    name: &'static str,
    findings: Vec<Finding>,
    open: bool,
) -> impl IntoView {
    let count = findings.len();
    let rows = findings
        .into_iter()
        .map(|f| {
            view! {
                <div class="host-finding-row">
                    <span class=format!("host-finding-dot {class}")></span>
                    <span class="host-finding-title">{f.finding_title}</span>
                    <span class="host-finding-plugin">{f.finding_category.to_string()}</span>
                </div>
            }
        })
        .collect_view();
    view! {
        <details class="host-collapse host-collapse-sub" open=open>
            <summary>
                <span class="host-collapse-chev" aria-hidden="true"></span>
                <span class=format!("host-severity-label {class}")>
                    {format!("{name} ({count})")}
                </span>
            </summary>
            {rows}
        </details>
    }
}

/// Connection state for one host (the backend holds a single session, so at
/// most one host is ever `Connected`).
#[derive(Clone, PartialEq)]
pub enum HostConnState {
    Disconnected,
    Connecting,
    Connected(String),
}

/// The expanded panel for one host. Ad-hoc targets pass `profile = None`, which
/// hides the connect/session strip (they are not saved) and shows a remove
/// affordance instead.
#[component]
pub fn HostPanel(
    /// Saved profile, or `None` for an ad-hoc target.
    profile: Option<RemoteHostProfile>,
    /// This host's latest normalised scan (bulk or session), if any.
    scan: Signal<Option<FleetHostScan>>,
    /// This host's connection state (always `Disconnected` for ad-hoc).
    conn: Signal<HostConnState>,
    /// Scheduler-db history key: profile name or ad-hoc canonical target.
    history_key: String,
    #[prop(into)] on_connect: Callback<()>,
    #[prop(into)] on_disconnect: Callback<()>,
    #[prop(into)] on_scan: Callback<()>,
    #[prop(into)] on_edit: Callback<()>,
    #[prop(into)] on_delete: Callback<()>,
    #[prop(into)] on_remove_adhoc: Callback<()>,
) -> impl IntoView {
    // Load persisted history once on mount (the panel exists only while open).
    let history = RwSignal::new(None::<Vec<HostSessionInfo>>);
    {
        let key = history_key.clone();
        leptos::task::spawn_local(async move {
            let rows = invoke_get_host_history(key, Some(10))
                .await
                .unwrap_or_default();
            history.set(Some(rows));
        });
    }

    let is_adhoc = profile.is_none();
    let delete_key = profile.as_ref().map(|p| p.name.clone()).unwrap_or_default();
    let pending_delete = RwSignal::new(None::<String>);

    view! {
        <div class="host-panel">
            // --- Connection + actions strip ---
            <div class="host-panel-strip">
                {move || {
                    if is_adhoc {
                        view! {
                            <span class="host-conn">
                                <span class="conn-dot"></span>
                                <span class="host-conn-label">"Ad-hoc target (not saved)"</span>
                            </span>
                            <div class="host-panel-actions">
                                <button class="btn btn-secondary" on:click=move |_| on_remove_adhoc.run(())>
                                    "Remove"
                                </button>
                            </div>
                        }
                        .into_any()
                    } else {
                        let state = conn.get();
                        let (dot_cls, label, connected) = match &state {
                            HostConnState::Disconnected => ("conn-dot", "Disconnected".to_string(), false),
                            HostConnState::Connecting => {
                                ("conn-dot conn-dot-connecting", "Connecting\u{2026}".to_string(), false)
                            }
                            HostConnState::Connected(user) => (
                                "conn-dot conn-dot-connected",
                                format!("Connected as {user}"),
                                true,
                            ),
                        };
                        let connecting = state == HostConnState::Connecting;
                        view! {
                            <span class="host-conn">
                                <span class=dot_cls></span>
                                <span class="host-conn-label">{label}</span>
                            </span>
                            <div class="host-panel-actions">
                                <Show
                                    when=move || connected
                                    fallback=move || view! {
                                        <button
                                            class="btn btn-primary"
                                            on:click=move |_| on_connect.run(())
                                            disabled=connecting
                                        >
                                            "Connect"
                                        </button>
                                    }
                                >
                                    <button class="btn btn-primary" on:click=move |_| on_scan.run(())>
                                        "Run Scan"
                                    </button>
                                    <button class="btn btn-secondary" on:click=move |_| on_disconnect.run(())>
                                        "Disconnect"
                                    </button>
                                </Show>
                                <button class="btn btn-secondary" on:click=move |_| on_edit.run(())>
                                    "Edit"
                                </button>
                                <ConfirmDeleteButton
                                    item_key=delete_key.clone()
                                    pending=pending_delete
                                    on_confirm=Callback::new(move |_: String| on_delete.run(()))
                                />
                            </div>
                        }
                        .into_any()
                    }
                }}
            </div>

            // --- Compliance detail (above Findings) ---
            {move || {
                let scanned = scan.get();
                // The scheme this host's posture was scored under. Read once,
                // beside the compliance it labels, because a badge that
                // disagreed with the rows below it would be worse than none.
                let host_profile = scanned.as_ref().map(|s| s.profile).unwrap_or_default();
                let compliance = scanned.map(|s| s.compliance).unwrap_or_default();
                // Frameworks with no control rows are dropped rather than
                // rendered as an empty expander: a host scanned before this
                // shipped, or one that failed, carries a summary and nothing
                // to drill into, and an expander that opens on nothing reads
                // as a host with no controls rather than as a missing answer.
                let controls_by_framework: Vec<_> = compliance
                    .iter()
                    .filter(|p| !p.controls.is_empty())
                    .map(|p| (p.framework, p.controls.clone()))
                    .collect();
                (!compliance.is_empty()).then(|| view! {
                    <details class="host-collapse" open=true>
                        <summary>
                            <span class="host-collapse-chev" aria-hidden="true"></span>
                            <span class="host-section-label">"Compliance detail"</span>
                        </summary>
                        <div class="host-compliance-scroll">
                            <table class="host-compliance-table">
                                <thead>
                                    <tr>
                                        <th class="host-col-left">"Framework"</th>
                                        <th>"Score"</th><th>"Pass"</th><th>"Fail"</th>
                                        <th>"Manual"</th><th>"N/A"</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {compliance.into_iter().map(|p| {
                                        let sm = p.summary;
                                        let score = sm.summary_score_percentage.round() as i32;
                                        let band = score_band_class(score_band(score));
                                        // Which identifier scheme scored this
                                        // row, where a scheme other than the
                                        // default was used. Without it the
                                        // control ids below read as canonical
                                        // ones that had gone strange.
                                        let scheme = profile_badge_label(host_profile, p.framework);
                                        view! {
                                            <tr>
                                                <td class="host-col-left">
                                                    {framework_short_label(p.framework)}
                                                    {scheme.map(|s| view! {
                                                        <span class="host-profile-badge">{s}</span>
                                                    })}
                                                </td>
                                                <td class=band>{score}</td>
                                                <td>{sm.summary_passing}</td>
                                                <td>{sm.summary_failing}</td>
                                                <td>{sm.summary_manual_review}</td>
                                                <td>{sm.summary_not_applicable}</td>
                                            </tr>
                                        }
                                    }).collect_view()}
                                </tbody>
                            </table>
                        </div>

                        // One collapsed list per framework, which is the
                        // drill-down the score column had no answer for (#50).
                        // Collapsed by default: nine frameworks of control rows
                        // would otherwise bury the Findings section below.
                        //
                        // The rows reuse the compliance tab's own `control-row`
                        // markup and `.status-*` classes rather than new ones,
                        // so one verdict cannot read two ways across two
                        // screens.
                        {controls_by_framework.into_iter().map(|(framework, controls)| {
                            let count = controls.len();
                            view! {
                                <details class="host-collapse">
                                    <summary>
                                        <span class="host-collapse-chev" aria-hidden="true"></span>
                                        <span class="host-section-label">
                                            {framework_short_label(framework)}
                                            " controls ("{count}")"
                                        </span>
                                    </summary>
                                    <ul class="compliance-controls-list">
                                        {controls.into_iter().map(|c| {
                                            let status_class = control_status_class(&c.control_status);
                                            view! {
                                                <li class="control-row">
                                                    <span class="control-id">{c.control_id}</span>
                                                    <span class="control-title">{c.control_title}</span>
                                                    <span class=format!("control-status {status_class}")>
                                                        {c.control_status.to_string()}
                                                    </span>
                                                </li>
                                            }
                                        }).collect_view()}
                                    </ul>
                                </details>
                            }
                        }).collect_view()}
                    </details>
                })
            }}

            // --- Findings (collapsible, severity subgroups collapsible) ---
            {move || {
                // Paired with the plugin that produced each finding, as the
                // shared split/group helpers now require; this panel does not
                // itself need the id; it renders no accept/remove control.
                let findings = scan.get().map(|s| {
                    s.scan_results.iter().flat_map(|r| {
                        let plugin_id = r.scan_plugin_id.as_str().to_string();
                        r.scan_findings.iter().cloned().map(move |f| (plugin_id.clone(), f))
                    }).collect::<Vec<_>>()
                }).unwrap_or_default();
                // Documented deviations are separated, never dropped: the
                // severity subgroups then count real problems only, and a host
                // whose findings are all excepted still renders a section
                // rather than reading as a host with nothing wrong.
                let (live, excepted) = split_policy_excepted(&findings);
                let groups = group_findings_by_severity(&live);
                let excepted: Vec<Finding> = excepted.into_iter().map(|(_, f)| f).collect();
                (!groups.is_empty() || !excepted.is_empty()).then(|| {
                    let mut rendered: Vec<_> = groups
                        .into_iter()
                        .enumerate()
                        // Lead severity (first group) open; the rest collapsed.
                        .map(|(i, (sev, group))| {
                            let group: Vec<Finding> = group.into_iter().map(|(_, f)| f).collect();
                            host_finding_subgroup(
                                severity_class(sev),
                                severity_label(sev),
                                group,
                                i == 0,
                            )
                        })
                        .collect();
                    if !excepted.is_empty() {
                        // Open only when there is no severity group above it to
                        // lead with, so deviations never outrank real findings.
                        let open = rendered.is_empty();
                        rendered.push(host_finding_subgroup(
                            "severity_exception",
                            "Policy Exceptions",
                            excepted,
                            open,
                        ));
                    }
                    view! {
                        <details class="host-collapse" open=true>
                            <summary>
                                <span class="host-collapse-chev" aria-hidden="true"></span>
                                <span class="host-section-label">"Findings"</span>
                            </summary>
                            {rendered}
                        </details>
                    }
                })
            }}

            // --- Scan history timeline ---
            <details class="host-collapse" open=true>
                <summary>
                    <span class="host-collapse-chev" aria-hidden="true"></span>
                    <span class="host-section-label">"Scan history"</span>
                </summary>
                {move || match history.get() {
                    None => view! { <p class="empty-state">"Loading history\u{2026}"</p> }.into_any(),
                    Some(rows) if rows.is_empty() => view! {
                        <p class="empty-state">
                            "No persisted history for this host (CLI batch and scheduled scans populate it)."
                        </p>
                    }.into_any(),
                    // Reuses the checkpoint-timeline rail (`.timeline-nodes`/`.timeline-node`):
                    // that structure carries the `position: relative` rail line and the dot's
                    // absolute placement, which a bare `.timeline` wrapper lacks. Direction is
                    // rendered with `.timeline-status`, the existing right-aligned meta label,
                    // rather than an undefined `.timeline-trend` class.
                    Some(rows) => view! {
                        <ol class="timeline-nodes">
                            {rows.into_iter().map(|r| {
                                let failed = r.status.eq_ignore_ascii_case("failed");
                                let dir = r.direction.clone().unwrap_or_default();
                                let dot_cls = if failed { "timeline-dot timeline-dot-failed" } else { "timeline-dot" };
                                let time = checkpoint_time(&r.started).to_string();
                                view! {
                                    <li class="timeline-node">
                                        <span class=dot_cls></span>
                                        <div class="timeline-body">
                                            <div class="timeline-head">
                                                <span class="timeline-name">{time}</span>
                                                {(!dir.is_empty()).then(|| view! {
                                                    <span class="timeline-status">{dir}</span>
                                                })}
                                            </div>
                                            <div class="timeline-meta">
                                                {format!("{} findings", r.total_findings)}
                                            </div>
                                        </div>
                                    </li>
                                }
                            }).collect_view()}
                        </ol>
                    }.into_any(),
                }}
            </details>
        </div>
    }
}
