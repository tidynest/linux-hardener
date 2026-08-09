//! One inventory row: the resting two-line summary (name, target, connection
//! dot, severity tallies, framework score strip) that expands in place into a
//! `HostPanel`. Ad-hoc targets pass `profile = None`.

use crate::components::{HostConnState, HostPanel};
use crate::types::{FleetHostScan, FleetHostStatus};
use crate::utils::framework_score_cells;
use hardener_types::remote::RemoteHostProfile;
use leptos::prelude::*;

/// Props are a single row's worth of state, supplied by `HostsPage`.
#[component]
pub fn HostRow(
    /// Selection/scan-map key: profile name or ad-hoc canonical target.
    key: String,
    /// Display name.
    label: String,
    /// `user@host:port`.
    detail: String,
    /// Saved profile, or `None` for an ad-hoc target.
    profile: Option<RemoteHostProfile>,
    /// This host's latest scan, if any.
    scan: Signal<Option<FleetHostScan>>,
    /// Whether this row's checkbox is ticked.
    selected: Signal<bool>,
    /// Whether this row is expanded (accordion, one at a time).
    expanded: Signal<bool>,
    /// Live per-host status glyph during a bulk scan: None (idle/pending done),
    /// Some(false) ok, Some(true) failed.
    progress: Signal<Option<bool>>,
    /// Whether a bulk scan is currently running. Gates the `progress` glyph
    /// so it only wins while the scan is live; once it ends the row falls
    /// back to `scan`'s tally line even though `progress` may still hold a
    /// stale `Some(_)` from the scan that just finished.
    scanning: Signal<bool>,
    conn: Signal<HostConnState>,
    #[prop(into)] on_toggle_select: Callback<()>,
    #[prop(into)] on_toggle_expand: Callback<()>,
    #[prop(into)] on_connect: Callback<()>,
    #[prop(into)] on_disconnect: Callback<()>,
    #[prop(into)] on_scan: Callback<()>,
    #[prop(into)] on_edit: Callback<()>,
    #[prop(into)] on_delete: Callback<()>,
    #[prop(into)] on_remove_adhoc: Callback<()>,
) -> impl IntoView {
    let history_key = key.clone();
    let profile_for_panel = profile.clone();

    view! {
        <div class="host-row" class:host-row-open=move || expanded.get()>
            <div class="host-row-main">
                <input
                    type="checkbox"
                    aria-label=format!("Select {label}")
                    prop:checked=move || selected.get()
                    on:change=move |_| on_toggle_select.run(())
                />
                <button
                    class="host-row-expand"
                    // Named for the host, matching the checkbox above it. A
                    // constant "Expand host" announced the same thing on every
                    // row, so a screen reader user could not tell which host
                    // they were opening and a test could reach a row only by
                    // index (#135). The state is on aria-expanded rather than
                    // in the verb, so the name stays stable while it toggles.
                    aria-label=format!("Expand {label}")
                    aria-expanded=move || expanded.get().to_string()
                    on:click=move |_| on_toggle_expand.run(())
                >
                    <span class="host-row-chev" class:host-row-chev-open=move || expanded.get()></span>
                </button>
                <span class="conn-dot" class:conn-dot-connected=move || {
                    matches!(conn.get(), HostConnState::Connected(_))
                }></span>
                <div class="host-row-id">
                    <div class="host-row-name">{label.clone()}</div>
                    <div class="host-row-detail">{detail}</div>
                </div>
                <div class="host-row-posture">
                    {move || {
                        // Live progress glyph wins only while a bulk scan is
                        // actually running; once it ends, fall through to the
                        // tally line below even if `progress` still holds a
                        // stale value from the scan that just finished.
                        if scanning.get() && let Some(failed) = progress.get() {
                            let (glyph, cls) = if failed { ("\u{2717}", "host-prog-failed") } else { ("\u{2713}", "host-prog-ok") };
                            return view! { <span class=cls>{glyph}</span> }.into_any();
                        }
                        match scan.get() {
                            None => view! { <span class="host-row-unscanned">"Not scanned yet"</span> }.into_any(),
                            Some(s) => match s.status {
                                FleetHostStatus::Failed(_) => view! {
                                    <span class="host-row-failed">"Failed"</span>
                                }.into_any(),
                                FleetHostStatus::Ok => {
                                    let t = s.tallies;
                                    view! {
                                        <span class="host-row-tallies">
                                            <span class="tally-crit">{format!("{} crit", t.critical)}</span>
                                            <span class="tally-high">{format!("{} high", t.high)}</span>
                                            <span class="tally-med">{format!("{} med", t.medium)}</span>
                                            <span class="tally-low">{format!("{} low", t.low)}</span>
                                        </span>
                                    }.into_any()
                                }
                            },
                        }
                    }}
                </div>
            </div>

            // Second line: framework score strip (only when the scan carries
            // compliance posture, i.e. a bulk scan).
            {move || {
                let cells = scan.get().map(|s| framework_score_cells(&s.compliance)).unwrap_or_default();
                (!cells.is_empty()).then(|| view! {
                    <div class="host-row-strip">
                        {cells.into_iter().map(|(fw, score, band)| view! {
                            <span class="host-strip-item">
                                {fw}" "<b class=band>{score}</b>
                            </span>
                        }).collect_view()}
                    </div>
                })
            }}

            // Failed line: the full error on its own full-width line, kept out
            // of the flex row so a long SSH message wraps and never overlaps
            // the name and detail.
            {move || {
                scan.get().and_then(|s| match s.status {
                    FleetHostStatus::Failed(e) => {
                        Some(view! { <div class="host-row-error">{e}</div> })
                    }
                    FleetHostStatus::Ok => None,
                })
            }}

            <Show when=move || expanded.get()>
                <HostPanel
                    profile=profile_for_panel.clone()
                    scan=scan
                    conn=conn
                    history_key=history_key.clone()
                    on_connect=on_connect
                    on_disconnect=on_disconnect
                    on_scan=on_scan
                    on_edit=on_edit
                    on_delete=on_delete
                    on_remove_adhoc=on_remove_adhoc
                />
            </Show>
        </div>
    }
}
