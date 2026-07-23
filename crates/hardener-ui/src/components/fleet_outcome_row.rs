//! One host's fleet outcome, rendered from a pre-computed `OutcomeView`
//! (see `utils::fleet_apply_cells` / `fleet_rollback_cells`). Dumb by design:
//! all "which counts, which colour, which glyph" logic is the tested mapper's;
//! this only lays out the header, the stat cells, and an optional full-width
//! error line (reusing `.host-row-error` so a long SSH message wraps instead
//! of overlapping the host identity).
//!
//! Not yet called from any view - the Fleet Apply results slice wires it up
//! next. `#[allow(dead_code)]` per-item does not reliably suppress this,
//! because Leptos's `#[component]` macro expands the function into a
//! function plus a separate Props struct that does not inherit an outer
//! attribute; a module-level allow covers both (see `status_icons.rs`).
#![allow(dead_code)]

use crate::utils::OutcomeView;
use leptos::prelude::*;

#[component]
pub fn FleetOutcomeRow(name: String, target: String, view: OutcomeView) -> impl IntoView {
    let OutcomeView {
        glyph,
        cells,
        error,
    } = view;
    view! {
        <div class="fleet-outcome">
            <div class="fleet-outcome-main">
                <div class="fleet-outcome-id">
                    <span class="fleet-outcome-name">{name}</span>
                    <span class="fleet-outcome-target">{target}</span>
                </div>
                <div class="fleet-outcome-stats">
                    {cells
                        .into_iter()
                        .map(|(label, band)| {
                            view! { <span class=format!("fleet-stat {band}")>{label}</span> }
                        })
                        .collect_view()}
                    <span class=format!("fleet-glyph {}", glyph.class()) aria-hidden="true">
                        {glyph.symbol()}
                    </span>
                </div>
            </div>
            {error.map(|e| view! { <div class="host-row-error">{e}</div> })}
        </div>
    }
}
