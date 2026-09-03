//! Read-only posture strip pinned above `<main>` on every route, styled like
//! a window-manager statusline: score and band from the compliance reports,
//! live critical and high counts from the scan results, the history-backed
//! last-scan stamp, and a scanning indicator.
//!
//! Reads only. The one scan action stays in the score hero: the Playwright
//! helper resolves `/Run.*Scan|Scanning/i` to exactly one button, and this
//! strip is on every page. It carries no `status` role and no `aria-live`
//! either. The hero's `<output>` is the page's status region and the hero
//! button already announces the scan, so a second live region here would
//! announce every change twice. For the same reason the empty wording avoids
//! "Not scanned yet" and "Latest", which the fleet and hardening specs count
//! as exact matches on their own routes.

use crate::components::{calculate_all_scores, live_counts};
use crate::state::AppState;
use crate::utils::{score_band, score_band_class, score_band_label};
use leptos::prelude::*;

/// A zero count stays in the strip so the segment keeps its place, but it
/// is painted muted rather than in the severity colour.
fn value_class(n: usize) -> &'static str {
    if n == 0 {
        "posture-value posture-zero"
    } else {
        "posture-value"
    }
}

#[component]
pub fn PostureStrip() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    let has_score = move || !app_state.compliance_reports.get().is_empty();
    let score = move || calculate_all_scores(&app_state.compliance_reports.get()).0;
    let band = move || score_band(score());
    let has_results = move || !app_state.scan_results.get().is_empty();
    let counts = move || live_counts(&app_state.scan_results.get());
    let busy = move || app_state.is_scanning.get() || app_state.deep_scan_running.get();

    view! {
        <section class="posture-strip" aria-label="Security posture" class:posture-busy=busy>
            <span class="posture-seg posture-score">
                <span class="posture-key">"score"</span>
                <Show
                    when=has_score
                    fallback=|| view! { <span class="posture-value posture-empty">"none"</span> }
                >
                    <span class=move || format!("posture-band {}", score_band_class(band()))>
                        <span class="posture-value">{move || format!("{}/100", score())}</span>
                        <span class="posture-band-label">{move || score_band_label(band())}</span>
                    </span>
                </Show>
            </span>
            <Show when=has_results>
                <span class="posture-seg posture-count posture-count-critical">
                    <span class="posture-key">"critical"</span>
                    <span class=move || value_class(counts().critical)>
                        {move || counts().critical.to_string()}
                    </span>
                </span>
                <span class="posture-seg posture-count posture-count-high">
                    <span class="posture-key">"high"</span>
                    <span class=move || value_class(counts().high)>
                        {move || counts().high.to_string()}
                    </span>
                </span>
            </Show>
            <span class="posture-seg posture-stamp">
                <span class="posture-key">"last scan"</span>
                <span class="posture-value">
                    {move || app_state
                        .last_scan_completed_at
                        .get()
                        .unwrap_or_else(|| "none on record".to_string())}
                </span>
            </span>
            <Show when=busy>
                <span class="posture-seg posture-activity">"Scanning..."</span>
            </Show>
        </section>
    }
}
