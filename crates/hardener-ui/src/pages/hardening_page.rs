//! Hardening page combining Configuration, Results, and Checkpoints.
//!
//! Provides a sectioned interface for configuring and applying hardening.

use crate::components::{ConfigureSection, HistorySection};
use crate::state::AppState;
use leptos::prelude::*;

/// Hardening page with Configure and History sections.
#[component]
pub fn HardeningPage() -> impl IntoView {
    // Access global app state
    let state = expect_context::<AppState>();

    // Section state: 0 = Configure, 1 = History
    let active_section = RwSignal::new(0_usize);

    // Show indicator only when there are apply results to review
    let has_history = move || !state.apply_results.get().is_empty();

    view! {
        <article class="hardening-page">
            <header class="hardening-header">
                <h1>"System Hardening"</h1>
                <p class="page-description">
                    "Configure and apply security hardening to your system. "
                    "Choose a security profile, customise plugin selection, then apply changes."
                </p>
            </header>

            <nav class="section-toggle" role="tablist">
                <button
                    class=move || {
                        if active_section.get() == 0 {
                            "section-btn section-active"
                        } else {
                            "section-btn"
                        }
                    }
                    on:click=move |_| active_section.set(0)
                >
                    "Configure"
                </button>
                <button
                    class=move || {
                        if active_section.get() == 1 {
                            "section-btn section-active"
                        } else {
                            "section-btn"
                        }
                    }
                    on:click=move |_| active_section.set(1)
                >
                    "History"
                    <Show when=has_history>
                        <span class="history-indicator"></span>
                    </Show>
                </button>
            </nav>

            <div class="section-content">
                <Show when=move || active_section.get() == 0>
                    <ConfigureSection />
                </Show>
                <Show when=move || active_section.get() == 1>
                    <HistorySection />
                </Show>
            </div>
        </article>
    }
}
