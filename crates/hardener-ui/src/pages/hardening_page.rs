//! Hardening page combining Configuration, Results, and Checkpoints.
//!
//! Provides a sectioned interface for configuring and applying hardening.

use crate::components::{ConfigureSection, HistorySection};
use leptos::prelude::*;

/// Hardening page with Configure and History sections.
#[component]
pub fn HardeningPage() -> impl IntoView {
    // Section state: 0 = Configure, 1 = History
    let active_section = RwSignal::new(0_usize);

    view! {
        <article class="hardening-page">
            <header class="hardening-header">
                <h1>"System Hardening"</h1>
                <p>"Configure security settings and apply hardening measures."</p>
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
                    <span class="history-indicator"></span>
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
