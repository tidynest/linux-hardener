//! Hardening page combining Configuration, Results, and Checkpoints.
//!
//! Provides a sectioned interface for configuring and applying hardening.

use crate::components::{ConfigureSection, HistorySection, TabBar, TabDef, TabPanel};
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

    let tabs = move || {
        vec![
            TabDef {
                id: "configure",
                label: "Configure",
                badge: None,
            },
            TabDef {
                id: "history",
                label: "History",
                badge: if has_history() { Some(state.apply_results.get().len()) } else { None },
            },
        ]
    };

    view! {
        <article class="hardening-page">
            <header class="hardening-header">
                <h1>"System Hardening"</h1>
                <p class="page-description">
                    "Configure and apply security hardening to your system. "
                    "Choose a security profile, customise plugin selection, then apply changes."
                </p>
            </header>

            <TabBar tabs=tabs() active_tab=active_section aria_label="Hardening sections" />

            <div class="section-content">
                <TabPanel id="configure" index=0 active_tab=active_section>
                    <ConfigureSection />
                </TabPanel>
                <TabPanel id="history" index=1 active_tab=active_section>
                    <HistorySection />
                </TabPanel>
            </div>
        </article>
    }
}
