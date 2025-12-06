//! Tab components for the consolidated page architecture
//!
//! Provides a reusable tab bar with animated transitions and optional badges.

use leptos::prelude::*;

/// A single tab definitions.
pub struct TabDef {
    /// Display label for the tab.
    pub label: &'static str,
    /// Optional badge count (e.g., number of findings).
    pub badge: Option<usize>,
}

/// Tab bar component that renders tab buttons.
///
/// # Arguments
/// * `tabs` - List of tab definitions
/// * `active_tab` - Signal tracking the currently active tab index
#[component]
pub fn TabBar(
    tabs: Vec<TabDef>,
    active_tab: RwSignal<usize>,
) -> impl IntoView {
    view! {
        <nav class="tab-bar" role="tablist">
            {tabs.into_iter().enumerate().map(|(idx, tab)| {
                let badge = tab.badge;
                let label = tab.label;

                view! {
                    <button
                        class=move || {
                            if active_tab.get() == idx {
                                "tab-button tab-active"
                            } else {
                                "tab-button"
                            }
                        }
                        role="tab"
                        aria-selected=move || active_tab.get() == idx
                        on:click=move |_| active_tab.set(idx)
                    >
                        {label}
                        {badge.map(|count| {
                            view! {
                                <span class="tab-badge">{count}</span>
                            }
                        })}
                    </button>
                }
            }).collect::<Vec<_>>()}
        </nav>
    }
}

/// Tab panel wrapper that shows/hides based on active tab.
///
/// # Arguments
/// * `index` - The index of this panel (0-based)
/// * `active_tab` - Signal tracking the currently active tab
/// * `children` - The panel content
#[component]
pub fn TabPanel(
    index: usize,
    active_tab: RwSignal<usize>,
    children: Children,
) -> impl IntoView {
    let is_visible = move || active_tab.get() == index;

    view! {
        <div
            class=move || {
                if is_visible() {
                  "tab-panel"
                } else {
                    "tab-panel panel-hidden"
                }
            }
            role="tabpanel"
            hidden=move || !is_visible()
        >
            {children()}
        </div>
    }
}
