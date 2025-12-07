//! Tab components for the consolidated page architecture
//!
//! Provides a reusable tab bar with animated transitions and optional badges.
//! Implements WAI-ARIA tabs pattern for accessibility.

use leptos::prelude::*;

/// A single tab definition.
pub struct TabDef {
    /// Unique identifier for the tab (used in ARIA attributes).
    pub id: &'static str,
    /// Display label for the tab.
    pub label: &'static str,
    /// Optional badge count (e.g., number of findings).
    pub badge: Option<usize>,
}

/// Tab bar component that renders tab buttons with proper ARIA attributes.
///
/// # Arguments
/// * `tabs` - List of tab definitions with unique IDs
/// * `active_tab` - Signal tracking the currently active tab index
/// * `aria_label` - Accessible label for the tablist
#[component]
pub fn TabBar(
    tabs: Vec<TabDef>,
    active_tab: RwSignal<usize>,
    #[prop(default = "Tabs")] aria_label: &'static str,
) -> impl IntoView {
    view! {
        <nav class="tab-bar" role="tablist" aria-label=aria_label>
            {tabs.into_iter().enumerate().map(|(idx, tab)| {
                let badge = tab.badge;
                let label = tab.label;
                let tab_id = format!("tab-{}", tab.id);
                let panel_id = format!("panel-{}", tab.id);

                view! {
                    <button
                        id=tab_id.clone()
                        class=move || {
                            if active_tab.get() == idx {
                                "tab-button tab-active"
                            } else {
                                "tab-button"
                            }
                        }
                        role="tab"
                        aria-selected=move || (active_tab.get() == idx).to_string()
                        aria-controls=panel_id
                        tabindex=move || if active_tab.get() == idx { "0" } else { "-1" }
                        on:click=move |_| active_tab.set(idx)
                    >
                        {label}
                        {badge.map(|count| {
                            view! {
                                <span class="tab-badge" aria-label=format!("{} items", count)>{count}</span>
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
/// * `id` - Unique identifier matching the tab's id
/// * `index` - The index of this panel (0-based)
/// * `active_tab` - Signal tracking the currently active tab
/// * `children` - The panel content
#[component]
pub fn TabPanel(
    id: &'static str,
    index: usize,
    active_tab: RwSignal<usize>,
    children: Children,
) -> impl IntoView {
    let is_visible = move || active_tab.get() == index;
    let panel_id = format!("panel-{}", id);
    let tab_id = format!("tab-{}", id);

    view! {
        <div
            id=panel_id
            class=move || {
                if is_visible() {
                  "tab-panel"
                } else {
                    "tab-panel panel-hidden"
                }
            }
            role="tabpanel"
            aria-labelledby=tab_id
            hidden=move || !is_visible()
        >
            {children()}
        </div>
    }
}
