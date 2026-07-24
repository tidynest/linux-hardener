//! Grouped left sidebar navigation with a collapsible icon rail.
//!
//! Replaces the old flat top navigation bar. Routes are grouped Local
//! (Dashboard/Analysis/Hardening) and Fleet (Hosts/Fleet Apply/Scheduler),
//! with a pinned Settings area underneath holding a routed link to the
//! Settings page plus the theme quick-switch. Every link is a
//! `leptos_router` `<A>`, so the active-route highlight keys off the
//! `aria-current="page"` attribute the router already sets - no manual
//! route comparison needed.

use super::ThemeToggle;
use super::icons::{
    IconAnalysis, IconChevronCollapse, IconDashboard, IconFleet, IconFleetApply, IconHardening,
    IconScheduler, IconSettings, IconShieldMark,
};
use leptos::prelude::*;
use leptos_router::components::A;
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;

/// localStorage key for the user's explicit collapse preference. Mirrors
/// the theme toggle's persistence pattern (`theme_toggle.rs`): read on
/// init, save on toggle. Stored as an optional choice - absent means "no
/// explicit preference yet", so the width breakpoint below decides; once
/// the user acts once, their choice is remembered and wins over the
/// breakpoint in both directions.
const COLLAPSE_STORAGE_KEY: &str = "sidebar-collapsed";

/// Viewport width, in CSS pixels, below which the sidebar auto-collapses
/// for tiled/narrow windows. Tracked in Rust (via `resize`) rather than a
/// CSS media query so the same single `rail` class also drives the
/// collapsed-content treatment (hidden labels, tooltip, and so on) with no
/// duplicated CSS between the auto and explicit-choice paths.
const AUTO_COLLAPSE_BREAKPOINT: f64 = 900.0;

/// Sidebar shell: wordmark, the two route groups, and the pinned Settings
/// area. Renders its own `<aside class="sidebar">` root.
#[component]
pub fn Sidebar() -> impl IntoView {
    let (explicit_collapsed, set_explicit_collapsed) = signal(get_stored_collapsed());
    let (is_narrow, set_is_narrow) = signal(window_width_below_breakpoint());

    if let Some(window) = web_sys::window() {
        let on_resize = Closure::<dyn Fn()>::new(move || {
            set_is_narrow.set(window_width_below_breakpoint());
        });
        let _ =
            window.add_event_listener_with_callback("resize", on_resize.as_ref().unchecked_ref());
        // Lives for the app's lifetime, same as the rate-limit timer in lib.rs.
        on_resize.forget();

        // A window that is still settling into its configured size when
        // this component first mounts (window-manager launch animation,
        // or a slow first layout) can race the synchronous read above with
        // no resize event to correct it. A one-shot recheck shortly after
        // mount closes that gap; harmless if the first read was already
        // right, since setting a signal to its current value is a no-op.
        let recheck = Closure::once(move || {
            set_is_narrow.set(window_width_below_breakpoint());
        });
        let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
            recheck.as_ref().unchecked_ref(),
            100,
        );
        recheck.forget();
    }

    // Explicit choice always wins, in both directions; absent one, the
    // viewport decides.
    let is_rail = move || explicit_collapsed.get().unwrap_or_else(|| is_narrow.get());

    let toggle_collapse = move |_| {
        let current = explicit_collapsed
            .get_untracked()
            .unwrap_or_else(|| is_narrow.get_untracked());
        let next = !current;
        set_explicit_collapsed.set(Some(next));
        store_collapsed(next);
    };

    let toggle_label = move || {
        if is_rail() {
            "Expand sidebar"
        } else {
            "Collapse sidebar"
        }
    };

    view! {
        <aside class="sidebar" class:rail=is_rail>
            <div class="sidebar-header">
                <span class="sidebar-wordmark">
                    <IconShieldMark class="sidebar-wordmark-icon"/>
                    <span class="sidebar-wordmark-text">"Hardener"</span>
                </span>
                <button
                    type="button"
                    class="sidebar-collapse-toggle"
                    title=toggle_label
                    aria-label=toggle_label
                    aria-expanded=move || (!is_rail()).to_string()
                    on:click=toggle_collapse
                >
                    <IconChevronCollapse class="sidebar-collapse-icon"/>
                </button>
            </div>

            <nav class="sidebar-nav" aria-label="Main navigation">
                <div class="sidebar-group">
                    <SidebarGroupLabel label="Local"/>
                    <ul class="sidebar-group-items">
                        <SidebarLink href="/" label="Dashboard">
                            <IconDashboard class="sidebar-link-icon"/>
                        </SidebarLink>
                        <SidebarLink href="/analysis" label="Analysis">
                            <IconAnalysis class="sidebar-link-icon"/>
                        </SidebarLink>
                        <SidebarLink href="/hardening" label="Hardening">
                            <IconHardening class="sidebar-link-icon"/>
                        </SidebarLink>
                    </ul>
                </div>

                <div class="sidebar-group">
                    <SidebarGroupLabel label="Fleet"/>
                    <ul class="sidebar-group-items">
                        <SidebarLink href="/fleet" label="Hosts">
                            <IconFleet class="sidebar-link-icon"/>
                        </SidebarLink>
                        <SidebarLink href="/fleet-apply" label="Fleet Apply">
                            <IconFleetApply class="sidebar-link-icon"/>
                        </SidebarLink>
                        <SidebarLink href="/scheduler" label="Scheduler">
                            <IconScheduler class="sidebar-link-icon"/>
                        </SidebarLink>
                    </ul>
                </div>
            </nav>

            <div class="sidebar-settings">
                <A
                    href="/settings"
                    attr:class="sidebar-link"
                    attr:title="Settings"
                    attr:aria-label="Settings"
                >
                    <IconSettings class="sidebar-link-icon"/>
                    <span class="sidebar-link-label">"Settings"</span>
                </A>
                <div class="sidebar-settings-content">
                    <ThemeToggle/>
                </div>
                <span class="app-version">
                    {concat!(
                        "v",
                        env!("CARGO_PKG_VERSION"),
                        " (",
                        env!("HARDENER_BUILD_IDENTITY"),
                        ")"
                    )}
                </span>
            </div>
        </aside>
    }
}

/// A group heading ("Local" / "Fleet"). Collapses to a plain divider line
/// in rail mode (the text stays in the DOM for screen readers; only its
/// visual box shrinks).
#[component]
fn SidebarGroupLabel(label: &'static str) -> impl IntoView {
    view! {
        <div class="sidebar-group-label">
            <span class="sidebar-group-label-text">{label}</span>
        </div>
    }
}

/// One nav entry: an icon (children) plus label, wired through `<A>`. The
/// `title`/`aria-label` pair keeps the accessible name and the rail's hover
/// tooltip (CSS `content: attr(title)`) in sync from a single value.
#[component]
fn SidebarLink(href: &'static str, label: &'static str, children: Children) -> impl IntoView {
    view! {
        <li>
            <A href=href attr:class="sidebar-link" attr:title=label attr:aria-label=label>
                {children()}
                <span class="sidebar-link-label">{label}</span>
            </A>
        </li>
    }
}

/// Reads the user's explicit collapse choice, if any has ever been saved.
/// `None` means "no explicit preference" - the width breakpoint decides.
fn get_stored_collapsed() -> Option<bool> {
    web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|storage| storage.get_item(COLLAPSE_STORAGE_KEY).ok().flatten())
        .map(|v| v == "true")
}

/// Whether the window is currently narrower than [`AUTO_COLLAPSE_BREAKPOINT`].
/// Fails open to "wide" (no auto-collapse) if the width cannot be read, so a
/// lookup failure never traps the sidebar in rail mode.
fn window_width_below_breakpoint() -> bool {
    web_sys::window()
        .and_then(|w| w.inner_width().ok())
        .and_then(|value| value.as_f64())
        .is_some_and(|width| width < AUTO_COLLAPSE_BREAKPOINT)
}

/// Persists the user's explicit collapse choice.
fn store_collapsed(collapsed: bool) {
    if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        let _ = storage.set_item(
            COLLAPSE_STORAGE_KEY,
            if collapsed { "true" } else { "false" },
        );
    }
}
