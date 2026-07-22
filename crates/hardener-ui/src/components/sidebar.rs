//! Grouped left sidebar navigation.
//!
//! Replaces the old flat top navigation bar. Routes are grouped Local
//! (Dashboard/Analysis/Hardening) and Fleet (Remote/Fleet/Fleet
//! Apply/Scheduler), with a pinned Settings area underneath holding the
//! theme switcher (Settings has no route of its own yet). Every link is a
//! `leptos_router` `<A>`, so the active-route highlight keys off the
//! `aria-current="page"` attribute the router already sets - no manual
//! route comparison needed.

use super::ThemeToggle;
use super::icons::{
    IconAnalysis, IconDashboard, IconFleet, IconFleetApply, IconHardening, IconRemote,
    IconScheduler, IconSettings, IconShieldMark,
};
use leptos::prelude::*;
use leptos_router::components::A;

/// Sidebar shell: wordmark, the two route groups, and the pinned Settings
/// area. Renders its own `<aside class="sidebar">` root.
#[component]
pub fn Sidebar() -> impl IntoView {
    view! {
        <aside class="sidebar">
            <div class="sidebar-header">
                <span class="sidebar-wordmark">
                    <IconShieldMark class="sidebar-wordmark-icon"/>
                    <span class="sidebar-wordmark-text">"Hardener"</span>
                </span>
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
                        <SidebarLink href="/remote" label="Remote">
                            <IconRemote class="sidebar-link-icon"/>
                        </SidebarLink>
                        <SidebarLink href="/fleet" label="Fleet">
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
                <div class="sidebar-group-label">
                    <IconSettings class="sidebar-group-icon"/>
                    <span class="sidebar-group-label-text">"Settings"</span>
                </div>
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

/// A group heading ("Local" / "Fleet"). Shares markup with the Settings
/// heading below so both can collapse identically once the icon rail
/// lands.
#[component]
fn SidebarGroupLabel(label: &'static str) -> impl IntoView {
    view! {
        <div class="sidebar-group-label">
            <span class="sidebar-group-label-text">{label}</span>
        </div>
    }
}

/// One nav entry: an icon (children) plus label, wired through `<A>`. The
/// `title`/`aria-label` pair keeps the accessible name explicit regardless
/// of how the label text is styled.
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
