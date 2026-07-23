//! Inline SVG icon set for the sidebar navigation.
//!
//! Small, dependency-free Tabler-outline-style glyphs (`viewBox="0 0 24 24"`,
//! `fill="none"`, `stroke="currentColor"`, rounded caps and joins) rendered
//! directly in markup - no webfont, no CDN, so the CSP stays simple for a
//! fixed handful of nav icons. Path data is embedded via `inner_html`; every
//! value below is a compile-time string literal, never user input, so the
//! usual innerHTML/XSS caution does not apply here.
//!
//! Icons are decorative - the visible nav label carries the meaning - so
//! every glyph is `aria-hidden="true"`. Size is entirely the caller's call
//! via the `class` prop (no width/height in the markup).

use leptos::prelude::*;

/// Declares one `#[component]` per icon, wrapping the shared `<svg>`
/// boilerplate so each glyph is just a name and its path data.
macro_rules! nav_icon {
    ($(#[$doc:meta])* $name:ident, $paths:literal) => {
        $(#[$doc])*
        #[component]
        pub fn $name(#[prop(into)] class: String) -> impl IntoView {
            view! {
                <svg
                    class=class
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="2"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    aria-hidden="true"
                    inner_html=$paths
                ></svg>
            }
        }
    };
}

nav_icon!(
    /// Dashboard: an asymmetric tile grid.
    IconDashboard,
    r#"<rect x="4" y="4" width="7" height="7" rx="1.5"/><rect x="13" y="4" width="7" height="4" rx="1.5"/><rect x="13" y="10" width="7" height="10" rx="1.5"/><rect x="4" y="13" width="7" height="7" rx="1.5"/>"#
);

nav_icon!(
    /// Analysis: a rising bar chart against an axis.
    IconAnalysis,
    r#"<path d="M4 4v16h16"/><rect x="7" y="12" width="3" height="6" rx="1"/><rect x="12" y="8" width="3" height="10" rx="1"/><rect x="17" y="5" width="3" height="13" rx="1"/>"#
);

nav_icon!(
    /// Hardening: a shield with a check mark.
    IconHardening,
    r#"<path d="M12 3l7 3v6c0 4.5 -3 8 -7 9c-4 -1 -7 -4.5 -7 -9v-6l7 -3z"/><path d="M9 12l2 2l4 -4"/>"#
);

nav_icon!(
    /// Fleet: two stacked hosts.
    IconFleet,
    r#"<rect x="4" y="4" width="16" height="6" rx="1.5"/><rect x="4" y="14" width="16" height="6" rx="1.5"/><path d="M8 7h.01"/><path d="M8 17h.01"/>"#
);

nav_icon!(
    /// Fleet Apply: a bolt, for "run now across the fleet".
    IconFleetApply,
    r#"<path d="M13 3l-9 11h7l-1 7l9 -11h-7z"/>"#
);

nav_icon!(
    /// Scheduler: a clock face.
    IconScheduler,
    r#"<circle cx="12" cy="12" r="8"/><path d="M12 8v4l3 2"/>"#
);

nav_icon!(
    /// Settings: a hub with eight spokes.
    IconSettings,
    r#"<circle cx="12" cy="12" r="3"/><path d="M12 2v3"/><path d="M12 19v3"/><path d="M4.2 4.2l2.1 2.1"/><path d="M17.7 17.7l2.1 2.1"/><path d="M2 12h3"/><path d="M19 12h3"/><path d="M4.2 19.8l2.1 -2.1"/><path d="M17.7 6.3l2.1 -2.1"/>"#
);

nav_icon!(
    /// Collapse / expand: a double chevron, rotated 180 degrees by CSS when
    /// the rail is expanded.
    IconChevronCollapse,
    r#"<path d="M11 6l-6 6l6 6"/><path d="M17 6l-6 6l6 6"/>"#
);

nav_icon!(
    /// Wordmark: a plain shield outline (no check mark, so it reads
    /// distinctly from the Hardening nav glyph).
    IconShieldMark,
    r#"<path d="M12 3l7 3v6c0 4.5 -3 8 -7 9c-4 -1 -7 -4.5 -7 -9v-6l7 -3z"/>"#
);
