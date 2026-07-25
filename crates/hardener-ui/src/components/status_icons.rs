//! Shared status/flag icon set (inline SVG, Tabler-outline style).
//!
//! Small, dependency-free glyphs (`viewBox="0 0 24 24"`, `fill="none"`,
//! `stroke="currentColor"`, rounded caps and joins) rendered directly in
//! markup, mirroring `icons.rs`'s pattern exactly. Path data is embedded via
//! `inner_html`; every value below is a compile-time string literal, never
//! user input, so the usual innerHTML/XSS caution does not apply here.
//!
//! This is the project's fixed status/flag vocabulary (redesign handoff,
//! section 2): one glyph plus one colour always means the same thing
//! everywhere it appears (applied/Failed/Manual step/Skipped, and the `(i)`
//! help affordance). Icons are decorative - the adjoining text or the
//! caller's `aria-label` carries the meaning - so every glyph is
//! `aria-hidden="true"`. Colour and size are entirely the caller's call via
//! the `class` prop (`currentColor`, no width/height/fill in the markup).
//!
//! `IconCheck`, `IconX`, `IconWrench`, `IconMinus`, and `IconInfo` are all
//! called from views (see the review/drawer/done/partial slices and the
//! rollback modal). `#[allow(dead_code)]` per-item does not reliably
//! suppress dead-code warnings, because Leptos's `#[component]` macro
//! expands each icon into a function plus a separate Props struct that does
//! not inherit an outer attribute; a module-level allow covers both, the
//! same way `card.rs` allows `dead_code` on `CardVariant`'s not-yet-used
//! variants.
#![allow(dead_code)]

use leptos::prelude::*;

/// Declares one `#[component]` per icon, wrapping the shared `<svg>`
/// boilerplate so each glyph is just a name and its path data. Kept as a
/// local copy of `icons.rs`'s `nav_icon!` rather than a shared macro: this
/// task must not touch `icons.rs`.
macro_rules! status_icon {
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

status_icon!(
    /// Status "applied": a check mark. Pair with `--color-good`.
    IconCheck,
    r#"<path d="M5 12l5 5l10 -10"/>"#
);

status_icon!(
    /// Status "Failed": a cross. Pair with `--color-critical`.
    IconX,
    r#"<path d="M18 6l-12 12"/><path d="M6 6l12 12"/>"#
);

status_icon!(
    /// Status "Manual step": a wrench. Pair with `--color-warning`.
    IconWrench,
    r#"<path d="M7 10h3v-3l-3.5 -3.5a6 6 0 0 1 8 8l6 6a2 2 0 0 1 -3 3l-6 -6a6 6 0 0 1 -8 -8l3.5 3.5"/>"#
);

status_icon!(
    /// Status "Skipped": a minus. Pair with `--text-muted`.
    IconMinus,
    r#"<path d="M5 12l14 0"/>"#
);

status_icon!(
    /// The `(i)` help affordance, used at points of need throughout the
    /// apply flow.
    IconInfo,
    r#"<circle cx="12" cy="12" r="9"/><path d="M12 8.5h.01"/><path d="M11 12h1v4h1"/>"#
);
