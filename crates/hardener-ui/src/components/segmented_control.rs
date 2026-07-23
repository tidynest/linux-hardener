//! A WAI-ARIA radiogroup rendered as a segmented control: one button per
//! segment, roving tabindex, arrow/Home/End moving focus AND selection.
//! Extracted from `configure_section.rs` so the Fleet Apply mode control and
//! the Hardening protection-level control share one implementation. Segment
//! semantics (a "custom" special-case, when to disable) stay in the consumer's
//! `on_select`/`disabled`; this component only reports the chosen id.

use leptos::prelude::*;
use wasm_bindgen::JsCast;

/// `segments` is a slice of `(id, label)`. `selected` holds the active id;
/// `on_select` fires the chosen id on click or keyboard move; `disabled`
/// greys every segment out (defaults to never).
#[component]
pub fn SegmentedControl(
    aria_label: &'static str,
    segments: &'static [(&'static str, &'static str)],
    #[prop(into)] selected: Signal<String>,
    #[prop(into)] on_select: Callback<String>,
    #[prop(optional, into)] disabled: Signal<bool>,
) -> impl IntoView {
    // Arrow keys move focus + selection (Space/Enter are native button clicks,
    // so only directional movement needs a handler).
    let on_keydown = move |ev: web_sys::KeyboardEvent| {
        let count = segments.len();
        let current = segments
            .iter()
            .position(|(id, _)| *id == selected.get_untracked())
            .unwrap_or(0);
        let next = match ev.key().as_str() {
            "ArrowRight" | "ArrowDown" => Some((current + 1) % count),
            "ArrowLeft" | "ArrowUp" => Some(current.checked_sub(1).unwrap_or(count - 1)),
            "Home" => Some(0),
            "End" => Some(count - 1),
            _ => None,
        };
        if let Some(idx) = next {
            ev.prevent_default();
            let (id, _) = segments[idx];
            on_select.run(id.to_string());
            // Focus by known element id, avoiding a race with the
            // aria-checked re-render.
            if let Some(el) = web_sys::window()
                .and_then(|w| w.document())
                .and_then(|d| d.get_element_by_id(&format!("segment-{}", id)))
                .and_then(|el| el.dyn_into::<web_sys::HtmlElement>().ok())
            {
                let _ = el.focus();
            }
        }
    };

    view! {
        <div
            class="segmented-control"
            role="radiogroup"
            aria-label=aria_label
            on:keydown=on_keydown
        >
            {segments
                .iter()
                .map(|(id, label)| {
                    let id = *id;
                    let label = *label;
                    let is_active = move || selected.get() == id;
                    view! {
                        <button
                            type="button"
                            id=format!("segment-{}", id)
                            role="radio"
                            aria-checked=move || is_active().to_string()
                            tabindex=move || if is_active() { "0" } else { "-1" }
                            disabled=move || disabled.get()
                            class="segment-btn"
                            class:is-active=is_active
                            on:click=move |_| on_select.run(id.to_string())
                        >
                            {label}
                        </button>
                    }
                })
                .collect::<Vec<_>>()}
        </div>
    }
}
