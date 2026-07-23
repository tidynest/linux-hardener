//! Theme swatch grid: a WAI-ARIA radiogroup of live-coloured preview cards,
//! one per `utils::theme::THEMES` entry. Each card sets its own `data-theme`,
//! so its chips render in that theme's real palette (the theme CSS blocks
//! match any `[data-theme]` element, not only `:root`). Selecting a card
//! writes the shared `AppState.theme` signal; the apply/persist `Effect` in
//! `App` does the rest. The keyboard model mirrors `segmented_control.rs`.

use crate::state::AppState;
use crate::utils::theme::THEMES;
use leptos::prelude::*;
use wasm_bindgen::JsCast;

/// Focuses a swatch card by its known element id, avoiding a race with the
/// aria-checked re-render (same trick as `SegmentedControl`).
fn focus_swatch(id: &str) {
    if let Some(el) = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.get_element_by_id(&format!("theme-swatch-{id}")))
        .and_then(|el| el.dyn_into::<web_sys::HtmlElement>().ok())
    {
        let _ = el.focus();
    }
}

/// Grid of theme preview cards. Reads and writes `AppState.theme`.
#[component]
pub fn ThemePicker() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Arrow/Home/End move focus AND selection (Space/Enter are native button
    // clicks, so only directional movement needs a handler).
    let on_keydown = move |ev: web_sys::KeyboardEvent| {
        let count = THEMES.len();
        let current = THEMES
            .iter()
            .position(|(id, _)| *id == app_state.theme.get_untracked())
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
            let (id, _) = THEMES[idx];
            app_state.theme.set(id.to_string());
            focus_swatch(id);
        }
    };

    view! {
        <div
            class="theme-grid"
            role="radiogroup"
            aria-label="Colour theme"
            on:keydown=on_keydown
        >
            {THEMES
                .iter()
                .map(|(id, name)| {
                    let id = *id;
                    let name = *name;
                    let is_active = move || app_state.theme.get() == id;
                    view! {
                        <button
                            type="button"
                            id=format!("theme-swatch-{id}")
                            class="theme-swatch"
                            class:is-active=is_active
                            data-theme=id
                            role="radio"
                            aria-checked=move || is_active().to_string()
                            aria-label=name
                            tabindex=move || if is_active() { "0" } else { "-1" }
                            on:click=move |_| app_state.theme.set(id.to_string())
                        >
                            <span class="theme-swatch-chips" aria-hidden="true">
                                <span class="theme-chip theme-chip-accent"></span>
                                <span class="theme-chip theme-chip-good"></span>
                                <span class="theme-chip theme-chip-warning"></span>
                                <span class="theme-chip theme-chip-critical"></span>
                            </span>
                            <span class="theme-swatch-name">{name}</span>
                            <span class="theme-swatch-check" aria-hidden="true">
                                {"\u{2713}"}
                            </span>
                        </button>
                    }
                })
                .collect::<Vec<_>>()}
        </div>
    }
}
