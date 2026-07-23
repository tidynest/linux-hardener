//! Theme quick-switch: a `<select>` bound to the shared `AppState.theme`
//! signal. Purely presentational - the single apply/persist `Effect` in `App`
//! reacts to the signal, and the theme list lives in `utils::theme`.

use crate::components::form_helpers;
use crate::state::AppState;
use crate::utils::theme::THEMES;
use leptos::prelude::*;

/// Dropdown that switches the application theme by writing the shared signal.
#[component]
pub fn ThemeToggle() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    view! {
        <div class="theme-toggle">
            <label for="theme-select" class="sr-only">"Colour theme"</label>
            <select
                id="theme-select"
                class="theme-select"
                prop:value=move || app_state.theme.get()
                on:change=move |ev| app_state.theme.set(form_helpers::select_value(&ev))
            >
                {THEMES
                    .iter()
                    .map(|(id, name)| view! { <option value=*id>{*name}</option> })
                    .collect::<Vec<_>>()}
            </select>
        </div>
    }
}
