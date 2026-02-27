//! Theme toggle component for switching between colour themes.

use leptos::prelude::*;

/// Available theme options
const THEMES: &[(&str, &str)] = &[
    ("default", "Midnight Teal"),
    ("fortress", "Fortress"),
    ("sentinel", "Sentinel"),
    ("command", "Command"),
    ("guardian", "Guardian"),
    ("daywatch", "Daywatch"),
    ("high-contrast", "High Contrast"),
];

/// Dropdown component for switching the application theme.
///
/// - Reads initial theme from localStorage
/// - Sets `data-theme` attribute on `<html>` element
/// - Persists selection to localStorage
#[component]
pub fn ThemeToggle() -> impl IntoView {
    // Get initial theme from localStorage or default
    let initial_theme = get_stored_theme().unwrap_or_else(|| "default".to_string());
    let (theme, set_theme) = signal(initial_theme.clone());

    // Apply theme on mount
    apply_theme(&initial_theme);

    // Update theme when selection changes
    let on_change = move |ev: web_sys::Event| {
        let select = event_target::<web_sys::HtmlSelectElement>(&ev);
        let new_theme = select.value();
        set_theme.set(new_theme.clone());
        apply_theme(&new_theme);
        store_theme(&new_theme);
    };

    view! {
        <div class="theme-toggle">
            <label for="theme-select" class="sr-only">"Colour theme"</label>
            <select
                id="theme-select"
                class="theme-select"
                on:change=on_change
            >
                <For
                    each=|| THEMES.iter()
                    key=|(id, _)| *id
                    children=move |(id, name)| {
                        let is_selected = theme.get() == *id;
                        view! {
                            <option value=*id selected=is_selected>
                                {*name}
                            </option>
                        }
                    }
                />
            </select>
        </div>
    }
}

/// Apply theme by setting data-theme attribute on <html>.
fn apply_theme(theme: &str) {
    if let Some(document) = web_sys::window().and_then(|w| w.document())
        && let Some(root) = document.document_element()
    {
        if theme == "default" {
            // Remove attribute to use base :root styles
            let _ = root.remove_attribute("data-theme");
        } else {
            let _ = root.set_attribute("data-theme", theme);
        }
    }
}

/// Get theme from localStorage, validated against known themes.
fn get_stored_theme() -> Option<String> {
    web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|storage| storage.get_item("theme").ok().flatten())
        .filter(|t| THEMES.iter().any(|(id, _)| *id == t.as_str()))
}

/// Save theme to localStorage.
fn store_theme(theme: &str) {
    if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        let _ = storage.set_item("theme", theme);
    }
}
