//! Shared form event extraction helpers to avoid JsCast boilerplate.

use leptos::wasm_bindgen::JsCast;

/// Extracts the string value from a text input change/input event.
pub fn input_value(event: &web_sys::Event) -> String {
    event
        .target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|el| el.value())
        .unwrap_or_default()
}

/// Extracts the string value from a `<select>` change event.
pub fn select_value(event: &web_sys::Event) -> String {
    event
        .target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlSelectElement>().ok())
        .map(|el| el.value())
        .unwrap_or_default()
}

/// Extracts the checked state from a checkbox change event.
pub fn checkbox_checked(event: &web_sys::Event) -> bool {
    event
        .target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|el| el.checked())
        .unwrap_or(false)
}
