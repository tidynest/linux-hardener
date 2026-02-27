//! Navigation helpers: scroll-to-top and focus management on route changes.

use leptos::prelude::*;
use leptos_router::hooks::use_location;
use wasm_bindgen::JsCast;

/// Scrolls to the top of the page and focuses `#main-content` whenever
/// the route pathname changes.
///
/// Must be called inside a `<Router>` context (needs `use_location`).
pub fn use_scroll_and_focus_on_navigate() {
    let location = use_location();

    Effect::new(move || {
        // Subscribe to pathname changes
        let _path = location.pathname.get();

        // Scroll to top
        if let Some(window) = web_sys::window() {
            window.scroll_to_with_x_and_y(0.0, 0.0);
        }

        // Move focus to main content for keyboard/screen reader users
        if let Some(main) = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.get_element_by_id("main-content"))
            && let Ok(el) = main.dyn_into::<web_sys::HtmlElement>()
        {
            let _ = el.focus();
        }
    });
}
