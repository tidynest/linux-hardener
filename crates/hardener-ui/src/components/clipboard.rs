//! Clipboard helpers for copy-to-clipboard buttons.

use leptos::prelude::*;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;

/// Copies `text` to the system clipboard via the async Clipboard API.
///
/// Updates `status` to `Some(true)` on success or `Some(false)` on failure,
/// then resets to `None` after 2 seconds so the UI feedback fades.
fn copy_to_clipboard(text: String, status: RwSignal<Option<bool>>) {
    leptos::task::spawn_local(async move {
        let ok = async {
            let window = web_sys::window()?;
            let promise = window.navigator().clipboard().write_text(&text);
            wasm_bindgen_futures::JsFuture::from(promise).await.ok()?;
            Some(())
        }
        .await
        .is_some();

        status.set(Some(ok));

        // Reset after 2 s via setTimeout — avoids adding gloo-timers dependency
        if let Some(window) = web_sys::window() {
            let cb = Closure::once(move || status.set(None));
            let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                cb.as_ref().unchecked_ref(),
                2_000,
            );
            cb.forget();
        }
    });
}

/// Small "Copy" button that copies the result of `text` to the clipboard.
///
/// Shows a brief "Copied!" / "Failed" flash after clicking.
#[component]
pub fn CopyButton(
    /// Signal that produces the text to copy when the button is clicked.
    #[prop(into)]
    text: Signal<String>,
    /// Optional CSS class override.
    #[prop(default = "btn btn-secondary btn-small")]
    class: &'static str,
) -> impl IntoView {
    let status = RwSignal::new(None::<bool>);

    let on_click = move |_| {
        copy_to_clipboard(text.get(), status);
    };

    let label = move || match status.get() {
        Some(true) => "Copied!",
        Some(false) => "Failed",
        None => "Copy",
    };

    view! {
        <button class=class on:click=on_click aria-live="polite">
            {label}
        </button>
    }
}
