use leptos::prelude::*;
use leptos_router::{
    StaticSegment,
    components::{A, Route, Router, Routes},
};

mod components;
mod pages;
pub mod state;
mod tauri_bindings;
mod types;
mod utils;

use components::ThemeToggle;
use pages::{AnalysisPage, DashboardPage, HardeningPage};
use state::AppState;
pub use types::*;

/// Main application component with routing and navigation.
///
/// This sets up:
/// - Application state (AppState) available to all child components via context
/// - Router with three routes: Dashboard, Analysis, Hardening
/// - Navigation bar for moving between pages
/// - Automatic loading of persisted scan results on mount
#[component]
pub fn App() -> impl IntoView {
    // Create application state and make it available to all child components
    let app_state = AppState::default();
    provide_context(app_state);

    // Load persisted scan results from database on app mount
    leptos::task::spawn_local(async move {
        match tauri_bindings::invoke_get_latest_scan().await {
            Ok(Some(results)) => {
                app_state.scan_results.set(results);
            }
            Ok(None) => {
                // No persisted scan results - that's fine, leave state empty
            }
            Err(e) => {
                // Log error but don't crash - user can still run a new scan
                web_sys::console::warn_1(&format!("Failed to load scan history: {}", e).into());
            }
        }
    });

    view! {
        <Router>
            // Skip link for keyboard/screen reader users - appears on focus
            <a href="#main-content" class="skip-link">"Skip to main content"</a>

            <header class="nav-header">
                <nav class="navigation" aria-label="Main navigation">
                    <h1>"Linux System Hardener"</h1>
                    <ul class="nav-links">
                        <li><A href="/">"Dashboard"</A></li>
                        <li><A href="/analysis">"Analysis"</A></li>
                        <li><A href="/hardening">"Hardening"</A></li>
                    </ul>
                    <ThemeToggle/>
                </nav>
            </header>

            <main id="main-content" class="main-content" tabindex="-1">
                <Routes fallback=|| view! {
                    <article class="error-page">
                        <div class="error-page-icon">"⚠"</div>
                        <h1>"404 - Page Not Found"</h1>
                        <p>"The requested page does not exist."</p>
                        <a href="/">"← Return to Dashboard"</a>
                    </article>
                }>
                    <Route path=StaticSegment("") view=DashboardPage/>
                    <Route path=StaticSegment("analysis") view=AnalysisPage/>
                    <Route path=StaticSegment("hardening") view=HardeningPage/>
                </Routes>
            </main>
        </Router>
    }
}

use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::wasm_bindgen;
use web_sys::HtmlElement;

/// Entry point for the WASM application.
/// Trunk calls this function to start the app.
#[wasm_bindgen(start)]
pub fn main() {
    let document = web_sys::window()
        .expect("no window")
        .document()
        .expect("no document");
    let app_element = document
        .get_element_by_id("app")
        .expect("element with id='app' not found")
        .dyn_into::<HtmlElement>()
        .expect("element is not HtmlElement");
    // Clear "Loading..." and mount the App component
    app_element.set_inner_html("");
    mount_to(app_element, App).forget();
}
