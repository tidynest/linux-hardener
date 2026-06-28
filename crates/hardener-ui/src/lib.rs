use leptos::prelude::*;
use leptos_router::{
    StaticSegment,
    components::{A, Route, Router, Routes},
};

mod components;
mod keyboard;
mod navigation;
mod pages;
pub mod state;
mod tauri_bindings;
mod types;
mod utils;

use components::ThemeToggle;
use pages::{
    AnalysisPage, DashboardPage, FleetApplyPage, FleetPage, HardeningPage, RemotePage,
    SchedulerPage,
};
use state::AppState;
pub use types::*;

/// Main application component with routing and navigation.
///
/// This sets up:
/// - Application state (AppState) available to all child components via context
/// - Router with six routes: Dashboard, Analysis, Hardening, Remote, Fleet, Scheduler
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
            // Install hooks that require Router context (use_navigate, use_location)
            <GlobalHooks/>

            // Skip link for keyboard/screen reader users - appears on focus
            <a href="#main-content" class="skip-link">"Skip to main content"</a>

            <header class="nav-header">
                <nav class="navigation" aria-label="Main navigation">
                    <h1>"Linux System Hardener"</h1>
                    <ul class="nav-links">
                        <li><A href="/">"Dashboard"</A></li>
                        <li><A href="/analysis">"Analysis"</A></li>
                        <li><A href="/hardening">"Hardening"</A></li>
                        <li><A href="/remote">"Remote"</A></li>
                        <li><A href="/fleet">"Fleet"</A></li>
                        <li><A href="/fleet-apply">"Fleet Apply"</A></li>
                        <li><A href="/scheduler">"Scheduler"</A></li>
                    </ul>
                    <ThemeToggle/>
                </nav>
            </header>

            // Global error notification banner
            <Show when=move || app_state.error_message.get().is_some()>
                <div class="error-banner" role="alert">
                    <span class="error-banner-message">
                        {move || app_state.error_message.get().unwrap_or_default()}
                    </span>
                    <button
                        class="error-banner-dismiss"
                        aria-label="Dismiss error"
                        on:click=move |_| app_state.error_message.set(None)
                    >
                        "✕"
                    </button>
                </div>
            </Show>

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
                    <Route path=StaticSegment("remote") view=RemotePage/>
                    <Route path=StaticSegment("fleet") view=FleetPage/>
                    <Route path=StaticSegment("fleet-apply") view=FleetApplyPage/>
                    <Route path=StaticSegment("scheduler") view=SchedulerPage/>
                </Routes>
            </main>
        </Router>
    }
}

/// Invisible component that installs global hooks requiring Router context.
///
/// Placed as the first child inside `<Router>` so it can access
/// `use_navigate()` and `use_location()`.
#[component]
fn GlobalHooks() -> impl IntoView {
    let app_state = expect_context::<AppState>();
    keyboard::use_global_keyboard(app_state);
    navigation::use_scroll_and_focus_on_navigate();
    // Renders nothing — purely side-effect driven
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
