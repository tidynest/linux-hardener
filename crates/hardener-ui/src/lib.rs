use leptos::prelude::*;
use leptos_router::{
    StaticSegment,
    components::{Route, Router, Routes},
};

mod components;
mod pages;
pub mod state;
mod tauri_bindings;
mod types;
mod utils;

use components::{ApplyResults, CheckpointList};
use pages::{CompliancePage, ConfigurationPage, DashboardPage, ScannerPage};
use state::AppState;
pub use types::*;

/// Main application component with routing and navigation.
///
/// This sets up:
/// - Application state (AppState) available to all child components via context
/// - Router with five routes: Checkpoints, Configuration, Dashboard, Results, Scanner
/// - Navigation bar for moving between pages
#[component]
pub fn App() -> impl IntoView {
    // Create application state and make it available to all child components
    let app_state = AppState::default();
    provide_context(app_state);

    view! {
        <Router>
            <header>
                <nav class="navigation">
                    <h1>"Linux System Hardener"</h1>
                    <ul class="nav-links">
                        <li><a href="/">"Dashboard"</a></li>
                        <li><a href="/scan">"Scanner"</a></li>
                        <li><a href="/config">"Configuration"</a></li>
                        <li><a href="/compliance">"Compliance"</a></li>
                        <li><a href="/results">"Results"</a></li>
                        <li><a href="/checkpoints">"Checkpoints"</a></li>
                    </ul>
                </nav>
            </header>

            <main class="main-content">
                <Routes fallback=|| view! {
                    <article class="error-page">
                        <h1>"404 - Page Not Found"</h1>
                        <p>"The requested page does not exist."</p>
                        <a href="/">"Return to Dashboard"</a>
                    </article>
                }>
                    <Route path=StaticSegment("") view=DashboardPage/>
                    <Route path=StaticSegment("checkpoints") view=CheckpointList/>
                    <Route path=StaticSegment("config") view=ConfigurationPage/>
                    <Route path=StaticSegment("compliance") view=CompliancePage/>
                    <Route path=StaticSegment("results") view=ApplyResults/>
                    <Route path=StaticSegment("scan") view=ScannerPage/>
                </Routes>
            </main>
        </Router>
    }
}

use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsCast;
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
