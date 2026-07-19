use leptos::prelude::*;
use leptos_router::{
    StaticSegment,
    components::{A, Route, Router, Routes},
};
use wasm_bindgen::closure::Closure;

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
/// - Router with seven routes: Dashboard, Analysis, Hardening, Remote, Fleet, Scheduler, Fleet Apply
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

                // Restore the security score too: report generation reads the
                // same persisted session these results came from, so this is
                // cheap, unprivileged, and never prompts.
                let frameworks = hardener_types::ComplianceFramework::ALL
                    .iter()
                    .map(|f| f.id().to_string())
                    .collect();
                match tauri_bindings::invoke_generate_report(frameworks).await {
                    Ok(reports) => {
                        app_state.compliance_reports.set(reports);
                    }
                    Err(e) => {
                        // Startup restore is best-effort: keep the empty score
                        // rather than greeting the user with an error banner.
                        web_sys::console::warn_1(
                            &format!("Failed to restore compliance reports: {}", e).into(),
                        );
                    }
                }
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
                    <span class="app-version">
                        {concat!(
                            "v",
                            env!("CARGO_PKG_VERSION"),
                            " (",
                            env!("HARDENER_BUILD_IDENTITY"),
                            ")"
                        )}
                    </span>
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
    arm_rate_limit_auto_dismiss(app_state);
    // Renders nothing: purely side-effect driven
}

/// Auto-dismisses the global error banner when it is showing the backend's
/// privileged-operation rate-limit message, since that is a transient
/// cooldown rather than a genuine failure the user needs to act on.
///
/// Watches `error_message` and, when it holds a rate-limit message with wait
/// time N seconds, arms a `set_timeout` for `(N + 5)` seconds. The timer's
/// callback clears the banner only if `error_message` still holds the exact
/// message it was armed for (compared by value, not just "is a rate-limit
/// message") - `error_message` is a single signal shared by every privileged
/// command, so a later, unrelated error that reuses it must never be wiped
/// by a stale timer. Manual dismissal (the X button or Escape) or a new
/// error replacing this one both make a pending timer a harmless no-op.
fn arm_rate_limit_auto_dismiss(app_state: AppState) {
    Effect::new(move |_| {
        let Some(armed_for) = app_state.error_message.get() else {
            return;
        };
        let Some(wait_secs) = utils::parse_rate_limit_wait_secs(&armed_for) else {
            return;
        };
        let Some(window) = web_sys::window() else {
            return;
        };

        let cb = Closure::once(move || {
            if app_state.error_message.get_untracked().as_deref() == Some(armed_for.as_str()) {
                app_state.error_message.set(None);
            }
        });
        let timeout_ms = ((wait_secs + 5) * 1000) as i32;
        let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
            cb.as_ref().unchecked_ref(),
            timeout_ms,
        );
        cb.forget();
    });
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
