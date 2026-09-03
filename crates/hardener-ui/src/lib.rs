//! The Leptos/WASM desktop frontend.
//!
//! Compiled to WASM by trunk and embedded in the Tauri shell; it reaches the
//! backend only through [`tauri_bindings`], never directly. Seven routes:
//! Dashboard at `/`, then `analysis`, `hardening`, `fleet`, `fleet-apply`,
//! `scheduler` and `settings`, with `remote` kept as a redirect to `fleet` so
//! older links still land.
//!
//! **The markup lives in this crate and the styling does not.** Rules are in
//! `styles.css` beside it, and `cargo build` does not run trunk, so a change to
//! either is invisible to the desktop app until `trunk build` has rebuilt
//! `dist/`, which is gitignored and absent from a fresh clone.
//!
//! Types shared with the backend come from `hardener-types` rather than being
//! mirrored here, so there is one definition of each and no copy to drift.

use leptos::prelude::*;
use leptos_router::{
    NavigateOptions, StaticSegment,
    components::{Route, Router, Routes},
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

use components::{PostureStrip, Sidebar};
use pages::{
    AnalysisPage, DashboardPage, FleetApplyPage, HardeningPage, HostsPage, SchedulerPage,
    SettingsPage,
};
use state::AppState;
pub use types::*;

/// Main application component with routing and navigation.
///
/// This sets up:
/// - Application state (AppState) available to all child components via context
/// - Router with seven routes: Dashboard, Analysis, Hardening, Hosts, Fleet Apply,
///   Scheduler, Settings (plus a `/remote` redirect to Hosts for old links)
/// - Grouped sidebar (Local / Fleet / Settings) for moving between pages
/// - Automatic loading of persisted scan results on mount
#[component]
pub fn App() -> impl IntoView {
    // Create application state and make it available to all child components
    let app_state = AppState::default();
    provide_context(app_state);

    // Theme: restore the persisted choice, then keep `<html data-theme>` and
    // localStorage in lockstep with the shared signal. Every theme control
    // just sets `app_state.theme`; this Effect is the only writer of the DOM
    // attribute and the storage key.
    app_state
        .theme
        .set(utils::theme::get_stored_theme().unwrap_or_else(|| "default".to_string()));
    Effect::new(move |_| {
        let theme = app_state.theme.get();
        utils::theme::apply_theme(&theme);
        utils::theme::store_theme(&theme);
    });

    // History-backed "last scanned" stamp: the single owner. Re-read whenever
    // a scan finishes, from any of the three places one can start (the hero,
    // the Analysis header, the keyboard shortcut). `is_scanning` starts
    // false, so this also performs the initial read. `deep_scan_running` is
    // in the key because the deep scan never sets `is_scanning`, which is
    // why the Dashboard's old per-page effect went stale after a privileged
    // run.
    Effect::new(move |_| {
        if app_state.is_scanning.get() || app_state.deep_scan_running.get() {
            return;
        }
        leptos::task::spawn_local(async move {
            if let Ok(sessions) = tauri_bindings::invoke_get_scan_history(Some(1)).await {
                app_state
                    .last_scan_completed_at
                    .set(utils::last_scan_completed_at(&sessions));
            }
        });
    });

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

            <div class="app-shell">
                <Sidebar/>

                <div class="app-content">
                    <PostureStrip/>

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

                    <main id="main-content" class="app-main" tabindex="-1">
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
                            <Route path=StaticSegment("remote") view=RedirectToFleet/>
                            <Route path=StaticSegment("fleet") view=HostsPage/>
                            <Route path=StaticSegment("fleet-apply") view=FleetApplyPage/>
                            <Route path=StaticSegment("scheduler") view=SchedulerPage/>
                            <Route path=StaticSegment("settings") view=SettingsPage/>
                        </Routes>
                    </main>
                </div>
            </div>
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

/// Retired `/remote` route target: the Remote and Fleet screens merged into
/// the single Hosts screen (`HostsPage`, routed at `/fleet`). Any stale link
/// or bookmark pointing at `/remote` lands here and is bounced on to the
/// merged screen rather than hitting the 404 fallback.
#[component]
fn RedirectToFleet() -> impl IntoView {
    let navigate = leptos_router::hooks::use_navigate();
    Effect::new(move |_| {
        navigate(
            "/fleet",
            NavigateOptions {
                replace: true,
                ..Default::default()
            },
        )
    });
    view! { <span></span> }
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
