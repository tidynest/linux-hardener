//! Global keyboard shortcut handling for the desktop application.
//!
//! Registers a `keydown` listener on `document` and dispatches actions
//! based on key + modifier combinations. The Escape key uses a priority
//! chain that closes the most recently opened overlay first.

use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use wasm_bindgen::prelude::*;
use web_sys::KeyboardEvent;

use crate::state::AppState;
use crate::utils::theme::THEMES;

/// Installs the global keyboard shortcut handler on `document`.
///
/// Must be called inside a reactive owner (e.g., inside `App()`).
/// The listener is automatically cleaned up when the owner is disposed.
pub fn use_global_keyboard(app_state: AppState) {
    let navigate = use_navigate();
    let is_fullscreen = RwSignal::new(false);
    // Provide fullscreen state so other components can read it
    provide_context(is_fullscreen);

    let handler = Closure::<dyn Fn(KeyboardEvent)>::new(move |ev: KeyboardEvent| {
        // Don't intercept when user is typing in an input/textarea/select
        if is_input_focused() {
            // Exception: Escape should still work from within inputs
            if ev.key() != "Escape" {
                return;
            }
        }

        let ctrl = ev.ctrl_key() || ev.meta_key();
        let shift = ev.shift_key();
        let alt = ev.alt_key();

        match ev.key().as_str() {
            // F11: Toggle fullscreen
            "F11" => {
                ev.prevent_default();
                toggle_fullscreen(is_fullscreen);
            }

            // Escape: Priority chain
            "Escape" => {
                handle_escape(app_state, is_fullscreen);
            }

            // Ctrl+1..5: Page navigation
            "1" if ctrl && !shift && !alt => {
                ev.prevent_default();
                navigate("/", Default::default());
            }
            "2" if ctrl && !shift && !alt => {
                ev.prevent_default();
                navigate("/analysis", Default::default());
            }
            "3" if ctrl && !shift && !alt => {
                ev.prevent_default();
                navigate("/hardening", Default::default());
            }
            "4" if ctrl && !shift && !alt => {
                ev.prevent_default();
                navigate("/fleet", Default::default());
            }
            "5" if ctrl && !shift && !alt => {
                ev.prevent_default();
                navigate("/scheduler", Default::default());
            }

            // Ctrl+Shift+S: Trigger scan from anywhere
            "S" if ctrl && shift && !alt => {
                ev.prevent_default();
                if !app_state.is_scanning.get_untracked() {
                    trigger_global_scan(app_state);
                }
            }

            // Alt+T: Cycle theme
            "t" if alt && !ctrl && !shift => {
                ev.prevent_default();
                cycle_theme(app_state);
            }

            _ => {}
        }
    });

    // Attach to document: runs once, cleaned up on dispose
    if let Some(document) = web_sys::window().and_then(|w| w.document()) {
        let _ =
            document.add_event_listener_with_callback("keydown", handler.as_ref().unchecked_ref());
    }

    // Leak the closure so it lives as long as the app
    // (Leptos doesn't currently provide a cleanup hook for global listeners)
    handler.forget();
}

/// Returns true if the currently focused element is a text input, textarea, or select.
fn is_input_focused() -> bool {
    web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.active_element())
        .map(|el| {
            let tag = el.tag_name().to_uppercase();
            tag == "INPUT" || tag == "TEXTAREA" || tag == "SELECT"
        })
        .unwrap_or(false)
}

/// Toggle browser fullscreen via the Fullscreen API.
fn toggle_fullscreen(is_fullscreen: RwSignal<bool>) {
    let Some(document) = web_sys::window().and_then(|w| w.document()) else {
        return;
    };

    if is_fullscreen.get_untracked() {
        // Exit fullscreen
        document.exit_fullscreen();
        is_fullscreen.set(false);
    } else if let Some(root) = document.document_element() {
        // Enter fullscreen
        let _ = root.request_fullscreen();
        is_fullscreen.set(true);
    }
}

/// Escape key priority chain: closes the most specific overlay first.
fn handle_escape(app_state: AppState, is_fullscreen: RwSignal<bool>) {
    // 1. Exit fullscreen
    if is_fullscreen.get_untracked() {
        if let Some(document) = web_sys::window().and_then(|w| w.document()) {
            document.exit_fullscreen();
        }
        is_fullscreen.set(false);
        return;
    }

    // 2. Dismiss error banner
    if app_state.error_message.get_untracked().is_some() {
        app_state.error_message.set(None);
        return;
    }

    // 3. Close finding detail panel
    if app_state.selected_finding.get_untracked().is_some() {
        app_state.selected_finding.set(None);
        return;
    }

    // 4. Close preview panel
    if app_state.show_preview.get_untracked() {
        app_state.show_preview.set(false);
    }

    // 5. Remaining Escape targets (host form) are handled by
    //    component-level listeners since they use local signals.
}

/// Trigger a scan from the global shortcut, equivalent to Dashboard "Run Scan".
fn trigger_global_scan(app_state: AppState) {
    use crate::tauri_bindings;

    app_state.is_scanning.set(true);
    leptos::task::spawn_local(async move {
        match tauri_bindings::invoke_scan(vec![], None).await {
            Ok(results) => {
                app_state.scan_results.set(results);
                // Auto-generate compliance reports (consistent with Dashboard)
                let frameworks = hardener_types::ComplianceFramework::ALL
                    .iter()
                    .map(|f| f.id().to_string())
                    .collect();
                match tauri_bindings::invoke_generate_report(frameworks).await {
                    Ok(reports) => app_state.compliance_reports.set(reports),
                    Err(e) => {
                        web_sys::console::warn_1(
                            &format!("Compliance report generation failed: {e}").into(),
                        );
                    }
                }
            }
            Err(e) => {
                app_state
                    .error_message
                    .set(Some(format!("Scan failed: {e}")));
            }
        }
        app_state.is_scanning.set(false);
    });
}

/// Cycle to the next theme by advancing the shared signal; the apply/persist
/// Effect in `App` reacts to it (single source of truth).
fn cycle_theme(app_state: AppState) {
    let current = app_state.theme.get_untracked();
    let idx = THEMES
        .iter()
        .position(|(id, _)| *id == current)
        .unwrap_or(0);
    let next = THEMES[(idx + 1) % THEMES.len()].0;
    app_state.theme.set(next.to_string());
}
