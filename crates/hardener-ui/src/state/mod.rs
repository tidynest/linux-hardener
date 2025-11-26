use crate::types::{ApplyResult, Finding, ScanResult};
use leptos::prelude::*;

/// Application state container holding all reactive signals for the UI.
///
/// This struct uses Leptos signals to provide reactive update throughout
/// the application. When signal values change, all components that read
/// them automatically re-render.
#[derive(Clone, Copy)]
pub struct AppState {
    /// Results from the most recent system scan.
    /// Each ScanResult contains findings from one plugin.
    pub scan_results: RwSignal<Vec<ScanResult>>,

    /// Currently selected finding for the detail view.
    /// Set to Some(finding) when user clicks a finding row.
    pub selected_finding: RwSignal<Option<Finding>>,

    /// History of apply operations.
    /// Stores results from each hardening application.
    pub apply_results: RwSignal<Vec<ApplyResult>>,

    /// Whether a system scan is currently in progress.
    pub is_scanning: RwSignal<bool>,

    /// Whether hardening changes are currently being applied.
    pub is_applying: RwSignal<bool>,
}

impl Default for AppState {
    fn default() -> AppState {
        AppState {
            scan_results: RwSignal::new(Vec::new()),
            selected_finding: RwSignal::new(None),
            apply_results: RwSignal::new(Vec::new()),
            is_scanning: RwSignal::new(false),
            is_applying: RwSignal::new(false),
        }
    }
}
