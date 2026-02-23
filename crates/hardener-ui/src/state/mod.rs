use crate::types::{ApplyResult, ComplianceReport, Finding, RollbackResult, ScanResult};
use hardener_types::ValidationReport;
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
    /// Result from the most recent rollback operation.
    pub rollback_result: RwSignal<Option<RollbackResult>>,
    /// Whether a system scan is currently in progress.
    pub is_scanning: RwSignal<bool>,
    /// Whether hardening changes are currently being applied.
    pub is_applying: RwSignal<bool>,
    /// Compliance reports from the most recent generation.
    pub compliance_reports: RwSignal<Vec<ComplianceReport>>,
    /// Whether compliance reports are currently being generated.
    pub is_generating_report: RwSignal<bool>,
    /// Results from the most recent dry-run preview.
    /// Contains estimated changes that would be applied.
    pub preview_results: RwSignal<Vec<ValidationReport>>,
    /// Whether a dry-run preview is currently being generated.
    pub is_previewing: RwSignal<bool>,
    /// Whether to show the preview panel.
    pub show_preview: RwSignal<bool>,
    /// Global error message displayed as a toast/banner.
    /// Set to Some(message) to show, None to dismiss.
    pub error_message: RwSignal<Option<String>>,
}

impl Default for AppState {
    fn default() -> AppState {
        AppState {
            scan_results: RwSignal::new(Vec::new()),
            selected_finding: RwSignal::new(None),
            apply_results: RwSignal::new(Vec::new()),
            rollback_result: RwSignal::new(None),
            is_scanning: RwSignal::new(false),
            is_applying: RwSignal::new(false),
            compliance_reports: RwSignal::new(Vec::new()),
            is_generating_report: RwSignal::new(false),
            preview_results: RwSignal::new(Vec::new()),
            is_previewing: RwSignal::new(false),
            show_preview: RwSignal::new(false),
            error_message: RwSignal::new(None),
        }
    }
}
