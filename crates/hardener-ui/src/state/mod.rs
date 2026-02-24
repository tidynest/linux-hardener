use crate::types::{ApplyResult, ComplianceReport, Finding, RollbackResult, ScanResult, SchedulerUiConfig, Severity};
use hardener_types::remote::{RemoteConnectionInfo, RemoteHostProfile};
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
    /// Minimum severity threshold for findings display.
    /// None shows all findings; Some(level) filters to findings >= level.
    pub severity_filter: RwSignal<Option<Severity>>,
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
    /// Saved remote host profiles.
    pub remote_hosts: RwSignal<Vec<RemoteHostProfile>>,
    /// Currently active remote connection info (None = disconnected).
    pub remote_connection: RwSignal<Option<RemoteConnectionInfo>>,
    /// Results from the most recent remote scan.
    pub remote_scan_results: RwSignal<Vec<ScanResult>>,
    /// Whether an SSH connection attempt is in progress.
    pub is_connecting: RwSignal<bool>,
    /// Whether a remote scan is currently running.
    pub is_remote_scanning: RwSignal<bool>,
    /// Loaded scheduler configuration from config.toml.
    pub scheduler_config: RwSignal<Option<SchedulerUiConfig>>,
    /// Whether scheduler config is being saved.
    pub is_saving_scheduler: RwSignal<bool>,
    /// Whether a test notification is in progress.
    pub is_testing_notification: RwSignal<bool>,
}

impl Default for AppState {
    fn default() -> AppState {
        AppState {
            scan_results: RwSignal::new(Vec::new()),
            selected_finding: RwSignal::new(None),
            severity_filter: RwSignal::new(None),
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
            remote_hosts: RwSignal::new(Vec::new()),
            remote_connection: RwSignal::new(None),
            remote_scan_results: RwSignal::new(Vec::new()),
            is_connecting: RwSignal::new(false),
            is_remote_scanning: RwSignal::new(false),
            scheduler_config: RwSignal::new(None),
            is_saving_scheduler: RwSignal::new(false),
            is_testing_notification: RwSignal::new(false),
        }
    }
}
