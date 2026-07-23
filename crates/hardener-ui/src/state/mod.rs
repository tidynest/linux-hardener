use crate::types::{
    ApplyResult, ComplianceReport, ConfigSummary, Finding, RollbackResult, ScanResult,
    SchedulerUiConfig, Severity,
};
use hardener_types::ValidationReport;
use hardener_types::remote::{RemoteConnectionInfo, RemoteHostProfile};
use leptos::prelude::*;

/// Total number of unchecked (requires-privileges) checks across scan
/// results. Raw, undeduplicated sum: the banner and score badge report this
/// as the honest count of unverified checks. Shared by UncheckedBanner and
/// SecurityScore, which call it inside their reactive closures.
pub fn total_unchecked(results: &[ScanResult]) -> usize {
    results.iter().map(|r| r.scan_unchecked.len()).sum()
}

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
    /// Path to a user-selected custom config file (None = default config).
    pub config_path: RwSignal<Option<String>>,
    /// Validation summary for the currently selected config file.
    pub config_summary: RwSignal<Option<ConfigSummary>>,
    /// Whether a privileged deep scan is currently running. Shared across
    /// every `UncheckedBanner` instance (Dashboard and Analysis both mount
    /// one) so the two buttons disable together during a single run.
    pub deep_scan_running: RwSignal<bool>,
    /// Active colour theme id (see `crate::utils::theme::THEMES`). The single
    /// source of truth shared by the sidebar quick-switch and the Settings
    /// page grid; a lone `Effect` in `App` applies it to `<html>` and persists
    /// it.
    pub theme: RwSignal<String>,
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
            config_path: RwSignal::new(None),
            config_summary: RwSignal::new(None),
            deep_scan_running: RwSignal::new(false),
            theme: RwSignal::new("default".to_string()),
        }
    }
}

/// Lifted form state for the Scheduler page: one owner for both the schedule
/// and notification fields, so a single page-level Save writes the whole
/// `SchedulerUiConfig` at once. The presentational sections read/write these
/// signals; `SchedulerPage` holds the sole config-sync `Effect` and the save.
#[derive(Clone, Copy)]
pub struct SchedulerForm {
    pub enabled: RwSignal<bool>,
    pub selected_preset: RwSignal<String>,
    pub custom_cron: RwSignal<String>,
    pub advanced_open: RwSignal<bool>,
    pub selected_plugins: RwSignal<Vec<String>>,
    pub min_severity: RwSignal<String>,
    pub email_enabled: RwSignal<bool>,
    pub email_recipients: RwSignal<String>,
    pub email_from: RwSignal<String>,
    pub webhook_enabled: RwSignal<bool>,
    pub webhook_url: RwSignal<String>,
    pub webhook_format: RwSignal<String>,
}

impl SchedulerForm {
    /// Fresh bundle with empty/default fields, before the config loads.
    pub fn new() -> Self {
        Self {
            enabled: RwSignal::new(false),
            selected_preset: RwSignal::new(String::new()),
            custom_cron: RwSignal::new(String::new()),
            advanced_open: RwSignal::new(false),
            selected_plugins: RwSignal::new(Vec::new()),
            min_severity: RwSignal::new("medium".to_string()),
            email_enabled: RwSignal::new(false),
            email_recipients: RwSignal::new(String::new()),
            email_from: RwSignal::new(String::new()),
            webhook_enabled: RwSignal::new(false),
            webhook_url: RwSignal::new(String::new()),
            webhook_format: RwSignal::new("generic".to_string()),
        }
    }
}

impl Default for SchedulerForm {
    fn default() -> Self {
        Self::new()
    }
}
