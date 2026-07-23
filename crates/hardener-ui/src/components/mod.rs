mod adhoc_host_input;
mod card;
mod clipboard;
mod compliance_tab;
mod config_file_card;
mod configure_section;
mod confirm_delete;
mod findings_tab;
pub(crate) mod form_helpers;
mod history_section;
mod host_form;
mod host_panel;
mod host_row;
mod icons;
mod notification_section;
mod recent_activity;
mod rollback_modal;
mod scan_history_tab;
mod schedule_section;
mod security_score;
mod severity_badge;
mod sidebar;
mod status_icons;
mod tabs;
mod theme_toggle;

pub use adhoc_host_input::AdhocHostInput;
#[allow(unused_imports)]
pub use card::CardVariant;
pub use card::{Card, HeadingLevel};
pub use clipboard::CopyButton;
pub use compliance_tab::ComplianceTab;
pub use config_file_card::ConfigFileCard;
pub use configure_section::ConfigureSection;
pub use confirm_delete::ConfirmDeleteButton;
pub use findings_tab::FindingsTab;
pub use history_section::HistorySection;
pub use host_form::HostForm;
pub use host_panel::{HostConnState, HostPanel};
pub use host_row::HostRow;
pub use notification_section::NotificationSection;
pub use recent_activity::RecentActivity;
pub use rollback_modal::RollbackModal;
pub use scan_history_tab::ScanHistoryTab;
pub use schedule_section::ScheduleSection;
pub use security_score::{SecurityScore, calculate_all_scores};
// SeverityBadge's only consumer was the fleet host FindingsGrid, retired in
// this slice with the Fleet screen it belonged to (the Analysis findings
// list carries severity via an inline dot and label instead). Kept, not
// deleted, in case a future screen wants a standalone badge.
#[allow(unused_imports)]
pub use severity_badge::SeverityBadge;
pub use sidebar::Sidebar;
// IconX/IconWrench/IconMinus/IconArrowRight are not yet called from any
// view - the review/drawer/done/partial slices wire them up (see
// status_icons.rs). Defined now so those slices import rather than re-add.
#[allow(unused_imports)]
pub use status_icons::{IconArrowRight, IconMinus, IconWrench, IconX};
pub use status_icons::{IconCheck, IconInfo};
pub use tabs::{TabBar, TabDef, TabPanel};
pub use theme_toggle::ThemeToggle;
