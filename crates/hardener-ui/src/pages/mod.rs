pub mod analysis_page;
pub mod dashboard_page;
pub mod fleet_apply_page;
pub mod fleet_page;
pub mod hardening_page;
pub mod hosts_page;
pub mod remote_page;
pub mod scheduler_page;

pub use analysis_page::AnalysisPage;
pub use dashboard_page::DashboardPage;
pub use fleet_apply_page::FleetApplyPage;
pub use hardening_page::HardeningPage;
pub use hosts_page::HostsPage;
// FleetPage is orphaned once `/fleet` routes to HostsPage (Task 4); the merged
// Hosts page replaces it. Kept (with its module) until Task 5 deletes
// fleet_page.rs, so the re-export is temporarily unused.
#[allow(unused_imports)]
pub use fleet_page::FleetPage;
pub use remote_page::RemotePage;
pub use scheduler_page::SchedulerPage;
