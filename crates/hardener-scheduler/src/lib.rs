//! Scheduled scanner daemon for Linux System Hardener
//!
//! Provides cron-like scheduled security scans with:
//! - Configurable scan intervals
//! - SQLite history storage
//! - JSON file exports
//! - Email and webhook notifications
//! - Systemd timer generation

pub mod config;
pub mod daemon;
pub mod db;
pub mod json_store;
pub mod runner;

pub use config::SchedulerConfig;
pub use daemon::Daemon;
pub use db::ScanHistoryManager;
pub use json_store::JsonStore;
pub use runner::{ScanRunner, ScanSummary, TriggerType};
