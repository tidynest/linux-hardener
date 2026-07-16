//! Compliance framework mapping and report generation.
//!
//! This crate provides:
//! - Compliance framework definitions (CIS, STIG, NIST, etc.)
//! - Report generation from scan findings
//! - Multiple output formats (text, JSON, CSV, HTML)
//!
//! # Architecture
//!
//! The compliance system is designed for use by both CLI and GUI:
//!
//! ```text
//! ┌─────────────┐     ┌─────────────┐
//! │ CLI         │     │ GUI         │
//! └──────┬──────┘     └──────┬──────┘
//!        │                   │
//!        ▼                   ▼
//! ┌─────────────────────────────────┐
//! │     hardener-compliance         │
//! │  - ReportConfig                 │
//! │  - ReportGenerator              │
//! │  - ReportFormatter              │
//! └─────────────────────────────────┘
//! ```

pub mod config;
pub mod frameworks;
pub mod generator;
pub mod output;
pub mod profiles;
pub mod report;

pub use config::{OutputFormat, ReportConfig, Scenario};
pub use generator::ReportGenerator;
pub use output::{
    CsvFormatter, HtmlFormatter, JsonFormatter, PdfFormatter, ReportFormatter, TextFormatter,
};
pub use profiles::{profile_label, translate};
pub use report::{ComplianceReport, ComplianceSummary, ControlResult};
