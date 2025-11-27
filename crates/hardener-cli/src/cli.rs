use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "hardener",
    author = "Eric Jingryd <tidynest@proton.me>",
    version,
    about = "Linux System Hardener - Security automation tool",
    long_about = "A comprehensive Linux security automation tool with \
    multi-distribution support.\n\n\
    Scans systems for security misconfigurations, applies \
    hardening recommendations,\n\
    and provides rollback capabilities via checkpoint \
    snapshots."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Output format.
    #[arg(global = true, short, long, default_value = "text")]
    pub format: OutputFormat,

    /// Suppress non-essential output.
    #[arg(global = true, short, long)]
    pub quiet: bool,

    /// Path to configuration file.
    #[arg(global = true, short = 'C', long, value_name = "FILE")]
    pub config: Option<std::path::PathBuf>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Scan system for security issues.
    Scan {
        /// Only scan specific plugins (can be repeated).
        #[arg(short, long)]
        plugin: Vec<String>,

        /// Audit mode: ignore config, pure security assessment.
        #[arg(long)]
        audit: bool,

        /// Compliance mode: only show policy violations.
        #[arg(long, conflicts_with = "audit")]
        compliance: bool,

        /// Exit with code 1 if findings exist (useful for CI/CD).
        #[arg(long)]
        exit_code: bool,

        /// Minimum severity to report.
        #[arg(short, long, default_value = "info")]
        severity: SeverityFilter,
    },

    /// Apply hardening recommendations.
    Apply {
        /// Apply specific plugins (can be repreated).
        #[arg(short, long)]
        plugin: Vec<String>,

        /// Apply all available plugins.
        #[arg(short, long, conflicts_with = "plugin")]
        all: bool,

        /// Show what would be changed without applying (dry-run).
        #[arg(long)]
        dry_run: bool,
    },

    /// Rollback to a previous checkpoint.
    Rollback {
        /// Checkpoint ID to restore.
        checkpoint_id: String,
    },

    /// Manage checkpoints.
    Checkpoint {
        #[command(subcommand)]
        action: CheckpointAction,
    },

    /// List available security plugins.
    Plugins,

    /// Generate compliance reports.
    Report {
        /// Yse case scenario (server, workstation, government, healthcare, financial, gdpr, all).
        #[arg(short, long)]
        scenario: Option<String>,

        /// Specific framework to report on (cis, stig, nist, pcidss, hipaa, gdpr).
        #[arg(long, conflicts_with = "scenario")]
        framework: Option<String>,

        /// Output format (text, json).
        #[arg(long, default_value = "text")]
        report_format: String,

        /// Output file path (prints to stdout if not specified).
        #[arg(short, long)]
        output: Option<String>,

        /// Launch interactive wizard to configure report.
        #[arg(short, long)]
        interactive: bool,
    },
}

#[derive(Subcommand)]
pub enum CheckpointAction {
    /// List all checkpoints.
    List,

    /// Create a new checkpoint.
    Create { name: String },

    /// Delete a checkpoint.
    Delete { checkpoint_id: String },

    /// Show checkpoint details.
    Show { checkpoint_id: String },
}

#[derive(ValueEnum, Clone, Default)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

#[derive(ValueEnum, Clone, Default)]
pub enum SeverityFilter {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Scan output mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ScanMode {
    /// Default mode: show all findings with policy annotations.
    #[default]
    Default,
    /// Audit mode: ignore config, pure security assessment.
    Audit,
    /// Compliance mode: only show findings without valid policy exceptions.
    Compliance,
}
