use clap::{Parser, Subcommand, ValueEnum};
pub(crate) use hardener_compliance::OutputFormat;

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

    /// Remote host to scan via SSH (user@host or host).
    #[arg(global = true, long, value_name = "HOST")]
    pub ssh: Option<String>,

    /// SSH port.
    #[arg(global = true, long, default_value = "22", value_name = "PORT")]
    pub port: u16,

    /// SSH identity file (private key).
    #[arg(global = true, long, value_name = "FILE")]
    pub ssh_key: Option<std::path::PathBuf>,

    /// SSH connection timeout in seconds.
    #[arg(global = true, long, default_value = "30", value_name = "SECONDS")]
    pub ssh_timeout: u64,

    /// Skip SSH host key verification (insecure).
    #[arg(global = true, long)]
    pub ssh_no_verify: bool,
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
        /// Apply specific plugins (can be repeated).
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

    /// Manage the scheduled scanning daemon.
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },

    /// Manage systemd unit files for scheduled scanning.
    Systemd {
        #[command(subcommand)]
        action: SystemdAction,
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

#[derive(Subcommand)]
pub enum DaemonAction {
    /// Start the scheduling daemon (blocks until shutdown).
    Start,
    /// Run a single scan immediately without starting the daemon,
    RunOnce,
    /// Show daemon status and recent scan history.
    Status {
        /// Number of recent sessions to show.
        limit: u32,
    },
}

#[derive(Subcommand)]
pub enum SystemdAction {
    /// Generate systemd unit files and print to stdout.
    Generate {
        /// Write files to this directory instead of stdout.
        #[arg(short, long, value_name = "DIR")]
        output: Option<std::path::PathBuf>,

        /// Path to the hardener binary (auto-detected if not specified).
        #[arg(long, value_name = "PATH")]
        binary: Option<std::path::PathBuf>,

        /// Schedule in systemd calendar format (e.g., "daily", "*-*-* 02:00:00").
          #[arg(short, long, default_value = "daily")]
          schedule: String,
    },

    /// Install unit files to systemd (requires root for system install).

    Install {
        /// Install as user service instead of system service.
        #[arg(long)]
        user: bool,

        /// Schedule in systemd calendar format.
        #[arg(short, long, default_value = "daily")]
        schedule: String,
    },

    /// Uninstall unit files from systemd.
    Uninstall {
        /// Uninstall user service instead of system service.
        #[arg(long)]
        user: bool,
    },

    /// Show systemd timer and service status.
    Status {
        /// Show user service status instead of system service.
        #[arg(long)]
        user: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportFormat {
    Text,
    Json,
    Csv,
    Html,
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_cli_parse_scan() {
        let cli = Cli::parse_from(["hardener", "scan"]);
        assert!(matches!(cli.command, Command::Scan { .. }));
    }

    #[test]
    fn test_cli_parse_scan_with_plugin() {
        let cli = Cli::parse_from(["hardener", "scan", "--plugin", "kernel"]);
        if let Command::Scan { plugin, .. } = cli.command {
            assert_eq!(plugin, vec!["kernel"]);
        } else {
            panic!("Expected Scan command");
        }
    }

    #[test]
    fn test_cli_parse_scan_with_severity() {
        let cli = Cli::parse_from(["hardener", "scan", "--severity", "high"]);
        if let Command::Scan { severity, .. } = cli.command {
            assert!(matches!(severity, SeverityFilter::High));
        } else {
            panic!("Expected Scan command");
        }
    }

    #[test]
    fn test_cli_parse_apply() {
        let cli = Cli::parse_from(["hardener", "apply", "--all"]);
        if let Command::Apply { all, .. } = cli.command {
            assert!(all);
        } else {
            panic!("Expected Apply command");
        }
    }

    #[test]
    fn test_cli_parse_apply_dry_run() {
        let cli = Cli::parse_from(["hardener", "apply", "--all", "--dry-run"]);
        if let Command::Apply { dry_run, .. } = cli.command {
            assert!(dry_run);
        } else {
            panic!("Expected Apply command");
        }
    }

    #[test]
    fn test_cli_parse_plugins() {
        let cli = Cli::parse_from(["hardener", "plugins"]);
        assert!(matches!(cli.command, Command::Plugins));
    }

    #[test]
    fn test_cli_parse_report_framework() {
        let cli = Cli::parse_from(["hardener", "report", "--framework", "cis"]);
        if let Command::Report { framework, .. } = cli.command {
            assert_eq!(framework, Some("cis".to_string()));
        } else {
            panic!("Expected Report command");
        }
    }

    #[test]
    fn test_cli_parse_checkpoint_list() {
        let cli = Cli::parse_from(["hardener", "checkpoint", "list"]);
        if let Command::Checkpoint { action } = cli.command {
            assert!(matches!(action, CheckpointAction::List));
        } else {
            panic!("Expected Checkpoint command");
        }
    }

    #[test]
    fn test_cli_parse_checkpoint_create() {
        let cli = Cli::parse_from(["hardener", "checkpoint", "create", "my-checkpoint"]);
        if let Command::Checkpoint { action } = cli.command {
            if let CheckpointAction::Create { name } = action {
                assert_eq!(name, "my-checkpoint");
            } else {
                panic!("Expected Create action");
            }
        } else {
            panic!("Expected Checkpoint command");
        }
    }

    #[test]
    fn test_cli_global_format_json() {
        let cli = Cli::parse_from(["hardener", "--format", "json", "scan"]);
        assert!(matches!(cli.format, OutputFormat::Json));
    }

    #[test]
    fn test_cli_global_quiet() {
        let cli = Cli::parse_from(["hardener", "--quiet", "scan"]);
        assert!(cli.quiet);
    }

    #[test]
    fn test_scan_mode_default() {
        let mode = ScanMode::default();
        assert_eq!(mode, ScanMode::Default);
    }

    #[test]
    fn test_severity_filter_default() {
        let filter = SeverityFilter::default();
        assert!(matches!(filter, SeverityFilter::Info));
    }

    #[test]
    fn test_report_format_values() {
        assert!(matches!(
            ReportFormat::from_str("text", true).unwrap(),
            ReportFormat::Text
        ));
        assert!(matches!(
            ReportFormat::from_str("json", true).unwrap(),
            ReportFormat::Json
        ));
        assert!(matches!(
            ReportFormat::from_str("csv", true).unwrap(),
            ReportFormat::Csv
        ));
        assert!(matches!(
            ReportFormat::from_str("html", true).unwrap(),
            ReportFormat::Html
        ));
    }

    #[test]
    fn test_cli_parse_systemd_generate() {
        let cli = Cli::parse_from(["hardener", "systemd", "generate"]);
        if let Command::Systemd { action } = cli.command {
            assert!(matches!(action, SystemdAction::Generate { .. }));
        } else {
            panic!("Expected Systemd command");
        }
    }

    #[test]
    fn test_cli_parse_systemd_install_user() {
        let cli = Cli::parse_from(["hardener", "systemd", "install", "--user"]);
        if let Command::Systemd { action } = cli.command {
            if let SystemdAction::Install { user, .. } = action {
                assert!(user);
            } else {
                panic!("Expected Install action");
            }
        } else {
            panic!("Expected Systemd command");
        }
    }

}
