//! CLI argument definitions — clap derive-based parser for all subcommands and global flags.

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
        /// Use case scenario (server, workstation, government, healthcare, financial, gdpr, all).
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

    /// Scan multiple remote hosts in one run.
    Batch {
        #[command(subcommand)]
        action: BatchAction,
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

    /// View and export scan history.
    History {
        #[command(subcommand)]
        action: HistoryAction,
    },
}

#[derive(Subcommand)]
pub enum BatchAction {
    /// Scan selected hosts concurrently and print an aggregate report.
    Scan {
        /// Scan every host in the inventory.
        #[arg(long, conflicts_with = "host")]
        all: bool,

        /// Inventory host name to scan (comma-separated or repeated).
        #[arg(long, value_delimiter = ',')]
        host: Vec<String>,

        /// Ad-hoc host not in the inventory (user@host, repeatable).
        #[arg(long)]
        ssh: Vec<String>,

        /// Maximum hosts scanned in parallel.
        #[arg(long, default_value_t = 8)]
        concurrency: usize,

        /// Write the report to a file instead of stdout.
        #[arg(long)]
        output: Option<String>,
    },

    /// Assess selected hosts against a compliance framework and print a fleet
    /// posture table.
    Report {
        /// Assess every host in the inventory.
        #[arg(long, conflicts_with = "host")]
        all: bool,

        /// Inventory host name to assess (comma-separated or repeated).
        #[arg(long, value_delimiter = ',')]
        host: Vec<String>,

        /// Ad-hoc host not in the inventory (user@host[:port], repeatable).
        #[arg(long)]
        ssh: Vec<String>,

        /// Single framework: cis, stig, nist, pcidss, hipaa, gdpr, iso27001.
        #[arg(long, conflicts_with = "scenario")]
        framework: Option<String>,

        /// Scenario preset: server, workstation, government, healthcare,
        /// financial, gdpr, all.
        #[arg(long)]
        scenario: Option<String>,

        /// Maximum hosts assessed in parallel.
        #[arg(long, default_value_t = 8)]
        concurrency: usize,

        /// Write the report to a file instead of stdout.
        #[arg(long)]
        output: Option<String>,
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
        #[arg(short, long, default_value = "10")]
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

        /// Schedule in systemd calendar format (e.g., "dail", "*-*-* 02:00:00").
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

#[derive(Subcommand)]
pub enum HistoryAction {
    /// List recent scan sessions.
    List {
        /// Maximum number of sessions to show.
        #[arg(short, long, default_value = "20")]
        limit: u32,

        /// Filter by host identifier.
        #[arg(long)]
        host: Option<String>,

        /// Filter by status (running, completed, failed).
        #[arg(long)]
        status: Option<String>,
    },

    /// Show a per-host security trend (findings over time, oldest first).
    Trends {
        /// Host identifier to chart (inventory name, or user@host:port for ad-hoc).
        #[arg(long)]
        host: String,

        /// Maximum number of scans to include.
        #[arg(short, long, default_value = "20")]
        limit: u32,
    },

    /// Report hosts whose latest scan is worse than the previous one.
    ///
    /// Exits 1 when any regression is found (so it can gate CI); 0 otherwise.
    Regressions {
        /// Limit to a single host identifier (default: check every host).
        #[arg(long)]
        host: Option<String>,
    },

    /// Show details of a specific scan session.
    Show {
        /// Session ID (UUID) to display.
        session_id: String,
    },

    /// Export a scan session to a JSON file.
    Export {
        /// Session ID (UUID) to export
        session_id: String,

        /// Output file path (defaults to session-<id>.json).
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
    },
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

    #[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
    pub enum ReportFormat {
        Text,
        Json,
        Csv,
        Html,
    }

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

    #[test]
    fn test_cli_parse_history_list() {
        let cli = Cli::parse_from(["hardener", "history", "list"]);
        if let Command::History { action } = cli.command {
            assert!(matches!(action, HistoryAction::List { .. }));
        } else {
            panic!("Expected History command");
        }
    }

    #[test]
    fn test_cli_parse_history_list_with_limit() {
        let cli = Cli::parse_from(["hardener", "history", "list", "--limit", "50"]);
        if let Command::History { action } = cli.command {
            if let HistoryAction::List { limit, .. } = action {
                assert_eq!(limit, 50);
            } else {
                panic!("Expected List action");
            }
        } else {
            panic!("Expected History command");
        }
    }

    #[test]
    fn test_cli_parse_history_list_with_filters() {
        let cli = Cli::parse_from([
            "hardener",
            "history",
            "list",
            "--host",
            "server1",
            "--status",
            "completed",
        ]);
        if let Command::History { action } = cli.command {
            if let HistoryAction::List { host, status, .. } = action {
                assert_eq!(host, Some("server1".to_string()));
                assert_eq!(status, Some("completed".to_string()));
            } else {
                panic!("Expected List action");
            }
        } else {
            panic!("Expected History command");
        }
    }

    #[test]
    fn test_cli_parse_history_show() {
        let cli = Cli::parse_from(["hardener", "history", "show", "abc-123"]);
        if let Command::History { action } = cli.command {
            if let HistoryAction::Show { session_id } = action {
                assert_eq!(session_id, "abc-123");
            } else {
                panic!("Expected Show action");
            }
        } else {
            panic!("Expected History command");
        }
    }

    #[test]
    fn test_cli_parse_history_export() {
        let cli = Cli::parse_from(["hardener", "history", "export", "abc-123"]);
        if let Command::History { action } = cli.command {
            if let HistoryAction::Export { session_id, output } = action {
                assert_eq!(session_id, "abc-123");
                assert!(output.is_none());
            } else {
                panic!("Expected Export action");
            }
        } else {
            panic!("Expected History command");
        }
    }

    #[test]
    fn test_cli_parse_batch_scan_all() {
        let cli = Cli::parse_from(["hardener", "batch", "scan", "--all"]);
        assert!(matches!(cli.command, Command::Batch { .. }));
        if let Command::Batch {
            action: BatchAction::Scan { all, .. },
        } = cli.command
        {
            assert!(all);
        } else {
            panic!("Expected Batch Scan command");
        }
    }

    #[test]
    fn test_cli_parse_batch_host_comma() {
        let cli = Cli::parse_from(["hardener", "batch", "scan", "--host", "web-01,db-02"]);
        if let Command::Batch {
            action: BatchAction::Scan { host, .. },
        } = cli.command
        {
            assert_eq!(host, vec!["web-01", "db-02"]);
        } else {
            panic!("Expected Batch Scan command");
        }
    }

    #[test]
    fn test_cli_parse_batch_all_conflicts_host() {
        assert!(
            Cli::try_parse_from(["hardener", "batch", "scan", "--all", "--host", "x"]).is_err()
        );
    }

    #[test]
    fn test_cli_parse_batch_defaults_and_output() {
        let cli = Cli::parse_from(["hardener", "batch", "scan", "--ssh", "u@h"]);
        if let Command::Batch {
            action:
                BatchAction::Scan {
                    concurrency,
                    output,
                    ..
                },
        } = cli.command
        {
            assert_eq!(concurrency, 8);
            assert!(output.is_none());
        } else {
            panic!("Expected Batch Scan command");
        }

        let cli = Cli::parse_from([
            "hardener",
            "batch",
            "scan",
            "--all",
            "--output",
            "/tmp/x",
            "--concurrency",
            "4",
        ]);
        if let Command::Batch {
            action:
                BatchAction::Scan {
                    concurrency,
                    output,
                    ..
                },
        } = cli.command
        {
            assert_eq!(output, Some("/tmp/x".to_string()));
            assert_eq!(concurrency, 4);
        } else {
            panic!("Expected Batch Scan command");
        }
    }

    #[test]
    fn test_cli_parse_batch_report_framework() {
        let cli = Cli::parse_from(["hardener", "batch", "report", "--all", "--framework", "cis"]);
        if let Command::Batch {
            action: BatchAction::Report { all, framework, .. },
        } = cli.command
        {
            assert!(all);
            assert_eq!(framework.as_deref(), Some("cis"));
        } else {
            panic!("Expected Batch Report command");
        }
    }

    #[test]
    fn test_cli_parse_batch_report_framework_conflicts_scenario() {
        assert!(
            Cli::try_parse_from([
                "hardener",
                "batch",
                "report",
                "--all",
                "--framework",
                "cis",
                "--scenario",
                "server",
            ])
            .is_err(),
            "--framework and --scenario are mutually exclusive",
        );
    }

    #[test]
    fn test_cli_parse_history_export_with_output() {
        let cli = Cli::parse_from([
            "hardener",
            "history",
            "export",
            "abc-123",
            "--output",
            "/tmp/export.json",
        ]);
        if let Command::History { action } = cli.command {
            if let HistoryAction::Export { session_id, output } = action {
                assert_eq!(session_id, "abc-123");
                assert_eq!(output, Some(std::path::PathBuf::from("/tmp/export.json")));
            } else {
                panic!("Expected Export action");
            }
        } else {
            panic!("Expected History command");
        }
    }
}
