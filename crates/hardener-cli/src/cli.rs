//! CLI argument definitions: clap derive-based parser for all subcommands and global flags.

use clap::{Parser, Subcommand, ValueEnum};
pub(crate) use hardener_compliance::OutputFormat;

#[derive(Parser)]
#[command(
    name = "hardener",
    author = "Eric Jingryd <tidynest@proton.me>",
    version = concat!(
        env!("CARGO_PKG_VERSION"),
        " (",
        env!("HARDENER_BUILD_IDENTITY"),
        ")"
    ),
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
    pub format: GlobalFormat,
    /// Suppress non-essential output.
    #[arg(global = true, short, long)]
    pub quiet: bool,
    /// Path to configuration file.
    #[arg(global = true, short = 'C', long, value_name = "FILE")]
    pub config: Option<std::path::PathBuf>,
    /// Remote host to act on via SSH (user@host or host). Refused, before any
    /// connection, by the commands that act on this host alone.
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

/// The formats the global `-f`/`--format` flag actually renders.
///
/// Deliberately two-valued, where the compliance crate's [`OutputFormat`] has
/// five. The flag was typed as that enum because it already existed, and clap
/// therefore accepted `csv`, `html` and `pdf` on every command in the binary
/// while not one of them rendered any of the three: every renderer matches
/// `Json` and sends the rest to a text arm, so the three were byte-identical
/// aliases of `text`. Proved rather than assumed, by hashing the output of
/// eight verbs across all five values.
///
/// The three real formatters are not lost, because the global flag was never
/// their route: `report --report-format` reaches them, and so does the wizard's
/// format multiselect. Narrowing the type here means clap refuses the three at
/// parse time, with the possible values listed, exactly as it already refuses
/// `--format xml` and as `report --report-format` already refuses a value it
/// cannot render.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum GlobalFormat {
    /// Human-readable output for a terminal.
    Text,
    /// Machine-readable output for automation.
    Json,
}

impl From<GlobalFormat> for OutputFormat {
    fn from(format: GlobalFormat) -> OutputFormat {
        match format {
            GlobalFormat::Text => OutputFormat::Text,
            GlobalFormat::Json => OutputFormat::Json,
        }
    }
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

        /// Exit with code 1 if findings exist (useful for CI/CD).
        #[arg(long)]
        exit_code: bool,

        /// Minimum severity to report.
        #[arg(short, long, default_value = "info")]
        severity: SeverityFilter,

        /// Print a per-plugin timing table after the scan.
        #[arg(long)]
        timings: bool,
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

        /// Specific framework to report on (cis, stig, nist, pcidss, hipaa, gdpr, iso27001, soc2, 800-171, fedramp).
        #[arg(long, conflicts_with = "scenario")]
        framework: Option<String>,

        /// Compliance ID profile (generic, rhel10). Default: auto-detect from
        /// the target system.
        #[arg(long)]
        profile: Option<String>,

        /// Output format (text, json, csv, html, pdf).
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

        /// Ad-hoc host not in the inventory (user@host[:port], repeatable).
        #[arg(long)]
        ssh: Vec<String>,

        /// Maximum hosts scanned in parallel.
        #[arg(long, default_value_t = 8)]
        concurrency: usize,

        /// Write the report to a file instead of stdout. Note: the command
        /// still exits 1 when findings exist, even on a successful scan, so
        /// a following `&&` will short-circuit; use `;` or inspect this file.
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

        /// Single framework: cis, stig, nist, pcidss, hipaa, gdpr, iso27001, soc2, 800-171, fedramp.
        #[arg(long, conflicts_with = "scenario")]
        framework: Option<String>,

        /// Compliance ID profile (generic, rhel10). Default: auto-detect from
        /// the target system.
        #[arg(long)]
        profile: Option<String>,

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

    /// Apply hardening to selected hosts concurrently. Dry-run (validate only)
    /// unless --execute is given.
    Apply {
        /// Apply to every host in the inventory.
        #[arg(long, conflicts_with = "host")]
        all: bool,

        /// Inventory host name to apply (comma-separated or repeated).
        #[arg(long, value_delimiter = ',')]
        host: Vec<String>,

        /// Ad-hoc host not in the inventory (user@host[:port], repeatable).
        #[arg(long)]
        ssh: Vec<String>,

        /// Apply only these plugins (comma-separated or repeated). Default: all.
        #[arg(long, value_delimiter = ',')]
        plugin: Vec<String>,

        /// Actually apply changes. Without this flag, runs a dry-run.
        #[arg(long)]
        execute: bool,

        /// Maximum hosts applied in parallel.
        #[arg(long, default_value_t = 8)]
        concurrency: usize,

        /// Write the report to a file instead of stdout.
        #[arg(long)]
        output: Option<String>,
    },

    /// Roll back selected hosts to their latest per-plugin checkpoint
    /// concurrently. Dry-run (preview only) unless --execute is given.
    Rollback {
        /// Roll back every host in the inventory.
        #[arg(long, conflicts_with = "host")]
        all: bool,

        /// Inventory host name to roll back (comma-separated or repeated).
        #[arg(long, value_delimiter = ',')]
        host: Vec<String>,

        /// Ad-hoc host not in the inventory (user@host[:port], repeatable).
        #[arg(long)]
        ssh: Vec<String>,

        /// Roll back only these plugins (comma-separated or repeated). Default: all.
        #[arg(long, value_delimiter = ',')]
        plugin: Vec<String>,

        /// Actually restore. Without this flag, runs a dry-run preview.
        #[arg(long)]
        execute: bool,

        /// Maximum hosts rolled back in parallel.
        #[arg(long, default_value_t = 8)]
        concurrency: usize,

        /// Write the report to a file instead of stdout.
        #[arg(long)]
        output: Option<String>,
    },
}

/// One command's refusal of the global `--ssh` flag: what to call the command,
/// and what it acts on instead.
///
/// A pair rather than a finished sentence so the wording is assembled at the
/// one place that prints it, and each arm below states only what is true of
/// itself.
pub struct SshRefusal {
    /// The invocation as an operator types it, such as `history list`.
    pub command: &'static str,
    /// What the command acts on, phrased to follow "because".
    pub because: &'static str,
}

impl Command {
    /// `None` where the global `--ssh` reaches this command's work, and a
    /// refusal where it does not.
    ///
    /// One executor is built for the whole process and then handed to some
    /// commands and not to others. Until this existed, the difference was
    /// invisible from the outside: a command that never receives it opened the
    /// connection, announced it unless `--quiet` had silenced that line, and
    /// then acted on the controller. The flag's only live effect on those
    /// commands was that an unreachable host stopped them, so it could refuse
    /// work but never redirect it, and under `--quiet` it did both silently.
    ///
    /// The answer is a property of the parse alone, so the refusal can be made
    /// before the connection is attempted: a refused command costs no round
    /// trip, no key prompt and no host-key decision.
    ///
    /// **`batch` is not one of the refusals, and the reason is worth knowing
    /// before changing this.** Each of its four subcommands declares an `ssh`
    /// argument of its own; clap resolves that and the global one to a single
    /// argument, since the identifiers are the same. `--ssh host batch scan`
    /// and `batch scan --ssh host` therefore produce one identical parse, in
    /// which the global field and batch's ad-hoc target list both hold the
    /// value. Refusing `batch` here would refuse every ad-hoc fleet run,
    /// including the desktop's, which composes exactly that vector.
    pub fn ssh_refusal(&self) -> Option<SshRefusal> {
        let refuse = |command, because| Some(SshRefusal { command, because });
        match self {
            // These four thread the executor through to the host they name.
            Command::Scan { .. }
            | Command::Apply { .. }
            | Command::Rollback { .. }
            | Command::Report { .. } => None,

            // `list` and `create` ask the target through the executor: the
            // first scopes its rows to that host's key, the second captures
            // that host's files. `show` and `delete` address one row of this
            // host's own database by an id that is unique across every host in
            // it, so the flag selects nothing there. Scoping those two to a
            // host was tried and reverted: the key of a decommissioned host
            // cannot be produced without connecting to it, so its rows became
            // undeletable, and the desktop deletes by id with no flags at all.
            Command::Checkpoint { action } => match action {
                CheckpointAction::List { .. } | CheckpointAction::Create { .. } => None,
                CheckpointAction::Show { .. } => refuse(
                    "checkpoint show",
                    "it reads one row of this host's checkpoint database, by an \
                     id that names it whichever host it was captured from",
                ),
                CheckpointAction::Delete { .. } => refuse(
                    "checkpoint delete",
                    "it removes one row from this host's checkpoint database, by \
                     an id that names it whichever host it was captured from",
                ),
            },

            // `batch` honours it, and not by accident of naming: each of its
            // four subcommands declares an `ssh` argument of its own, and clap
            // resolves both to one argument because the identifiers match. So
            // `--ssh host batch scan` and `batch scan --ssh host` are the same
            // parse, and both fill batch's ad-hoc target list. Measured, not
            // assumed, and asserted below in `cli/tests.rs`.
            Command::Batch { .. } => None,
            Command::Plugins => refuse(
                "plugins",
                "it lists the plugins compiled into this binary and asks no host \
                 anything",
            ),
            Command::Daemon { action } => match action {
                DaemonAction::Start => refuse(
                    "daemon start",
                    "the scheduling daemon runs on this host, on this host's \
                     timer, and writes this host's database",
                ),
                DaemonAction::RunOnce => refuse(
                    "daemon run-once",
                    "it scans through a local context and files the result under \
                     this host; scanning a remote is `--ssh HOST scan`",
                ),
                DaemonAction::Status { .. } => refuse(
                    "daemon status",
                    "it reads this host's own scheduler database",
                ),
            },
            Command::Systemd { action } => match action {
                SystemdAction::Generate { .. } => refuse(
                    "systemd generate",
                    "it writes a unit file naming this host's binary and this \
                     host's configuration",
                ),
                SystemdAction::Install { .. } => refuse(
                    "systemd install",
                    "it installs unit files into this host's own systemd",
                ),
                SystemdAction::Uninstall { .. } => refuse(
                    "systemd uninstall",
                    "it removes unit files from this host's own systemd",
                ),
                SystemdAction::Status { .. } => {
                    refuse("systemd status", "it reads this host's own systemd")
                }
            },
            Command::History { action } => match action {
                HistoryAction::List { .. } => refuse(
                    "history list",
                    "it reads this host's own scan history, in which a host is \
                     selected with --host",
                ),
                HistoryAction::Trends { .. } => refuse(
                    "history trends",
                    "it reads this host's own scan history, and it already takes \
                     the host as --host",
                ),
                HistoryAction::Regressions { .. } => refuse(
                    "history regressions",
                    "it reads this host's own scan history, in which a host is \
                     selected with --host",
                ),
                HistoryAction::Show { .. } => refuse(
                    "history show",
                    "it reads one session out of this host's own scan history",
                ),
                HistoryAction::Export { .. } => refuse(
                    "history export",
                    "it writes one session out of this host's own scan history \
                     to a file on this host",
                ),
            },
        }
    }
}

#[derive(Subcommand)]
pub enum CheckpointAction {
    /// List checkpoints, newest first.
    List {
        /// Maximum number of checkpoints to show.
        #[arg(short, long, default_value = "20")]
        limit: usize,

        /// Show every checkpoint, ignoring the limit.
        #[arg(long)]
        all: bool,
    },

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
}

#[cfg(test)]
mod tests;
