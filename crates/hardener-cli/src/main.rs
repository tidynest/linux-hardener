//! CLI entry point: parses arguments and dispatches to subcommand handlers.

mod cli;
mod commands;
mod output;
mod ssh_config;

use anyhow::Result;
use clap::Parser;
use cli::{
    BatchAction, CheckpointAction, Cli, Command, DaemonAction, HistoryAction, OutputFormat,
    SystemdAction,
};
use commands::scan::ScanOptions;
use hardener_core::{LocalExecutor, SshExecutor, executor::SystemExecutor};
use ssh_config::SshConnectionConfig;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    // Without a subscriber the tracing macros are a no-op, so every warning the
    // engine raises on the path where apply actually runs was being discarded.
    // Some of those warnings have no `Change` counterpart and were the only
    // record that a step degraded, which made them wholly silent.
    hardener_common::logging::init_logger();

    let cli = Cli::parse();

    // The flag is two-valued; every command below takes the compliance crate's
    // wider enum, so the widening happens once, here, rather than at twenty-one
    // call sites.
    let format: OutputFormat = cli.format.into();

    // A command that cannot honour --ssh refuses it here, before the
    // connection is opened. Every command used to accept the flag while only
    // some received the executor built from it, so the rest announced a
    // connection, silently under --quiet, and then acted on this host. The
    // check is on the parsed global field: `batch` has its own --ssh for
    // ad-hoc targets, and matching the flag as a token would refuse that too.
    if cli.ssh.is_some()
        && let Some(refusal) = cli.command.ssh_refusal()
    {
        eprintln!(
            "Error: --ssh is not honoured by `{}`, because {}.",
            refusal.command, refusal.because
        );
        eprintln!("Re-run without --ssh, which changed nothing here but the exit status.");
        std::process::exit(2);
    }

    // Create executor based on SSH flags. Batch keeps a case of its own: its
    // subcommands declare an `ssh` argument that clap resolves to the same
    // argument as the global one, so `--ssh host batch scan` fills batch's
    // ad-hoc target list rather than asking for a session here. Connecting
    // would open a second, unused session to a host batch is about to reach on
    // its own terms.
    let executor: Arc<dyn SystemExecutor> = if matches!(cli.command, Command::Batch { .. }) {
        Arc::new(LocalExecutor::new())
    } else if let Some(ref ssh_target) = cli.ssh {
        let ssh_config = SshConnectionConfig::from_cli(
            ssh_target,
            cli.port,
            cli.ssh_key.clone(),
            cli.ssh_timeout,
            cli.ssh_no_verify,
        );

        if !cli.quiet {
            eprint!("Connecting to {}...", ssh_config.display());
        }

        let core_config = ssh_config.to_core_config();
        match SshExecutor::connect(core_config).await {
            Ok(executor) => Arc::new(executor),
            Err(e) => {
                eprintln!("SSH connection failed: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        Arc::new(LocalExecutor::new())
    };

    let result = match cli.command {
        Command::Scan {
            plugin,
            severity,
            audit,
            exit_code,
            timings,
        } => {
            commands::scan::run(ScanOptions {
                plugin_filter: &plugin,
                severity_filter: severity,
                format,
                quiet: cli.quiet,
                config_path: cli.config.as_ref(),
                audit,
                exit_code,
                timings,
                executor: executor.clone(),
            })
            .await
        }
        Command::Apply {
            plugin,
            all,
            dry_run,
        } => commands::apply::run(&plugin, all, dry_run, format, cli.quiet, executor.clone()).await,
        Command::Rollback { checkpoint_id } => {
            commands::checkpoint::rollback(&checkpoint_id, format, cli.quiet, executor.clone())
                .await
        }
        Command::Checkpoint { action } => match action {
            CheckpointAction::List { limit, all } => {
                commands::checkpoint::list(format, cli.quiet, executor.clone(), limit, all).await
            }
            CheckpointAction::Create { name } => {
                commands::checkpoint::create(&name, format, cli.quiet, executor.clone()).await
            }
            CheckpointAction::Delete { checkpoint_id } => {
                commands::checkpoint::delete(&checkpoint_id, format, cli.quiet).await
            }
            CheckpointAction::Show { checkpoint_id } => {
                commands::checkpoint::show(&checkpoint_id, format, cli.quiet).await
            }
        },
        Command::Plugins => commands::plugins::run(format, cli.quiet).await,
        Command::Report {
            scenario,
            framework,
            profile,
            report_format,
            output,
            interactive,
        } => {
            if interactive {
                commands::report_wizard::run(cli.quiet, executor.clone(), profile).await
            } else {
                commands::report::run(
                    scenario,
                    framework,
                    profile,
                    report_format,
                    output,
                    format,
                    cli.quiet,
                    executor.clone(),
                    cli.config.as_ref(),
                )
                .await
            }
        }
        Command::Batch { action } => match action {
            BatchAction::Scan {
                all,
                host,
                ssh,
                concurrency,
                output,
            } => {
                commands::batch::run(commands::batch::BatchOptions {
                    all,
                    host,
                    ssh,
                    concurrency,
                    config: cli.config.clone(),
                    format,
                    output,
                    quiet: cli.quiet,
                    global_key: cli
                        .ssh_key
                        .as_ref()
                        .map(|p| p.to_string_lossy().to_string()),
                    global_port: cli.port,
                    global_timeout: cli.ssh_timeout,
                    global_no_verify: cli.ssh_no_verify,
                })
                .await
            }
            BatchAction::Report {
                all,
                host,
                ssh,
                framework,
                profile,
                scenario,
                concurrency,
                output,
            } => {
                commands::batch::run_report(commands::batch::BatchReportOptions {
                    all,
                    host,
                    ssh,
                    concurrency,
                    config: cli.config.clone(),
                    framework,
                    profile,
                    scenario,
                    format,
                    output,
                    quiet: cli.quiet,
                    global_key: cli
                        .ssh_key
                        .as_ref()
                        .map(|p| p.to_string_lossy().to_string()),
                    global_port: cli.port,
                    global_timeout: cli.ssh_timeout,
                    global_no_verify: cli.ssh_no_verify,
                })
                .await
            }
            BatchAction::Apply {
                all,
                host,
                ssh,
                plugin,
                execute,
                concurrency,
                output,
            } => {
                commands::batch::run_apply(commands::batch::BatchApplyOptions {
                    all,
                    host,
                    ssh,
                    plugin,
                    execute,
                    concurrency,
                    config: cli.config.clone(),
                    format,
                    output,
                    quiet: cli.quiet,
                    global_key: cli
                        .ssh_key
                        .as_ref()
                        .map(|p| p.to_string_lossy().to_string()),
                    global_port: cli.port,
                    global_timeout: cli.ssh_timeout,
                    global_no_verify: cli.ssh_no_verify,
                })
                .await
            }
            BatchAction::Rollback {
                all,
                host,
                ssh,
                plugin,
                execute,
                concurrency,
                output,
            } => {
                commands::batch::run_rollback(commands::batch::BatchRollbackOptions {
                    all,
                    host,
                    ssh,
                    plugin,
                    execute,
                    concurrency,
                    format,
                    output,
                    quiet: cli.quiet,
                    global_key: cli
                        .ssh_key
                        .as_ref()
                        .map(|p| p.to_string_lossy().to_string()),
                    global_port: cli.port,
                    global_timeout: cli.ssh_timeout,
                    global_no_verify: cli.ssh_no_verify,
                })
                .await
            }
        },
        Command::Daemon { action } => match action {
            DaemonAction::Start => commands::daemon::start(format, cli.quiet).await,
            DaemonAction::RunOnce => commands::daemon::run_once(format, cli.quiet).await,
            DaemonAction::Status { limit } => {
                commands::daemon::status(format, cli.quiet, limit).await
            }
        },
        Command::Systemd { action } => match action {
            SystemdAction::Generate {
                output,
                binary,
                schedule,
            } => commands::systemd::generate(output, binary, schedule, cli.config, cli.quiet).await,
            SystemdAction::Install { user, schedule } => {
                commands::systemd::install(user, schedule, cli.config, cli.quiet).await
            }
            SystemdAction::Uninstall { user } => {
                commands::systemd::uninstall(user, cli.quiet).await
            }
            SystemdAction::Status { user } => commands::systemd::status(user, cli.quiet).await,
        },
        Command::History { action } => match action {
            HistoryAction::List {
                limit,
                host,
                status,
            } => commands::history::list(format, cli.quiet, limit, host, status).await,
            HistoryAction::Trends { host, limit } => {
                commands::history::trends(format, cli.quiet, &host, limit).await
            }
            HistoryAction::Regressions { host } => {
                commands::history::regressions(format, cli.quiet, host).await
            }
            HistoryAction::Show { session_id } => {
                commands::history::show(&session_id, format, cli.quiet).await
            }
            HistoryAction::Export { session_id, output } => {
                commands::history::export(&session_id, output, format, cli.quiet).await
            }
        },
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    Ok(())
}
