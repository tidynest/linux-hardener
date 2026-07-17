//! CLI entry point — parses arguments and dispatches to subcommand handlers.

mod cli;
mod commands;
mod output;
mod ssh_config;

use anyhow::Result;
use clap::Parser;
use cli::{
    BatchAction, CheckpointAction, Cli, Command, DaemonAction, HistoryAction, SystemdAction,
};
use commands::scan::ScanOptions;
use hardener_core::{LocalExecutor, SshExecutor, executor::SystemExecutor};
use ssh_config::SshConnectionConfig;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Create executor based on SSH flags
    let executor: Arc<dyn SystemExecutor> = if matches!(cli.command, Command::Batch { .. }) {
        Arc::new(LocalExecutor::new()) // unused by batch; avoids a global SSH connect
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
            compliance,
            exit_code,
            timings,
        } => {
            commands::scan::run(ScanOptions {
                plugin_filter: &plugin,
                severity_filter: severity,
                format: cli.format,
                quiet: cli.quiet,
                config_path: cli.config.as_ref(),
                audit,
                compliance,
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
        } => {
            commands::apply::run(
                &plugin,
                all,
                dry_run,
                cli.format,
                cli.quiet,
                executor.clone(),
            )
            .await
        }
        Command::Rollback { checkpoint_id } => {
            commands::checkpoint::rollback(&checkpoint_id, cli.format, cli.quiet, executor.clone())
                .await
        }
        Command::Checkpoint { action } => match action {
            CheckpointAction::List => {
                commands::checkpoint::list(cli.format, cli.quiet, executor.clone()).await
            }
            CheckpointAction::Create { name } => {
                commands::checkpoint::create(&name, cli.format, cli.quiet, executor.clone()).await
            }
            CheckpointAction::Delete { checkpoint_id } => {
                commands::checkpoint::delete(&checkpoint_id, cli.format, cli.quiet).await
            }
            CheckpointAction::Show { checkpoint_id } => {
                commands::checkpoint::show(&checkpoint_id, cli.format, cli.quiet).await
            }
        },
        Command::Plugins => commands::plugins::run(cli.format, cli.quiet).await,
        Command::Report {
            scenario,
            framework,
            profile,
            report_format,
            output,
            interactive,
        } => {
            if interactive {
                commands::report_wizard::run(cli.quiet).await
            } else {
                commands::report::run(
                    scenario,
                    framework,
                    profile,
                    report_format,
                    output,
                    cli.format,
                    cli.quiet,
                    executor.clone(),
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
                    format: cli.format,
                    output,
                    quiet: cli.quiet,
                    global_key: cli
                        .ssh_key
                        .as_ref()
                        .map(|p| p.to_string_lossy().to_string()),
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
                    framework,
                    profile,
                    scenario,
                    format: cli.format,
                    output,
                    quiet: cli.quiet,
                    global_key: cli
                        .ssh_key
                        .as_ref()
                        .map(|p| p.to_string_lossy().to_string()),
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
                    format: cli.format,
                    output,
                    quiet: cli.quiet,
                    global_key: cli
                        .ssh_key
                        .as_ref()
                        .map(|p| p.to_string_lossy().to_string()),
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
                    format: cli.format,
                    output,
                    quiet: cli.quiet,
                    global_key: cli
                        .ssh_key
                        .as_ref()
                        .map(|p| p.to_string_lossy().to_string()),
                    global_timeout: cli.ssh_timeout,
                    global_no_verify: cli.ssh_no_verify,
                })
                .await
            }
        },
        Command::Daemon { action } => match action {
            DaemonAction::Start => commands::daemon::start(cli.format, cli.quiet).await,
            DaemonAction::RunOnce => commands::daemon::run_once(cli.format, cli.quiet).await,
            DaemonAction::Status { limit } => {
                commands::daemon::status(cli.format, cli.quiet, limit).await
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
            } => commands::history::list(cli.format, cli.quiet, limit, host, status).await,
            HistoryAction::Trends { host, limit } => {
                commands::history::trends(cli.format, cli.quiet, &host, limit).await
            }
            HistoryAction::Regressions { host } => {
                commands::history::regressions(cli.format, cli.quiet, host).await
            }
            HistoryAction::Show { session_id } => {
                commands::history::show(&session_id, cli.format, cli.quiet).await
            }
            HistoryAction::Export { session_id, output } => {
                commands::history::export(&session_id, output, cli.format, cli.quiet).await
            }
        },
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    Ok(())
}
