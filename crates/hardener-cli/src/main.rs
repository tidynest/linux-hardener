mod cli;
mod commands;
mod output;
mod ssh_config;

use anyhow::Result;
use clap::Parser;
use cli::{CheckpointAction, Cli, Command, DaemonAction, SystemdAction};
use commands::scan::ScanOptions;
use hardener_core::{executor::SystemExecutor, LocalExecutor, SshExecutor};
use ssh_config::SshConnectionConfig;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Create executor based on SSH flags
    let executor: Arc<dyn SystemExecutor> = if let Some(ref ssh_target) = cli.ssh {
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
                executor: executor.clone(),
            })
            .await
        }
        Command::Apply {
            plugin,
            all,
            dry_run,
        } => commands::apply::run(
            &plugin, all, dry_run, cli.format, cli.quiet, executor.clone()
        ).await,
        Command::Rollback { checkpoint_id } => {
            commands::checkpoint::rollback(
                &checkpoint_id, cli.format, cli.quiet
            ).await
        }
        Command::Checkpoint { action } => match action {
            CheckpointAction::List => commands::checkpoint::list(cli.format, cli.quiet).await,
            CheckpointAction::Create { name } => {
                commands::checkpoint::create(&name, cli.format, cli.quiet).await
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
                    report_format,
                    output,
                    cli.format,
                    cli.quiet,
                    executor.clone(),
                )
                .await
            }
        }
        Command::Daemon { action } => match action {
            DaemonAction::Start => commands::daemon::start(cli.format, cli.quiet).await,
            DaemonAction::RunOnce => commands::daemon::run_once(cli.format, cli.quiet).await,
            DaemonAction::Status { limit } => {
                commands::daemon::status(cli.format, cli.quiet, limit).await
            }
        },
        Command::Systemd { action } => match action {
            SystemdAction::Generate { output, binary, schedule } => {
                commands::systemd::generate(output, binary, schedule, cli.config, cli.quiet).await
            }
            SystemdAction::Install { user, schedule } => {
                commands::systemd::install(user, schedule, cli.config, cli.quiet).await
            }
            SystemdAction::Uninstall { user } => {
                commands::systemd::uninstall(user, cli.quiet).await
            }
            SystemdAction::Status { user } => {
                commands::systemd::status(user, cli.quiet).await
            }
        },
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    Ok(())
}
