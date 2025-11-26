mod cli;
mod commands;
mod output;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Command, CheckpointAction};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    let result = match cli.command {
        Command::Scan { plugin, severity } => {
            commands::scan::run(&plugin, severity, cli.format, cli.quiet).await
        }
        Command::Apply { plugin, all, dry_run } => {
            commands::apply::run(&plugin, all, dry_run, cli.format, cli.quiet).await
        }
        Command::Rollback { checkpoint_id } => {
            commands::checkpoint::rollback(&checkpoint_id, cli.format, cli.quiet).await
        }
        Command::Checkpoint { action } => match action {
            CheckpointAction::List => {
                commands::checkpoint::list(cli.format, cli.quiet).await
            }
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
        Command::Plugins => {
            commands::plugins::run(cli.format, cli.quiet).await
        }
        Command::Report { scenario, framework, report_format, output } => {
            commands::report::run(scenario, framework, report_format, output, cli.format, cli.quiet).await
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
    
    Ok(())
}