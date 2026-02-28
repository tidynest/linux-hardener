//! Systemd unit file management commands.

use anyhow::{Context, Result, bail};
use hardener_scheduler::systemd::{SystemdGenerator, cron_to_calendar, service_name, timer_name};
use std::path::PathBuf;
use tokio::{fs, process::Command};

/// Generates systemd unit files.
///
/// Prints to stdout or writes to the specified directory.
pub async fn generate(
    output_dir: Option<PathBuf>,
    binary_path: Option<PathBuf>,
    schedule: String,
    config_path: Option<PathBuf>,
    quiet: bool,
) -> Result<()> {
    let binary = resolve_binary_path(binary_path)?;
    let calendar = resolve_calendar(&schedule);

    let mut generator = SystemdGenerator::new(binary, calendar);
    if let Some(cfg) = config_path {
        generator = generator.with_config(cfg);
    }

    let service_content = generator.generate_service();
    let timer_content = generator.generate_timer();

    match output_dir {
        Some(dir) => {
            fs::create_dir_all(&dir)
                .await
                .context("Failed to create output directory")?;

            let service_path = dir.join(service_name());
            let timer_path = dir.join(timer_name());

            fs::write(&service_path, &service_content)
                .await
                .context("Failed to write service file")?;
            fs::write(&timer_path, &timer_content)
                .await
                .context("Failed to write timer file")?;

            if !quiet {
                println!("Generated: {}", service_path.display());
                println!("Generated: {}", timer_path.display());
            }
        }
        None => {
            println!("# {}\n{}", service_name(), service_content);
            println!("# {}\n{}", timer_name(), timer_content);
        }
    }

    Ok(())
}

/// Installs systemd unit files.
pub async fn install(
    user_mode: bool,
    schedule: String,
    config_path: Option<PathBuf>,
    quiet: bool,
) -> Result<()> {
    let binary = resolve_binary_path(None)?;
    let calendar = resolve_calendar(&schedule);

    let mut generator = SystemdGenerator::new(binary, calendar).with_user_mode(user_mode);
    if let Some(cfg) = config_path {
        generator = generator.with_config(cfg);
    }

    let unit_dir = if user_mode {
        dirs::home_dir()
            .context("Could not determine home directory")?
            .join(".config/systemd/user")
    } else {
        PathBuf::from("/etc/systemd/system")
    };

    // Check permissions for system install
    if !user_mode && !nix::unistd::Uid::effective().is_root() {
        bail!("System install requires root privileges. Use --user for user install.");
    }

    fs::create_dir_all(&unit_dir)
        .await
        .context("Failed to create unit directory")?;

    let service_path = unit_dir.join(service_name());
    let timer_path = unit_dir.join(timer_name());

    fs::write(&service_path, generator.generate_service())
        .await
        .context("Failed to write service file")?;
    fs::write(&timer_path, generator.generate_timer())
        .await
        .context("Failed to write timer file")?;

    if !quiet {
        println!("Installed: {}", service_path.display());
        println!("Installed: {}", timer_path.display());
    }

    // Reload systemd and enable timer
    let systemctl_args: &[&str] = if user_mode {
        &["--user", "daemon-reload"]
    } else {
        &["daemon-reload"]
    };

    Command::new("systemctl")
        .args(systemctl_args)
        .status()
        .await
        .context("Failed to reload systemd")?;

    let enable_args: Vec<&str> = if user_mode {
        vec!["--user", "enable", "--now", timer_name()]
    } else {
        vec!["enable", "--now", timer_name()]
    };

    Command::new("systemctl")
        .args(&enable_args)
        .status()
        .await
        .context("Failed to enable timer")?;

    if !quiet {
        println!("Timer enabled and started");
    }

    Ok(())
}

/// Uninstalls systemd unit files.
pub async fn uninstall(user_mode: bool, quiet: bool) -> Result<()> {
    // Check permissions for system uninstall
    if !user_mode && !nix::unistd::Uid::effective().is_root() {
        bail!("System uninstall requires root privileges. Use --user for user uninstall.");
    }

    let unit_dir = if user_mode {
        dirs::home_dir()
            .context("Could not determine home directory")?
            .join(".config/systemd/user")
    } else {
        PathBuf::from("/etc/systemd/system")
    };

    // Stop and disable timer
    let stop_args: Vec<&str> = if user_mode {
        vec!["--user", "disable", "--now", timer_name()]
    } else {
        vec!["disable", "--now", timer_name()]
    };

    let _ = Command::new("systemctl").args(&stop_args).status().await;

    // Remove files
    let service_path = unit_dir.join(service_name());
    let timer_path = unit_dir.join(timer_name());

    if service_path.exists() {
        fs::remove_file(&service_path).await?;
        if !quiet {
            println!("Removed: {}", service_path.display());
        }
    }

    if timer_path.exists() {
        fs::remove_file(&timer_path).await?;
        if !quiet {
            println!("Removed: {}", timer_path.display());
        }
    }

    // Reload systemd
    let reload_args: &[&str] = if user_mode {
        &["--user", "daemon-reload"]
    } else {
        &["daemon-reload"]
    };

    Command::new("systemctl")
        .args(reload_args)
        .status()
        .await
        .context("Failed to reload systemd")?;

    if !quiet {
        println!("Systemd units removed")
    }

    Ok(())
}

/// Shows systemd timer and service status.
pub async fn status(user_mode: bool, quiet: bool) -> Result<()> {
    let status_args: Vec<&str> = if user_mode {
        vec!["--user", "status", timer_name(), service_name()]
    } else {
        vec!["status", timer_name(), service_name()]
    };

    if !quiet {
        let mode = if user_mode { "user" } else { "system" };
        println!("Checking {} service status", mode);
    }

    let output = Command::new("systemctl")
        .args(&status_args)
        .output()
        .await
        .context("Failed to run systemctl")?;

    // Print output regardless of exit code (inactive services return non-zero)
    print!("{}", String::from_utf8_lossy(&output.stdout));
    if !output.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
    }

    Ok(())
}

/// Resolves the binary path, defaulting to current executable.
fn resolve_binary_path(specified: Option<PathBuf>) -> Result<PathBuf> {
    match specified {
        Some(p) => Ok(p),
        None => std::env::current_exe().context("Failed to determine current executable path"),
    }
}

/// Converts schedule to systemd calendar if needed.
fn resolve_calendar(schedule: &str) -> String {
    // If it looks like a cron expression, convert it
    if schedule.split_whitespace().count() == 5 {
        cron_to_calendar(schedule).unwrap_or_else(|| schedule.to_string())
    } else {
        // Already in calendar format or a preset like "daily"
        schedule.to_string()
    }
}
