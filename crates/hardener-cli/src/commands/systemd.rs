//! Systemd unit file management commands.

use anyhow::{Context, Result, bail};
use hardener_compliance::OutputFormat;
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
    format: OutputFormat,
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

            report(
                &format,
                serde_json::json!({
                    "generated": [service_path.display().to_string(),
                                  timer_path.display().to_string()],
                }),
                quiet,
                || {
                    println!("Generated: {}", service_path.display());
                    println!("Generated: {}", timer_path.display());
                },
            );
        }
        None => {
            // The units themselves are the output here, so they are the
            // envelope's body rather than something a caller has to scrape out
            // from between two comment headers. `false` for `quiet`, because
            // this is the command's whole result and printing it is the point
            // of the invocation, in either rendering.
            report(
                &format,
                serde_json::json!({
                    "service": { "name": service_name(), "content": service_content },
                    "timer": { "name": timer_name(), "content": timer_content },
                }),
                false,
                || {
                    println!("# {}\n{}", service_name(), service_content);
                    println!("# {}\n{}", timer_name(), timer_content);
                },
            );
        }
    }

    Ok(())
}

/// Installs systemd unit files.
pub async fn install(
    user_mode: bool,
    schedule: String,
    config_path: Option<PathBuf>,
    format: OutputFormat,
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

    if !quiet && !matches!(format, OutputFormat::Json) {
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

    // `.status()` only errors when the process cannot be spawned, so a
    // non-zero exit was being discarded and the envelope asserted an outcome
    // nothing had checked. Report what happened.
    let enabled = Command::new("systemctl")
        .args(&enable_args)
        .status()
        .await
        .context("Failed to enable timer")?
        .success();

    report(
        &format,
        serde_json::json!({
            "installed": [service_path.display().to_string(), timer_path.display().to_string()],
            "timer_enabled": enabled,
        }),
        quiet,
        || {
            if enabled {
                println!("Timer enabled and started");
            } else {
                println!("Units installed, but enabling the timer failed");
            }
        },
    );

    Ok(())
}

/// Uninstalls systemd unit files.
pub async fn uninstall(user_mode: bool, format: OutputFormat, quiet: bool) -> Result<()> {
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

    // Reported rather than discarded, for the reason `install` reports its
    // own: `.status()` only errors when the process cannot be spawned, so a
    // failure to stop the timer was invisible and the envelope described an
    // uninstall that might have left it running. A unit that was never enabled
    // also fails here, which is why this is carried as a fact rather than
    // raised as an error.
    let timer_disabled = Command::new("systemctl")
        .args(&stop_args)
        .status()
        .await
        .map(|status| status.success())
        .unwrap_or(false);

    // Remove files
    let service_path = unit_dir.join(service_name());
    let timer_path = unit_dir.join(timer_name());

    let mut removed: Vec<String> = Vec::new();
    for path in [&service_path, &timer_path] {
        // `try_exists`, not `exists`: the latter is `metadata(..).is_ok()` and
        // answers `false` for a unit this process may not stat, which would
        // report a successful uninstall that removed nothing. Here that answer
        // decides whether the file is touched at all, so an error is surfaced.
        let present = path
            .try_exists()
            .with_context(|| format!("Failed to check for {}", path.display()))?;
        if present {
            fs::remove_file(path).await?;
            removed.push(path.display().to_string());
            if !quiet && !matches!(format, OutputFormat::Json) {
                println!("Removed: {}", path.display());
            }
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

    let summary = uninstall_summary(removed.len(), timer_disabled);
    report(
        &format,
        serde_json::json!({ "removed": removed, "timer_disabled": timer_disabled }),
        quiet,
        || println!("{summary}"),
    );

    Ok(())
}

/// The one line `uninstall` prints, chosen from what actually happened.
///
/// It used to say "Systemd units removed" unconditionally, which was wrong in
/// both directions: on a host with nothing installed it claimed a removal that
/// never happened, and on one where `disable --now` failed it did not mention
/// that the timer may still be running against units that are now gone.
fn uninstall_summary(removed: usize, timer_disabled: bool) -> &'static str {
    match (removed, timer_disabled) {
        (0, _) => "No systemd units were installed here; nothing to remove",
        (_, true) => "Systemd units removed",
        (_, false) => "Systemd units removed, but disabling the timer failed",
    }
}

/// Shows systemd timer and service status.
pub async fn status(user_mode: bool, format: OutputFormat, quiet: bool) -> Result<()> {
    let status_args: Vec<&str> = if user_mode {
        vec!["--user", "status", timer_name(), service_name()]
    } else {
        vec!["status", timer_name(), service_name()]
    };

    let json = matches!(format, OutputFormat::Json);
    if !quiet && !json {
        let mode = if user_mode { "user" } else { "system" };
        println!("Checking {} service status", mode);
    }

    let output = Command::new("systemctl")
        .args(&status_args)
        .output()
        .await
        .context("Failed to run systemctl")?;

    // Reported regardless of exit code: an inactive timer is a status worth
    // printing and systemctl returns non-zero for it. Under JSON the exit code
    // is carried rather than discarded, since it is the only thing that
    // distinguishes "inactive" from "no such unit" without parsing prose.
    if json {
        println!(
            "{}",
            serde_json::json!({
                "user_mode": user_mode,
                "exit_code": output.status.code(),
                "stdout": String::from_utf8_lossy(&output.stdout),
                "stderr": String::from_utf8_lossy(&output.stderr),
            })
        );
        return Ok(());
    }
    print!(
        "{}",
        status_report(
            &String::from_utf8_lossy(&output.stdout),
            &String::from_utf8_lossy(&output.stderr),
        )
    );

    Ok(())
}

/// Joins what `systemctl` said into the one stream a status answer belongs on.
///
/// `systemctl status` reports absent units as `Unit X could not be found.` on
/// stderr with nothing on stdout, so forwarding each stream to its counterpart
/// left `hardener systemd status | ...` holding a progress line and no answer,
/// while `--format json` carried both fields on stdout. The two renderers
/// disagreed about where the answer was; this is the half that was wrong.
///
/// Joined here rather than at the call site so the decision has a test: the
/// caller shells out to `systemctl`, and a check that has to boot a container to
/// observe a stream is a check nothing runs.
fn status_report(stdout: &str, stderr: &str) -> String {
    format!("{stdout}{stderr}")
}

/// Renders one command result in whichever form the global `--format` asked for.
///
/// The four `systemd` verbs were passed no format at all, so `--format json`
/// produced a unit file beginning with `#` and a systemctl status table. Each
/// verb's JSON body differs, so what is shared is only the choice between them
/// and the rule that `--quiet` suppresses progress and never a result.
fn report(format: &OutputFormat, envelope: serde_json::Value, quiet: bool, text: impl FnOnce()) {
    // The envelope is the result, so `--quiet` does not remove it: a caller
    // asking for JSON and silence wants the machine-readable answer without the
    // chatter, not an empty stdout it then fails to parse. The human lines keep
    // the rule they shipped with, where `--quiet` does suppress them.
    if matches!(format, OutputFormat::Json) {
        println!("{envelope}");
        return;
    }
    if !quiet {
        text();
    }
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

#[cfg(test)]
mod tests;
