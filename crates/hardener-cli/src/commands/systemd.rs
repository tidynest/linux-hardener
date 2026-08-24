//! Systemd unit file management commands.

use anyhow::{Context, Result, bail};
use hardener_common::executor::CommandOutput;
use hardener_compliance::OutputFormat;
use hardener_core::config_write::{WriteAudit, remove_file_audited, write_atomically};
use hardener_core::{LocalExecutor, executor::SystemExecutor};
use hardener_scheduler::systemd::{SystemdGenerator, cron_to_calendar, service_name, timer_name};
use hardener_state::audit::{ActionType, AuditLogger};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::{fs, process::Command};

/// The audit descriptor for one unit file joining or leaving this host.
///
/// A timer that runs `hardener scan` as root is host state in the same sense a
/// configuration file is, and its removal is the direction that reports itself
/// least: a scan that stops running produces no failure and no output. The
/// target names the unit rather than its path, because `--user` and a system
/// install write the same two unit names to different directories and an
/// auditor asking "was the scheduled scan changed" wants both.
fn unit_audit<'a>(
    logger: Option<&'a AuditLogger>,
    unit: &str,
    operation: &str,
    user_mode: bool,
    detail: &[(&str, String)],
) -> WriteAudit<'a> {
    let mut details = HashMap::from([
        ("operation".to_string(), operation.to_string()),
        ("scope".to_string(), scope_name(user_mode).to_string()),
    ]);
    details.extend(detail.iter().map(|(k, v)| (k.to_string(), v.clone())));
    WriteAudit {
        logger,
        action: ActionType::ConfigChange,
        target: format!("unit:{unit}"),
        details,
    }
}

/// One `systemctl` invocation, through the executor rather than spawned here.
///
/// The executor is what makes `install` and `uninstall` drivable at all. Before
/// this, both spawned `systemctl` directly, so a test of either would have
/// reloaded the operator's own systemd and enabled a real timer in their
/// session, and the whole `systemctl` half of both verbs went unasserted for
/// that reason.
///
/// **Stderr is forwarded on failure and dropped on success.** The child used to
/// inherit this process's streams, so everything `systemctl` said reached the
/// operator: the `Created symlink ...` line from `enable --now` along with
/// anything that went wrong. Keeping the failure half is what matters, since a
/// `daemon-reload` that fails is otherwise silent. The success chatter is noise
/// beside the summary these verbs already print for themselves.
///
/// The `--user` flag is prepended here rather than at each call site, because it
/// was written out five times and a verb that forgot it would act on the system
/// instance while reporting the user one.
async fn systemctl(
    executor: &dyn SystemExecutor,
    user_mode: bool,
    args: &[&str],
) -> Result<CommandOutput> {
    let mut full: Vec<&str> = Vec::with_capacity(args.len() + 1);
    if user_mode {
        full.push("--user");
    }
    full.extend_from_slice(args);

    let output = executor.execute_command("systemctl", &full).await?;
    if !output.success() && !output.stderr.trim().is_empty() {
        eprint!("{}", output.stderr);
    }
    Ok(output)
}

/// What an install did, once it has stopped talking to systemd.
///
/// Returned rather than reported from inside, so a test reads the outcome
/// instead of scraping stdout. `install` renders it.
struct InstallOutcome {
    service_path: PathBuf,
    timer_path: PathBuf,
    timer_enabled: bool,
}

/// What an uninstall did. The counterpart to [`InstallOutcome`].
struct UninstallOutcome {
    removed: Vec<PathBuf>,
    timer_disabled: bool,
}

/// Which systemd instance the units belong to.
///
/// A user timer runs as the operator and only while they are logged in; a
/// system one runs as root on a timer the host keeps. Two entries that named
/// only the unit would be indistinguishable.
fn scope_name(user_mode: bool) -> &'static str {
    if user_mode { "user" } else { "system" }
}

/// Where a `--user` or system install puts its units.
fn unit_dir_for(user_mode: bool) -> Result<PathBuf> {
    if user_mode {
        Ok(dirs::home_dir()
            .context("Could not determine home directory")?
            .join(".config/systemd/user"))
    } else {
        Ok(PathBuf::from("/etc/systemd/system"))
    }
}

/// Writes both unit files into `unit_dir`, filing one entry per unit.
///
/// Split out of [`install`] because everything else that verb does is
/// `systemctl`: a test driving `install` itself would reload the operator's own
/// systemd and enable a real timer in their session. This is the half that
/// touches the filesystem, and it takes the directory as an argument rather
/// than resolving it from `HOME`, so a test can point it somewhere it may write
/// without moving an environment variable other threads are reading.
///
/// One entry per unit rather than one for the install: a run that writes the
/// service and then cannot write the timer has done something, and the log
/// should say which half.
async fn write_units(
    unit_dir: &Path,
    generator: &SystemdGenerator,
    logger: Option<&AuditLogger>,
    user_mode: bool,
    calendar_detail: &[(&str, String)],
) -> Result<(PathBuf, PathBuf)> {
    fs::create_dir_all(unit_dir)
        .await
        .context("Failed to create unit directory")?;

    let service_path = unit_dir.join(service_name());
    let timer_path = unit_dir.join(timer_name());

    // Through the shared writer, so a unit file is replaced whole rather than
    // truncated and rewritten in place. A half-written `.service` is one
    // systemd fails to parse, and the caller's `daemon-reload` would read it.
    for (path, unit, contents) in [
        (&service_path, service_name(), generator.generate_service()),
        (&timer_path, timer_name(), generator.generate_timer()),
    ] {
        write_atomically(
            path,
            &contents,
            unit_audit(logger, unit, "install", user_mode, calendar_detail),
        )
        .await
        .with_context(|| format!("Failed to write {unit}"))?;
    }

    Ok((service_path, timer_path))
}

/// Removes both unit files from `unit_dir`, answering which were there.
///
/// The counterpart to [`write_units`], split from [`uninstall`] for the same
/// reason and testable on the same terms.
///
/// Through the shared remover, which keeps the `try_exists` rule this loop
/// already had (`exists` is `metadata(..).is_ok()` and answers `false` for a
/// unit this process may not stat, which would report an uninstall that removed
/// nothing) and adds the entry it did not. `timer_disabled` is carried on both
/// entries, because a unit file removed while its timer is still loaded is the
/// state an operator most needs to find later.
async fn remove_units(
    unit_dir: &Path,
    logger: Option<&AuditLogger>,
    user_mode: bool,
    timer_disabled: bool,
) -> Result<Vec<PathBuf>> {
    let disabled_detail = [("timer_disabled", timer_disabled.to_string())];
    let mut removed = Vec::new();
    for (path, unit) in [
        (unit_dir.join(service_name()), service_name()),
        (unit_dir.join(timer_name()), timer_name()),
    ] {
        let was_present = remove_file_audited(
            &path,
            unit_audit(logger, unit, "uninstall", user_mode, &disabled_detail),
        )
        .await
        .with_context(|| format!("Failed to remove {unit}"))?;
        if was_present {
            removed.push(path);
        }
    }
    Ok(removed)
}

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
#[allow(clippy::too_many_arguments)]
pub async fn install(
    user_mode: bool,
    schedule: String,
    config_path: Option<PathBuf>,
    format: OutputFormat,
    quiet: bool,
    logger: Option<AuditLogger>,
) -> Result<()> {
    let binary = resolve_binary_path(None)?;
    let calendar = resolve_calendar(&schedule);
    // Kept for the audit entry before the generator takes it: what an operator
    // asked for and what systemd was given can differ, since a five-field cron
    // expression is translated here, and the entry should carry the translated
    // calendar the timer actually runs on.
    let calendar_detail = [("schedule", calendar.clone())];

    let mut generator = SystemdGenerator::new(binary, calendar).with_user_mode(user_mode);
    if let Some(cfg) = config_path {
        generator = generator.with_config(cfg);
    }

    // Check permissions for system install
    if !user_mode && !nix::unistd::Uid::effective().is_root() {
        bail!("System install requires root privileges. Use --user for user install.");
    }

    let outcome = install_with(
        &LocalExecutor::new(),
        &unit_dir_for(user_mode)?,
        &generator,
        logger.as_ref(),
        user_mode,
        &calendar_detail,
    )
    .await?;

    if !quiet && !matches!(format, OutputFormat::Json) {
        println!("Installed: {}", outcome.service_path.display());
        println!("Installed: {}", outcome.timer_path.display());
    }

    report(
        &format,
        serde_json::json!({
            "installed": [outcome.service_path.display().to_string(),
                          outcome.timer_path.display().to_string()],
            "timer_enabled": outcome.timer_enabled,
        }),
        quiet,
        || {
            if outcome.timer_enabled {
                println!("Timer enabled and started");
            } else {
                println!("Units installed, but enabling the timer failed");
            }
        },
    );

    Ok(())
}

/// The whole of an install except deciding where it goes and how it is
/// rendered: write both units, reload systemd, enable the timer.
///
/// Everything it depends on is an argument, so a test drives it against a
/// temporary directory and a mock executor. What stays outside is
/// [`unit_dir_for`], which reads `HOME`, the root check, which is about this
/// process, [`LocalExecutor`] itself, and the logger.
///
/// **The logger is an argument and not resolved here**, which is not a detail.
/// `get_audit_logger` answers with this host's real audit trail, chosen by uid,
/// so an `install_with` that opened its own would have every test of it filing
/// invented install entries into the log of whoever ran `cargo test`. Passing
/// it in is what makes the tests inert.
///
/// The reload comes after the units are on disk and before the enable, which is
/// the only order that works: `enable --now` on a unit systemd has not read
/// fails, and reloading before the write reads the previous generation.
async fn install_with(
    executor: &dyn SystemExecutor,
    unit_dir: &Path,
    generator: &SystemdGenerator,
    logger: Option<&AuditLogger>,
    user_mode: bool,
    calendar_detail: &[(&str, String)],
) -> Result<InstallOutcome> {
    let (service_path, timer_path) =
        write_units(unit_dir, generator, logger, user_mode, calendar_detail).await?;

    systemctl(executor, user_mode, &["daemon-reload"])
        .await
        .context("Failed to reload systemd")?;

    // A non-zero exit was once discarded here, so the envelope asserted an
    // outcome nothing had checked. Carried as a fact rather than raised: the
    // units are already written and saying so is more use than an error that
    // hides it.
    let timer_enabled = systemctl(executor, user_mode, &["enable", "--now", timer_name()])
        .await
        .context("Failed to enable timer")?
        .success();

    Ok(InstallOutcome {
        service_path,
        timer_path,
        timer_enabled,
    })
}

/// Uninstalls systemd unit files.
pub async fn uninstall(
    user_mode: bool,
    format: OutputFormat,
    quiet: bool,
    logger: Option<AuditLogger>,
) -> Result<()> {
    // Check permissions for system uninstall
    if !user_mode && !nix::unistd::Uid::effective().is_root() {
        bail!("System uninstall requires root privileges. Use --user for user uninstall.");
    }

    let outcome = uninstall_with(
        &LocalExecutor::new(),
        &unit_dir_for(user_mode)?,
        logger.as_ref(),
        user_mode,
    )
    .await?;

    if !quiet && !matches!(format, OutputFormat::Json) {
        for path in &outcome.removed {
            println!("Removed: {}", path.display());
        }
    }

    let summary = uninstall_summary(outcome.removed.len(), outcome.timer_disabled);
    let removed: Vec<String> = outcome
        .removed
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    report(
        &format,
        serde_json::json!({ "removed": removed, "timer_disabled": outcome.timer_disabled }),
        quiet,
        || println!("{summary}"),
    );

    Ok(())
}

/// The whole of an uninstall except where it looks and how it is rendered:
/// disable the timer, remove both units, reload systemd.
///
/// The counterpart to [`install_with`], and the order is again the only one
/// that works: the timer is stopped while its unit file still exists, because
/// `disable --now` on a unit systemd can no longer read cannot stop what it
/// started.
async fn uninstall_with(
    executor: &dyn SystemExecutor,
    unit_dir: &Path,
    logger: Option<&AuditLogger>,
    user_mode: bool,
) -> Result<UninstallOutcome> {
    // Carried as a fact rather than raised as an error, for the reason
    // `install_with` carries its own. A unit that was never enabled fails here
    // too, and that host is exactly the one with nothing to remove. A
    // `systemctl` that cannot be spawned is also `false` rather than an error,
    // so the units still come off a host whose systemd cannot be reached; the
    // reload below is what fails in that case, after the removal.
    let timer_disabled = systemctl(executor, user_mode, &["disable", "--now", timer_name()])
        .await
        .map(|output| output.success())
        .unwrap_or(false);

    let removed = remove_units(unit_dir, logger, user_mode, timer_disabled).await?;

    systemctl(executor, user_mode, &["daemon-reload"])
        .await
        .context("Failed to reload systemd")?;

    Ok(UninstallOutcome {
        removed,
        timer_disabled,
    })
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
