//! CLI output formatting: multiplexes between JSON and coloured terminal output.

use colored::Colorize;
use hardener_common::types::Severity;
use hardener_core::{
    ApplyResult, PluginMetadata, ScanResult, ValidationReport, plugin::UncheckedCheck,
};
use hardener_state::{Checkpoint, FileState, RollbackResult};
use hardener_types::{DivergenceState, RollbackDivergence};

use crate::cli::OutputFormat;

pub fn status(format: &OutputFormat, message: &str) {
    match format {
        OutputFormat::Json => {}
        _ => eprintln!("{} {}", "→".blue(), message),
    }
}

pub fn info(format: &OutputFormat, message: &str) {
    match format {
        // stderr, matching `error` and `warning` below. Writing this to stdout
        // put a second top-level document in front of the payload, so a strict
        // parser rejected the whole stream ("Extra data") even though the
        // payload itself was well formed.
        OutputFormat::Json => {
            eprintln!("{}", serde_json::json!({ "info": message }));
        }
        _ => println!("{} {}", "i".cyan(), message),
    }
}

pub fn error(format: &OutputFormat, message: &str) {
    match format {
        OutputFormat::Json => {
            eprintln!("{}", serde_json::json!({ "error": message }));
        }
        _ => eprintln!("{} {}", "x".red(), message),
    }
}

pub fn warning(format: &OutputFormat, message: &str) {
    match format {
        OutputFormat::Json => {
            eprintln!("{}", serde_json::json!({ "warning": message }));
        }
        _ => eprintln!("{} {}", "W".yellow(), message),
    }
}

pub fn scan_results(format: &OutputFormat, results: &[(PluginMetadata, ScanResult)]) {
    match format {
        OutputFormat::Json => match serde_json::to_string_pretty(&scan_json(results)) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("{{\"error\": \"serialisation failed: {e}\"}}"),
        },
        _ => {
            println!("\n{}", "═══ Scan Results ═══".bold());

            let mut total_findings = 0;
            for (metadata, result) in results {
                for line in scan_plugin_lines(metadata, result) {
                    println!("{line}");
                }
                total_findings += result.scan_findings.len();
            }

            println!("\n{}", "═══════════════════".dimmed());
            println!(
                "Total: {} finding(s) across {} plugin(s)",
                total_findings,
                results.len()
            );

            let unchecked = results.iter().flat_map(|(_, r)| r.scan_unchecked.iter());
            if let Some(note) = hardener_types::unchecked_summary(unchecked) {
                println!("{}", note.dimmed());
            }

            let failed = results.iter().filter(|(_, r)| !r.scan_success).count();
            if failed > 0 {
                println!(
                    "{}",
                    format!(
                        "{failed} plugin scan(s) did not complete; \
                         findings above are not a complete picture"
                    )
                    .yellow()
                );
            }
        }
    }
}

/// Builds the `--format json` payload for a scan.
///
/// Split out so the machine-facing contract is testable without capturing
/// stdout. `scan_success` and `scan_error` are part of that contract: without
/// them a plugin whose scan failed is byte-identical to a compliant host for
/// every machine consumer.
fn scan_json(results: &[(PluginMetadata, ScanResult)]) -> Vec<serde_json::Value> {
    results
        .iter()
        .map(|(m, r)| {
            serde_json::json!({
                "plugin_id": m.plugin_id.as_str(),
                "plugin_name": m.plugin_name,
                "findings": r.scan_findings,
                "unchecked": r.scan_unchecked,
                "scan_success": r.scan_success,
                "scan_error": r.scan_error,
            })
        })
        .collect()
}

/// Builds the terminal lines for one plugin's scan section, returned as
/// strings so tests can assert attribution without capturing stdout.
///
/// The plugin-name header prints whenever the plugin has findings OR
/// unchecked entries; an unchecked-only plugin therefore never renders an
/// anonymous block that visually attaches to the previous plugin's header.
/// Unchecked entries are deduplicated by `unchecked_check_id` (the audit
/// plugin emits one entry per underlying rule and several rules share an
/// id), mirroring the GUI's findings-tab dedupe; headers keep the honest
/// raw count and collapsed lines carry an `(xN)` multiplier so no check
/// appears to have vanished.
fn scan_plugin_lines(metadata: &PluginMetadata, result: &ScanResult) -> Vec<String> {
    let findings = &result.scan_findings;
    let unchecked = &result.scan_unchecked;

    // A plugin whose own scan failed carries no findings, which is exactly
    // what a compliant host looks like. Never let that render as a tick.
    if !result.scan_success {
        return vec![format!(
            "\n{} {} - {}",
            "✗".red(),
            metadata.plugin_name.bold(),
            format!(
                "scan did not complete: {}",
                result
                    .scan_error
                    .as_deref()
                    .unwrap_or("reason not reported")
            )
            .red()
        )];
    }

    if findings.is_empty() && unchecked.is_empty() {
        return vec![format!(
            "{} {} - {}",
            "✓".green(),
            metadata.plugin_name,
            "No issues found".dimmed()
        )];
    }

    let mut lines = Vec::new();
    let unchecked_note = hardener_types::unchecked_summary(unchecked).unwrap_or_default();

    // Unchecked entries nest one level deeper when they sit under a
    // findings sub-header rather than directly under the plugin header.
    let mut unchecked_indent = "  ";
    if findings.is_empty() {
        lines.push(format!(
            "\n{} {} - {}",
            "?".dimmed(),
            metadata.plugin_name.bold(),
            unchecked_note.dimmed()
        ));
    } else {
        lines.push(format!(
            "\n{} {} - {} finding(s)",
            "!".yellow(),
            metadata.plugin_name.bold(),
            findings.len()
        ));
        for finding in findings {
            // A documented deviation keeps its line, so a result resting on an
            // exception stays distinguishable from a genuinely clean one, but
            // it never wears a severity. The label is wider than the
            // four-character severity column deliberately: the ragged line is
            // what separates it from the violations around it.
            let severity_str = if finding.is_policy_excepted() {
                hardener_types::POLICY_EXCEPTION_LABEL.dimmed()
            } else {
                format_severity(&finding.finding_severity)
            };
            lines.push(format!(
                "  {} [{}] {}",
                "•".dimmed(),
                severity_str,
                finding.finding_title
            ));
            if !finding.finding_description.is_empty() {
                lines.push(format!("    {}", finding.finding_description.dimmed()));
            }
            // An exception is keyed per check, and nothing told an operator
            // that key: a finding's id is derived from it by a transform that
            // loses information. Say nothing rather than guess where an
            // unrecognised plugin is configured, and say nothing to an
            // operator already resting on an exception. The key is quoted
            // unconditionally because net.ipv4.ip_forward and
            // /etc/ssh/sshd_config are not bare TOML keys, and a document
            // built from an unquoted one parses as nested tables rather than
            // failing, so nothing would report the mistake.
            //
            // A declined exception is excluded for the same reason: the
            // operator already wrote one at this key and it did not apply.
            // Telling them how to write it again, right beside the line
            // saying why the one they have did not work, reads as though
            // the tool never noticed their exception at all. What they need
            // is the declined line below, which says what to fix.
            if let Some(key) = &finding.finding_exception_key
                && !finding.is_policy_excepted()
                && !matches!(
                    finding.finding_exception,
                    hardener_types::ExceptionOutcome::Declined(_)
                )
                && let Some(section) =
                    hardener_core::HardenerConfig::config_section(metadata.plugin_id.as_str())
            {
                lines.push(format!(
                    "    {}",
                    format!("accept as a documented deviation: [{section}.exceptions.{key:?}]")
                        .dimmed()
                ));
            }
            // A configured exception that did not apply leaves the finding
            // live, so it keeps its real severity above and merely gains
            // this line, rather than the label branch that replaces
            // severity for an applied exception.
            if let hardener_types::ExceptionOutcome::Declined(declined) = &finding.finding_exception
            {
                lines.push(format!(
                    "    {}",
                    hardener_types::exception_declined_line(declined).yellow()
                ));
            }
        }
        if !unchecked.is_empty() {
            lines.push(format!("  {} {}", "?".dimmed(), unchecked_note.dimmed()));
            unchecked_indent = "    ";
        }
    }

    for (entry, occurrences) in dedupe_unchecked(unchecked) {
        let multiplier = if occurrences > 1 {
            format!(" (x{occurrences})")
        } else {
            String::new()
        };
        lines.push(format!(
            "{unchecked_indent}{} {}{} - {}",
            "·".dimmed(),
            entry.unchecked_title.dimmed(),
            multiplier.dimmed(),
            entry.unchecked_reason.dimmed()
        ));
    }
    lines
}

/// Deduplicates unchecked entries by `unchecked_check_id`, preserving first
/// appearance order and counting occurrences so renderers can keep the raw
/// total honest.
fn dedupe_unchecked(unchecked: &[UncheckedCheck]) -> Vec<(&UncheckedCheck, usize)> {
    let mut deduped: Vec<(&UncheckedCheck, usize)> = Vec::new();
    let mut index: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for entry in unchecked {
        match index.get(entry.unchecked_check_id.as_str()) {
            Some(&at) => deduped[at].1 += 1,
            None => {
                index.insert(entry.unchecked_check_id.as_str(), deduped.len());
                deduped.push((entry, 1));
            }
        }
    }
    deduped
}

/// Prints a per-plugin timing table, sorted slowest first.
///
/// Written to stderr so `--format json` stdout stays machine-parseable.
/// Plugins run concurrently, so the summed plugin time exceeds wall clock.
pub fn scan_timings(timings: &[(String, u64)], wall: std::time::Duration) {
    let mut rows: Vec<_> = timings.to_vec();
    rows.sort_by_key(|(_, us)| std::cmp::Reverse(*us));

    let width = rows
        .iter()
        .map(|(name, _)| name.len())
        .chain([19])
        .max()
        .unwrap_or(19);
    let ms = |us: f64| format!("{:>10.1} ms", us / 1000.0);

    eprintln!("\n{}", "═══ Plugin Timings ═══".bold());
    for (name, us) in &rows {
        eprintln!("{name:<width$} {}", ms(*us as f64));
    }
    let total: u64 = rows.iter().map(|(_, us)| us).sum();
    eprintln!("{}", "─".repeat(width + 14).dimmed());
    eprintln!("{:<width$} {}", "Total (plugin time)", ms(total as f64));
    eprintln!(
        "{:<width$} {}",
        "Wall clock",
        ms(wall.as_secs_f64() * 1_000_000.0)
    );
}

pub fn apply_results(format: &OutputFormat, results: &[(PluginMetadata, ApplyResult)]) {
    match format {
        OutputFormat::Json => match serde_json::to_string_pretty(&results) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("{{\"error\": \"serialisation failed: {e}\"}}"),
        },
        _ => {
            println!("\n{}", "═══ Apply Results ═══".bold());

            for (metadata, result) in results {
                let icon = if result.apply_success {
                    "✓".green()
                } else {
                    "✗".red()
                };

                println!(
                    "{} {} - {}",
                    icon,
                    metadata.plugin_name,
                    apply_result_line(result)
                );

                for change in &result.apply_changes {
                    let status = if change.is_skipped() {
                        "○".dimmed()
                    } else if change.change_success {
                        "✓".green()
                    } else {
                        "✗".red()
                    };
                    println!("  {} {}", status, change.change_description);

                    if !change.change_success
                        && let Some(err) = &change.change_error
                    {
                        println!("{}", format_change_error(err));
                    }
                }
            }
        }
    }
}

/// The phrase printed after a plugin's name in apply output.
///
/// A plugin can fail and still have applied most of what it set out to, and
/// [`apply_summary`] has already counted that. Printing the error on its own
/// discarded it: the audit plugin in a container writes its rules file and
/// fails only the reload, so an operator was told "Some changes failed" with no
/// indication that anything had been written at all. Found by the differential
/// suite's first container run, whose preview-agreement row could not read a
/// count that was never printed.
///
/// The error stands alone again when the plugin recorded no change whatever,
/// where [`apply_summary`] reads "no changes needed" and would contradict the
/// error beside it. That is the firewall plugin's "No firewall backend" shape,
/// which returns an empty change list.
fn apply_result_line(result: &ApplyResult) -> String {
    match &result.apply_error {
        Some(err) if result.apply_changes.is_empty() => err.clone(),
        Some(err) => format!("{}: {err}", apply_summary(result)),
        None => apply_summary(result),
    }
}

/// Builds the per-plugin summary phrase for apply output. When any change
/// failed the phrase says so numerically ("1 of 5 change(s) applied,
/// 4 failed") so the number next to "applied" only ever counts successes;
/// with no failures the plain "N change(s) applied[, M skipped]" wording is
/// kept. A plugin that hardened nothing (only a rollback checkpoint, or an
/// already-compliant host) reads "no changes needed" so a bare checkpoint
/// never looks like remediation.
fn apply_summary(result: &ApplyResult) -> String {
    let applied = result.applied_change_count();
    let failed = result.failed_change_count();
    let skipped = result.skipped_change_count();
    let skip_suffix = if skipped > 0 {
        format!(", {skipped} skipped")
    } else {
        String::new()
    };
    if failed > 0 {
        let attempted = applied + failed;
        format!("{applied} of {attempted} change(s) applied, {failed} failed{skip_suffix}")
    } else if applied == 0 {
        format!("no changes needed{skip_suffix}")
    } else {
        format!("{applied} change(s) applied{skip_suffix}")
    }
}

/// Formats the indented, dimmed detail line printed under a failed change so
/// a terminal user sees why it failed, not just that it did.
fn format_change_error(error: &str) -> String {
    format!("    {}", error.dimmed())
}

/// The dimmed second line under each plugin in the text listing.
///
/// The category leads it because that is the field the text view was missing:
/// `plugins --format json` carries `plugin_category` for all eight plugins and
/// the table carried it for none, so the two views of one command disagreed
/// about what a plugin is. It is also the field that answers "which of these
/// eight do I want", which the description alone does not.
fn plugin_detail_line(plugin: &PluginMetadata) -> String {
    format!("[{}] {}", plugin.plugin_category, plugin.plugin_description)
}

pub fn plugin_list(format: &OutputFormat, plugins: &[PluginMetadata]) {
    match format {
        OutputFormat::Json => match serde_json::to_string_pretty(&plugins) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("{{\"error\": \"serialisation failed: {e}\"}}"),
        },
        _ => {
            println!("{}", "Available Plugins".bold());
            println!("{}", "─".repeat(60));
            // Measured, not guessed. The literal was 20 and the longest id,
            // `permissions-hardening`, is 21, so that one row overflowed its
            // field and began its second column one character right of the
            // other seven. A fixed width is wrong again the moment a longer id
            // is added; this cannot be.
            let id_width = plugins
                .iter()
                .map(|p| p.plugin_id.as_str().len())
                .max()
                .unwrap_or(0);
            for plugin in plugins {
                // Padded by hand rather than through `{:width$}`: the id is
                // coloured, and a colour code is bytes the formatter counts as
                // width, so a styled value inside a padded field pads short.
                let id = plugin.plugin_id.as_str();
                println!(
                    "{}{} {} {}",
                    id.cyan(),
                    " ".repeat(id_width - id.len()),
                    plugin.plugin_name,
                    format!("v{}", plugin.plugin_version).dimmed()
                );
                println!("  {}", plugin_detail_line(plugin).dimmed());
            }
        }
    }
}

/// Renders the checkpoint list. `checkpoints` is newest-first; only the first
/// `limit` are shown unless `all` is set (both text and JSON honour the cap, so
/// `--format json` matches what the table shows). A dimmed footer discloses the
/// total whenever the list is capped.
pub fn checkpoint_list(format: &OutputFormat, checkpoints: &[Checkpoint], limit: usize, all: bool) {
    let total = checkpoints.len();
    let shown = if all { total } else { limit.min(total) };
    let visible = &checkpoints[..shown];

    match format {
        OutputFormat::Json => match serde_json::to_string_pretty(&visible) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("{{\"error\": \"serialisation failed: {e}\"}}"),
        },
        _ => {
            if total == 0 {
                println!("No checkpoints found.");
                return;
            }

            // Widths measured from the rows, not fixed. The literals were 36
            // and 24 against ids of 25 and names up to 31, so every
            // `service-minimisation-pre-apply` row overflowed NAME and pushed
            // HOST and CREATED right: on this host the HOST column began at
            // five different offsets down one listing.
            //
            // Padding is applied outside the styling. A colour code is bytes
            // that `{:<width$}` counts as width, so a styled value inside a
            // padded field pads short and the fix would not survive a terminal.
            let pad = |s: &str, w: usize| " ".repeat(w.saturating_sub(s.len()));
            let id_w = visible
                .iter()
                .map(|c| c.checkpoint_id.as_str().len())
                .chain(std::iter::once("ID".len()))
                .max()
                .unwrap_or(0);
            let name_w = visible
                .iter()
                .map(|c| c.checkpoint_name.len())
                .chain(std::iter::once("NAME".len()))
                .max()
                .unwrap_or(0);
            let host_w = visible
                .iter()
                .map(|c| c.host_key.len())
                .chain(std::iter::once("HOST".len()))
                .max()
                .unwrap_or(0);
            let rule = "─".repeat(id_w + name_w + host_w + 23 + 6);

            println!("{}", "Checkpoints".bold());
            println!("{rule}");
            println!(
                "{}{}  {}{}  {}{}  {}",
                "ID".bold(),
                pad("ID", id_w),
                "NAME".bold(),
                pad("NAME", name_w),
                "HOST".bold(),
                pad("HOST", host_w),
                "CREATED".bold()
            );
            println!("{rule}");
            for cp in visible {
                let id = cp.checkpoint_id.as_str();
                println!(
                    "{}{}  {}{}  {}{}  {}",
                    id.cyan(),
                    pad(id, id_w),
                    cp.checkpoint_name,
                    pad(&cp.checkpoint_name, name_w),
                    cp.host_key.dimmed(),
                    pad(&cp.host_key, host_w),
                    format_timestamp(cp.checkpoint_timestamp).dimmed()
                );
            }
            if let Some(footer) = checkpoint_list_footer(shown, total) {
                println!("{}", footer.dimmed());
            }
        }
    }
}

/// The footer shown beneath a capped checkpoint list, or `None` when every
/// checkpoint is already visible. Tells the admin how many exist and how to
/// see them all.
fn checkpoint_list_footer(shown: usize, total: usize) -> Option<String> {
    match (shown, total) {
        // Handled before the table is drawn, with "No checkpoints found."; a
        // count here would answer the same question twice.
        (_, 0) => None,
        // An uncapped listing states its total too. `history list` closes every
        // listing with "N session(s) shown.", and this one closed only the
        // capped ones, so an operator reading a full table had to count the
        // rows and had nothing saying the table was complete.
        (shown, total) if shown >= total => Some(format!("{total} checkpoint(s) shown.")),
        (shown, total) => Some(format!("showing {shown} of {total}; use --all to see all")),
    }
}

pub fn checkpoint_created(format: &OutputFormat, id: &hardener_state::CheckpointId) {
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::json!({ "checkpoint_id": id.as_str() }));
        }
        _ => {
            println!("{} Checkpoint created: {}", "✓".green(), id.as_str().cyan());
        }
    }
}

/// Reports a checkpoint that was removed. Shaped after `checkpoint_created`,
/// its opposite number: a mutating verb says on stdout which row it acted on,
/// rather than leaving a machine consumer to read success out of an empty
/// stream. The claim is only safe to print because a delete that removed
/// nothing is now an error and never reaches here.
pub fn checkpoint_deleted(format: &OutputFormat, id: &hardener_state::CheckpointId) {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::json!({ "deleted": true, "checkpoint_id": id.as_str() })
            );
        }
        _ => {
            println!("{} Checkpoint deleted: {}", "✓".green(), id.as_str().cyan());
        }
    }
}

/// Reports what a database repair found, and what it removed if it was asked to.
///
/// `removed` is `None` for a run that only looked, which is the default, so the
/// two runs are distinguishable in JSON rather than differing only in a count
/// that happens to be zero.
pub fn checkpoint_repair(
    format: &OutputFormat,
    found: hardener_state::OrphanedFileStates,
    removed: Option<u64>,
) {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::json!({
                    "orphaned_rows": found.rows,
                    "orphaned_checkpoints": found.checkpoints,
                    "executed": removed.is_some(),
                    "removed_rows": removed,
                })
            );
        }
        _ if found.rows == 0 => {
            println!("{} No orphaned file rows.", "✓".green());
        }
        _ => match removed {
            Some(removed) => println!(
                "{} Removed {} orphaned file row(s) from {} absent checkpoint(s).",
                "✓".green(),
                removed.to_string().cyan(),
                found.checkpoints.to_string().cyan()
            ),
            None => println!(
                "{} orphaned file row(s) from {} absent checkpoint(s). \
                 Re-run with --execute to remove them.",
                found.rows.to_string().yellow(),
                found.checkpoints.to_string().yellow()
            ),
        },
    }
}

pub fn checkpoint_details(format: &OutputFormat, checkpoint: &Checkpoint, files: &[FileState]) {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::json!({
                    "checkpoint": checkpoint,
                    "files": files
                })
            );
        }
        _ => {
            println!("{}", "Checkpoint Details".bold());
            println!("{}", "─".repeat(60));
            println!("ID:        {}", checkpoint.checkpoint_id.as_str().cyan());
            println!("Name:      {}", checkpoint.checkpoint_name);
            println!("Host:      {}", checkpoint.host_key);
            println!(
                "Created:   {}",
                format_timestamp(checkpoint.checkpoint_timestamp)
            );
            println!("User:      {}", checkpoint.checkpoint_username);
            println!("Files:     {}", files.len());

            if !files.is_empty() {
                println!("\n{}", "Captured Files:".bold());
                for file in files {
                    println!("  {}", file.file_path);
                }
            }
        }
    }
}

pub fn rollback_result(format: &OutputFormat, result: &RollbackResult) {
    use hardener_state::FileRestoreAction;

    match format {
        OutputFormat::Json => match serde_json::to_string_pretty(&result) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("{{\"error\": \"serialisation failed: {e}\"}}"),
        },
        _ => {
            let icon = if result.rollback_success {
                "✓".green()
            } else {
                "✗".red()
            };
            println!(
                "\n{icon} Rolled back to: {} ({})",
                result.rollback_checkpoint_name.bold(),
                result.rollback_checkpoint_id.dimmed()
            );

            for file in &result.rollback_files {
                let status = if file.restore_success {
                    "✓".green()
                } else {
                    "✗".red()
                };
                let action = match file.restore_action {
                    FileRestoreAction::Restored => "restored",
                    FileRestoreAction::Removed => "removed",
                    FileRestoreAction::PermissionsRestored => "permissions",
                    FileRestoreAction::Skipped => "skipped",
                };
                println!("  {status} [{action}] {}", file.restore_path);
                if let Some(err) = &file.restore_error {
                    println!("    {}", err.as_str().red());
                }
            }

            let restored = result
                .rollback_files
                .iter()
                .filter(|f| f.restore_success)
                .count();
            println!(
                "\n{} file(s) processed, {restored} restored successfully.",
                result.rollback_files.len()
            );

            if !result.rollback_reloads.is_empty() {
                println!("\nReloads:");
                for reload in &result.rollback_reloads {
                    let status = if reload.reload_success {
                        "ok".green().to_string()
                    } else {
                        match &reload.reload_error {
                            Some(err) => format!("{} {err}", "FAILED:".red()),
                            None => "FAILED".red().to_string(),
                        }
                    };
                    println!(
                        "  {:<18} {:<25} {status}",
                        reload.reload_plugin_id, reload.reload_action
                    );
                }
            }

            for line in divergence_lines(result) {
                println!("{line}");
            }
        }
    }
}

/// The divergence block, one header line and two or three lines per row, or
/// nothing at all when there is nothing to say.
///
/// Split from the printing so it can be asserted on. `diverged` is yellow and
/// not red: nothing failed, and colouring an advisory like a failure is how an
/// operator learns to ignore both. Ranking is the same argument one step on
/// (#152): a routine row printed beside a surprising one teaches the operator
/// to skip the block that carries both. Unexpected rows print first, expected
/// ones follow under their own heading, and nothing is hidden or dropped.
///
/// Within the unexpected group, `Diverged` prints before `Unverifiable`
/// (#152 follow-up): on every systemd host, `/usr/lib/sysctl.d/50-default.conf`
/// names managed parameters through a glob this scan does not resolve, which
/// puts one glob-source `Unverifiable` row and the per-parameter rows it
/// blocks in front of every genuine finding unless the surprising state is
/// sorted forward. The sort is stable and touches only ordering within the
/// unexpected group: the expected group and every classification are
/// unchanged.
pub(crate) fn divergence_lines(result: &RollbackResult) -> Vec<String> {
    if result.rollback_divergences.is_empty() {
        return Vec::new();
    }
    let (expected, mut unexpected): (Vec<_>, Vec<_>) = result
        .rollback_divergences
        .iter()
        .partition(|divergence| divergence.divergence_expected.is_some());
    unexpected.sort_by_key(|d| d.divergence_state != DivergenceState::Diverged);

    let mut lines = vec!["\nDivergences:".to_string()];
    lines.extend(unexpected.iter().flat_map(|d| divergence_row_lines(d)));
    if !expected.is_empty() {
        lines.push("\n  Expected, by design:".to_string());
        lines.extend(expected.iter().flat_map(|d| divergence_row_lines(d)));
    }
    lines
}

/// One row: its state line, its sentence, and its reason where it has one.
fn divergence_row_lines(divergence: &RollbackDivergence) -> Vec<String> {
    let state = match divergence.divergence_state {
        DivergenceState::Diverged => "diverged".yellow().to_string(),
        DivergenceState::Unverifiable => "could not check".to_string(),
    };
    // 41 characters wide: the longest managed parameter name this feature
    // prints is net.ipv4.conf.default.accept_source_route. A narrower column
    // ragged-edges the state on exactly the rows this feature exists to print.
    let mut lines = vec![
        format!(
            "  {:<18} {:<41} {state}",
            divergence.divergence_plugin_id, divergence.divergence_subject
        ),
        format!("    {}", divergence.divergence_detail),
    ];
    if let Some(reason) = &divergence.divergence_expected {
        lines.push(format!("    ({reason})"));
    }
    lines
}

pub fn validation_reports(format: &OutputFormat, reports: &[ValidationReport]) {
    match format {
        OutputFormat::Json => match serde_json::to_string_pretty(&reports) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("{{\"error\": \"serialisation failed: {e}\"}}"),
        },
        _ => {
            for report in reports {
                for line in validation_report_lines(report) {
                    println!("{line}");
                }
            }
        }
    }
}

/// Builds the terminal lines for one plugin's dry-run section.
///
/// Issues are rendered alongside the estimated changes, not dropped. A plugin
/// that could not read its config reports zero pending changes, which is
/// character-for-character what a host needing none reports; without the
/// issues an unreadable `sshd_config` reads as "0 change(s) to apply".
/// Severity is shown so an operator can tell a blocking problem from a note.
fn validation_report_lines(report: &ValidationReport) -> Vec<String> {
    let marker = if report.validation_report_is_valid {
        "○".blue()
    } else {
        "✗".red()
    };
    let mut lines = vec![format!(
        "{} {} - {} change(s) to apply{}",
        marker,
        report.validation_report_plugin_id.as_str(),
        report.validation_report_estimated_changes.len(),
        compliant_suffix(report.validation_report_compliant_count),
    )];

    for item in &report.validation_report_estimated_changes {
        lines.push(format!("  {} {}", "•".dimmed(), item));
    }

    // A setting left alone because it is excepted is neither a pending change
    // nor nothing: printing the count alone would report a documented
    // deviation as an absence.
    for item in &report.validation_report_exceptions {
        lines.push(format!("  {} {}", "~".dimmed(), item.dimmed()));
    }

    for issue in &report.validation_report_issues {
        let key = issue
            .validation_issue_config_key
            .as_deref()
            .map(|k| format!(" ({k})"))
            .unwrap_or_default();
        lines.push(format!(
            "  {} [{}] {}{}",
            "!".yellow(),
            format_severity(&issue.validation_issue_severity),
            issue.validation_issue_message,
            key.dimmed(),
        ));
    }
    lines
}

/// The " (N already compliant)" tail appended to dry-run summaries, or an empty
/// string when nothing was already compliant. Shared by the single-host and
/// batch renderers so an already-compliant count is surfaced identically and
/// is never folded into the pending total.
pub(crate) fn compliant_suffix(compliant: usize) -> String {
    if compliant > 0 {
        format!(" ({compliant} already compliant)")
    } else {
        String::new()
    }
}

/// Applies the shared severity colour scheme to an arbitrary label so other
/// renderers (the batch per-host sections) colour severity words identically
/// to the single-host output without duplicating the palette.
pub(crate) fn severity_label(text: &str, severity: &Severity) -> colored::ColoredString {
    match severity {
        Severity::Critical => text.red().bold(),
        Severity::High => text.red(),
        Severity::Medium => text.yellow(),
        Severity::Low => text.blue(),
        Severity::Info => text.dimmed(),
    }
}

fn format_severity(severity: &Severity) -> colored::ColoredString {
    let label = match severity {
        Severity::Critical => "CRIT",
        Severity::High => "HIGH",
        Severity::Medium => "MED ",
        Severity::Low => "LOW ",
        Severity::Info => "INFO",
    };
    severity_label(label, severity)
}

/// Renders a Unix timestamp for a human, in UTC, saying so.
///
/// One definition for the whole binary. There were two, both converting to
/// local time and both printing no zone, so `history list` and `checkpoint
/// list` disagreed with `report` about what a timestamp meant while looking
/// identical to it. On a `CEST` host the same instant read `09:06:17` in the
/// history table, `07:06:17 UTC` in the report and `2026-08-13T07:06:17Z` in
/// the tracing lines, and only the report said which it was. An operator
/// correlating the history table against `journalctl`, or against the scan's
/// own log lines, saw a two hour gap with nothing to explain it (#164).
///
/// UTC rather than labelled local, because the report already prints UTC and
/// the alternative would have left two conventions in one tool. Timeline
/// reconstruction after an incident is a core use of this output, and it
/// usually spans hosts that are not in one zone.
///
/// The width is fixed at 23 characters, which the table layouts depend on.
pub(crate) fn format_timestamp(timestamp: i64) -> String {
    chrono::DateTime::from_timestamp(timestamp, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "Unknown".to_string())
}

#[cfg(test)]
mod tests;
