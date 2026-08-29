//! Split from the former flat `commands.rs` along the seams its test files
//! had already named. Shared plumbing lives in the parent; each domain here
//! keeps its own commands and their private helpers.

use super::*;

/// Reads the [scheduler] section from config.toml and returns it as SchedulerUiConfig.
#[tauri::command]
pub async fn get_scheduler_config() -> Result<hardener_types::scheduler::SchedulerUiConfig, String>
{
    let path = hardener_config_path()?;
    if !path.exists() {
        return Ok(hardener_types::scheduler::SchedulerUiConfig::default());
    }

    let content = std::fs::read_to_string(&path)
        .map_err(|e| safe_err(format!("Failed to read config: {e}")))?;

    #[derive(serde::Deserialize)]
    struct ConfigFile {
        #[serde(default)]
        scheduler: hardener_types::scheduler::SchedulerUiConfig,
    }

    let config: ConfigFile =
        toml::from_str(&content).map_err(|e| safe_err(format!("Failed to parse config: {e}")))?;

    Ok(config.scheduler)
}

/// Saves the scheduler section to config.toml without disturbing other sections.
///
/// Uses `toml_edit` to perform a targeted update of only the `[scheduler]` table,
/// preserving comments, formatting, and unrelated sections.
#[tauri::command]
pub async fn save_scheduler_config(
    config: hardener_types::scheduler::SchedulerUiConfig,
) -> Result<String, String> {
    validate_ipc_string(&config.schedule, "schedule")?;
    for plugin in &config.plugins {
        validate_ipc_string(plugin, "scheduler_plugin")?;
    }
    validate_ipc_string(&config.notifications.webhooks.url, "webhook_url")?;
    validate_ipc_string(&config.notifications.email.from_address, "from_address")?;
    for recipient in &config.notifications.email.recipients {
        validate_ipc_string(recipient, "email_recipient")?;
    }
    crate::validation::validate_notification_channels(&config.notifications)?;

    let write_path = writable_config_path()?;

    if let Some(parent) = write_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| safe_err(format!("Failed to create config directory: {e}")))?;
    }

    // Read existing config (user file first, fall back to system config as template)
    let content = if write_path.exists() {
        std::fs::read_to_string(&write_path)
            .map_err(|e| safe_err(format!("Failed to read config: {e}")))?
    } else {
        hardener_config_path()
            .ok()
            .filter(|p| p.exists())
            .and_then(|p| std::fs::read_to_string(p).ok())
            .unwrap_or_default()
    };

    let logger = get_audit_logger().await;
    write_scheduler_config(&write_path, &content, &config, logger.as_ref()).await?;

    Ok("Configuration saved".to_string())
}

/// Rewrites `[scheduler]` inside `existing` and writes the result to
/// `write_path`, filing the entry that says what changed.
///
/// Takes the path, the document it is editing and the logger as arguments
/// rather than resolving any of them, which is the whole reason this is
/// separate from [`save_scheduler_config`]. That command reads both paths from
/// the process environment, so a test driving it would have to move
/// `XDG_CONFIG_HOME` while every other test in this binary is running in a
/// thread beside it. Here the join between the descriptor and the write is
/// observable without touching the environment at all.
pub(crate) async fn write_scheduler_config(
    write_path: &std::path::Path,
    existing: &str,
    config: &hardener_types::scheduler::SchedulerUiConfig,
    logger: Option<&hardener_state::audit::AuditLogger>,
) -> Result<(), String> {
    let mut document: toml_edit::DocumentMut = existing
        .parse()
        .map_err(|e| safe_err(format!("Failed to parse config: {e}")))?;

    // Remove existing scheduler section, serialise the rest, then append
    // a properly grouped [scheduler] block at the end.  toml_edit scatters
    // dotted subtables ([scheduler.notifications.*]) between unrelated
    // sections when assigned via the Table API, so we build the block as
    // a plain string instead.
    document.remove("scheduler");
    let mut output = document.to_string();

    output.push_str(&render_scheduler_section(config, existing)?);

    // Through the shared writer, which is what makes this atomic, makes it
    // preserve the target's mode, and files the audit entry. Before the writer
    // moved into `hardener-core` this was a bare `std::fs::write` recording
    // nothing, not by decision but because `hardener-cli` is a binary and the
    // code that would have done otherwise could not be reached from here.
    write_atomically(
        write_path,
        &output,
        WriteAudit {
            logger,
            action: ActionType::ConfigChange,
            target: "scheduler".to_string(),
            details: scheduler_details(config),
        },
    )
    .await
    .map_err(|e| safe_err(format!("Failed to write config: {e:#}")))
}

/// The audit detail for a scheduler change.
///
/// What an auditor needs is which scans this host now runs unattended and who
/// hears about them, so the schedule, the plugin set and the reporting
/// thresholds all go in. `enabled` first, because turning the scheduler off is
/// the change most easily mistaken for nothing having happened.
///
/// Recipient addresses and the webhook URL are deliberately left out. Whether a
/// channel is on is what changed; the addresses are in the config file, and
/// copying them into an append-only log spreads personal data for no audit
/// question they answer.
pub(crate) fn scheduler_details(
    config: &hardener_types::scheduler::SchedulerUiConfig,
) -> std::collections::HashMap<String, String> {
    std::collections::HashMap::from([
        ("enabled".to_string(), config.enabled.to_string()),
        ("schedule".to_string(), config.schedule.clone()),
        ("plugins".to_string(), config.plugins.join(",")),
        ("min_severity".to_string(), config.min_severity.clone()),
        (
            "notify_min_severity".to_string(),
            config.notifications.notify_min_severity.clone(),
        ),
        (
            "email_enabled".to_string(),
            config.notifications.email.enabled.to_string(),
        ),
        (
            "webhook_enabled".to_string(),
            config.notifications.webhooks.enabled.to_string(),
        ),
    ])
}

/// The `[scheduler]` table already in a config file, or an empty one.
///
/// Fails closed. Returning an empty table on a parse error would be the very
/// defect this merge exists to fix, silently and with no bad input required:
/// every key the form does not model would be dropped on the next save. The
/// caller has already parsed the same text with `toml_edit`, so an error here
/// means the two parsers disagree, and refusing the save is the only answer
/// that cannot lose the operator's settings.
///
/// Empty content is not an error, it is a new file with nothing to preserve.
pub(crate) fn existing_scheduler_table(content: &str) -> Result<toml::Value, String> {
    let document: toml::Value = toml::from_str(content).map_err(|e| {
        safe_err(format!(
            "Failed to read the existing scheduler section: {e}"
        ))
    })?;
    Ok(document
        .get("scheduler")
        .cloned()
        .filter(toml::Value::is_table)
        .unwrap_or_else(|| toml::Value::Table(toml::map::Map::new())))
}

/// Writes `incoming` over `destination`, keeping keys `incoming` does not name.
///
/// Deliberately generic rather than a list of fields to carry across. The whole
/// defect was that the desktop's type models a subset of the scheduler's and the
/// save replaced the section wholesale, so a hardcoded list would have to be
/// remembered every time the backend gains a key, which is the same failure one
/// step later. A key the form does not emit is a key the form does not own.
///
/// Tables merge; every other value, arrays included, is replaced. That is what
/// makes `plugins`, `recipients` and the webhook `endpoints` list editable: the
/// form does emit those, including as an empty array, so clearing one in the GUI
/// clears it in the file.
pub(crate) fn overlay(destination: &mut toml::Value, incoming: toml::Value) {
    match incoming {
        toml::Value::Table(incoming_table) if destination.is_table() => {
            let destination_table = destination
                .as_table_mut()
                .expect("the guard above proved this is a table");
            for (key, value) in incoming_table {
                match destination_table.get_mut(&key) {
                    Some(slot) => overlay(slot, value),
                    None => {
                        destination_table.insert(key, value);
                    }
                }
            }
        }
        other => *destination = other,
    }
}

/// Renders the desktop's scheduler settings as a `[scheduler]` block.
///
/// A seam, not decoration: what the desktop writes has to be what the scheduler
/// reads, and until now nothing checked that. `WebhookUiConfig` rendered a flat
/// `url`/`format` pair into a table whose backend struct expects `endpoints`,
/// nothing rejects an unknown key, and so a saved webhook reached the daemon as
/// an empty list. Testing it through the real `SchedulerConfig` is the only
/// assertion that could have failed.
pub(crate) fn render_scheduler_section(
    config: &hardener_types::scheduler::SchedulerUiConfig,
    existing: &str,
) -> Result<String, String> {
    let mut merged = existing_scheduler_table(existing)?;
    let incoming = toml::Value::try_from(config)
        .map_err(|e| safe_err(format!("Failed to serialise scheduler config: {e}")))?;
    overlay(&mut merged, incoming);
    drop_superseded_webhook_keys(&mut merged);

    // Serialised nested under its own key, so the serialiser emits
    // `[scheduler]` and `[scheduler.notifications.email]` itself. This replaced
    // a pass that re-prefixed each rendered header textually, which could not
    // tell a header from a line of a multi-line string beginning with `[`: it
    // rewrote those too, and since the merge now carries every existing string
    // through, each save nested the mangled value one level deeper than the
    // last. Letting the serialiser name the tables removes the question.
    let mut wrapper = toml::map::Map::new();
    wrapper.insert("scheduler".to_string(), merged);
    let rendered = toml::to_string_pretty(&toml::Value::Table(wrapper))
        .map_err(|e| safe_err(format!("Failed to serialise scheduler config: {e}")))?;

    Ok(format!("\n{rendered}"))
}

/// Removes the flat webhook keys earlier desktop builds wrote.
///
/// `WebhookWire` stopped emitting `url`/`format`, which was enough to retire
/// them while the save replaced the whole section. Under the merge it is not:
/// a key the form does not emit is a key the form keeps, so they would survive
/// every save, and the read path prefers them whenever the endpoint list is
/// empty. Clearing the URL in the GUI wrote `endpoints = []`, the next load
/// showed the deleted URL again, and the save after that promoted it back to a
/// live endpoint the daemon posts to.
///
/// Narrow on purpose: these two are the desktop's own historical spelling of a
/// setting it still owns, and nothing in `hardener-scheduler` has ever read
/// them. They are the exception that proves the ownership rule rather than a
/// hole in it.
pub(crate) fn drop_superseded_webhook_keys(scheduler: &mut toml::Value) {
    let Some(webhooks) = scheduler
        .get_mut("notifications")
        .and_then(|notifications| notifications.get_mut("webhooks"))
        .and_then(toml::Value::as_table_mut)
    else {
        return;
    };
    webhooks.remove("url");
    webhooks.remove("format");
}

/// Reduces one result per channel to the single line the settings pane shows.
///
/// A plain function over plain types, for the reason `summarise_config` is one:
/// the command around it needs a config file, a temporary database and a live
/// dispatcher, and none of that is the decision. The decision is what to tell
/// an operator who pressed "send test" and is waiting to learn whether their
/// notification setup works.
///
/// **Every message names its channels.** `NotificationResult::channel` is
/// populated by both notifiers, and by the webhook one per endpoint, which is
/// only worth doing if a reader sees it. It was dropped here until 2026-08-26,
/// so a host with email and three webhooks configured was told
/// "Failed: connection refused" and could not tell which of the four it was.
///
/// **A failure with no reason recorded is still a failure.** The reasons used
/// to be collected with a `filter_map` over `error`, which drops a row it
/// cannot describe, so a channel that failed without a message would have been
/// counted into `results.len()` and reported as sent. Nothing builds such a row
/// today, because `NotificationResult::failed` is the only constructor that
/// sets `success: false` and it always carries a reason. The fields are `pub`
/// though, so that is a property of the current call sites rather than of the
/// type, and the failing direction is the one that hides.
pub(crate) fn test_notification_verdict(
    results: &[hardener_scheduler::notification::NotificationResult],
) -> hardener_types::scheduler::TestNotificationResult {
    if results.is_empty() {
        return hardener_types::scheduler::TestNotificationResult {
            success: false,
            message: "No notification channels are enabled".into(),
        };
    }

    let failures: Vec<String> = results
        .iter()
        .filter(|r| !r.success)
        .map(|r| {
            let reason = r.error.as_deref().unwrap_or("failed, no reason recorded");
            format!("{}: {reason}", r.channel)
        })
        .collect();

    if failures.is_empty() {
        let names: Vec<&str> = results.iter().map(|r| r.channel.as_str()).collect();
        return hardener_types::scheduler::TestNotificationResult {
            success: true,
            message: format!("Test sent to {}", names.join(", ")),
        };
    }

    hardener_types::scheduler::TestNotificationResult {
        success: false,
        message: format!(
            "{} of {} channels failed. {}",
            failures.len(),
            results.len(),
            failures.join("; ")
        ),
    }
}

/// Sends a test notification through all enabled channels.
///
/// Creates a temporary database so the test doesn't pollute real scan history.
/// Returns a success/failure summary suitable for display in the GUI.
#[tauri::command]
pub async fn test_notification() -> Result<hardener_types::scheduler::TestNotificationResult, String>
{
    let _guard = PrivilegedOpGuard::acquire()?;
    let path = hardener_config_path()?;
    let scheduler_config = if path.exists() {
        let content = std::fs::read_to_string(&path)
            .map_err(|e| safe_err(format!("Failed to read config: {e}")))?;

        #[derive(serde::Deserialize)]
        struct ConfigFile {
            #[serde(default)]
            scheduler: hardener_scheduler::SchedulerConfig,
        }

        let config: ConfigFile = toml::from_str(&content)
            .map_err(|e| safe_err(format!("Failed to parse config: {e}")))?;
        config.scheduler
    } else {
        hardener_scheduler::SchedulerConfig::default()
    };

    // Create temporary database for notification logging
    let tmp_dir =
        tempfile::tempdir().map_err(|e| safe_err(format!("Failed to create temp dir: {e}")))?;
    let db_manager = hardener_scheduler::ScanHistoryManager::new(&tmp_dir.path().join("test.db"))
        .await
        .map_err(|e| safe_err(format!("Failed to create temp DB: {e}")))?;

    let summary = hardener_scheduler::ScanSummary {
        session_id: "test-notification".into(),
        host: hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".into()),
        plugins_scanned: vec!["test".into()],
        total_findings: 1,
        critical_count: 0,
        high_count: 1,
        medium_count: 0,
        low_count: 0,
        info_count: 0,
        json_path: None,
        json_hash: None,
        had_errors: false,
        regression: None,
    };

    let dispatcher = hardener_scheduler::NotificationDispatcher::new(
        &scheduler_config.notifications,
        std::sync::Arc::new(db_manager),
    );

    Ok(test_notification_verdict(
        &dispatcher.send_test(&summary).await,
    ))
}
