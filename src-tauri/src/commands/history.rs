//! Split from the former flat `commands.rs` along the seams its test files
//! had already named. Shared plumbing lives in the parent; each domain here
//! keeps its own commands and their private helpers.

use super::*;

/// Converts a stored `ScanSession` into the frontend's session metadata.
///
/// A free function rather than `impl From`: both types are now foreign to this
/// crate, so the coherence rules reject the trait impl (E0117).
pub(crate) fn session_to_info(s: ScanSession) -> ScanSessionInfo {
    ScanSessionInfo {
        session_id: s.session_id.as_str().to_string(),
        started_at: format_timestamp(s.session_started_at),
        completed_at: s.session_completed_at.map(format_timestamp),
        total_findings: s.session_total_findings,
        total_plugins: s.session_total_plugins,
        status: s.session_status.as_str().to_string(),
    }
}

/// The most history rows one desktop call asks for.
///
/// A ceiling rather than a preference: these lists render every row they are
/// handed, and the databases behind them grow without bound. `get_host_history`
/// has clamped at this number since it was written. `get_scan_history` passed
/// its argument to SQL's `LIMIT` untouched, so the one command with no ceiling
/// was also the one that could be asked to remove the ceiling it did not have.
pub(crate) const HISTORY_ROW_CEILING: u32 = 100;

/// How many rows a scan-history query asks for.
///
/// **Refuses a negative rather than clamping it.** In SQLite `LIMIT -1` is no
/// limit at all and `LIMIT 0` returns nothing, so the sign carries a meaning
/// no caller intends, and quietly reading it as 1 or as the default would turn
/// an obviously wrong argument into a plausible answer. Zero is left alone: it
/// asks for no rows and gets none, which is what it says.
///
/// Split out so the rule can be driven without a database. Its sibling
/// `get_host_history` takes a `u32` and cannot be asked this at all; this one
/// is on the IPC boundary with an `i32` that `tauri_bindings.rs` also spells,
/// and changing that spelling would move the WASM bundle and owe a sweep for a
/// guard that belongs on this side of the boundary anyway.
pub(crate) fn scan_history_rows(requested: Option<i32>) -> Result<i32, String> {
    let wanted = requested.unwrap_or(20);
    if wanted < 0 {
        return Err(format!(
            "scan history limit must not be negative, got {wanted}"
        ));
    }
    Ok(wanted.min(HISTORY_ROW_CEILING as i32))
}

/// Lists recent scan history sessions (metadata only).
#[tauri::command]
pub async fn get_scan_history(limit: Option<i32>) -> Result<Vec<ScanSessionInfo>, String> {
    let take = scan_history_rows(limit)?;
    let manager = create_scan_history_manager().await?;
    let sessions = manager.list_sessions(take).await.map_err(safe_err)?;

    Ok(sessions.into_iter().map(session_to_info).collect())
}

/// Retrieves full scan results for a specific session.
#[tauri::command]
pub async fn get_scan_session(session_id: String) -> Result<Vec<ScanResult>, String> {
    validate_ipc_string(&session_id, "session_id")?;

    let manager = create_scan_history_manager().await?;
    let id = ScanSessionId::new(session_id);

    manager.get_session_results(&id).await.map_err(safe_err)
}

/// Resolves the scheduler history database path: the `[scheduler]` section of
/// the hardener config when present, else the scheduler default. Matches the
/// CLI's resolution so the GUI reads the history `batch scan` writes.
pub(crate) fn scheduler_db_path() -> Result<std::path::PathBuf, String> {
    #[derive(serde::Deserialize)]
    struct ConfigFile {
        #[serde(default)]
        scheduler: hardener_scheduler::SchedulerConfig,
    }

    let path = hardener_config_path()?;
    if path.exists()
        && let Ok(content) = std::fs::read_to_string(&path)
        && let Ok(config) = toml::from_str::<ConfigFile>(&content)
    {
        return Ok(config.scheduler.storage.database_path);
    }
    Ok(hardener_scheduler::SchedulerConfig::default()
        .storage
        .database_path)
}

/// Maps newest-first completed sessions to display rows, each carrying a
/// severity-priority direction against the next-older scan. `take` bounds the
/// rows returned; the slice may hold one extra session so the oldest shown row
/// still gets a direction.
pub(crate) fn sessions_to_info(
    sessions: &[hardener_scheduler::db::ScanSession],
    take: usize,
) -> Vec<HostSessionInfo> {
    use hardener_scheduler::db::is_worse;

    sessions
        .iter()
        .take(take)
        .enumerate()
        .map(|(i, s)| {
            let direction = sessions.get(i + 1).map(|prev| {
                if is_worse(prev.severity_tuple(), s.severity_tuple()) {
                    "worse"
                } else if is_worse(s.severity_tuple(), prev.severity_tuple()) {
                    "better"
                } else {
                    "same"
                }
                .to_string()
            });
            HostSessionInfo {
                started: s
                    .started_at_utc()
                    .with_timezone(&chrono::Local)
                    .format("%Y-%m-%d %H:%M")
                    .to_string(),
                status: s.status.clone(),
                total_findings: s.total_findings,
                critical: s.critical_count,
                high: s.high_count,
                medium: s.medium_count,
                low: s.low_count,
                info: s.info_count,
                direction,
            }
        })
        .collect()
}

/// Per-host scan history from the scheduler database. Written by `batch scan`
/// and scheduled scans; GUI fleet scans are in-memory and do not persist
/// here. `host` is the inventory name or the canonical ad-hoc target.
#[tauri::command]
pub async fn get_host_history(
    host: String,
    limit: Option<u32>,
) -> Result<Vec<HostSessionInfo>, String> {
    validate_ipc_string(&host, "host")?;
    // Same ceiling as the scan-history list, from the one place it is stated.
    // The default differs on purpose: this is a rail inside an expanded host
    // row rather than a page of its own.
    let take = limit.unwrap_or(10).min(HISTORY_ROW_CEILING);

    let db = hardener_scheduler::ScanHistoryManager::new(&scheduler_db_path()?)
        .await
        .map_err(safe_err)?;
    let filter = hardener_scheduler::db::SessionFilter {
        host: Some(host),
        status: Some("completed".to_string()),
        // One extra row so the oldest displayed scan still gets a direction.
        limit: Some(take + 1),
        ..Default::default()
    };
    let sessions = db.list_sessions(&filter).await.map_err(safe_err)?;
    Ok(sessions_to_info(&sessions, take as usize))
}

// ---------------------------------------------------------------------------
// Fleet apply / rollback
// ---------------------------------------------------------------------------
