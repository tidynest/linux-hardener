//! Split from the former flat `commands.rs` along the seams its test files
//! had already named. Shared plumbing lives in the parent; each domain here
//! keeps its own commands and their private helpers.

use super::*;

/// Whether one checkpoint database could be consulted.
///
/// `Absent` and `Unreadable` were one case while this used `Path::exists`,
/// which is `metadata(..).is_ok()` and so answers `false` for a file it merely
/// may not stat. They are not the same: one means there is nothing to show, the
/// other means there may be something that cannot be shown.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DatabaseReach {
    /// Definitely not there, so nothing is missing from the list.
    Absent,
    /// Opened and listed. Its rows, if any, are in the list.
    Read,
    /// Present, or impossible to ask about, and not readable from here.
    Unreadable,
}

/// Adds one database's checkpoints to `entries`, skipping ids already present.
///
/// De-duplicating on the id matters because the same checkpoint can be reached
/// through either database, and the first database consulted keeps the row.
pub(crate) async fn collect_checkpoints(
    db: &std::path::Path,
    entries: &mut Vec<(Checkpoint, CheckpointManager)>,
) -> DatabaseReach {
    if matches!(db.try_exists(), Ok(false)) {
        return DatabaseReach::Absent;
    }
    let Ok(manager) = create_checkpoint_manager(db).await else {
        return DatabaseReach::Unreadable;
    };
    let Ok(checkpoints) = manager.list_checkpoints().await else {
        return DatabaseReach::Unreadable;
    };
    for checkpoint in checkpoints {
        if !entries
            .iter()
            .any(|(seen, _)| seen.checkpoint_id == checkpoint.checkpoint_id)
        {
            entries.push((checkpoint, manager.clone()));
        }
    }
    DatabaseReach::Read
}

/// Splits collected rows into the ones a rollback here could restore and a
/// count of the ones it could not.
///
/// Every checkpoint records the host it captured. `CheckpointManager::rollback`
/// refuses to restore one host's state onto another, so a row whose key is not
/// this host's is not a restore point this desktop can offer: the red button
/// beside it could only ever fail.
///
/// It is reachable, and not rarely. **`batch apply --execute` runs unprivileged
/// and writes every remote host's pre-apply checkpoints into the local user
/// database**, which is the first source this list reads. The database on the
/// machine this was found on holds 84 such rows and no local one.
///
/// The operator does not even reach the cross-host refusal, because
/// `run_rollback` escalates through `pkexec` first and the root CLI resolves to
/// the system database alone, where a user-database row is simply absent. So
/// the sequence was: pick a remote host's checkpoint from a list headed as this
/// machine's, read a preview of that host's files, authenticate, and be told
/// the checkpoint does not exist. `resolve_delete` states the principle for the
/// neighbouring verb: raising an authentication dialog for an operation that
/// cannot succeed is a prompt the operator can do nothing with.
///
/// Split out and taking the key as an argument so the rule can be tested
/// without a database, an executor or a pkexec prompt. Generic in what travels
/// beside the checkpoint for the same reason it is split out at all: the
/// decision reads `host_key` and nothing else, and a `CheckpointManager` in the
/// signature would have made that only testable against a real database.
pub(crate) fn restorable_here<T>(
    entries: Vec<(Checkpoint, T)>,
    local_key: &str,
) -> (Vec<(Checkpoint, T)>, usize) {
    let total = entries.len();
    let kept: Vec<_> = entries
        .into_iter()
        .filter(|(cp, _)| cp.host_key == local_key)
        .collect();
    let dropped = total - kept.len();
    (kept, dropped)
}

/// Retrieves the checkpoints of THIS host from both user and system databases.
///
/// The system database holds what privileged operations captured, the desktop's
/// own `create_checkpoint` included, since it goes through `pkexec`. The user
/// database holds what an unprivileged CLI run captured, which today means the
/// remote hosts `batch apply` reached. Both are merged and then narrowed to this
/// host by `restorable_here`, which is where the reasoning for the narrowing is.
#[tauri::command]
pub async fn get_checkpoints() -> Result<CheckpointList, String> {
    let mut entries: Vec<(Checkpoint, CheckpointManager)> = Vec::new();

    collect_checkpoints(&get_user_db_path(), &mut entries).await;

    // The system database is root-owned, so an unprivileged desktop often
    // cannot read it, and a list silently missing every privileged checkpoint
    // looks exactly like a host that has none. Report it to the caller as
    // well as the log: the log is not where the operator is looking.
    let system_db = get_system_db_path();
    let system_unreadable =
        collect_checkpoints(&system_db, &mut entries).await == DatabaseReach::Unreadable;
    if system_unreadable {
        tracing::warn!(
            "system checkpoint database at {} could not be read; any checkpoint \
             it holds is missing from this list",
            system_db.display()
        );
    }

    // Narrowed before the signature pass, not after: verifying a checkpoint
    // this host can never restore is a database read and a signing-key lookup
    // spent on a row nobody will be shown.
    let (entries, other_host_count) = restorable_here(
        entries,
        &hardener_common::executor::host_key_for(&hardener_core::LocalExecutor::new()),
    );

    // Sort by timestamp descending (newest first)
    let mut entries = entries;
    entries.sort_by_key(|(cp, _)| std::cmp::Reverse(cp.checkpoint_timestamp));

    // Verify each checkpoint's signature and build response
    let mut result = Vec::with_capacity(entries.len());
    for (cp, manager) in &entries {
        let verified = manager.verify_checkpoint(&cp.checkpoint_id).await.is_ok();

        result.push(CheckpointInfo {
            checkpoint_id: cp.checkpoint_id.as_str().to_string(),
            checkpoint_name: cp.checkpoint_name.clone(),
            checkpoint_created: format_timestamp(cp.checkpoint_timestamp),
            checkpoint_user: cp.checkpoint_username.clone(),
            checkpoint_verified: verified,
        });
    }

    Ok(CheckpointList {
        checkpoints: result,
        system_unreadable,
        other_host_count,
    })
}

/// Creates a manual checkpoint of the current system state.
///
/// Requires root privileges via pkexec since it reads protected system files.
///
/// The name goes last, behind `--`, so one beginning with a hyphen cannot be
/// read as a flag, and nothing may be appended after it. `rollback_args`
/// records what happens when something is: clap refuses the whole command.
///
/// Deserialised into `CheckpointCreated` rather than indexed out of an untyped
/// `Value`. This was the one CLI payload the desktop read by a key spelled at
/// both ends, and the shape it invited is a bad one: renaming the CLI's key
/// still creates the checkpoint, and the desktop reports a failure for an
/// operation that succeeded, whose obvious remedy is to make a second one.
/// `hardener-cli` is a binary and cannot be depended on, so the struct lives in
/// `hardener-state`, which both ends already use.
#[tauri::command]
pub async fn create_checkpoint(name: String) -> Result<String, String> {
    let _guard = PrivilegedOpGuard::acquire()?;
    validate_checkpoint_name(&name)?;

    let args = vec!["checkpoint", "create", "--format", "json", "--", &name];

    let output = run_privileged_command(&args).await.map_err(safe_err)?;

    let created: hardener_state::CheckpointCreated = serde_json::from_str(output.trim())
        .map_err(|e| safe_err(format!("Failed to parse response: {e}")))?;

    Ok(created.checkpoint_id)
}

/// Deletes a checkpoint by ID.
///
/// Tries the user database first, which needs no privilege. A row it does not
/// hold escalates through `pkexec` unless the system database is readable and
/// positively lacks the id; see `resolve_delete` for why absence of an answer
/// still escalates.
#[tauri::command]
pub async fn delete_checkpoint(checkpoint_id: String) -> Result<bool, String> {
    let _guard = PrivilegedOpGuard::acquire()?;
    validate_checkpoint_id(&checkpoint_id)?;

    let cp_id = CheckpointId::new(&checkpoint_id);

    match resolve_delete(&get_user_db_path(), &get_system_db_path(), &cp_id).await {
        DeleteResolution::Removed => Ok(true),
        DeleteResolution::NotFound => Err(format!("no checkpoint with id '{checkpoint_id}'")),
        DeleteResolution::NeedsPrivilege => {
            let args = vec!["checkpoint", "delete", &checkpoint_id];
            run_privileged_command(&args)
                .await
                .map(|_| true)
                .map_err(safe_err)
        }
    }
}

/// What a delete should do, decided without escalating anything.
///
/// Split out so the decision can be tested. Everything the branch turns on is a
/// pair of databases and an id; only the consequence of `NeedsPrivilege` needs
/// `pkexec`, and that is exactly what a test must not run. Returning the
/// decision rather than acting on it means an inverted branch is a failing test
/// rather than a defect nobody can reach.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DeleteResolution {
    /// The user database held the row and it is gone.
    Removed,
    /// Neither database has it, so escalating could only fail.
    NotFound,
    /// It may be a root-owned row, or the system database could not be asked.
    NeedsPrivilege,
}

/// Decides a delete from the two databases alone.
///
/// The user database is tried first because the desktop's own checkpoints live
/// there and need no privilege. Failing that, the fallback exists for root-owned
/// rows and is right, but an id in NEITHER database is what a stale list, a
/// double click, or a row already removed from the CLI produces, and raising an
/// authentication dialog for an operation that cannot succeed is a prompt the
/// operator can do nothing with.
pub(crate) async fn resolve_delete(
    user_db: &std::path::Path,
    system_db: &std::path::Path,
    checkpoint_id: &CheckpointId,
) -> DeleteResolution {
    if user_db.exists()
        && let Ok(manager) = create_checkpoint_manager(user_db).await
        && manager.delete_checkpoint(checkpoint_id).await.is_ok()
    {
        return DeleteResolution::Removed;
    }

    if system_database_denies(system_db, checkpoint_id).await {
        return DeleteResolution::NotFound;
    }
    DeleteResolution::NeedsPrivilege
}

/// Whether the system database is readable and positively lacks this row.
///
/// `false` whenever the question cannot be answered, which is the safe
/// direction: it means "escalate and let the privileged run decide", which is
/// what happened unconditionally before.
pub(crate) async fn system_database_denies(
    system_db: &std::path::Path,
    checkpoint_id: &CheckpointId,
) -> bool {
    // `try_exists`, not `exists`. `Path::exists` is `metadata(..).is_ok()`, so
    // it answers `false` for a file it merely may not stat, and the system
    // database lives under a root-owned directory that an unprivileged desktop
    // frequently cannot search: this host's is `drwx------ root`. Reading that
    // `false` as "no such database" would make every root-owned checkpoint
    // undeletable, which is the precise opposite of leaving the fallback
    // reachable.
    match system_db.try_exists() {
        // Definitely not there: the answer this guard exists to act on.
        Ok(false) => return true,
        // Cannot even be asked. Not an answer, so the privileged run decides.
        Err(_) => return false,
        Ok(true) => {}
    }
    let Ok(manager) = create_checkpoint_manager(system_db).await else {
        return false;
    };
    let Ok(checkpoints) = manager.list_checkpoints().await else {
        return false;
    };
    !checkpoints
        .iter()
        .any(|c| &c.checkpoint_id == checkpoint_id)
}

/// Converts a `Checkpoint` and its `FileState` entries into frontend detail.
pub(crate) fn checkpoint_to_detail(cp: Checkpoint, files: Vec<FileState>) -> CheckpointDetail {
    CheckpointDetail {
        checkpoint_id: cp.checkpoint_id.as_str().to_string(),
        checkpoint_name: cp.checkpoint_name,
        checkpoint_created: format_timestamp(cp.checkpoint_timestamp),
        checkpoint_user: cp.checkpoint_username,
        file_count: files.len(),
        files: files
            .into_iter()
            .map(|f| CheckpointFileInfo {
                // `restore_mode_string`, not the raw mode: `file_permissions`
                // carries the type field, so a file captured at 0644 read
                // `100644` under a column headed "permissions", and the number
                // the operator saw was not the one a rollback would chmod.
                permissions: f.restore_mode_string(),
                path: f.file_path,
                has_content: f.file_content.is_some(),
            })
            .collect(),
    }
}

/// Retrieves detailed checkpoint information including captured files.
///
/// Searches both user and system databases.
#[tauri::command]
pub async fn get_checkpoint_detail(checkpoint_id: String) -> Result<CheckpointDetail, String> {
    validate_checkpoint_id(&checkpoint_id)?;

    let cp_id = CheckpointId::new(&checkpoint_id);

    // Try user database first
    let user_db = get_user_db_path();
    if user_db.exists()
        && let Ok(manager) = create_checkpoint_manager(&user_db).await
        && let Ok((cp, files)) = manager.get_checkpoint(&cp_id).await
    {
        return Ok(checkpoint_to_detail(cp, files));
    }

    // Try system database
    let system_db = get_system_db_path();
    if system_db.exists()
        && let Ok(manager) = create_checkpoint_manager(&system_db).await
        && let Ok((cp, files)) = manager.get_checkpoint(&cp_id).await
    {
        return Ok(checkpoint_to_detail(cp, files));
    }

    Err(format!("Checkpoint '{}' not found", checkpoint_id))
}
