use super::*;
use hardener_state::audit::QueryFilter;

/// Every failure used to fold to `None`, so a privileged run simply had no
/// audit trail and said nothing. The failure must survive as an error carrying
/// the path, which is what lets the caller report it.
#[tokio::test]
async fn an_unusable_audit_directory_produces_an_error_not_silence() {
    let dir = tempfile::tempdir().unwrap();
    // A regular file where a directory belongs: create_dir_all below it fails
    // with ENOTDIR.
    let not_a_dir = dir.path().join("not-a-dir");
    fs::write(&not_a_dir, "regular file").unwrap();

    // AuditLogger has no Debug, so unwrap the Result by hand.
    let message = match audit_logger_in(&not_a_dir.join("logs"), None).await {
        Ok(_) => panic!("an uncreatable audit directory must not fold to success"),
        Err(e) => format!("{e:#}"),
    };
    assert!(
        message.contains("audit log directory"),
        "the error must say what it was doing: {message}"
    );
    assert!(
        message.contains("not-a-dir"),
        "the error must name the path: {message}"
    );
}

/// The ordinary case still works, so the guard above is not just rejecting
/// everything.
#[tokio::test]
async fn a_usable_directory_opens_the_audit_log() {
    let dir = tempfile::tempdir().unwrap();
    let logger_dir = dir.path().join("audit");

    audit_logger_in(&logger_dir, Some(0o700))
        .await
        .expect("a writable directory must yield a logger");

    assert!(logger_dir.join("audit.log").exists());
}

/// A rename over an existing file otherwise carries the temporary file's own
/// mode (the writer's umask default), silently discarding whatever mode the
/// operator set on the target.
#[test]
fn write_file_atomically_preserves_the_target_mode() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "existing = true\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

    write_file_atomically(&path, "existing = true\nnew = 1\n").unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o640);
}

/// A target that does not exist yet has no mode to preserve, so the write still
/// succeeds and the file lands with the temporary file's default mode.
#[test]
fn write_file_atomically_succeeds_for_a_new_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");

    write_file_atomically(&path, "new = 1\n").unwrap();

    assert_eq!(std::fs::read_to_string(&path).unwrap(), "new = 1\n");
}

/// A missing file reads as an empty document rather than an error: the first
/// setting written on a host may be the first line of its config.
#[test]
fn read_or_empty_treats_a_missing_file_as_empty() {
    let dir = tempfile::tempdir().unwrap();

    let text = read_or_empty(&dir.path().join("absent.toml")).unwrap();

    assert_eq!(text, "");
}

/// An unreadable path is an error rather than an empty document, because
/// treating it as empty would silently discard whatever the file holds on the
/// next write.
#[test]
fn read_or_empty_refuses_a_path_it_cannot_read() {
    let dir = tempfile::tempdir().unwrap();

    // A directory is readable as an entry and not as a string, which reaches
    // the arm a permission failure would reach without needing to drop
    // privilege inside a test.
    assert!(read_or_empty(dir.path()).is_err());
}

/// The write files its entry, carrying the details the caller described.
#[tokio::test]
async fn a_successful_write_files_the_entry_the_caller_described() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let log = dir.path().join("audit.log");
    let log_path = log.to_str().unwrap();
    let logger = logger_at(log_path).await.expect("a logger opens");

    write_atomically(
        &path,
        "new = 1\n",
        WriteAudit {
            logger: Some(&logger),
            action: ActionType::ConfigChange,
            target: "scheduler".to_string(),
            details: HashMap::from([("schedule".to_string(), "daily".to_string())]),
        },
    )
    .await
    .expect("the write succeeds");

    let entries = AuditLogger::query(log_path, QueryFilter::new())
        .await
        .expect("query");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].entry_action_type, ActionType::ConfigChange);
    assert_eq!(entries[0].entry_result, ActionResult::Success);
    assert_eq!(entries[0].entry_target, "scheduler");
    assert_eq!(entries[0].entry_details["schedule"], "daily");
    assert!(
        AuditLogger::verify_integrity(log_path)
            .await
            .expect("verify"),
        "the details sit inside the hash chain"
    );
}

/// A write that cannot be made is the attempt an unprivileged operator meets,
/// and it is the one that previously left no trace at all. The entry records
/// the failure and the cause, and the error still reaches the caller.
#[tokio::test]
async fn a_failed_write_is_audited_and_still_returns_its_cause() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("audit.log");
    let log_path = log.to_str().unwrap();
    let logger = logger_at(log_path).await.expect("a logger opens");

    // The parent exists as a file, so creating it as a directory fails and the
    // write never lands.
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, "not a directory").unwrap();

    let outcome = write_atomically(
        &blocker.join("config.toml"),
        "new = 1\n",
        WriteAudit {
            logger: Some(&logger),
            action: ActionType::ConfigChange,
            target: "scheduler".to_string(),
            details: HashMap::from([("schedule".to_string(), "daily".to_string())]),
        },
    )
    .await;

    assert!(outcome.is_err(), "the caller is told the write failed");

    let entries = AuditLogger::query(log_path, QueryFilter::new())
        .await
        .expect("query");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].entry_result, ActionResult::Failure);
    assert!(
        entries[0].entry_details.contains_key("error"),
        "the cause is in the one detail a failure entry hashes"
    );
}

/// A host whose log directory is unwritable still has to be usable, so a
/// missing logger is a state this writer handles rather than refuses.
#[tokio::test]
async fn a_write_without_a_logger_still_lands() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");

    write_atomically(
        &path,
        "new = 1\n",
        WriteAudit {
            logger: None,
            action: ActionType::ConfigChange,
            target: "scheduler".to_string(),
            details: HashMap::new(),
        },
    )
    .await
    .expect("the write succeeds without an audit trail");

    assert_eq!(std::fs::read_to_string(&path).unwrap(), "new = 1\n");
}
