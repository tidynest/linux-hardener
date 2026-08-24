#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. Present so the file
// says what it is on its own terms, matching its siblings in this directory.

//! Tests for the audit detail the desktop's three in-process config writes
//! carry.
//!
//! The writes themselves reach `~/.config` and the audit log through paths
//! chosen from the process environment, so a test cannot drive
//! `save_scheduler_config` or `save_remote_host` without moving both. What a
//! test can pin, and what actually decides whether an entry is worth reading
//! months later, is the detail map each one hands the writer. That is what
//! these assert.
//!
//! Ceiling: an entry whose detail is right and which is never filed passes
//! every test here. That the writes file at all is asserted where the writer
//! lives, in `hardener-core/src/config_write/tests.rs`, and for the inventory
//! in `hardener-core/tests/inventory_shared_path.rs`.

use super::*;
use hardener_types::scheduler::{
    EmailUiConfig, NotificationUiConfig, SchedulerUiConfig, WebhookUiConfig,
};

fn scheduler(enabled: bool) -> SchedulerUiConfig {
    SchedulerUiConfig {
        enabled,
        schedule: "daily".to_string(),
        plugins: vec!["kernel-hardening".to_string(), "ssh-hardening".to_string()],
        min_severity: "medium".to_string(),
        notifications: NotificationUiConfig {
            notify_min_severity: "high".to_string(),
            email: EmailUiConfig {
                enabled: true,
                recipients: vec!["ops@example.com".to_string()],
                ..EmailUiConfig::default()
            },
            webhooks: WebhookUiConfig {
                enabled: false,
                url: "https://hooks.example.com/abc".to_string(),
                ..WebhookUiConfig::default()
            },
        },
    }
}

fn profile(host_key_checking: bool) -> RemoteHostProfile {
    RemoteHostProfile {
        name: "web-01".to_string(),
        hostname: "web-01.example.com".to_string(),
        user: Some("admin".to_string()),
        port: 2222,
        key_file: None,
        host_key_checking,
    }
}

/// What the host now runs unattended, and who hears about it.
#[test]
fn scheduler_detail_names_the_schedule_and_the_plugin_set() {
    let details = scheduler_details(&scheduler(true));

    assert_eq!(details["enabled"], "true");
    assert_eq!(details["schedule"], "daily");
    assert_eq!(details["plugins"], "kernel-hardening,ssh-hardening");
    assert_eq!(details["min_severity"], "medium");
    assert_eq!(details["notify_min_severity"], "high");
    assert_eq!(details["email_enabled"], "true");
    assert_eq!(details["webhook_enabled"], "false");
}

/// Turning the scheduler off is the change most easily mistaken for nothing
/// having happened: no scan runs afterwards, and no failure is reported,
/// because there is nothing left to fail.
#[test]
fn scheduler_detail_records_the_scheduler_being_turned_off() {
    let details = scheduler_details(&scheduler(false));

    assert_eq!(details["enabled"], "false");
}

/// Recipient addresses and the webhook URL stay in the config file.
///
/// Whether a channel is on is the change; the addresses are personal data, and
/// an append-only hash-chained log is the worst place to copy them to for an
/// audit question they do not answer.
#[test]
fn scheduler_detail_carries_no_recipient_or_webhook_url() {
    let details = scheduler_details(&scheduler(true));

    let joined = details.values().cloned().collect::<Vec<_>>().join(" ");
    assert!(
        !joined.contains("ops@example.com"),
        "a recipient address reached the audit log: {joined}"
    );
    assert!(
        !joined.contains("hooks.example.com"),
        "the webhook URL reached the audit log: {joined}"
    );
}

/// A host joining the inventory is named by where it is, not only by what it
/// was called.
#[test]
fn host_detail_names_the_endpoint_and_the_operation() {
    let details = host_details("save", &profile(true));

    assert_eq!(details["operation"], "save");
    assert_eq!(details["hostname"], "web-01.example.com");
    assert_eq!(details["port"], "2222");
    assert_eq!(details["user"], "admin");
    assert_eq!(details["host_key_checking"], "true");
}

/// The one field on a profile that weakens a security decision.
///
/// A host saved with host-key checking off accepts whatever key the far end
/// presents. Without this in the entry, the operator who turned it off is the
/// only record that it happened.
#[test]
fn host_detail_records_host_key_checking_being_turned_off() {
    let details = host_details("save", &profile(false));

    assert_eq!(details["host_key_checking"], "false");
}

/// A profile with no user runs as whoever is logged in, which is a different
/// claim from a profile naming a user, and the entry must not read as though a
/// user was named.
#[test]
fn host_detail_says_so_when_no_user_was_named() {
    let mut anonymous = profile(true);
    anonymous.user = None;

    let details = host_details("save", &anonymous);

    assert_eq!(details["user"], "(current)");
}

// --- The join between a descriptor and a write -------------------------------
//
// Everything above this line asserts a detail map in isolation. That is worth
// having and it is not the whole question: a detail map that is correct and
// never reaches the writer passes every one of those tests. `save_scheduler_config`
// itself cannot be driven here, because it reads both the config path and the
// audit log path from the process environment and moving those under the other
// tests in this binary is the race that put
// `crates/hardener-core/tests/inventory_shared_path.rs` in a binary of its own.
// `write_scheduler_config` takes both as arguments, which is what makes the
// join observable without touching the environment.
//
// Still out of reach: which path `writable_config_path` picks, and which
// document the command hands in when the user file does not exist yet and the
// system config is read as a template.

/// A scheduler save writes the document and files one entry describing it.
///
/// The three assertions have separate jobs. The file must hold the new section,
/// because a writer reporting success and writing nothing is what the shared
/// writer exists to prevent. The unrelated section must survive, because this
/// command edits one table of a file the CLI also writes and a save that
/// flattened the rest would silently drop an operator's exceptions. And exactly
/// one entry must be filed, at the target an auditor filters on.
#[tokio::test]
async fn a_scheduler_save_writes_the_document_and_records_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("config.toml");
    let log_path = dir.path().join("audit.log");
    let log = log_path.to_str().expect("utf-8 path");
    let logger = hardener_core::config_write::logger_at(log).await;

    let existing = "[scan]\nplugins = [\"kernel-hardening\"]\n";
    super::write_scheduler_config(&config_path, existing, &scheduler(true), logger.as_ref())
        .await
        .expect("the scheduler section is written");

    let written = std::fs::read_to_string(&config_path).expect("the config file exists");
    assert!(
        written.contains("[scheduler]"),
        "the section this command exists to write must be in the file: {written}"
    );
    assert!(
        written.contains("[scan]"),
        "the sections it does not own must survive it: {written}"
    );

    let entries =
        hardener_state::audit::AuditLogger::query(log, hardener_state::audit::QueryFilter::new())
            .await
            .expect("query");
    assert_eq!(entries.len(), 1, "one entry per save");
    assert_eq!(entries[0].entry_target, "scheduler");
    assert_eq!(entries[0].entry_action_type, ActionType::ConfigChange);
    assert_eq!(entries[0].entry_details["enabled"], "true");
}

/// Turning the scheduler off is recorded as a change, not as silence.
///
/// The green half of the pair. `enabled = false` is the save most easily
/// mistaken for nothing having happened, and it is the one an auditor asking
/// why the unattended scans stopped is looking for. A write that filed an entry
/// only when the scheduler was on would pass the test above.
#[tokio::test]
async fn turning_the_scheduler_off_is_recorded() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("config.toml");
    let log_path = dir.path().join("audit.log");
    let log = log_path.to_str().expect("utf-8 path");
    let logger = hardener_core::config_write::logger_at(log).await;

    super::write_scheduler_config(&config_path, "", &scheduler(false), logger.as_ref())
        .await
        .expect("an empty starting document is a valid one");

    let entries =
        hardener_state::audit::AuditLogger::query(log, hardener_state::audit::QueryFilter::new())
            .await
            .expect("query");
    assert_eq!(
        entries.len(),
        1,
        "the off switch is a change like any other"
    );
    assert_eq!(entries[0].entry_details["enabled"], "false");
}

/// The inventory the two host writes read back, and the log they file into.
struct HostScratch {
    _dir: tempfile::TempDir,
    inventory: std::path::PathBuf,
    log: std::path::PathBuf,
}

impl HostScratch {
    fn new() -> HostScratch {
        let dir = tempfile::tempdir().expect("tempdir");
        let inventory = dir.path().join("hosts.toml");
        let log = dir.path().join("audit.log");
        HostScratch {
            _dir: dir,
            inventory,
            log,
        }
    }

    fn log_path(&self) -> &str {
        self.log.to_str().expect("utf-8 path")
    }

    async fn logger(&self) -> Option<hardener_state::audit::AuditLogger> {
        hardener_core::config_write::logger_at(self.log_path()).await
    }

    /// The inventory as the next reader would parse it, not as a string.
    ///
    /// A host that reached the file under a mangled key, or twice, is a
    /// difference `contains` would not see and every later lookup would.
    fn hosts(&self) -> Vec<hardener_types::remote::RemoteHostProfile> {
        let text = std::fs::read_to_string(&self.inventory).expect("the inventory file exists");
        toml::from_str::<hardener_types::remote::HostsConfig>(&text)
            .expect("what was written parses as an inventory")
            .hosts
    }

    async fn entries(&self) -> Vec<hardener_state::AuditEntry> {
        hardener_state::audit::AuditLogger::query(
            self.log_path(),
            hardener_state::audit::QueryFilter::new(),
        )
        .await
        .expect("query")
    }
}

/// A host joining the inventory reaches the file, and the entry names it.
///
/// The mutation this exists for is not a wrong detail map, which the tests
/// above already catch. It is the map being built correctly and the write never
/// happening, or happening to a file nobody reads.
#[tokio::test]
async fn saving_a_host_writes_it_to_the_inventory_and_records_it() {
    let scratch = HostScratch::new();
    let logger = scratch.logger().await;

    super::upsert_host(
        &scratch.inventory,
        hardener_types::remote::HostsConfig::default(),
        profile(true),
        logger.as_ref(),
    )
    .await
    .expect("the host is saved");

    let hosts = scratch.hosts();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].name, "web-01");
    assert_eq!(
        hosts[0].port, 2222,
        "the profile's own values, not defaults"
    );

    let entries = scratch.entries().await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].entry_target, "host:web-01");
    assert_eq!(entries[0].entry_details["operation"], "save");
}

/// Re-saving a name already in the inventory replaces it.
///
/// The green half of the pair above: a write that appended would pass every
/// assertion there and leave two rows claiming `web-01`. Every lookup in this
/// file takes the first match, so the edit would read as having been ignored
/// while the file grew a row per save.
#[tokio::test]
async fn saving_a_host_that_is_already_there_replaces_it() {
    let scratch = HostScratch::new();
    let logger = scratch.logger().await;
    let existing = hardener_types::remote::HostsConfig {
        hosts: vec![profile(true)],
    };
    let mut edited = profile(true);
    edited.hostname = "web-01.internal.example.com".to_string();

    super::upsert_host(&scratch.inventory, existing, edited, logger.as_ref())
        .await
        .expect("the host is replaced");

    let hosts = scratch.hosts();
    assert_eq!(hosts.len(), 1, "one row per name, not one row per save");
    assert_eq!(hosts[0].hostname, "web-01.internal.example.com");
}

/// A deleted host leaves the file, and the others stay.
///
/// Two assertions with opposite jobs. The named host must be gone, since a
/// delete that recorded itself and wrote the host back is the failure with no
/// symptom: the fleet keeps scanning a host the operator removed. The other
/// must remain, since a `retain` inverted or widened would empty the inventory
/// and look, in the log, exactly like this test's success.
#[tokio::test]
async fn deleting_a_host_removes_only_that_host() {
    let scratch = HostScratch::new();
    let logger = scratch.logger().await;
    let mut other = profile(true);
    other.name = "db-01".to_string();
    let existing = hardener_types::remote::HostsConfig {
        hosts: vec![profile(true), other],
    };

    super::remove_host(&scratch.inventory, existing, "web-01", logger.as_ref())
        .await
        .expect("the host is deleted");

    let names: Vec<String> = scratch.hosts().into_iter().map(|h| h.name).collect();
    assert_eq!(names, vec!["db-01".to_string()]);

    let entries = scratch.entries().await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].entry_target, "host:web-01");
    assert_eq!(
        entries[0].entry_details["hostname"], "web-01.example.com",
        "the entry says what left, not only that something did"
    );
}

/// Deleting a name that is not in the inventory is still recorded.
///
/// The case with nothing to see afterwards. The file comes back unchanged, so
/// the only evidence the operator acted at all is the entry, and it is the
/// evidence that matters when the name was a typo and the host they meant to
/// remove is still being scanned. The entry carries no `hostname`, because
/// there was no profile to read one off.
#[tokio::test]
async fn deleting_a_name_that_is_not_there_still_records_the_attempt() {
    let scratch = HostScratch::new();
    let logger = scratch.logger().await;
    let existing = hardener_types::remote::HostsConfig {
        hosts: vec![profile(true)],
    };

    super::remove_host(&scratch.inventory, existing, "web-02", logger.as_ref())
        .await
        .expect("a name matching nothing is not an error");

    assert_eq!(
        scratch.hosts().len(),
        1,
        "the inventory is written back unchanged"
    );

    let entries = scratch.entries().await;
    assert_eq!(entries.len(), 1, "the attempt is recorded");
    assert_eq!(entries[0].entry_target, "host:web-02");
    assert_eq!(entries[0].entry_details["operation"], "delete");
    assert!(
        !entries[0].entry_details.contains_key("hostname"),
        "there was no profile to name: {:?}",
        entries[0].entry_details
    );
}
