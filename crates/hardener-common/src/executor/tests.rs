#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`executor`](super).
//!
//! Split out of `executor/mod.rs`. That file *is* the module `executor`, so
//! its tests go here in the directory it already owns; a `executor/mod/`
//! would resolve to no module at all. `super` is unchanged.

use super::*;
use anyhow::{anyhow, bail};

/// A host that ships no `which`, which is every Red Hat and SUSE image the
/// cross-distro suite builds. Only `execute_command` is implemented, so
/// `command_exists` is exercised through the trait's own default body
/// rather than through an override that could answer a different question.
struct WhichlessHost {
    /// Programs present in `PATH`, as `command -v` would resolve them.
    installed: &'static [&'static str],
}

#[async_trait]
impl SystemExecutor for WhichlessHost {
    fn description(&self) -> String {
        "whichless".to_string()
    }

    fn is_remote(&self) -> bool {
        false
    }

    async fn execute_command(&self, program: &str, args: &[&str]) -> Result<CommandOutput> {
        // A missing binary cannot be spawned, so the executor never gets an
        // exit status to report: it fails the whole call. This is the exact
        // shape of the shipped symptom, "Executor error: Failed to execute
        // command which".
        if program != "sh" {
            bail!("Failed to execute command {program}");
        }
        // `sh -c <script> sh <program>`: the probe passes the program as a
        // positional argument, so the name under test is the last one.
        let queried = args.last().copied().unwrap_or_default();
        Ok(CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: i32::from(!self.installed.contains(&queried)),
        })
    }

    async fn read_file(&self, _path: &Path) -> Result<String> {
        Err(anyhow!("unused"))
    }
    async fn read_file_optional(&self, _path: &Path) -> Result<Option<String>> {
        Err(anyhow!("unused"))
    }
    async fn write_file(&self, _path: &Path, _content: &str) -> Result<()> {
        Err(anyhow!("unused"))
    }
    async fn path_exists(&self, _path: &Path) -> Result<bool> {
        Err(anyhow!("unused"))
    }
    async fn file_metadata(&self, _path: &Path) -> Result<FileMetadata> {
        Err(anyhow!("unused"))
    }
    async fn read_dir(&self, _path: &Path) -> Result<Vec<PathBuf>> {
        Err(anyhow!("unused"))
    }
}

#[tokio::test]
async fn an_installed_command_is_found_without_which() {
    let host = WhichlessHost {
        installed: &["systemctl"],
    };
    assert!(
        host.command_exists("systemctl").await.unwrap(),
        "a host without `which` must still be able to confirm systemctl"
    );
}

#[tokio::test]
async fn a_missing_command_reads_as_absent_not_as_a_failed_probe() {
    let host = WhichlessHost { installed: &[] };
    assert!(
        !host.command_exists("systemctl").await.unwrap(),
        "an absent command is an answer, not an error: probing with a tool \
         the host lacks turns every caller's question into a plugin failure"
    );
}

/// Positive control for the group below, which is otherwise about what the key
/// is NOT: a local scan on a host with a readable name still keys on that name,
/// so a failure in the group cannot be a reader that stopped reading.
#[tokio::test]
async fn a_local_scan_still_keys_on_the_host_name() {
    let executor = MockExecutor::new().with_file("/etc/hostname", "workstation\n");

    assert_eq!(session_host_key(&executor).await, "workstation");
}

#[tokio::test]
async fn a_remote_scan_keys_on_the_target_it_was_reached_at() {
    // `hardener --ssh root@remote scan` must not file under the controller,
    // which is the whole of issue #70. It keys on the target rather than on the
    // remote's own name: the name is neither unique nor stable, and no
    // /etc/hostname is read for a remote at all.
    let executor = MockExecutor::new()
        .remote()
        .with_description("ssh://root@10.242.117.2:22")
        .with_file("/etc/hostname", "remote-box\n");

    assert_eq!(
        session_host_key(&executor).await,
        "ssh://root@10.242.117.2:22"
    );
    assert!(
        !executor
            .log()
            .files_read
            .contains(&std::path::PathBuf::from("/etc/hostname")),
        "a remote's key comes off the target, so its /etc/hostname is not read at all"
    );
}

#[tokio::test]
async fn two_remotes_sharing_a_hostname_do_not_share_a_row() {
    // The collision the first version of this fix would have moved rather than
    // removed: a fresh Rocky host answers `localhost.localdomain`, and two of
    // them keyed on that name would pile into one row, so one host's trend
    // would be built from the other's findings.
    let one = MockExecutor::new()
        .remote()
        .with_description("ssh://root@10.0.0.5:22")
        .with_file("/etc/hostname", "localhost.localdomain\n");
    let two = MockExecutor::new()
        .remote()
        .with_description("ssh://root@10.0.0.6:22")
        .with_file("/etc/hostname", "localhost.localdomain\n");

    assert_ne!(
        session_host_key(&one).await,
        session_host_key(&two).await,
        "two hosts answering to the same name must still key apart"
    );
}

#[tokio::test]
async fn an_unreadable_local_name_falls_back_to_the_executor_key() {
    // The old fallbacks were the literal "localhost" on both sides, which
    // cannot be told apart from a real remote's row.
    let executor = MockExecutor::new();

    assert_eq!(session_host_key(&executor).await, "local");
}

#[tokio::test]
async fn an_empty_name_file_does_not_become_an_empty_key() {
    // A file that exists and holds nothing but a newline reads Ok, so the
    // error branch never sees it. An empty key groups every such host into one
    // row.
    let executor = MockExecutor::new().with_file("/etc/hostname", "\n");

    assert_eq!(session_host_key(&executor).await, "local");
}

#[tokio::test]
async fn a_commented_name_file_keys_on_the_name_and_not_on_the_comment() {
    // hostname(5) allows comments, and a whole-file trim would have made the
    // key the file: the name, a newline and the comment, which no other
    // surface would ever produce for that host.
    let executor = MockExecutor::new().with_file("/etc/hostname", "# set by the installer\nbox\n");

    assert_eq!(session_host_key(&executor).await, "box");
}
