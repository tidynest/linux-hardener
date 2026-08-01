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
