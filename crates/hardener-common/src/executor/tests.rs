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

/// A host that runs commands for real via `std::process::Command`, in the
/// same spirit as [`WhichlessHost`]: only `execute_command` is implemented,
/// so a method under test is still exercised through the trait's own default
/// body rather than through an override that could answer a different
/// question.
///
/// Used to prove [`LINK_PROBE_SCRIPT`]'s `$E` handling against a real shell:
/// a fixture that fakes stdout, as [`ScriptedProbeHost`] does below, can only
/// state what the script does with its elevation argument, never prove it.
struct RealShellHost;

#[async_trait]
impl SystemExecutor for RealShellHost {
    fn description(&self) -> String {
        "real-shell".to_string()
    }

    fn is_remote(&self) -> bool {
        false
    }

    async fn execute_command(&self, program: &str, args: &[&str]) -> Result<CommandOutput> {
        let output = std::process::Command::new(program)
            .args(args)
            .output()
            .map_err(|e| anyhow!("failed to execute {program}: {e}"))?;
        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or(-1),
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

/// Runs [`LINK_PROBE_SCRIPT`] through a real shell with a stated elevation,
/// bypassing [`SystemExecutor::link_target_as_writer`]'s own choice of one.
///
/// Shared by the two tests below, which is the point: both need to drive the
/// script with an elevation the trait would never pick, and duplicating the
/// argv would let the two drift into exercising different invocations.
///
/// The script exits 0 for every outcome of its own, a failed elevation
/// included, so that is asserted here rather than folded into a refusal: a
/// non-zero status would mean the script did not run to completion at all,
/// which is a different finding from any answer it prints.
async fn probe_with_elevation(
    host: &RealShellHost,
    path: &Path,
    elevation: &str,
) -> Result<Option<PathBuf>> {
    let path_str = path.to_string_lossy();
    let output = host
        .execute_command("sh", &["-c", LINK_PROBE_SCRIPT, "_", &path_str, elevation])
        .await
        .expect("sh runs");
    assert_eq!(
        output.exit_code, 0,
        "the script itself always exits 0 for every one of its own outcomes"
    );
    parse_link_probe(&output.stdout)
}

/// Whether the test runner is root, asked of the same shell the probe uses.
///
/// [`LINK_PROBE_SCRIPT`] sets `E=""` whenever the runner is root, whatever
/// `$2` holds, so a test that states something about an elevation argument has
/// to know which case it is in. Asked rather than assumed: the cross-distro
/// containers run as root and a contributor's machine does not.
async fn runner_is_root(host: &RealShellHost) -> bool {
    let output = host
        .execute_command("id", &["-u"])
        .await
        .expect("id runs on any POSIX host");
    output.stdout.trim() == "0"
}

/// The script pins `PATH` to the very list `resolve_binary` searches.
///
/// Every other command this crate runs is resolved to an absolute path through
/// [`crate::binary_utils::resolve_binary`] as an explicit CWE-426 mitigation.
/// The four commands inside this script are resolved by the shell instead, so
/// the mitigation has to be re-stated as a `PATH` assignment, and this is what
/// stops the two lists drifting apart: adding a directory to `TRUSTED_PATH`
/// without adding it here would leave the probe searching a shorter list than
/// the rest of the crate, and removing one would leave it searching a longer.
#[test]
fn the_probe_pins_path_to_the_same_trusted_list_resolve_binary_uses() {
    let expected = format!("PATH={}\n", crate::binary_utils::TRUSTED_PATH.join(":"));

    assert!(
        LINK_PROBE_SCRIPT.starts_with(&expected),
        "the script must open by pinning PATH to the trusted list, expected to \
         start with {expected:?}"
    );
}

/// An elevation that runs nothing at all must produce no token, not the
/// admitting one.
///
/// This is the assertion the script's single-invocation shape exists for. When
/// each command elevated separately, the `else` branch of `test -h` inferred
/// "not a symlink" from an exit status that also meant "could not `lstat`" and
/// "the elevated command never ran", so a `sudo` rule scoped to a command
/// list, an absent binary or any transient exec failure printed `NOTLINK` for
/// a real symlink. `false` stands in for every one of those: it is a real
/// binary that accepts any arguments, runs nothing and fails, needing no
/// privilege and no host configuration to reproduce.
///
/// The sibling test below asserts the same outcome for two elevations, which
/// is what makes it blind to the prefix being dropped entirely; this one is
/// the opposite, an elevation that must **change** the answer.
///
/// Under a root runner the script sets `E=""` regardless of `$2`, so `false`
/// is never reached and the correct answer is the real one. That is asserted
/// as such rather than skipped, so the test still says something true on the
/// cross-distro containers instead of quietly passing.
#[tokio::test]
async fn an_elevation_that_runs_nothing_yields_no_answer_rather_than_admitting() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("real.conf");
    let link = dir.path().join("link.conf");
    std::fs::write(&target, "content\n").expect("write target");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    let resolved_target = target.canonicalize().expect("canonicalize target");

    let host = RealShellHost;
    let outcome = probe_with_elevation(&host, &link, "false").await;

    if runner_is_root(&host).await {
        assert_eq!(
            outcome.expect("a root runner ignores $2, so this is an ordinary answer"),
            Some(resolved_target),
            "a root runner sets E empty whatever $2 holds, so the elevation is \
             never reached and the real answer stands"
        );
        return;
    }

    assert!(
        outcome.is_err(),
        "an elevation that runs nothing must yield no token at all: printing \
         NOTLINK here is exactly the admitting answer that let root write \
         through a symlink the probe never looked at"
    );
}

/// Proves the word-splitting `LINK_PROBE_SCRIPT` relies on: it sets
/// `E="$2"` and later runs `$E readlink ...` and `$E test ...` unquoted,
/// precisely so a two-word elevation prefix such as `sudo -n` splits into a
/// command and its flag. Nothing else in this suite runs the script through a
/// real shell with a real multi-word prefix; [`ScriptedProbeHost`] only ever
/// fakes the answer.
///
/// `sudo` itself cannot be exercised here without privilege, and a test that
/// needed passwordless sudo would fail on a contributor's machine that lacks
/// it, so this proves the mechanism with a harmless stand-in instead: `env -u
/// LINK_PROBE_UNSET_MARKER`, a two-word prefix that unsets a variable nothing
/// sets and then runs the command that follows unchanged, needing no
/// privilege at all. If `$E` were ever quoted as `"$E"`, that whole two-word
/// string would be looked up as a single command name, no `env
/// -u LINK_PROBE_UNSET_MARKER` binary exists, the run would fail, and the
/// answer would degrade to `UNDETERMINED` rather than the correct one.
///
/// The uid check in the script sets `E=""` whenever the runner is root,
/// regardless of `$2`, which would make the two-word case indistinguishable
/// from the empty one under a root test runner. This is not hidden: both
/// elevations are asserted against the one outcome that is true either way,
/// so under a root runner this test proves only that the empty-elevation path
/// answers correctly, and it does that honestly rather than by skipping.
///
/// Asserting one outcome for both elevations is also this test's blind spot:
/// a script that ignored `$2` entirely would satisfy every assertion here.
/// `an_elevation_that_runs_nothing_yields_no_answer_rather_than_admitting`
/// above is the complement, an elevation that must change the answer.
#[tokio::test]
async fn the_elevation_prefix_is_word_split_by_a_real_shell() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("real.conf");
    let link = dir.path().join("link.conf");
    std::fs::write(&target, "content\n").expect("write target");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    let resolved_target = target.canonicalize().expect("canonicalize target");

    let host = RealShellHost;

    for elevation in ["", "env -u LINK_PROBE_UNSET_MARKER"] {
        assert_eq!(
            probe_with_elevation(&host, &link, elevation)
                .await
                .expect("a link is an answer"),
            Some(resolved_target.clone()),
            "elevation {elevation:?} must still answer LINK for a real symlink: \
             if $E were quoted this two-word prefix would be one unfindable \
             command name and the answer would degrade to UNDETERMINED instead"
        );
        assert_eq!(
            probe_with_elevation(&host, &target, elevation)
                .await
                .expect("a file is an answer"),
            None,
            "elevation {elevation:?} must still answer NOTLINK for a real file: \
             if $E were quoted this two-word prefix would be one unfindable \
             command name and the answer would degrade to UNDETERMINED instead"
        );
    }
}

/// A host that answers the link probe with whatever a fixture states, and
/// records the argv it was handed.
///
/// Only `execute_command` is implemented, so `link_target_as_writer` is
/// exercised through the trait's own default body rather than through an
/// override that could answer a different question. That is the same reason
/// [`WhichlessHost`] exists.
struct ScriptedProbeHost {
    /// Exactly what the probe script is to print on stdout.
    answer: &'static str,
    /// The exit code `execute_command` reports alongside `answer`. Real runs
    /// of [`LINK_PROBE_SCRIPT`] never exit non-zero themselves; this exists so
    /// a test can state the shape of a run that did not complete, `sh` absent
    /// or the process killed after flushing partial output.
    exit_code: i32,
    /// What [`SystemExecutor::is_remote`] reports, which is what
    /// [`SystemExecutor::link_target_as_writer`] chooses the probe's
    /// elevation argument from.
    remote: bool,
    /// The argv of the last `execute_command`, for asserting how the path
    /// reaches the script.
    seen: std::sync::Mutex<Vec<String>>,
}

impl ScriptedProbeHost {
    fn answering(answer: &'static str) -> Self {
        Self {
            answer,
            exit_code: 0,
            remote: true,
            seen: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn answering_with_exit_code(answer: &'static str, exit_code: i32) -> Self {
        Self {
            answer,
            exit_code,
            remote: true,
            seen: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// A local, non-remote variant of [`Self::answering`], for asserting what
    /// a local executor passes as the probe's elevation argument.
    fn answering_as_local(answer: &'static str) -> Self {
        Self {
            answer,
            exit_code: 0,
            remote: false,
            seen: std::sync::Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl SystemExecutor for ScriptedProbeHost {
    fn description(&self) -> String {
        "scripted-probe".to_string()
    }

    fn is_remote(&self) -> bool {
        self.remote
    }

    async fn execute_command(&self, program: &str, args: &[&str]) -> Result<CommandOutput> {
        let mut argv = vec![program.to_string()];
        argv.extend(args.iter().map(|a| a.to_string()));
        *self.seen.lock().expect("seen mutex poisoned") = argv;
        Ok(CommandOutput {
            stdout: self.answer.to_string(),
            stderr: String::new(),
            exit_code: self.exit_code,
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

/// The path reaches the script as a positional argument, never as shell text.
///
/// This is the assertion that keeps the probe free of quoting bugs: a path
/// holding a space, a quote or a `;` is one `argv` entry and the script reads
/// it as `"$1"`. Building a command string instead would put the caller one
/// missed `shell_escape` away from running the path as code, on a host where
/// the very next step writes as root.
#[tokio::test]
async fn the_probed_path_is_passed_as_argv_and_never_interpolated() {
    let host = ScriptedProbeHost::answering("NOTLINK");
    // No trailing slash: that is a different concern, covered by
    // `a_trailing_slash_is_stripped_before_the_script_ever_sees_it`, and
    // mixing it in here would make this assertion fail for a reason that has
    // nothing to do with quoting.
    let path = Path::new("/etc/x/a file; rm -rf /tmp");

    host.link_target_as_writer(path)
        .await
        .expect("the probe answers");

    let seen = host.seen.lock().expect("seen mutex poisoned").clone();
    assert_eq!(seen[0], "sh", "the probe runs one shell");
    assert_eq!(seen[1], "-c", "the script arrives as -c");
    assert_eq!(
        seen.len(),
        6,
        "argv is sh, -c, script, $0, path, elevation: a shift here means a \
         positional slid into the wrong slot"
    );
    assert_eq!(
        seen[4], "/etc/x/a file; rm -rf /tmp",
        "the path is the second-to-last positional, verbatim and unescaped, \
         with the elevation argument after it"
    );
    assert!(
        !seen[2].contains("rm -rf"),
        "the path must never be interpolated into the script itself"
    );
}

/// The elevation the probe asks for is the executor's own property, not a
/// constant: it must match whatever that executor's own `write_file`
/// elevates with, or the probe answers for a different user than the one
/// that acts.
///
/// `SshExecutor::write_file` goes through `sudo tee`, so a remote probe must
/// ask `sudo -n` too. `LocalExecutor::write_file` calls `std::fs::write`
/// directly with no elevation at all, so a local probe must ask for none: a
/// local session asking for `sudo -n` would answer as root for a write that
/// in fact happens as the process user, which is the same mismatch this
/// guard exists to remove, pointed the other way. It also has a second cost
/// left unfixed: on a local session without passwordless sudo, every probe
/// would answer UNDETERMINED, failing any test that exercises this path on a
/// non-root contributor machine.
#[tokio::test]
async fn the_elevation_argument_matches_this_executors_own_write_privilege() {
    let remote_host = ScriptedProbeHost::answering("NOTLINK");
    remote_host
        .link_target_as_writer(Path::new("/etc/x/plain.conf"))
        .await
        .expect("the probe answers");
    let remote_seen = remote_host
        .seen
        .lock()
        .expect("seen mutex poisoned")
        .clone();
    assert_eq!(
        remote_seen.last().map(String::as_str),
        Some("sudo -n"),
        "a remote executor's write_file elevates via sudo tee, so its probe \
         must ask for sudo -n or it answers for a different user than the \
         one that will act"
    );

    let local_host = ScriptedProbeHost::answering_as_local("NOTLINK");
    local_host
        .link_target_as_writer(Path::new("/etc/x/plain.conf"))
        .await
        .expect("the probe answers");
    let local_seen = local_host.seen.lock().expect("seen mutex poisoned").clone();
    assert_eq!(
        local_seen.last().map(String::as_str),
        Some(""),
        "a local executor's write_file never elevates, so its probe must ask \
         for nothing: asking sudo -n here would answer as root for a write \
         that in fact happens as the process user"
    );
}

#[tokio::test]
async fn a_plain_file_is_positively_not_a_symlink() {
    let host = ScriptedProbeHost::answering("NOTLINK");

    assert_eq!(
        host.link_target_as_writer(Path::new("/etc/x/plain.conf"))
            .await
            .expect("NOTLINK is an answer, not a failure"),
        None,
        "NOTLINK is the positive answer the guard admits on"
    );
}

#[tokio::test]
async fn a_link_reports_the_path_it_finally_resolves_to() {
    let host = ScriptedProbeHost::answering("LINK /usr/lib/systemd/system/sshd.service");

    assert_eq!(
        host.link_target_as_writer(Path::new("/etc/x/sshd.service"))
            .await
            .expect("LINK is an answer"),
        Some(PathBuf::from("/usr/lib/systemd/system/sshd.service")),
        "the resolved destination is what the allowlist is judged against"
    );
}

/// The whole of issue #83: an answer the probe could not determine must not
/// arrive as the positive "not a symlink".
#[tokio::test]
async fn an_undetermined_probe_is_an_error_and_never_not_a_symlink() {
    let host = ScriptedProbeHost::answering("UNDETERMINED");

    let outcome = host.link_target_as_writer(Path::new("/root/.ssh/authorized_keys"));

    assert!(
        outcome.await.is_err(),
        "a path the probe could not look at must fail closed: reading it as \
         'not a symlink' is what let root write through a link it never saw"
    );
}

/// Noise on stdout is not an answer either.
///
/// A login banner, a sudo lecture or a locale-translated warning must not be
/// folded into a positive. This is the lesson `parse_path_exists_probe` was
/// written for, applied to a gate that authorises a root write.
#[test]
fn unexpected_probe_output_fails_closed() {
    for noise in [
        "",
        "Last login: Tue Aug  4 09:00:00 2026\nNOTLINK",
        "notlink",
        "LINK ",
        "sudo: a terminal is required to read the password",
    ] {
        assert!(
            parse_link_probe(noise).is_err(),
            "output the probe cannot have produced must refuse, got a pass for {noise:?}"
        );
    }
}

/// The control for the test above, and it is what makes it non-vacuous: a
/// parser that refused everything would satisfy every assertion there.
#[test]
fn the_two_answers_the_probe_can_produce_are_accepted() {
    assert_eq!(
        parse_link_probe("NOTLINK").expect("NOTLINK parses"),
        None,
        "the positive answer must survive the strictness above"
    );
    assert_eq!(
        parse_link_probe("LINK /etc/target.conf").expect("LINK parses"),
        Some(PathBuf::from("/etc/target.conf")),
        "a resolved target must survive the strictness above"
    );
}

/// A trailing slash reaches the script with the slash removed, and the root
/// itself still probes as `/` rather than as an empty string.
///
/// A trailing slash forces the kernel to resolve the terminal component
/// before the `lstat` behind `test -h`, which reads a symlink as `NOTLINK`:
/// the whole of issue #83's trailing-slash finding. Fixing that in the shell
/// script would leave the same bug for any other caller of the script; fixing
/// it in Rust, before the argv is built, is what this test pins down.
#[tokio::test]
async fn a_trailing_slash_is_stripped_before_the_script_ever_sees_it() {
    let host = ScriptedProbeHost::answering("LINK /abs/realdir");

    host.link_target_as_writer(Path::new("/etc/x/linkdir/"))
        .await
        .expect("the probe answers");

    {
        let seen = host.seen.lock().expect("seen mutex poisoned");
        assert_eq!(
            seen[seen.len() - 2],
            "/etc/x/linkdir",
            "the trailing slash must not reach the script: it would make test -h \
             follow the link and hide a real symlink as NOTLINK"
        );
    }

    let root_host = ScriptedProbeHost::answering("NOTLINK");
    root_host
        .link_target_as_writer(Path::new("/"))
        .await
        .expect("the probe answers");

    let seen = root_host.seen.lock().expect("seen mutex poisoned");
    assert_eq!(
        seen[seen.len() - 2],
        "/",
        "the root must still be probed as / rather than collapsing to an empty argument"
    );
}

/// Pure unit coverage of [`normalise_probe_path`] itself, independent of the
/// executor plumbing above.
#[test]
fn normalise_probe_path_trims_trailing_slashes_and_keeps_the_root() {
    assert_eq!(
        normalise_probe_path("/etc/x/plain.conf").expect("a plain path must normalise"),
        "/etc/x/plain.conf",
        "a path with no trailing slash must pass through unchanged"
    );
    assert_eq!(
        normalise_probe_path("/etc/x/linkdir/").expect("a trailing slash must normalise"),
        "/etc/x/linkdir",
        "a single trailing slash must be removed"
    );
    assert_eq!(
        normalise_probe_path("/etc/x/linkdir///")
            .expect("a run of trailing slashes must normalise"),
        "/etc/x/linkdir",
        "a run of trailing slashes must all be removed, not just the last one"
    );
    assert_eq!(
        normalise_probe_path("/").expect("the root must normalise"),
        "/",
        "the root must be preserved rather than trimmed to an empty string"
    );
    assert_eq!(
        normalise_probe_path("//").expect("an all-slash path must normalise"),
        "/",
        "an all-slash path names the root and must reduce to it, not to empty"
    );
}

/// Issue #83's second finding: a trailing dot segment dereferences the final
/// named component for the identical reason a trailing slash does, so it
/// must be refused rather than probed.
///
/// `linkdir/.` genuinely names whatever `linkdir` resolves to, so `test -h`
/// answering false for it is correct POSIX behaviour; the naive fix of
/// resolving the dot segment ourselves was rejected because doing so by name
/// disagrees with the kernel whenever the component before it is a symlink,
/// in the admitting direction. `NOTLINK` is this probe's admitting answer, so
/// a shape with no final named component to be about must never reach the
/// script at all.
#[test]
fn a_trailing_dot_segment_is_refused_rather_than_probed() {
    for refused in ["/etc/x/.", "/etc/x/..", "/etc/x/./", ".", ".."] {
        assert!(
            normalise_probe_path(refused).is_err(),
            "a path whose final component is . or .. must refuse, got a pass for {refused:?}: \
             NOTLINK is the admitting answer, so guessing at what the dot segment names is not \
             an option"
        );
    }
}

/// The control for the refusal above, and what makes it non-vacuous: a
/// function that refused every path would satisfy every assertion there too.
#[test]
fn ordinary_paths_still_normalise_after_the_dot_segment_refusal() {
    assert_eq!(
        normalise_probe_path("/etc/x").expect("an ordinary path with no dot segment must pass"),
        "/etc/x",
        "a path with no trailing slash and no dot segment must be accepted unchanged"
    );
    assert_eq!(
        normalise_probe_path("/etc/x/").expect("a plain trailing slash must still normalise"),
        "/etc/x",
        "a trailing slash with no dot segment behind it must still be accepted, not \
         swept up by the new refusal"
    );
    assert_eq!(
        normalise_probe_path("/").expect("the root must still normalise"),
        "/",
        "the filesystem root must still be accepted and probed as /"
    );
    assert_eq!(
        normalise_probe_path("/etc/x/.env").expect("a dotfile is not a dot segment"),
        "/etc/x/.env",
        "an ordinary dotfile is not a dot segment: refusing one would block a rollback \
         of a real file"
    );
    assert_eq!(
        normalise_probe_path("/etc/x/..bak")
            .expect("a leading-double-dot name is not a dot segment"),
        "/etc/x/..bak",
        "an ordinary dotfile is not a dot segment: refusing one would block a rollback \
         of a real file"
    );
    assert_eq!(
        normalise_probe_path("/etc/x/...").expect("three dots is not a dot segment"),
        "/etc/x/...",
        "an ordinary dotfile is not a dot segment: refusing one would block a rollback \
         of a real file"
    );
}

/// The refusal above must happen before any command is built, not after a
/// probe that then gets discarded: a refused shape must never reach
/// `execute_command` at all.
#[tokio::test]
async fn a_refused_dot_segment_never_executes_a_command() {
    let host = ScriptedProbeHost::answering("NOTLINK");

    let outcome = host.link_target_as_writer(Path::new("/etc/x/.")).await;

    assert!(
        outcome.is_err(),
        "a trailing dot segment must refuse rather than being probed"
    );
    assert!(
        host.seen.lock().expect("seen mutex poisoned").is_empty(),
        "no command may run for a refused shape: an execute_command call recorded here would \
         mean the refusal happened after the probe ran instead of before it"
    );
}

/// A non-zero exit is refused even when stdout already carries a well-formed
/// `NOTLINK`.
///
/// Every outcome the script produces on its own exits 0; a non-zero status
/// can only mean the script did not run to completion, `sh` absent (127) or
/// the process killed after flushing a token that happens to parse. Reading
/// stdout in that case would let a truncated or never-run probe pass as a
/// real "not a symlink" answer, admitting a write it never checked.
#[tokio::test]
async fn a_non_zero_exit_refuses_even_with_well_formed_stdout() {
    let host = ScriptedProbeHost::answering_with_exit_code("NOTLINK", 127);

    let outcome = host.link_target_as_writer(Path::new("/etc/x/plain.conf"));

    assert!(
        outcome.await.is_err(),
        "a non-zero exit must refuse regardless of stdout: sh being absent must \
         not be read as a well-formed NOTLINK"
    );
}

/// The sibling case the guard's own doc comment names: a signal-killed
/// process, not just a positive exit code such as 127.
///
/// Both shipped executors report `-1` for a signal-killed process, via
/// `output.status.code().unwrap_or(-1)`. The source already checks with
/// `!= 0`, which covers this; this test is what proves it, so a future
/// narrowing to `> 0` goes red instead of shipping silently.
#[tokio::test]
async fn a_negative_exit_code_refuses_even_with_well_formed_stdout() {
    let host = ScriptedProbeHost::answering_with_exit_code("NOTLINK", -1);

    let outcome = host.link_target_as_writer(Path::new("/etc/x/plain.conf"));

    assert!(
        outcome.await.is_err(),
        "a negative exit code must refuse regardless of stdout: a signal-killed probe \
         flushing a token that happens to parse must not be read as a well-formed NOTLINK"
    );
}

// ---------------------------------------------------------------------------
// session_is_root
//
// The privilege probe behind `hardener-plugins/src/lib.rs:49` and the ssh
// plugin's remote-root check at `ssh/mod.rs:416`. It had no test at all, which
// the 2026-08-11 mutation pass found by surviving replacement of the whole
// function with BOTH `true` and `false`: a constant in either direction was
// indistinguishable from the real thing.
//
// Its contract is fail-closed, so the three ways it must refuse are worth more
// than the one way it may agree. A single happy-path test would kill the
// `false` mutant and leave the `true` mutant alive, which is the half that
// hands a caller root it does not have.
// ---------------------------------------------------------------------------

fn uid_probe_answering(stdout: &str, exit_code: i32) -> MockExecutor {
    MockExecutor::new().with_command(
        "id",
        &["-u"],
        CommandOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code,
        },
    )
}

/// A uid of zero, and nothing else, is root. The trailing newline is the shape
/// a real `id -u` produces, so the `trim()` is part of the contract rather
/// than defensive tidying.
#[tokio::test]
async fn a_uid_of_zero_is_root() {
    let executor = uid_probe_answering("0\n", 0);

    assert!(
        session_is_root(&executor).await,
        "`id -u` answering 0 on a successful exit is the one reading that means root"
    );
}

/// The ordinary negative case, and the one that kills a constant `true`.
#[tokio::test]
async fn a_non_zero_uid_is_not_root() {
    let executor = uid_probe_answering("1000\n", 0);

    assert!(
        !session_is_root(&executor).await,
        "a uid of 1000 is not root, and reading it as root would hand a caller \
         privileges the far end has not granted"
    );
}

/// The sharp case: stdout says `0` while the command failed. Answering from
/// the text alone would read a broken probe as a root session, which is the
/// exact inversion the fail-closed contract exists to prevent.
#[tokio::test]
async fn a_failed_probe_is_not_root_even_when_its_stdout_says_zero() {
    let executor = uid_probe_answering("0\n", 127);

    assert!(
        !session_is_root(&executor).await,
        "a non-zero exit must refuse whatever stdout holds: a probe that could \
         not answer must never be read as an answer"
    );
}

/// The probe did not run at all. The mock refuses an unregistered command, so
/// this is the `Err` arm of the `matches!` rather than a crafted failure.
#[tokio::test]
async fn a_probe_that_could_not_run_is_not_root() {
    let executor = MockExecutor::new();

    assert!(
        !session_is_root(&executor).await,
        "an executor that could not run `id -u` must refuse, not default to root"
    );
}

/// A host whose `readlink` answer the test chooses, and whose checkpoint key an
/// earlier release may have filed differently.
///
/// It overrides `legacy_description`, which is the case under test there, and
/// deliberately does **not** override `read_link`, so the provided body that
/// shells out to `readlink` is the one that runs. `MockExecutor` cannot stand in
/// for the second half: it answers `read_link` from its own symlink registry
/// rather than through a command, so the provided body never executes under it.
struct LinkHost {
    /// What `readlink -n -- <path>` reports on this host.
    readlink: CommandOutput,
    /// The key an earlier release filed this target's checkpoints under.
    legacy: Option<String>,
}

impl LinkHost {
    const KEY: &'static str = "root@10.242.117.2:22";

    /// A host that answers `readlink` and whose key never moved.
    fn answering(stdout: &str, exit_code: i32) -> Self {
        Self {
            readlink: CommandOutput {
                stdout: stdout.to_string(),
                stderr: "readlink: command not found".to_string(),
                exit_code,
            },
            legacy: None,
        }
    }

    /// A host whose key moved, with `readlink` left unasked.
    fn filed_under(legacy: &str) -> Self {
        let mut host = Self::answering("", 1);
        host.legacy = Some(legacy.to_string());
        host
    }
}

#[async_trait]
impl SystemExecutor for LinkHost {
    fn description(&self) -> String {
        Self::KEY.to_string()
    }

    fn is_remote(&self) -> bool {
        true
    }

    fn legacy_description(&self) -> Option<String> {
        self.legacy.clone()
    }

    async fn execute_command(&self, program: &str, _args: &[&str]) -> Result<CommandOutput> {
        assert_eq!(program, "readlink", "no other command is under test here");
        Ok(self.readlink.clone())
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

/// `read_link` has three outcomes and they must stay three.
///
/// The doc comment on it says why: a checkpoint that stores a symlink's
/// followed content instead of its target cannot restore it, so `Err` must
/// never be read as "not a symlink". Asking only whether a target came back
/// cannot fail under a body replaced by a constant `Ok`, and asking only
/// whether it errored cannot fail either, since two of the three arms do not.
/// All three are asked, and the failure is read for what it names.
#[tokio::test]
async fn read_link_tells_a_target_a_non_symlink_and_a_failed_probe_apart() {
    let path = Path::new("/usr/bin/vi");

    let symlink = LinkHost::answering("/etc/alternatives/vi", 0);
    assert_eq!(
        symlink.read_link(path).await.unwrap(),
        Some("/etc/alternatives/vi".to_string()),
        "exit 0 means readlink resolved it, and the target is what it printed"
    );

    let regular_file = LinkHost::answering("", 1);
    assert_eq!(
        regular_file.read_link(path).await.unwrap(),
        None,
        "readlink(1) exits 1 for a path that is not a symlink, which is the \
         positive answer and not a failure"
    );

    let no_readlink = LinkHost::answering("", 127);
    let err = no_readlink
        .read_link(path)
        .await
        .expect_err("any other status is readlink itself failing");
    assert!(
        err.to_string().contains("exited 127"),
        "and it must say so, because a caller that read this as `not a symlink` \
         would write through the link: {err}"
    );
}

/// A target whose key never moved offers exactly that key, and offers it once.
///
/// `MockExecutor` is the executor here on purpose: it overrides
/// `legacy_description` nowhere, so the trait's own `None` body is what answers,
/// and a body replaced by any `Some` would add a second key to this list.
#[tokio::test]
async fn a_target_whose_key_never_moved_offers_exactly_that_key() {
    let executor = MockExecutor::new()
        .remote()
        .with_description("root@host:22");

    assert_eq!(
        host_keys_for(&executor),
        vec!["root@host:22".to_string()],
        "the current key, alone: an extra key here is a lookup accepting \
         checkpoints filed against a target this is not"
    );
}

/// A target whose key did move offers both, newest first, and never the same
/// key twice.
///
/// The equal case is the one the `!=` guard exists for. Without it a target
/// reporting a legacy key identical to its current one would be looked up twice
/// under the same key, and the duplicate would reach an operator as the same
/// checkpoint offered twice as two rollback points.
#[tokio::test]
async fn a_target_whose_key_moved_offers_both_and_never_the_same_key_twice() {
    let moved = LinkHost::filed_under("hardener@10.242.117.2:22");
    assert_eq!(
        host_keys_for(&moved),
        vec![
            LinkHost::KEY.to_string(),
            "hardener@10.242.117.2:22".to_string(),
        ],
        "both keys, current first: captures write the first and lookups must \
         still find what an earlier release filed under the second"
    );

    let unmoved = LinkHost::filed_under(LinkHost::KEY);
    assert_eq!(
        host_keys_for(&unmoved),
        vec![LinkHost::KEY.to_string()],
        "a legacy key equal to the current one is not a second key, and \
         listing it twice would offer one checkpoint as two rollback points"
    );
}
