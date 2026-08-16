# Evidence Ledger

**Last Updated**: 2026-08-15

This release does not claim to be proven bug-free. It claims something narrower
and checkable: every capability it advertises carries a named piece of evidence
and a written ceiling, and where no evidence exists that is written down too.

The **Ceiling** column is the point of the document. A green test proves that
the code agreed with whatever the test handed it, which is not the same as the
code agreeing with Linux. A row whose ceiling says nothing useful is a row that
has not been thought about hard enough.

---

## The four columns

| Column | What it holds |
|---|---|
| Claim | What the release says the capability does, stated as narrowly as the evidence actually supports. |
| Evidence | The files that carry the proof, as repo-relative paths in backticks. `validate_evidence_ledger.py` reads every path in this document rather than this column alone, the Command and Ceiling cells and the surrounding prose included, and fails `validate_all.py` when one no longer exists, so a row cannot outlive the file it points at and no citation is exempt because of where it sits. |
| Command | What a reader runs to watch the evidence pass, with no privileged setup unless the cell says otherwise. In most rows this is deliberately the part of the Evidence column a reader can run unprivileged rather than all of it, and what it leaves out of the row's strongest evidence is named in that row's Ceiling: a container suite, a booted host, an `#[ignore]`d test. A cited file the default suite already runs may go unnamed there. |
| Ceiling | What the row does **not** prove. Where the only evidence is a mock, it says so. Where the evidence is an `#[ignore]`d test the default suite never runs, it says so, because a regression there is invisible to `cargo test`. |

---

## Baseline, as measured on 2026-08-14

Numbers taken from commands rather than from prose. Re-measure before amending
them; do not copy a figure from an older document.

| Measurement | Command | Reading |
|---|---|---|
| Workspace version measured | `grep -m1 '^version' Cargo.toml` | 1.5.1 |
| Tests the default suite runs | `cargo nextest run --workspace` | 2054 passed, 42 skipped |
| Tests `cargo test` runs, doctests included (nextest total plus 6 doctests) | `cargo test --workspace`, summing every `test result:` line | 2060 passed, 0 failed, 49 ignored |
| Doctests, which nextest does not run at all | `cargo test --doc --workspace` | 6 passed, 7 ignored |
| Test binaries reporting a result | `cargo test --workspace` piped through `grep -c "^test result:"` | 61 |
| Documentation and naming validators | `python3 scripts/validate/validate_all.py` | All 25 validations passed |
| Test annotations in the tree | `grep -rEc '^\s*#\[(tokio::)?test\]' crates src-tauri` summed | 2096 |
| Tests the assertion check reads | `python3 scripts/validate/validate_test_assertions.py --all` | 2096 across 299 files |

Three of these rows are re-derived from the tree on every `validate_all.py` run
by `scripts/validate/validate_test_counts.py`: the annotation count, the
ignored count, and the validator count, each by the command stated beside it.
Those three carry today's answer rather than the header date's, and the date above
governs only the rows a build produces. The validator row read 21 for two days
after the count became 23, which is what prompted the check.

The rows a build produces are not re-measured there, and are not therefore
unchecked: they are pinned to each other by the identities this section states,
so a figure edited alone fails even though nothing about it was measured.

The gap between 2096 annotations and 2054 executions is exactly 42, and all 42
are `#[ignore]`d tests, listed by
`cargo nextest list --workspace --run-ignored ignored-only`. Every one of them
is named in the rows below. Nothing in the tree is skipped for a reason this
ledger does not record.

Two further reconciliations, because three of the rows above look like they
disagree and do not. The annotation count and the assertion check's walk total
are the same number, 2096, and they are meant to be: the check globs every `.rs`
file under `crates/*/src/` and `src-tauri/src/` rather than the file names unit
tests are conventionally split out under, so every annotated test in the tree is
one it reads. A walk total below the annotation count would mean tests were
going unread, which is what issue #130 was. And `cargo test --workspace` reports
6 more passes and 7 more ignores than `cargo nextest run --workspace` does;
those 13 are doctests, which nextest does not run and which no annotation count
covers. 2054 + 6 = 2060 and 42 + 7 = 49.

---

## Three grades of evidence

Every row is graded by what its evidence actually asks:

1. **Mock.** A `MockExecutor` is told what the system says, and the test checks
   the plugin's reaction. Deterministic and fast, and it proves only that the
   plugin's logic is self-consistent. It cannot catch a reader that disagrees
   with the real command.
2. **Real filesystem.** The test writes into a temporary directory and reads it
   back with the operating system. Stronger, and still unprivileged, so nothing
   root-owned or system-wide is touched.
3. **Live oracle.** The setting's real consumer is asked: `sshd -T`, `sysctl`,
   `chage`, `nft list ruleset`, `systemctl is-enabled`, `stat`. This is the only
   grade that can catch a reader and a writer that agree with each other and
   disagree with Linux. It lives in two scripts,
   `scripts/test/differential-suite.sh` and `scripts/test/full-test-suite.sh`,
   and both run only inside an nspawn container, as root, by hand.

---

## Mutation testing, run across the integrity-critical crates on 2026-08-11

The three grades above say what a test's evidence is worth once it runs. None
of them, and no coverage figure either, can say whether a test checks anything
at all: a line a test reaches and asserts nothing about counts exactly as
covered as a line it pins. Mutation testing asks the one question that
separates the two. Change the code, and does anything go red?

**The full pass has now run, on 2026-08-11 at `56245cc7`.** All three
integrity-critical crates, `-j 1` throughout, 24 minutes of wall clock:

| Crate | Mutants | Caught | Missed | Unviable | Timeouts | Missed, of viable |
|---|---|---|---|---|---|---|
| `hardener-common` | 164 | 106 | 48 | 10 | 0 | 31% |
| `hardener-state` | 217 | 146 | 19 | 52 | 0 | 12% |
| `hardener-core` | 319 | 178 | 94 | 47 | 0 | 35% |
| **Total as the pass read it** | **700** | **430** | **161** | **109** | **0** | **27%** |

**A hundred and fifty-one of those 161 have since been killed**, all on 2026-08-11, so the
tree as it stands reads:

| Crate | Caught | Missed | Change |
|---|---|---|---|
| `hardener-common` | 152 | 2 | both `session_is_root`, 13 of the 14 in `file_utils.rs`, and all nine left in `executor/mod.rs` |
| `hardener-state` | 165 | 0 | all seven in `signing.rs`, and the twelve left across `manager.rs`, `audit.rs` and `scan_manager.rs` |
| `hardener-core` | 263 | 8 | all twenty in `executor/local.rs`, 12 of the 16 in `config_loader.rs`, and the pure functions in `executor/ssh.rs`, one of them by fixing the code the mutant indicted |
| **Total now** | **580** | **10** | **2% of viable** |

### Confirmed by a full re-run under a wider scope, 2026-08-12

The figures above were assembled from per-file re-runs. A complete pass has
since been run against the whole set, with **every one of the three crates'
tests running for every mutant** rather than `hardener-core`'s alone:

```
cargo mutants --test-tool nextest -j 1 --timeout 300 \
  -p hardener-common -p hardener-state -p hardener-core \
  --test-package hardener-common --test-package hardener-state --test-package hardener-core \
  --cargo-test-arg --run-ignored=all
```

with the SSH fixture booted and `SSH_TEST_*` exported. **702 mutants in 53
minutes: 583 caught, 10 missed, 109 unviable, 0 timeouts.**

| Crate | Caught | Missed | Unviable |
|---|---:|---:|---:|
| `hardener-common` | 152 | 2 | 10 |
| `hardener-state` | 165 | 0 | 52 |
| `hardener-core` | 266 | 8 | 47 |

`hardener-common` and `hardener-state` reproduce the assembled figures exactly.
`hardener-core` reads 266 rather than 263 against 321 mutants rather than 319,
which is source drift since `56245cc7`, not a change in what the tests catch.

**Four of those 10 have since been killed**, leaving 6, of which every one is equivalent or unreachable. Two were in `inventory.rs`, one was the XOR in `parse_stat_fields`, and one was a mutant introduced by the seam added to pin the root half of the user-config rule.
`save -> Ok(())` and `load -> Ok(Default::default())` survived because the unit
tests exercised `save_to` and `load_from` while the front ends call the
wrappers, and a wrapper is not its inner function. Re-running the file reports
**6 mutants, 6 caught**. The tests are in
`crates/hardener-core/tests/inventory_shared_path.rs`, an integration binary
rather than a unit test, because reaching the wrappers means moving
`XDG_CONFIG_HOME` and writing an environment variable races every other thread
in the same binary that reads one. Put in `inventory/tests.rs` they made the
pre-existing `save_then_load_round_trips` fail, under `cargo test` but not under
`cargo nextest`, which gives each test its own process.

**The wider scope killed nothing extra.** Going from 174 tests to 453, with the
three crates able to cross-kill for the first time, moved the survivor count by
zero. The caveat recorded above, that a narrower measurement is pessimistic and
a wider run can only kill more, holds in principle and is worth exactly nothing
here. The 10 survivors are a property of the tests, not of the scope they were
measured under.

Baseline discipline that this run had to establish first: the pass was preceded
by a baseline reading **14 failures instead of 6**, all eight extra downstream of
`message_indicates_permission_denied` returning false. That was a mutated
artefact left in the shared target directory by an earlier aborted run, not a
defect. `cargo mutants` aborts on a failing baseline, so a poisoned artefact
costs the entire pass. Prove the baseline against its recorded value before
starting; a clean `git status` does not mean a clean build.

Every kill in the table above was verified by re-running the runner over the
affected scope rather than by reasoning about the tests:

| Scope | Before | After |
|---|---|---|
| `--re session_is_root` | 2 missed | **2 caught** |
| `--file crates/hardener-state/src/signing.rs` | 7 missed | **43 mutants, 35 caught, 8 unviable, none missed** |
| `--file crates/hardener-common/src/file_utils.rs` | 14 missed | **47 mutants, 44 caught, 2 unviable, 1 missed** |
| `--file crates/hardener-core/src/executor/local.rs` | 20 missed | **31 mutants, 29 caught, 2 unviable, none missed** |
| `--file crates/hardener-core/src/config_loader.rs` | 16 missed | **33 mutants, 28 caught, 1 unviable, 4 missed** |
| `--file crates/hardener-common/src/executor/mod.rs` | 9 missed | **40 mutants, 38 caught, 2 unviable, none missed** |
| `--file crates/hardener-core/src/executor/ssh.rs` | 25 missed | **55 mutants, 29 caught, 6 unviable, 20 missed** |
| `--file crates/hardener-state/src/manager.rs` | 5 missed | **81 mutants, 60 caught, 21 unviable, none missed** |
| `--file crates/hardener-state/src/audit.rs` | 4 missed | **32 mutants, 25 caught, 7 unviable, none missed** |
| `--file crates/hardener-state/src/scan_manager.rs` | 3 missed | **25 mutants, 17 caught, 8 unviable, none missed** |

`signing.rs` and `local.rs` are clear of survivors entirely rather than clear of
the ones that were listed. `file_utils.rs` keeps one and `config_loader.rs`
keeps four, deliberately, and all five are recorded below as acceptable rather
than left unexplained.

No timeouts anywhere, so no verdict here is a stalled build reported as a
survivor. The per-crate survivor lists are the runner's own `missed.txt`, kept
outside the tree because they are a measurement rather than a document.

**The remaining 10 are identified, not resolved.** G4 asks for each to be
killed by a test or recorded with the reason it is acceptable, and for these
only the first half of that, the identification, is done. Where they sit, and
what the Phase 4 triage rule makes of them:

| Cluster | Survivors | Reading |
|---|---|---|
| `hardener-core/executor/local.rs` | 0, was 20 | **Resolved.** All twenty killed; see below. |
| `hardener-common/file_utils.rs` | 1, was 14 | **Resolved.** Thirteen killed; the survivor is recorded as acceptable below. |
| `hardener-core/executor/ssh.rs` | 4, was 25 | **The stated ceiling was wrong, and measuring it is what showed that.** "No SSH host" was recorded as the reason twenty survived; running the pass with the fixture booted and `--run-ignored=all` killed **eleven of them outright, with tests that already existed**. Nobody had ever run the mutation pass against a live container. Two new `#[ignore]`d tests took five more. The four left are described below and none is an ordinary gap: two are unreachable, one is provably equivalent, one needs a change to the container image. |
| `hardener-common/executor/mock.rs` | 0, was 19 | **Resolved.** `MockExecutor` itself, so the rule called these notes, and **the rule was the wrong reading**: a mock whose `command_exists` returns either answer unnoticed is a fixture that cannot fail, and a fixture bounds what every test above it can detect. All nineteen killed; see below. |
| `hardener-core/config_loader.rs` | 1, was 16 | **Resolved.** Fifteen killed, three of them by giving the loader a path seam. The one left is **provably equivalent**: `is_running_as_root` replaced by `false`, which is what the real function already returns on a non-root runner. |
| `hardener-core/context.rs`, `config_validation.rs` | 0, was 24 | **Resolved.** The rule called these notes because neither reaches disk or a host, but `context.rs` is what tells every plugin which distribution and kernel it is running on, and `config_validation.rs` is a guard against path traversal. All twenty-four killed; see below. |
| `hardener-common/executor/mod.rs` | 0, was 11 | **Resolved.** Reaches a host, so a bug by the rule throughout. All eleven killed; see below. |
| `hardener-state/signing.rs` | 0, was 7 | A signature, so a bug by the rule, and the sharpest finding of the pass. **All seven killed**; see below. |
| Remainder | 4, was 25 | **`hardener-state`'s twelve are resolved**, which clears that crate outright: `manager.rs` 5, `audit.rs` 4 and `scan_manager.rs` 3, all reaching disk and so bugs by the rule. **`hardener-core`'s and `hardener-common`'s nine are resolved too**: `plugin.rs` 3, `error.rs` 3, and one each in `config.rs`, `registry.rs` and `inventory.rs`. Four stay, all recorded below: `inventory.rs`'s `load` and `save`, `testing.rs`'s mock, and `logging.rs`'s process-global logger init. |

**The two that were killed, and why these first.** `session_is_root` survived
replacement of the whole function with **both** `true` and `false`, meaning the
fail-closed privilege probe behind `hardener-plugins/src/lib.rs:49` and the ssh
plugin's remote-root check at `ssh/mod.rs:419` was pinned by nothing at all: it
had no test. Four now stand in `hardener-common/src/executor/tests.rs`, and the
shape of them is the point. The contract is fail-closed, so the three ways it
must refuse are worth more than the one way it may agree: a uid of zero on a
successful exit is root; a uid of 1000 is not; **a non-zero exit is not root
even when stdout says `0`**; and an executor that could not run `id -u` at all
is not root. A single happy-path test would have killed the `false` mutant and
left `true` alive, and `true` is the half that hands a caller privileges the far
end never granted. Re-running the pair with
`cargo mutants -p hardener-common --re session_is_root` reports **2 caught**.

**The other nine in the same file, and the two doubles that killed them.**
`executor/mod.rs` is now clear of survivors entirely. Three tests did it, and
which executor each uses is the whole of the difficulty.

`host_keys_for` survived being replaced by three constants and survived its
`!=` becoming `==`. It decides which checkpoints a rollback can see, so
`vec![]` makes an operator's existing rollback points invisible, and the guard
it lost is what stops a target reporting a legacy key equal to its current one
being looked up twice. The equal case is therefore the one worth writing: a
duplicate key would reach an operator as one checkpoint offered as two rollback
points. Both cases are asked.

`legacy_description` survived being replaced by `Some(String::new())` and
`Some("xyzzy")`. It is a **provided** trait method returning `None`, so only an
executor that does not override it can pin it, and `MockExecutor` is exactly
that: `host_keys_for` over a mock must return one key, and any `Some` body adds
a second. That is why the mock is the executor in that test rather than the
purpose-built double beside it.

`read_link` survived three constant `Ok` bodies, and it needed the opposite
choice. It is provided too, but `MockExecutor` **does** override it, answering
from its own symlink registry rather than by running a command, so the body
under test never executes under the mock. A small double that implements only
the trait's nine required methods runs it instead. Its three outcomes have to
stay three: a target, a positive "not a symlink" from `readlink`'s exit 1, and
`Err` for anything else. `Err` must never read as "not a symlink", because a
checkpoint storing a symlink's followed content cannot restore it, and the
write would go through the link into whatever it points at. Asking only whether
a target came back cannot fail under a constant `Ok`, and asking only whether
it errored cannot fail under one either, since two of the three arms do not
error.

The general shape, worth carrying to the next provided method: **a default trait
body is pinned only by an implementor that inherits it.** Which double is
correct is decided by what the type under test overrides, and the answer went
opposite ways for two methods sitting thirty lines apart.

**The `local.rs` twenty, and the contract that killed most of them at once.**
This was the largest cluster in the workspace needing no host, and it was
mostly one mistake repeated: `description`, `read_file`, `read_file_optional`
and `path_exists` each survived being replaced by constants, and the `NotFound`
match guard that `read_file_optional`, `path_exists`, `file_metadata` and
`read_dir` all share survived being forced one way or the other in each of
them.

The guard is worth a single test rather than four, because it is a single rule:
**only `NotFound` is positive confirmation of absence**, and every other error
means "could not determine" and must propagate. Forcing it to `true` is the
dangerous direction, since an unreadable path then reports as a confirmed
absence and a rollback that believes a file was absent deletes it. That is not
hypothetical here: `path_exists`'s own comment records the rollback guard
protecting `/etc/shadow` becoming unreachable on a local target for exactly
this reason. One test asks all four readers about a path below a regular file,
where `ENOTDIR` is unreachability that is emphatically not absence, and it
needs no privileges. Asking them separately would take four tests and would
still miss the fifth reader somebody adds later.

`execute_command` survived the `-` being deleted from
`output.status.code().unwrap_or(-1)`, turning the signal-killed sentinel from
`-1` into `1`. No ordinary assertion separates those, because callers test
`success()`, which is `exit_code == 0`, and both read as failure. What
separates them is the sentinel's meaning: `-1` says no exit code exists, while
`1` is a status a program can genuinely return. A shell told to kill itself is
the test.

**The `config_loader.rs` twelve, and the four that stay.** This file decides
which configuration the whole tool believes, and it reaches disk, so the triage
rule calls its survivors bugs. Twelve are dead and the five tests that killed
them stand in `crates/hardener-core/src/config_loader/tests.rs`.

Six were the three size ceilings, `MAX_CONFIG_SIZE`, `MAX_DIRECTIVES_PER_PLUGIN`
and `MAX_EXCEPTIONS_PER_PLUGIN`, each surviving `>` becoming `==` and `>=`. A
test that feeds a wildly oversized config cannot fail under either: `>=` still
refuses it and `==` refuses it too. Only the boundary separates them, and only
from both sides. Exactly the maximum must be accepted, which kills `>=` and
`==` alike, and exactly one past it must be refused, which kills `==`. The size
fixture pads with a TOML comment so that a file sized to the byte is still a
file the parser accepts and the size comparison is the only thing under test.

Five were `parse_and_validate_env_list`, which survived being replaced by three
different constant `Ok`s and survived both its `!` being deleted. Deleting the
`!` in the membership check inverts it into accepting every unknown plugin id
and refusing every known one, which is the direction that matters: the
`HARDENER_ENABLED_PLUGINS` and `HARDENER_DISABLED_PLUGINS` variables are what an
operator uses to turn hardening off. One test asks both directions and reads the
refusal for the id and the variable name it must carry, because a mutant that
also returns an error passes any assertion that merely says an error came back.

The twelfth was `skip_defaults` surviving replacement by `Default::default()`.
Every existing test in the file called it before `with_cli_config`, an order
under which the mutant is invisible: the CLI path is set afterwards on the fresh
loader, and the two default locations it wrongly stopped skipping are absent on
the machine running the suite. Reversing the call order is the whole test. The
lesson generalises past this file: **a builder method is only pinned by a test
that calls something before it.**

**Three of the four that stayed are now dead, and it took a seam in the code.**
`ConfigLoader` gained `with_config_dir`, which points the user-config lookup at
a directory a test owns instead of at `dirs::config_dir()`. Without it the two
branches deciding whether user config is read at all had no observable
difference: `~/.config/linux-hardener/config.toml` is absent on a runner, so
taking either branch produced an identical configuration and deleting a `!`
changed nothing an assertion could see. This is the same shape of fix #155 took
for `stat`: pin the input rather than teach the code about the environment, and
the earlier note here that the alternative was an unsafe `env::set_var` under a
threaded `cargo test` is why the seam is a field rather than a variable.

The dangerous halves are what the tests ask. `skip_defaults` must actually skip
the user config, or the flag names nothing. An unprivileged session must read
it, since `pkexec` is the reason the root rule exists and the rule inverted
reads user config **only** as root. `is_running_as_root` replaced by `true`
answers root for everyone and silently drops the operator's own configuration.

**One stays and always will.** `is_running_as_root` replaced by `false` is
**provably equivalent** under a non-root runner: the real function already
returns `false` there, so no assertion can separate them. Killing it would need
the suite to run as root, which would change what every other test in the tree
is asking.

**`inventory`'s `load` and `save` stay, for a structural reason worth stating.**
Each is a two-line wrapper: resolve the ambient location, then delegate.
`default_path` is pinned, and `load_from` and `save_to` are pinned by a
round-trip and a missing-file case, so the composition is covered piecewise; what
is not pinned is the composition itself, and it cannot be without controlling
the ambient location. `load()` and `save()` take no arguments by design, and
three callers depend on that, the CLI's `batch` and two Tauri commands. Giving
them the seam `ConfigLoader` just got means changing a signature across the CLI
and the desktop IPC, which is a larger change than two mutants justify while a
release is pending. Recorded as a deliberate ceiling, with the fix named.

**The host-free four in `ssh.rs`, and the one that indicted the code.**
`unique_delimiter` survived being replaced by `String::new()` and by
`"xyzzy"`, which is worth more than its size: the delimiter it returns
terminates the heredoc that writes a remote file, so a delimiter the content
already contains ends the body early and `write_file` reports success having
truncated an sshd_config. Three cases pin it, the third being content that
collides with both the base delimiter and its first grown form, and the
invariant the loop exists for is asserted outright.

`resolve_ssh_user` survived `Some("xyzzy")` **while carrying a test**, and the
test is the lesson. It asked whether *a* non-empty user came back, which any
constant satisfies. That value becomes the checkpoint key a bare remote target
is filed under, so a fabricated one silently refiles an operator's rollback
points. It now compares against a second, independent reading of the same
`ssh -G` output, since only an independent reference can fail a constant. The
ceiling is stated in the test: both readings look for the same prefix, so a
wrong prefix would still agree with itself.

`parse_stat_fields` survived `<` becoming `>` in its length guard. `rsplitn(5,
' ')` yields at most five parts, so `parts.len() > 5` can never fire and a
short line indexes past the end. A three-field line, an empty line, and a
complete line as the control kill it; the control is not optional, because a
guard that refused everything would satisfy the first two on its own.

**One stays, and it is equivalent.** `|` becoming `^` in `mode: type_bit |
permission_bits` agrees with the original in every reachable case: `type_bit` is
`0o040000` or `0o100000` and `permission_bits` comes from `%a`, which is at most
`0o7777`, so the operands never share a bit. Only a malformed `stat` line
carrying an oversized mode field separates them, and pinning that would be
pinning nonsense.

**The other was not a gap in the tests but a bug in the code, and it is fixed.**
`||` becoming `&&` in `is_file: file_type.contains("regular") ||
file_type.contains("file")` produced a mutant **more correct than the shipped
line**. Every `%F` string for a regular file, `regular file` and `regular empty
file`, contains both words, so the two forms agreed there. They diverged on
`character special file` and `block special file`, which contain `file` but not
`regular`: the shipped `||` called a device a file and `&&` did not.
`LocalExecutor` answers from `std::fs::Metadata::is_file`, which is false for a
device, so the remote and local executors disagreed about the same path, and
`hardener-state/src/manager.rs:598` gates checkpoint capture on exactly this
field. Pinning the shipped behaviour would have enshrined the divergence, so the
condition was reduced to `file_type.contains("regular")` instead: it matches the
mutant on every `%F` value and is shorter than either form. The mutant is gone
because the operator it mutated is gone, which is the better outcome of the two
available. `only_a_regular_file_reads_as_a_file_over_ssh` now walks the six `%F`
shapes, the two special-file rows being the ones that were wrong and the rest
the control that stops the fix over-correcting into "nothing is a file".
**The ceiling that fix left is now fixed in code too, tracked as #155.** The fix
landed in commit `dabbb1fe` on 2026-08-11, but that commit and every one after
it are still unpushed to GitHub as of this writing, so the tracker has not seen
the `Closes` trailer and #155 reads OPEN there; it should close on the next
push. `%F` is translated, so a
`stat` under a non-English locale reported every path as neither a file nor a
directory: measured on 2026-08-11, `LC_ALL=sv_SE.utf8 stat -c '%F' /etc/passwd`
prints `normal fil` and the same command on `/etc` prints `katalog`, so `is_dir`
failed beside `is_file` and the wrong type bit landed in `mode`. That was the
larger of the two gaps, since it affected ordinary files rather than devices.
`metadata_probe_command` now pins `LC_ALL=C` on the `stat` invocation, which is
the only remote probe parsing translated prose; the rest read paths, numbers,
exit codes, or literals the command itself chose.

The test for it is a live oracle rather than a substring check, because a
substring check cannot tell a pin on `stat` from one placed where it does
nothing. It runs the real probe through a real shell with a hostile `LC_ALL`
inherited, and **it searches the installed locales for one that actually changes
`stat`'s answer rather than naming a locale that may not be generated.** That
search is the vacuity guard: a hard-coded name absent from the machine would
leave `stat` answering in English, and the test would then pass while asking
nothing. Where no such locale exists the skip says so. Confirmed to go red:
removing the pin fails it with the probe output in the message, `"E\nnormal fil
644 7 1000 1000\n"`.

**The `hardener-state` twelve, which clear the crate.** All three files reach
disk, so all twelve are bugs by the rule, and `hardener-state` now has no
survivors at all.

`verify_checkpoint` survived being replaced by `Ok(())`. It is the function that
answers whether a checkpoint has been tampered with, and every caller reads
`Ok` as safe to restore. Nothing but a genuine tamper can separate the two
bodies, so the test alters a stored row through the pool and asserts the
refusal, with an untouched verify beside it as the control.

Two of `rollback_target_refusal`'s guards survived. The path check is three
clauses joined by `||`, and as `&&` it refuses only a path that is relative
**and** carries `..` **and** sits outside the allowlist, which no real one is:
an absolute `/etc/x/../../root/.ssh/authorized_keys` was admitted. Each case in
the test fails exactly one clause so none can stand in for another, with an
admitted path as the control. The other guard is `within` on a resolved symlink
target, forced to `false`: every symlinked row would then be refused, including
the ones a rollback exists to restore. The out-of-bounds direction already had a
test; the in-bounds one did not, and the failure it hid is a rollback that
quietly does nothing rather than one that writes somewhere wrong.

`snapshot_current_state`'s `exists && is_file` survived becoming `||`. **The
first assertion written for it was wrong**, and that is worth recording: the
guard decides whether the content is *read*, not whether the path is recorded,
so a directory still produces a row, carrying no content. The test asserts what
the code does rather than what it was assumed to do, both that the call
succeeds and that the row holds no content, because either half alone is
satisfiable by the wrong code.

`restore_command_refusal` survived its `stderr.trim().is_empty()` guard being
forced false, which leaves a silent failure described by nothing at all. Both
arms are asserted, plus a success as the control.

In `audit.rs`, `add_detail` survived being replaced by nothing, so the log could
record an action without the context it is read for. `QueryFilter`'s time range
survived `<` becoming `<=` and `>` becoming `>=`: both fields document
themselves as inclusive, and only the two boundary seconds can fail those
mutants, since any entry well inside the window matches either way. And
`recover_chain` survived returning a genesis chain, which is the sharpest of the
four: recovery runs whenever the logger reopens an existing file, and a fresh
chain relinks the next entry to nothing, so everything already written stops
being covered and tampering becomes undetectable by restarting the tool. The
test asserts the exact recovered hash against the entry's own, not merely that
it is not genesis.

`scan_manager`'s `current_timestamp` survived `0`, `1` and `-1`. It stamps
`started_at` and `completed_at` on every scan session, which is what the
history, the trend report and the regression check order rows by; as a constant
the whole history collapses onto one instant. No test asked what it returned,
only that a row was written. One test kills all three by bracketing it between
two independent readings of the system clock, which is the same rule as
elsewhere: only an independent reference can fail a constant.

Both `audit.rs` and `scan_manager.rs` needed a new `tests.rs` beside them,
because `recover_chain`, `QueryFilter::matches` and `current_timestamp` are all
private and the existing integration tests cannot reach any of them.

**The last nine of the remainder, and the four that stay.** Verified per file:
`plugin.rs` 3 mutants 3 caught, `config.rs` 59/54 with 5 unviable, `error.rs`
18/16 with 2 unviable, `registry.rs` 17/7 with 10 unviable, `inventory.rs` 6/4
with 2 missed, `testing.rs` 16/1 with 14 unviable and 1 missed, `logging.rs`
1 mutant and 1 missed.

`plugin.rs`'s two rollback hooks are **provided** trait methods, so the rule
from `executor/mod.rs` applies again: only an implementor that overrides
neither can pin them, and `MockPlugin` is that implementor. The directions
differ. `reloads_for_path` defaulting to `true` would have every plugin claim
every restored path, reloading subsystems a rollback never touched, and the
permissions plugin depends on the `false` answer because its paths come from
operator directives and cannot be enumerated. `reload_after_rollback`
defaulting to `Some` puts a row in the rollback output for work nobody did, and
`Some(String::new())` prints a blank line claiming an action.

`PolicyException::is_expired` survived `>` becoming `>=`. `expires` names the
last day an exception is honoured, so the comparison is strict; as `>=` the
exception stops being honoured on the morning of the date the operator wrote
down, and a scan reports a deviation that had approval. Only that one day
separates the two operators, which is why a test asking about a long-past or
far-future date could never have caught it.

`PluginRegistry::count` survived `Ok(1)`, and the reason is the sharpest small
lesson here: `test_register_plugin` asserts the count is 1 after registering
one plugin, which the constant satisfies exactly. **A test can assert the right
value and still pin nothing, when the value it asserts is the one the constant
returns.** The replacement walks 0, 1, 2 and 3.

`message_indicates_ssh_auth_failure` survived three of its four `||`s becoming
`&&`. Each turns a pair of signatures into a conjunction, so a message carrying
only one of the pair stops matching and the ssh-agent hint disappears from
exactly the failure it exists for. Each case in the test carries one signature
and none of the others, which is what lets it fail, and the four network
messages are the control, since a predicate matching everything would satisfy
the first half alone.

`inventory::default_path` survived `Ok(PathBuf::new())`, which would have every
caller read and write the empty path: a saved host vanishes and a fleet run
finds no inventory. The assertion is on the shape, the file name, the parent
directory and absoluteness, rather than on the whole string, because the prefix
is the operator's own config directory and naming it would pin this machine
instead of the contract.

**`load` and `save` beside it stay, and it is the same ceiling as
`config_loader`'s.** Both resolve through `default_path`, so both read
`dirs::config_dir()` and therefore the environment. `load` returning
`Ok(Default::default())` is indistinguishable from the real thing whenever the
operator has no inventory file, which is the state of any test runner, and
pinning `save` would mean a test writing over the maintainer's own
`hosts.toml`. The injectable pair `load_from` and `save_to` already exists and
is what the tests use; making `load` and `save` askable means the same path
injection #155's sibling gap needs.

`testing.rs`'s survivor is `MockPlugin::divergences_after_rollback`, which is
test infrastructure and a note by the rule. It is worth one sentence anyway,
for the same reason `MockExecutor`'s nineteen are: a mock that can return
either answer unnoticed is a fixture that cannot fail, and a fixture bounds
what every test above it can detect.

`logging.rs`'s `init_logger` survived being replaced by nothing. It installs a
process-global `tracing` subscriber and its own documentation records that it
panics if called twice, so a test exercising it would either poison every other
test in the binary or be the only test allowed to run. Recorded as acceptable
on those grounds rather than left unexplained: what it costs is that a build
shipping no logging at all would go unnoticed by the suite.

**The forty-three the triage rule had wrong.** `context.rs` 18,
`executor/mock.rs` 19 and `config_validation.rs` 6 were all filed as *notes*,
because none of them reaches disk or a host. Every one is now dead, and the
filing is worth correcting rather than quietly amending: **"touches no I/O" is
not the same as "cannot hurt anyone".**

`context.rs` is what tells every plugin which distribution, version, kernel and
architecture it is running on. All five detectors survived `Ok("xyzzy")`, so a
constant distribution turns distribution-specific hardening into a coin flip
and a constant kernel version defeats every version-gated check. Each is now
compared against a **second, independent way of asking**: `/proc/sys/kernel/
osrelease` against `uname(2)`, `/proc/sys/kernel/hostname` against the hostname
syscall, the standard library's own `ARCH` constant, a hand-parse of
`/etc/os-release` against the parser under test. Comparing a detector with
itself would agree under any constant body, which is exactly what let these
survive. `read_os_release` survived five constant bodies and is pinned by the
assignment count, which no single-entry map can match, and `log_audit` survived
`Ok(())`, reporting every entry as recorded while recording none.

**One of those tests was itself vacuous on the first attempt, and the runner
caught it.** The two distribution detectors were asserted inside `if let
Some(expected) = field("VERSION_ID")`, and this machine is Arch, which is
rolling and carries no `VERSION_ID`: the assertion never ran and
`detect_distribution_version` was still reported alive. The documented fallback
is part of the contract, so it is asserted rather than skipped, and the case now
runs on every host. A guard written for a field that may be absent is a guard
that may ask nothing.

`config_validation.rs` guards against path traversal through the kernel
plugin's `key.replace('.', "/")`. Its `||`s became `&&`s and its length
comparisons lost their boundaries. **The permissions test failed to fail on the
first attempt too**, and for the reason this ledger keeps recording: it asked
only whether a refusal came back, and the mutant still refused, one check
further down. `"77"` fell through the width check and was caught as
world-writable; `"07555"` was caught as setting special bits. The widths in it
are now otherwise-valid modes, so nothing downstream refuses them, and the
message is read for what it names.

`executor/mock.rs` was the plainest misfiling. Seven builders survived
`Default::default()`, which discards both the registration being made and
everything set up before it; `log` survived returning a default, `clear_log`
survived doing nothing, `files` survived three constants, `read_file_optional`
survived three more, `write_file` survived `Ok(())`, and `command_exists`
survived **both** `true` and `false`. A test asserting "the plugin wrote this
file" against a log that is always empty passes only because it was written to
expect nothing. One builder chain exercises all seven, since the failure is
precisely that a later call throws away an earlier one and a chain is the only
shape that shows it.

Writing those tests surfaced an asymmetry in the mock worth recording:
`command_exists`'s fallback reads the `commands` registry only, so a program
registered through `with_command_program` is **not** inferred to exist. The two
registration forms answer differently, and a fixture using the whole-program
form has to add `with_command_exists` beside it or its subject will skip the
work. Left as it is and noted at the test, rather than changed under a pending
release.

`testing.rs`'s single survivor turns out to need no test at all.
`MockPlugin::divergences_after_rollback`'s body is `Vec::new()` and the mutant
is `vec![]`: the same value spelled differently, so it is **provably
equivalent** and no assertion can separate them. It was filed as a note about
test infrastructure, which was the right verdict for the wrong reason.

**The sixteen in `executor/ssh.rs`, and the ceiling that was not one.** This
file was recorded as having twenty survivors the default suite "cannot kill
because it has no SSH host". That was a belief, not a reading. Booting
`scripts/containers/boot-ssh-test-container.sh` and re-running the pass as

```
cargo mutants --test-tool nextest --cargo-test-arg --run-ignored=all \
  --timeout 300 -j 1 --file "crates/hardener-core/src/executor/ssh.rs"
```

reports **20 missed becoming 9**, with no new tests written at all: the
`#[ignore]`d suites that had existed all along killed eleven.

**The rationale first recorded for omitting `-p` was false, and the number it
produced is narrower than the text claimed.** The omission was justified here as
widening the test scope, on the grounds that the mutants are in `hardener-core`
while four of the tests that kill them are `hardener-cli::batch_ssh_integration`.
`-p` selects what gets **mutated**; what gets **run** is `--test-workspace`,
which defaults to false. Measured three ways on 2026-08-12:

| Invocation | Tests run | Crates under test | Per mutant |
|---|---:|---|---:|
| no `-p`, as recorded above | 174 | `hardener-core` only | ~2s |
| `--test-package` x 5 | 453 | the three mutated crates | 24.7s |
| `--test-workspace true` | 453 | the same three | 73.2s |

`hardener-cli` joins under none of them: cargo-mutants builds only the packages
a mutant needs, so those test binaries never exist for nextest to run. The four
tests credited with kills above cannot have made them.

The **20 becoming 9** stands. It was measured under the first row, a narrower
suite than the prose described, and narrower is pessimistic: a wider run can
only kill more. The mechanism was wrong, not the count.

Note the middle row against the last. Naming five packages is three times
*faster* than `--test-workspace true`, because naming them bounds what cargo
must build. Removing the flag made it slower.

Two new `#[ignore]`d tests in `tests/ssh_executor_tests.rs` took five more.
`read_dir` survived three mutants that each make a remote directory look empty,
the body replaced by an empty vector, by a vector holding one empty path, and
the `!` deleted from the blank-line filter so only blank lines survive it; the
checkpoint layer captures directories by listing them, so a rollback would have
restored a directory as though it had held nothing. `legacy_description`
survived two `Some` constants, either of which offers an operator the
checkpoints of a target this is not.

**The four that remain, and not one is an ordinary gap.**

Two are **unreachable over ssh**: `unwrap_or(-1)` in `run_command` and in
`execute_command`. Measured rather than argued: a remote command killed by a
signal makes the **local** ssh client exit 255, not die itself, so
`output.status.code()` is always `Some` and the `-1` branch never runs.

```
$ ssh root@<fixture> 'kill -9 $$'; echo $?
255
```

This is the same line as `LocalExecutor::execute_command`, whose identical
sentinel **was** killed earlier in this pass by a self-killing shell. The
difference is structural rather than a matter of effort: `LocalExecutor` spawns
the process, so a signal-killed child really does report no exit code;
`SshExecutor` spawns the ssh client, which survives its child and translates the
death into a status. Identical code, identical mutant, killable in one executor
and impossible in the other.

One is **provably equivalent**: `|` becoming `^` in `mode: type_bit |
permission_bits`, already recorded above.

One needs a **change to the fixture, not to the tests**.
`legacy_description -> None` is only observable on a *bare* target, one that
named no user, and connecting without naming a user makes ssh offer the
controller's own login name. The container has `root` and no account named
after whoever runs the suite, so the connection is refused before an executor
exists to ask. `checkpoint_host_key` and `legacy_checkpoint_host_key` are both
pinned unprivileged; what is unpinned is this method's choice between them.

**The lesson is about the ledger rather than about the code.** A ceiling
recorded without being measured is a belief with a citation. This one had stood
since the pass was first run, it named the right obstacle, and it was still
wrong about eleven of twenty: the fixture that would have answered it was in the
repository the whole time.

**The one survivor recorded as acceptable, and why that is not a shrug.**
`file_utils.rs:228`, replacing `||` with `&&` in `if trimmed.is_empty() ||
trimmed.starts_with('#')`, makes the condition unsatisfiable: a string cannot
be both empty and begin with `#`, so nothing is skipped and every comment and
blank line is parsed. No test dies, and the reason is that a comment cannot
match anything. Both format arms compare from the start of the trimmed line, so
a comment's key is `#PermitRootLogin` rather than `PermitRootLogin` and a blank
line's key is empty; neither equals a directive name unless the caller asks for
one beginning with `#`, and none of the twenty-odd call sites does.

It is not strictly equivalent: `parse_config_value(content, "#", …)` would tell
the two apart. Pinning that would be pinning nonsense, and worse, it would
enshrine comment-parsing as a behaviour. So the skip stays, with a comment at
the site saying it is defence in depth rather than the thing that stops a
commented-out directive being honoured, and that it is what holds if
`split_directive` ever learns to strip a leading marker.

**The `file_utils.rs` thirteen.** These reach disk, which the triage rule calls
a bug outright. `create_timestamped_backup` survived returning
`Ok(Default::default())`, writing no backup and handing back an empty path
while reporting success: every plugin's rollback rests on that copy, and a
backup that silently is not written stays invisible until the rollback that
needs it. `safe_copy_to_new` survived `||` becoming `&&` in the guard that
refuses an existing destination, and a **dangling symlink** is the input that
separates them, since it is a symlink that does not exist; that guard is there
to stop a symlink race on a predictable backup path, so the difference is a
security one. Both readers survived being replaced by constants, and the
`NotFound` match guard survived being forced both ways, which would have turned
a present-but-unreadable path into a reported absence, the same conflation this
project has already paid for in the pam plugin.

Two of them are worth noting as a pattern rather than a list.
`parse_config_value` already carried thirteen tests and still lost two mutants,
which is the reminder that a function having tests is not the same as its
behaviour being pinned. And `safe_copy_to_new`'s mutant still fails, just later
and with a different message, so asserting that an error came back would have
passed on both; asserting **which** error is what kills it.

**The signing seven, what they were and what killed them.** These were the
sharpest finding of the pass, and all seven are now dead.

`derive_encryption_key` survived returning `Ok([0; 32])` and `Ok([1; 32])`, so
the AES-256 key encrypting the signing key at rest could be a constant, which
would give every host the same at-rest key.  `derive_encryption_key_from` had a
cross-implementation known answer; the outer function that reads
`/etc/machine-id` and calls it had nothing. It is now compared against the
derivation of the identity read the same way, and where no machine-id is
readable it must fail rather than answer.

`decrypt_key`'s length guard survived `<` becoming `>` and `+` becoming `-`,
both of which move the 64-byte boundary that `MAGIC(4) + NONCE(12) +
CIPHERTEXT(32) + TAG(16)` spells out. Forty bytes separates all three readings:
refused for its length by the real guard, and passed through to fail as a
decryption error under either mutant, so the test asserts on **which** error
comes back. An 80-byte case holds the other side, so the guard cannot widen
into rejecting well-formed input.

`can_sign` survived returning `false`, which would leave every checkpoint
unsigned on a host able to sign perfectly well.

`public_key_bytes` survived returning both `[0; 32]` and `[1; 32]`, and its
cause is the one to generalise. The only assertion touching it compared
`signer.public_key_bytes()` against `reloaded.public_key_bytes()`. **A mutant
making the function constant satisfies both sides**, so that test proves the
two calls agree and never that either is right. Any assertion shaped
`f(a) == f(b)` is blind to every constant mutation of `f`. It is now held
against the `.pub` file `save_public_key` wrote beside the key, which is a
different path to the same bytes.

The pattern across all four: **an independent reference kills a constant, a
second call never can.**

The `hardener-distro` smoke below is kept because the `-j 1` finding it
produced is what makes the numbers above believable.

| Measurement | Command | Reading |
|---|---|---|
| Runner installed | `cargo install cargo-mutants --locked` | cargo-mutants 27.1.0 |
| Mutants tested in `hardener-distro` | `cargo mutants -p hardener-distro --timeout 120 -j 1` | 126 tested in 68s: 36 caught, 73 missed, 17 unviable, 0 timeouts. Taken before the Phase 3 deletion recorded below, and not reproducible on the crate as it now stands. |

Run that command as printed, with a bare `cargo` and no wrapper in front of it.
One correction to it cost a wrong answer to find, and the 2026-08-11 pass above
inherited it by copying the line verbatim.

**`-j 1`, never `-j 2`.** On this machine that is a correctness requirement
rather than a preference. A single global `build.target-dir` sends every one of
the runner's scratch trees to one shared target directory, and because those
trees are structurally identical cargo derives the same crate metadata hash in
each, so every mutant's test binary is written to the same path. With two
workers that is a race, and one worker's build overwrites the binary the other
is about to run. Under `-j 2`, 89 of the 126 per-mutant logs recorded a block on
the shared build directory and five verdicts came back wrong: three mutants
reported as survivors are caught, one reported as a survivor does not compile,
and one reported caught does not compile either. `replace < with >` at line 34
of the crate's since-deleted `package/mod.rs` was reported a survivor with all
16 tests passing; applied to that file by hand it fails six of them. Under
`-j 1` no log blocks, that mutant is caught, and the totals above are what
remains. Four of those five err towards claiming too much work rather than too
little, but the swap has no preferred direction and can as easily report a
genuine survivor as caught, which is the reading that matters: a baseline
overstating what its tests pin is worse than no baseline at all.
**A run reporting survivors that cannot be reproduced by hand is reporting
nothing.** So a Phase 4 run should grep its own logs for that block message
before any of its numbers are written down, and should be the only cargo
running on the machine while it does, because the shared target directory is
reachable from another session just as easily as from a second worker. The
predicate has to be the long one, `Blocking waiting for file lock on build
directory`: the shorter `Blocking waiting for file lock` also matches benign
contention on the package cache, which accounted for 287 of the 415 hits in the
`-j 2` run and would over-flag a clean one. The runner writes its logs and its
`outcomes.json` to `mutants.out/` at the repository root, which is gitignored
because the directory is 3 MB of regenerable output full of absolute paths.

**The reading is not representative, must not be projected, and can no longer
be reproduced.** It was taken while five of this crate's seven non-test source
files were its `package` module, which the coverage baseline confirmed had no
reference anywhere outside itself and named as a Phase 3 deletion candidate.
Every one of the 73 survivors sat inside it. The live code,
`crates/hardener-distro/src/lib.rs`, contributed 12 mutants of which 9 were
caught and 3 could not compile, so **none survived**, and the crate's
`adapter.rs`, dead for the same reason and deleted with it, contributed one
mutant that does not compile. The honest summary is therefore not that 58 per
cent of this crate's mutants survive. It is that the live code killed
everything thrown at it while the unreachable code was already scheduled for
deletion.

Phase 3 has since carried that deletion out, under issue #127: the `package`
module and `adapter.rs` are gone, and with them every path this section used to
cite. `crates/hardener-distro/src/lib.rs` and its tests are the whole crate
now, so the command above no longer has 126 mutants to reach and cannot return
the totals beside it. **Those totals are a historic reading kept for the `-j 1`
finding they paid for, not a figure a later run should be compared against.**
What carries forward is the invocation and that finding. One survivor is worth
remembering as the shape of what the module hid: `replace < with <=` on the
same line 34 showed the minimum-length boundary of `validate_package_name`, a
shell-injection guard, was unpinned, because no name in the module's own tests
was exactly two characters long. A guard nothing in the tree called, carrying a
real gap no test would have caught, is an argument for deleting it rather than
for testing it.

---

## Ceilings that apply to every row

These are stated once here rather than repeated in every cell below.

- **Nothing automated runs above grade 2.** `.github/workflows/ci.yml` runs
  `cargo test --workspace $WORKSPACE_EXCLUDE`, where `WORKSPACE_EXCLUDE` is
  `--exclude linux-hardener-desktop --exclude hardener-ui`. It executes no
  `#[ignore]`d test and no shell suite, and those two exclusions make CI's set
  strictly smaller than the 1991 recorded above, so a green CI run is a weaker
  reading than that number. Every grade-3 result in this ledger was produced by
  a person starting a root session, since 2026-08-07 through
  `scripts/test/release-readiness-root.sh`, which batches every root-only suite
  into one prompt and rebuilds all six containers before each suite that uses
  one. The date of the last such run, and its per-distribution readings, are in
  `docs/reference/distribution-validation.md`, not here. That script was first
  run on 2026-08-07: four of its six suites passed, and neither failure was a
  product defect. Both are recorded in that document.
- **The gate's assertion check proves an assertion is reached, never that it is
  worth reaching.** `validate_test_assertions.py` now runs over the whole tree
  (issue #130), so no test escapes it by living in a `src/` module. What it
  reads is control flow: every path through a test body must arrive at an
  assertion. It cannot judge whether that assertion pins anything, so a test
  asserting `true == true` on every path satisfies it. That half is a reading
  made at review time and by mutation testing, not by this check.
  It also cannot see a table declared in another file, and refuses to count a
  loop over one, deliberately: an emptied table is exactly the silent vacuity
  the check exists to catch.
- **`scripts/test/differential-suite.sh` applies eight plugins at most.** Its
  `DIFF_PLUGINS` list is ssh, pam, permissions, firewall, kernel, audit and mac,
  and the services plugin joins only in a booted run. Two of the eight carry a
  ceiling stated in the oracle itself. Audit's rows read what `augenrules`
  compiled, which is what the next boot would load rather than what auditd is
  enforcing, because no auditd can run in a container. Mac's single row proves
  only that the apply wrote nothing, on a kernel whose LSM registry carries
  neither SELinux nor AppArmor; **nothing anywhere reads mac ENFORCEMENT back**,
  and that needs a virtual machine (#18).
  Their applies are placed differently again:
  section 12A of `scripts/test/full-test-suite.sh` reads audit's whole write
  surface back off a real filesystem after an apply and again after a rollback,
  while `mac-hardening`'s apply reaches a live host only through section 15's
  `apply --all`. That section's one check now reads the apply's own JSON result
  document rather than grepping the aggregate text, and asks three things of it:
  that a result exists at all, that every plugin in the suite's table left one,
  and that the exit code and the document agree about success. All three are put
  to the tool's account of itself, so **nothing reads mac's apply back off the
  host**. What a container skips is that plugin's dedicated section 14 apply,
  not its apply as such: `apply --all` selects every registered plugin, so
  mac's apply does run there, checkpoints its config paths, and on a container
  that carries SELinux or AppArmor tries to raise the mode. Its scan gets an unconditional exit-status check in section
  2 and runs again inside the section 8 per-plugin dry run, and between those
  two that is the whole of it.
- **A container without its own network namespace cannot be asked about the
  kernel.** Under a bare `systemd-nspawn --pipe`, `/proc/sys/net` is the host's
  and read-only, so the suite records those rows as unaskable rather than
  passing them. `--private-network` is what lifts it, with or without a boot
  (#137), and the differential runner passes it on both paths.
- **The desktop application has no row here yet.** Its Tauri IPC surface and its
  Leptos frontend are not covered by anything in this table, so nothing in it
  should be read as a claim about the GUI.

---

## Capabilities

### The eight plugins

| Claim | Evidence | Command | Ceiling |
|---|---|---|---|
| `audit-hardening` reports the auditd state its checks describe, and its apply writes the rules it names | `crates/hardener-plugins/tests/audit_mock_tests.rs` (41 tests), `crates/hardener-plugins/src/audit/tests.rs` (14 tests), `crates/hardener-plugins/tests/audit_tests.rs` (4 run, 1 `#[ignore]`d behind root), `scripts/test/full-test-suite.sh` (section 12A: the rules file the apply writes, the compiled `audit.rules` line count, and the whole `/etc/audit` tree diffed pre-apply against post-rollback) | `cargo nextest run -p hardener-plugins --test audit_mock_tests` | **Mock only for the scan.** `auditctl` and `augenrules` are asked in no test and in no script in this tree, and `audit-hardening` is absent from the differential suite's plugin list, so every claim about what this plugin *reports* is the plugin agreeing with a fixture it was handed. The apply is better placed: section 12A of `scripts/test/full-test-suite.sh` runs it on a real host and then judges the filesystem rather than the exit status, requiring that the rules file appeared, that a rollback removed it, that `/etc/audit` diffs identical to its pre-apply state, and that the compiled `audit.rules` line count came back. That runs only inside a container, as root, by hand, behind the suite's `--apply` flag, and only in a container no earlier `--apply` run has touched: where the rules file is already present the section reports the reading void rather than passing it. The single real-host Rust test is `#[ignore]`d because it modifies system audit configuration, so a default `cargo test` still asserts nothing about auditd at all. |
| `firewall-hardening` reports the active backend's rules, and its apply installs the rules it names | `crates/hardener-plugins/tests/firewall_mock_tests.rs` (62 tests), `crates/hardener-plugins/src/firewall/tests.rs` (74 tests), `crates/hardener-plugins/tests/firewall_tests.rs` (6 run, 4 `#[ignore]`d), `scripts/test/differential-suite.sh` (3 firewall rows against `nft list ruleset`), `scripts/containers/nftables-fixture.sh` | `cargo nextest run -p hardener-plugins --test firewall_mock_tests` | Three backends are supported (nftables, firewalld, ufw) and the live oracle asks only the one the fixture container installs, which is nftables. The firewalld and ufw paths are `#[ignore]`d on "only run on systems with that backend installed" and have grade-1 evidence only. A fixture container can also boot the wrong distribution and still pass, so a live result is worth nothing until `/etc/os-release` has been read over the connection that produced it. |
| `kernel-hardening` reports the sysctl values it names, and its apply leaves the running kernel enforcing them | `crates/hardener-plugins/tests/kernel_mock_tests.rs` (61 tests), `crates/hardener-plugins/src/kernel/tests.rs` (8 tests), `crates/hardener-plugins/src/kernel/persistence/tests.rs` (18 tests), `crates/hardener-plugins/tests/kernel_tests.rs` (4 run, 1 `#[ignore]`d behind root), `scripts/test/differential-suite.sh` (11 parameters read back with `sysctl`, plus 10 seeded looser-than-target controls and 1 seeded stricter-than-baseline control) | `cargo nextest run -p hardener-plugins --test kernel_mock_tests` | The default suite is grade 1 throughout: `/proc/sys` is never touched. The only oracle is the differential suite, and all 11 of its kernel rows are recorded unaskable unless the run holds its own network namespace, because otherwise `/proc/sys/net` belongs to the host and is read-only. **The namespace is the whole of the requirement and a boot is not part of it** (#137): this row said "booted with its own network namespace" until 2026-08-09, and `systemd-nspawn --private-network --pipe` was measured on 2026-08-08 to make `/proc/sys/net` writable with no `--boot` anywhere. Both paths of `run-cross-distro-tests.sh` now declare the namespace, so an unbooted `--pipe` differential run asks all 11 rows rather than recording them unaskable; the boot signal is still required for the services rows, which need systemd as PID 1, and the two are separate signals. **Read on both paths on 2026-08-09, against containers created immediately beforehand: 81 of 81 under `--pipe --private-network` on arch, and booted across all six distributions 86 of 86 on arch with 88 of 88 on each of the other five. Not one kernel row was unaskable in either.** The load-bearing line of that reading is the pre-apply control, which found 10 of the 11 parameters away from target beforehand: the suite's looser-than-baseline seeds were written into `/proc/sys/net` and stood there, which is what a namespace that only claimed to be writable could not produce. A further 7 parameters are declared permanently unaskable and are proven nowhere, because `/proc/sys` outside `/proc/sys/net` is the host's and read-only whatever the namespace. |
| `mac-hardening` reports whether SELinux or AppArmor is enforcing, and its apply raises the mode it names | `crates/hardener-plugins/tests/mac_mock_tests.rs` (32 tests), `crates/hardener-plugins/src/mac/tests.rs` (18 tests), `crates/hardener-plugins/tests/mac_tests.rs` (4 run, 1 `#[ignore]`d behind root) | `cargo nextest run -p hardener-plugins --test mac_mock_tests` | **No oracle anywhere reads MAC ENFORCEMENT back, and one now reads its no-op case.** `scripts/test/differential-suite.sh` compares this plugin for what it must NOT do: the kernel's LSM registry says this host carries neither SELinux nor AppArmor, and the suite digests `/etc/selinux`, `/etc/apparmor` and `/etc/apparmor.d` either side of the apply to prove nothing was written there. That catches the plugin configuring a MAC system the host does not have. It says nothing about enforcement, and where the registry does name a system the rows are declared unaskable rather than passed. Live runs do exist: `crates/hardener-plugins/tests/mac_tests.rs` scans the host by default, and `scripts/test/full-test-suite.sh` scans, dry-runs and applies this plugin inside a container, so `getenforce` and `aa-status` are reached through the real executor on any host carrying them. Every one of those runs judges an exit status, a plugin id, a non-zero duration or the tool's own result document, and none holds what those tools answer against what the plugin reported. The enforcing comparison would live in the differential suite, and cannot: loading an LSM policy is host-global, so a container cannot be given the question (#18). The mock decides which of the two systems is present by planting `/sys/fs/selinux` metadata, so the detection logic is proven against a fixture and never against a host that actually runs either one. |
| `pam-hardening` reports the password and lockout policy the stack will enforce, including inline overrides | `crates/hardener-plugins/tests/pam_mock_tests.rs` (80 tests), `crates/hardener-plugins/src/pam/tests.rs` (20 tests), `crates/hardener-plugins/src/pam/layer_drift/tests.rs` (8 tests), `crates/hardener-plugins/src/pam/login_defs/tests.rs` (2 tests), `crates/hardener-plugins/tests/pam_tests.rs` (4 run, 1 `#[ignore]`d behind root), `scripts/test/differential-suite.sh` (3 login.defs rows via `chage` and `passwd -S`, 2 pwquality enforcement rows: `module-loaded`, which offers no password at all and holds the PAM stack text against the tool's own minlen findings, and `weak-password-refused`, which carries both probes in the one check and requires the weak password refused and the strong one accepted) | `cargo nextest run -p hardener-plugins --test pam_mock_tests` | Apply deliberately refuses to edit `/etc/pam.d/*` and reports a manual action instead, so the strongest claim available for the stack files is that the tool told the truth about what a person must do, not that it did it. `PASS_MIN_DAYS` is unaskable on Arch, whose shadow is built without the field, so that row is absent from a run on the project's own development distribution. The pwquality oracle needs the module actually loaded, which is a booted container, and neither probe password ever reaches the live PAM stack: both are piped to `pwscore`, libpwquality's own CLI, which applies the same configuration file the module would. That makes the file's consumer the thing answering rather than a second parser, and it leaves the path from a real authentication attempt through PAM to a refusal tested nowhere. |
| `permissions-hardening` reports the modes and ownership on the paths it names, and its apply sets them | `crates/hardener-plugins/tests/permissions_mock_tests.rs` (40 tests), `crates/hardener-plugins/src/permissions/tests.rs` (14 tests), `crates/hardener-plugins/tests/permissions_tests.rs` (4 run, 1 `#[ignore]`d behind root), `scripts/test/differential-suite.sh` (9 permission rows read back with `stat`) | `cargo nextest run -p hardener-plugins --test permissions_mock_tests` | The live oracle asks `stat` about 9 paths, which covers modes and nothing else: no oracle anywhere reads back ownership or an ACL after an apply. The remote path, where this plugin runs through `SshExecutor`, has grade-1 evidence only. Shadow and gshadow use a no-loosen mask, so a host already stricter than the target is left alone, and the oracle rows are written to accept that rather than to demand equality. |
| `service-minimisation` reports which units systemd will start at boot, and its apply disables or masks the units it names | `crates/hardener-plugins/tests/services_mock_tests.rs` (21 tests), `crates/hardener-plugins/src/services/tests.rs` (10 tests), `crates/hardener-plugins/tests/services_tests.rs` (4 run, 1 `#[ignore]`d behind root), `scripts/test/differential-suite.sh` (3 rows via `systemctl is-enabled`, `is-active` and `readlink`), `scripts/test/full-test-suite.sh` (section 12B: the mask symlink read off the filesystem after an apply and after a rollback, booted hosts only) | `cargo nextest run -p hardener-plugins --test services_mock_tests` | The smallest mock suite of the eight, at 21 tests against 80 for pam. Under `--pipe` this plugin's scan errors and its apply does nothing, so it joins the compared set only in a booted run; the differential suite declares its rows unaskable rather than letting an empty reading compare equal to an empty reading and pass. `systemctl mask` leaves a link into `/dev/null`, which is the case the rollback guard finds hardest, so this plugin and the checkpoint row below share a failure mode; section 12B of `scripts/test/full-test-suite.sh` is the reading that can catch it, and it needs a booted container run with the suite's `--apply` flag. |
| `ssh-hardening` reports the effective sshd configuration, including drop-ins and includes, and its apply leaves sshd serving what it reported | `crates/hardener-plugins/tests/ssh_mock_tests.rs` (82 tests), `crates/hardener-plugins/src/ssh/include/tests.rs` (10 tests), `crates/hardener-plugins/src/ssh/dropin/tests.rs` (2 tests), `crates/hardener-plugins/tests/ssh_tests.rs` (7 run, 1 `#[ignore]`d behind root), `scripts/test/differential-suite.sh` (7 rows read back through `sshd -T` itself, plus seeded no-loosen rows and a reload cycle) | `cargo nextest run -p hardener-plugins --test ssh_mock_tests` | The best-evidenced plugin in the tree, because sshd is its own oracle and `sshd -T` cannot be satisfied by this project's parser agreeing with this project's writer. The ceiling is availability, not depth: that oracle runs only inside a container, as root, started by hand. The crypto allow-lists are intersected with `ssh -Q` at runtime, so what a given host ends up offering depends on its OpenSSH build and is not pinned by any test. |

### The two executors

| Claim | Evidence | Command | Ceiling |
|---|---|---|---|
| `LocalExecutor` reads and writes the local filesystem as the plugins expect, and refuses paths it must not reach | `crates/hardener-core/src/executor/local/tests.rs` (12 tests against a real temporary filesystem), `crates/hardener-core/tests/mock_executor_tests.rs` (15 tests pinning the mock to the same contract) | `cargo nextest run -p hardener-core executor::local` | This is the only executor the default suite exercises against a real filesystem, and it does so entirely in unprivileged temporary directories. Nothing in a default run writes a root-owned file, runs `sudo tee`, or chmods a path outside the test's own tree, so the privileged behaviour that every apply depends on is proven only by the container suites. The `MockExecutor` conformance tests keep the two implementations answering the same shape, which is a weaker guarantee than answering the same values. |
| `SshExecutor` performs the same reads and writes against a remote host over a key-authenticated connection | `crates/hardener-core/tests/ssh_executor_tests.rs` (3 run, 14 `#[ignore]`d behind `SSH_TEST_HOST`), `crates/hardener-plugins/tests/ssh_integration_tests.rs` (2 run, 12 `#[ignore]`d), `scripts/containers/boot-ssh-test-container.sh`, `crates/hardener-cli/tests/ssh_refusal.rs` (12 tests) | `cargo test -p hardener-core --test ssh_executor_tests -- --ignored`, after running `scripts/containers/boot-ssh-test-container.sh` under `sudo` and then, in your own shell, exporting the variables it prints and running the `ssh-add` it prints. The script prints those lines for you to paste; a child process cannot export into the shell that invoked it. | Only 3 of the 17 tests run by default, and those three assert config shape and description formatting: nothing that touches a wire runs in the default suite or in CI, so **a regression in the SSH transport is invisible to `cargo test`**. Both suites fail loudly rather than silently when `SSH_TEST_HOST` is unset, which is the correct behaviour and which the fleet row below now shares. There is no password authentication path by design, so nothing here covers one. |

### Checkpoint and rollback

| Claim | Evidence | Command | Ceiling |
|---|---|---|---|
| A checkpoint captures the files an apply is about to change, and a rollback restores the bytes and modes it captured | `crates/hardener-state/tests/checkpoint_system.rs` (14 tests), `crates/hardener-state/src/manager/tests.rs` (48 tests), `crates/hardener-state/tests/signing_tests.rs` (11 tests), `crates/hardener-plugins/src/kernel/divergence/tests.rs` (36 tests, the kernel rollback probe's own), `scripts/test/verify-rollback.sh`, `scripts/test/differential-suite.sh` (a rollback and reload cycle read back through `sshd -T`), `scripts/test/full-test-suite.sh` (sections 12A and 12B, which read the audit tree and the services mask link back off a real filesystem after a rollback) | `cargo nextest run -p hardener-state --test checkpoint_system` | **Checkpoints are text-only.** Restore writes content through `String::from_utf8_lossy`, so a file with non-UTF-8 bytes cannot round-trip and no test asserts that it can. Non-root remote restore degrades to content-only, because the `chmod`, `chown` and `rm` that follow the write run without sudo; the content write itself uses `sudo tee`, so the two halves have different privilege requirements. Cross-host rollback is refused outright by comparing `host_key`. Account databases are captured metadata-only on purpose, which the `ContentAbsence` discriminant distinguishes from a read that failed, so a rollback that could not read what it was asked to no longer reports success. The oracles that re-read a system after a rollback are `scripts/test/verify-rollback.sh` and sections 12A and 12B of `scripts/test/full-test-suite.sh`, and every one of them is container-and-root only. The two full-test-suite sections need that suite's `--apply` flag as well, and 12A needs a container no earlier `--apply` run has touched, or it reports its reading void. The kernel arm of `scripts/test/verify-rollback.sh` reads a runtime `sysctl` value back only where `/proc/sys/net` is writable, which needs a container holding its own network namespace. Its only runner now passes `--private-network`, which is sufficient under `--pipe` (`--boot` is not required, measured 2026-08-08), and the arm was read green that day: seeded to 0, raised to 1 by the apply, back to 0 after the rollback. Where the namespace is absent the arm still skips, and the script exits 2 rather than 0 so a skip cannot be recorded as a reading. **A rollback now reports what it left diverged from the configuration it restored, for two of the eight plugins.** `RollbackResult.rollback_divergences` carries a row when kernel-hardening's sysctl or firewall-hardening's ufw still disagrees with the restored state after the reload, and a row when either probe could not answer at all. This is reporting only: no rollback behaviour, exit code or `rollback_success` value changed to add it. `scripts/test/verify-rollback.sh` gained an eighth arm, TEST 8, asserting exactly this against a real container, and it was read green on 2026-08-08: 23 of 23, none skipped, replacing the 21-of-21 reading above. That run also measured the kernel probe's output, 15 rows of which 12 were `Diverged` and 3 `Unverifiable`, the 3 being the glob source `/usr/lib/sysctl.d/50-default.conf` and the two managed keys its patterns could name, `net.ipv4.conf.all.rp_filter` and `net.ipv4.conf.all.accept_source_route`. The 26-of-26 run below re-measured that breakdown against the post-change binary and read it identical, 15 rows, 12 `Diverged` and 3 `Unverifiable`, the same three subjects, so the `/etc/sysctl.conf` work moved no row in it. **The kernel probe also reads `/etc/sysctl.conf`, which no boot applier on a systemd host reads** (#140): a parameter named only there stays `Diverged`, and the sentence says the value is lost at the next reboot rather than that no file names it. Where the probe cannot tell which applier runs at boot the row is `Unverifiable` instead, and where an unprivileged run cannot read a drop-in at all the disagreeing parameters it could have decided are reported `Unverifiable` rather than `Diverged`, because a probe that cannot read the files is not entitled to accuse the host. **Which parameters those are is decided by the unread file's NAME as of #145**, not by the host: both appliers let the lexicographically last filename win (`sysctl.d(5)` and `sysctl(8) --system`, both read 2026-08-09), so an unread drop-in sorting before the file that decided a key cannot have decided it and no longer blocks it. It still earns a row of its own naming it, so nothing is hidden. A directory nobody could list, a ufw file nobody could read, and the silence case where no file was credited at all are all un-narrowable and still block every parameter. A ninth arm, TEST 9, asks that of a real container, and the suite was read green on 2026-08-08 at **26 of 26, none failed and none skipped** (TEST 9 asks three questions, which is why 23 became 26 rather than 24), reporting `net.ipv4.conf.all.log_martians` as `Diverged`. **Re-read at 26 of 26 on 2026-08-09**, twice: after that arm stopped writing its fixture through a symlink (#144), and again after the name narrowing (#145), the second run reporting zero `Unverifiable` rows because the container runs as root and has no unreadable drop-in to offer, which makes it a no-regression reading rather than a reading of the narrowing, with the branch it exercised recorded on the log rather than inferred: the sentence names `/etc/sysctl.conf` as the only file naming the parameter and says the value is lost at the next reboot, which is the branch the arm exists for. The `rm -f` that fix adds is a no-op on arch, which ships neither the file nor a link, so the reading confirms no regression rather than the fixed case; **the symlinked case is exercised by no image in the matrix and remains unread**. **All eight plugins now answer the divergence question rather than two (#142), and the trait's default is deleted so a ninth plugin cannot inherit silence.** `ssh-hardening`'s probe was measured 2026-08-10 in a booted arch container: masking `sshd.service` before a rollback left it reporting `active` both before the mask and after the rollback's restart attempt, which the probe now reports as `Diverged`, and a second run confirmed it fires. `permissions-hardening` and `pam-hardening` each earned an empty vector rather than inheriting one: `/etc/shadow` was forced to `666` and verified back at `600`, and an appended `faillock.conf` line was forced in and verified gone, across three reproductions of one distribution in a container, which is strong evidence for that host and not a proof for every one. `audit-hardening` reports a single `Unverifiable` row naming #18: `auditctl` cannot run in any container this project builds at all, measured twice, booted and unbooted. `mac-hardening` reports nothing at all in the same containers, not an `Unverifiable` row: none of them expose SELinux or AppArmor, so `MacDetection::Absent` is what it reads there, and a host with no MAC system installed has no restored configuration and no enforced policy for either to disagree with, the same reasoning firewall-hardening's probe already applies to no firewall backend installed. Neither audit-hardening's row nor mac-hardening's silence is a `Diverged` reading of anything, and **neither measurement says the plugin cannot diverge, only that nothing here could ask**. `service-minimisation`'s probe is readable on any booted host, but its one safe forcing candidate, `bluetooth.service`, could not be started in any container this project builds (measured 2026-08-10: a forced start left it `failed` rather than `active`), so **this probe has never fired against a real divergence, which is the same unmeasured status as mac and audit rather than a weaker one**. Dispatch changed from gating the divergence question on `reloads_for_path` to asking every plugin unconditionally, because `permissions-hardening` and `pam-hardening` override that predicate for no path and could never have been asked under the old gate; the two probes that already existed keep the identical predicate one level down, so their own behaviour is unchanged. `scripts/test/verify-rollback.sh` now runs as two passes, an unbooted one (TESTs 1-14, where TEST 10 and TEST 11 gate on `host_is_booted` and skip) and a booted one added specifically for TEST 10 and TEST 11, which need systemd as PID 1; both were read green on 2026-08-10, **30 passed and 2 skipped on the unbooted pass, exiting 2 rather than 0 because a skip must never be recorded as a clean pass, and 5 of 5 on the booted pass**, where TEST 10 and TEST 11 are the only new work: TESTs 12 to 14 carry no such gate and run in both passes, so their assertions are counted a second time in the booted pass rather than added once. **A row can now also say whether it was expected (#152).** `RollbackDivergence.divergence_expected: Option<String>` carries `Some(reason)` when the row is the designed consequence of the plugin's own apply plus a rollback that never starts, stops or writes anything live, and `None` otherwise, with no default so every construction site, including a ninth plugin's, must answer. Direction decides it, not frequency: kernel's 12 unnamed-parameter rows above are marked, because a rollback never writes `/proc/sys` and the host is left stronger than its restored files ask for; the two `/etc/sysctl.conf` rows measured by TEST 9 are not, despite firing on every rollback of a host carrying that file, because they leave the host weaker at the next reboot. firewall-hardening marks ufw enforcing over a restored `ENABLED=no`, never the reverse. mac-hardening and audit-hardening mark their #18 ceiling row. service-minimisation marks enabled-but-stopped, never not-enabled-but-running. ssh-hardening marks nothing, pinned by a test: every row it can emit is a reload that did not take. An expected row is still `Diverged` where it is one; the field is a predictability claim, not a severity claim, and no renderer drops or hides it: the CLI and the desktop rollback modal print unexpected rows first and expected ones under an "Expected, by design:" heading, and the fleet `batch rollback` summary reorders without changing its counts. |

### The compliance renderers

| Claim | Evidence | Command | Ceiling |
|---|---|---|---|
| A control the engine does not assess is reported as ManualReview and never as a green Pass | `crates/hardener-compliance/tests/assessment_honesty.rs` (6 tests), `crates/hardener-compliance/src/generator/tests.rs` (19 tests), `crates/hardener-compliance/tests/report_tests.rs` (9 tests) | `cargo nextest run -p hardener-compliance --test assessment_honesty` | Coverage is declared by each plugin's own `coverage()` function, so the honesty guarantee is only as good as those declarations: a plugin that over-declares turns a ManualReview into a Pass and nothing here would notice. The framework catalogues themselves are curated for CIS and ISO 27001 and derived from coverage for the rest, so a mapping error in a derived framework is a data defect no test in this crate can see. |
| Every output format renders a report the intended consumer can read | `crates/hardener-compliance/src/output/text/tests.rs` (4 tests), `crates/hardener-compliance/src/output/json/tests.rs` (2 tests), `crates/hardener-compliance/src/output/csv/tests.rs` (4 tests), `crates/hardener-compliance/src/output/html/tests.rs` (3 tests), `crates/hardener-compliance/src/output/pdf/tests.rs` (2 tests) | `cargo nextest run -p hardener-compliance output::` | **Fifteen tests, of which ten assert on substrings of the rendered string, one asserts a prefix and a byte length on it rather than a substring, and four assert on a helper rather than on any rendered output (`test_csv_escape`, `test_csv_formula_injection_guard`, `test_html_escape`, `test_truncate_string`).** No test parses a rendered report back with the consumer that will read it: the JSON is never handed to a deserialiser, the CSV never to a CSV reader, the HTML never to a parser, and the PDF row checks only that the output starts with `%PDF-` and exceeds 1000 bytes, so a structurally invalid document no reader can open would pass. The CSV escaping and formula-injection guard are the strongest of the four helper tests, being asserted directly on the escaper that the injection risk lives in. |

### The fleet verbs

| Claim | Evidence | Command | Ceiling |
|---|---|---|---|
| `batch scan`, `report`, `apply` and `rollback` reach every host in the inventory, default to a dry run, and refuse a host whose privilege probe fails | `crates/hardener-cli/src/commands/batch/tests.rs` (83 run, 1 `#[ignore]`d eyeball helper), `crates/hardener-cli/src/ssh_config/tests.rs` (4 tests), `crates/hardener-cli/tests/ssh_refusal.rs` (12 tests) | `cargo nextest run -p hardener-cli commands::batch` | The 83 in-crate tests are target parsing, output shaping and refusal policy over fixtures. None of them opens a connection, so multi-host behaviour against real hosts, partial failure across a fleet, and a privilege refusal from a host that genuinely refuses are all unproven at grade 3. |
| Each of the four fleet verbs completes against a live remote host | `crates/hardener-cli/tests/batch_ssh_integration.rs` (4 tests, all 4 `#[ignore]`d behind `SSH_TEST_HOST`), `scripts/containers/boot-ssh-test-container.sh` | `cargo test -p hardener-cli --test batch_ssh_integration -- --ignored`, after running `scripts/containers/boot-ssh-test-container.sh` under `sudo` and then, in your own shell, exporting the variables it prints and running the `ssh-add` it prints. The script prints those lines rather than exporting them, so a reader who skipped the paste has `SSH_TEST_HOST` unset; the run then aborts by name rather than reporting four passes. | Four tests, one happy path per verb, and **none of them runs in the default suite or in CI**: all four are `#[ignore]`d and every one needs a booted fixture container, so no `cargo test` and no CI job produces a single live reading of any fleet verb. What has changed is what a green reading is worth, not how much is covered. The shared `target()` helper in that file panics with `SSH_TEST_HOST not set` where it used to return early, so a run against no host now fails instead of exiting 0 with "4 passed", matching the two SSH suites in the executor row. That closed a silent pass and left the gap beneath it exactly where it was: four happy paths, one per verb, against one container, started by hand. |

---

## Adding a row

1. State the claim as narrowly as the evidence supports. If the honest claim is
   "the parser accepts this input", do not write "the feature works".
2. Cite evidence as repo-relative paths in backticks, beginning `crates/`,
   `scripts/`, `src-tauri/` or `gui-tests/`. A bare filename sits here
   permanently unchecked, which is the vacuity this ledger exists to remove.
3. Give a command a reader can run. Say in the cell when it needs root, a
   container, or an environment variable.
4. Write the ceiling last, and write it as though a sceptical reader will use it
   to decide whether to trust the row. Name the grade of evidence, name what the
   row does not reach, and name any `#[ignore]` that keeps it out of a default
   run.
