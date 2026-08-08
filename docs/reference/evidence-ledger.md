# Evidence Ledger

**Last Updated**: 2026-08-08

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

## Baseline, as measured on 2026-08-08

Numbers taken from commands rather than from prose. Re-measure before amending
them; do not copy a figure from an older document.

| Measurement | Command | Reading |
|---|---|---|
| Workspace version measured | `grep -m1 '^version' Cargo.toml` | 1.5.1 |
| Tests the default suite runs | `cargo nextest run --workspace` | 1815 passed, 40 skipped |
| Tests `cargo test` runs, doctests included | `cargo test --workspace`, summing every `test result:` line | 1821 passed, 0 failed, 47 ignored |
| Doctests, which nextest does not run at all | `cargo test --doc --workspace` | 6 passed, 7 ignored |
| Test binaries reporting a result | `cargo test --workspace` piped through `grep -c "^test result:"` | 60 |
| Documentation and naming validators | `python3 scripts/validate/validate_all.py` | All 21 validations passed |
| Test annotations in the tree | `grep -rEc '^\s*#\[(tokio::)?test\]' crates src-tauri` summed | 1855 |
| Tests the assertion check reads | `python3 scripts/validate/validate_test_assertions.py --all` | 1855 across 281 files |

The gap between 1855 annotations and 1815 executions is exactly 40, and all 40
are `#[ignore]`d tests, listed by
`cargo nextest list --workspace --run-ignored ignored-only`. Every one of them
is named in the rows below. Nothing in the tree is skipped for a reason this
ledger does not record.

Two further reconciliations, because three of the rows above look like they
disagree and do not. The annotation count and the assertion check's walk total
are the same number, 1855, and they are meant to be: the check globs every `.rs`
file under `crates/*/src/` and `src-tauri/src/` rather than the file names unit
tests are conventionally split out under, so every annotated test in the tree is
one it reads. A walk total below the annotation count would mean tests were
going unread, which is what issue #130 was. And `cargo test --workspace` reports
6 more passes and 7 more ignores than `cargo nextest run --workspace` does;
those 13 are doctests, which nextest does not run and which no annotation count
covers. 1815 + 6 = 1821 and 40 + 7 = 47.

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

## Mutation testing, smoked on 2026-08-07

The three grades above say what a test's evidence is worth once it runs. None
of them, and no coverage figure either, can say whether a test checks anything
at all: a line a test reaches and asserts nothing about counts exactly as
covered as a line it pins. Mutation testing asks the one question that
separates the two. Change the code, and does anything go red?

Phase 4 is where that runs across the integrity-critical crates. What is
recorded here is narrower, namely that the runner is installed and that its
verdicts can be believed. Both were proven on `hardener-distro`, chosen because
it is the smallest crate in the workspace and not because its result is
interesting.

| Measurement | Command | Reading |
|---|---|---|
| Runner installed | `cargo install cargo-mutants --locked` | cargo-mutants 27.1.0 |
| Mutants tested in `hardener-distro` | `cargo mutants -p hardener-distro --timeout 120 -j 1` | 126 tested in 68s: 36 caught, 73 missed, 17 unviable, 0 timeouts. Taken before the Phase 3 deletion recorded below, and not reproducible on the crate as it now stands. |

Run that command as printed, with a bare `cargo` and no wrapper in front of it.
One correction to it cost a wrong answer to find, and Phase 4 inherits it
because it will copy the line above.

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
  strictly smaller than the 1815 recorded above, so a green CI run is a weaker
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
- **`scripts/test/differential-suite.sh` applies six plugins at most.** Its
  `DIFF_PLUGINS` list is ssh, pam, permissions, firewall and kernel, and the
  services plugin joins only in a booted run. `audit-hardening` and
  `mac-hardening` are in neither list, so no oracle anywhere asks either
  plugin's scan against a live system. Their applies are not equally placed:
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
| `kernel-hardening` reports the sysctl values it names, and its apply leaves the running kernel enforcing them | `crates/hardener-plugins/tests/kernel_mock_tests.rs` (61 tests), `crates/hardener-plugins/src/kernel/tests.rs` (8 tests), `crates/hardener-plugins/src/kernel/persistence/tests.rs` (18 tests), `crates/hardener-plugins/tests/kernel_tests.rs` (4 run, 1 `#[ignore]`d behind root), `scripts/test/differential-suite.sh` (11 parameters read back with `sysctl`, plus 10 seeded looser-than-target controls and 1 seeded stricter-than-baseline control) | `cargo nextest run -p hardener-plugins --test kernel_mock_tests` | The default suite is grade 1 throughout: `/proc/sys` is never touched. The only oracle is the differential suite, and all 11 of its kernel rows are recorded unaskable unless the run holds its own network namespace, because otherwise `/proc/sys/net` belongs to the host and is read-only. **The namespace is the whole of the requirement and a boot is not part of it** (#137): this row said "booted with its own network namespace" until 2026-08-09, and `systemd-nspawn --private-network --pipe` was measured on 2026-08-08 to make `/proc/sys/net` writable with no `--boot` anywhere. Both paths of `run-cross-distro-tests.sh` now declare the namespace, so an unbooted `--pipe` differential run asks all 11 rows rather than recording them unaskable; the boot signal is still required for the services rows, which need systemd as PID 1, and the two are separate signals. A further 7 parameters are declared permanently unaskable and are proven nowhere, because `/proc/sys` outside `/proc/sys/net` is the host's and read-only whatever the namespace. |
| `mac-hardening` reports whether SELinux or AppArmor is enforcing, and its apply raises the mode it names | `crates/hardener-plugins/tests/mac_mock_tests.rs` (32 tests), `crates/hardener-plugins/src/mac/tests.rs` (18 tests), `crates/hardener-plugins/tests/mac_tests.rs` (4 run, 1 `#[ignore]`d behind root) | `cargo nextest run -p hardener-plugins --test mac_mock_tests` | **No oracle anywhere reads MAC state back.** Live runs do exist: `crates/hardener-plugins/tests/mac_tests.rs` scans the host by default, and `scripts/test/full-test-suite.sh` scans, dry-runs and applies this plugin inside a container, so `getenforce` and `aa-status` are reached through the real executor on any host carrying them. Every one of those runs judges an exit status, a plugin id, a non-zero duration or the tool's own result document, and none holds what those tools answer against what the plugin reported. `mac-hardening` is absent from the differential suite's plugin list, which is where that comparison would live. The mock decides which of the two systems is present by planting `/sys/fs/selinux` metadata, so the detection logic is proven against a fixture and never against a host that actually runs either one. |
| `pam-hardening` reports the password and lockout policy the stack will enforce, including inline overrides | `crates/hardener-plugins/tests/pam_mock_tests.rs` (80 tests), `crates/hardener-plugins/src/pam/tests.rs` (20 tests), `crates/hardener-plugins/src/pam/layer_drift/tests.rs` (8 tests), `crates/hardener-plugins/src/pam/login_defs/tests.rs` (2 tests), `crates/hardener-plugins/tests/pam_tests.rs` (4 run, 1 `#[ignore]`d behind root), `scripts/test/differential-suite.sh` (3 login.defs rows via `chage` and `passwd -S`, 2 pwquality enforcement rows: `module-loaded`, which offers no password at all and holds the PAM stack text against the tool's own minlen findings, and `weak-password-refused`, which carries both probes in the one check and requires the weak password refused and the strong one accepted) | `cargo nextest run -p hardener-plugins --test pam_mock_tests` | Apply deliberately refuses to edit `/etc/pam.d/*` and reports a manual action instead, so the strongest claim available for the stack files is that the tool told the truth about what a person must do, not that it did it. `PASS_MIN_DAYS` is unaskable on Arch, whose shadow is built without the field, so that row is absent from a run on the project's own development distribution. The pwquality oracle needs the module actually loaded, which is a booted container, and neither probe password ever reaches the live PAM stack: both are piped to `pwscore`, libpwquality's own CLI, which applies the same configuration file the module would. That makes the file's consumer the thing answering rather than a second parser, and it leaves the path from a real authentication attempt through PAM to a refusal tested nowhere. |
| `permissions-hardening` reports the modes and ownership on the paths it names, and its apply sets them | `crates/hardener-plugins/tests/permissions_mock_tests.rs` (40 tests), `crates/hardener-plugins/src/permissions/tests.rs` (14 tests), `crates/hardener-plugins/tests/permissions_tests.rs` (4 run, 1 `#[ignore]`d behind root), `scripts/test/differential-suite.sh` (9 permission rows read back with `stat`) | `cargo nextest run -p hardener-plugins --test permissions_mock_tests` | The live oracle asks `stat` about 9 paths, which covers modes and nothing else: no oracle anywhere reads back ownership or an ACL after an apply. The remote path, where this plugin runs through `SshExecutor`, has grade-1 evidence only. Shadow and gshadow use a no-loosen mask, so a host already stricter than the target is left alone, and the oracle rows are written to accept that rather than to demand equality. |
| `service-minimisation` reports which units systemd will start at boot, and its apply disables or masks the units it names | `crates/hardener-plugins/tests/services_mock_tests.rs` (21 tests), `crates/hardener-plugins/src/services/tests.rs` (10 tests), `crates/hardener-plugins/tests/services_tests.rs` (4 run, 1 `#[ignore]`d behind root), `scripts/test/differential-suite.sh` (3 rows via `systemctl is-enabled`, `is-active` and `readlink`), `scripts/test/full-test-suite.sh` (section 12B: the mask symlink read off the filesystem after an apply and after a rollback, booted hosts only) | `cargo nextest run -p hardener-plugins --test services_mock_tests` | The smallest mock suite of the eight, at 21 tests against 80 for pam. Under `--pipe` this plugin's scan errors and its apply does nothing, so it joins the compared set only in a booted run; the differential suite declares its rows unaskable rather than letting an empty reading compare equal to an empty reading and pass. `systemctl mask` leaves a link into `/dev/null`, which is the case the rollback guard finds hardest, so this plugin and the checkpoint row below share a failure mode; section 12B of `scripts/test/full-test-suite.sh` is the reading that can catch it, and it needs a booted container run with the suite's `--apply` flag. |
| `ssh-hardening` reports the effective sshd configuration, including drop-ins and includes, and its apply leaves sshd serving what it reported | `crates/hardener-plugins/tests/ssh_mock_tests.rs` (82 tests), `crates/hardener-plugins/src/ssh/include/tests.rs` (10 tests), `crates/hardener-plugins/src/ssh/dropin/tests.rs` (2 tests), `crates/hardener-plugins/tests/ssh_tests.rs` (7 run, 1 `#[ignore]`d behind root), `scripts/test/differential-suite.sh` (7 rows read back through `sshd -T` itself, plus seeded no-loosen rows and a reload cycle) | `cargo nextest run -p hardener-plugins --test ssh_mock_tests` | The best-evidenced plugin in the tree, because sshd is its own oracle and `sshd -T` cannot be satisfied by this project's parser agreeing with this project's writer. The ceiling is availability, not depth: that oracle runs only inside a container, as root, started by hand. The crypto allow-lists are intersected with `ssh -Q` at runtime, so what a given host ends up offering depends on its OpenSSH build and is not pinned by any test. |

### The two executors

| Claim | Evidence | Command | Ceiling |
|---|---|---|---|
| `LocalExecutor` reads and writes the local filesystem as the plugins expect, and refuses paths it must not reach | `crates/hardener-core/src/executor/local/tests.rs` (12 tests against a real temporary filesystem), `crates/hardener-core/tests/mock_executor_tests.rs` (15 tests pinning the mock to the same contract) | `cargo nextest run -p hardener-core executor::local` | This is the only executor the default suite exercises against a real filesystem, and it does so entirely in unprivileged temporary directories. Nothing in a default run writes a root-owned file, runs `sudo tee`, or chmods a path outside the test's own tree, so the privileged behaviour that every apply depends on is proven only by the container suites. The `MockExecutor` conformance tests keep the two implementations answering the same shape, which is a weaker guarantee than answering the same values. |
| `SshExecutor` performs the same reads and writes against a remote host over a key-authenticated connection | `crates/hardener-core/tests/ssh_executor_tests.rs` (3 run, 12 `#[ignore]`d behind `SSH_TEST_HOST`), `crates/hardener-plugins/tests/ssh_integration_tests.rs` (2 run, 12 `#[ignore]`d), `scripts/containers/boot-ssh-test-container.sh`, `crates/hardener-cli/tests/ssh_refusal.rs` (12 tests) | `cargo test -p hardener-core --test ssh_executor_tests -- --ignored`, after running `scripts/containers/boot-ssh-test-container.sh` under `sudo` and then, in your own shell, exporting the variables it prints and running the `ssh-add` it prints. The script prints those lines for you to paste; a child process cannot export into the shell that invoked it. | Only 3 of the 15 tests run by default, and those three assert config shape and description formatting: nothing that touches a wire runs in the default suite or in CI, so **a regression in the SSH transport is invisible to `cargo test`**. Both suites fail loudly rather than silently when `SSH_TEST_HOST` is unset, which is the correct behaviour and which the fleet row below now shares. There is no password authentication path by design, so nothing here covers one. |

### Checkpoint and rollback

| Claim | Evidence | Command | Ceiling |
|---|---|---|---|
| A checkpoint captures the files an apply is about to change, and a rollback restores the bytes and modes it captured | `crates/hardener-state/tests/checkpoint_system.rs` (14 tests), `crates/hardener-state/src/manager/tests.rs` (48 tests), `crates/hardener-state/tests/signing_tests.rs` (11 tests), `crates/hardener-plugins/src/kernel/divergence/tests.rs` (36 tests, the kernel rollback probe's own), `scripts/test/verify-rollback.sh`, `scripts/test/differential-suite.sh` (a rollback and reload cycle read back through `sshd -T`), `scripts/test/full-test-suite.sh` (sections 12A and 12B, which read the audit tree and the services mask link back off a real filesystem after a rollback) | `cargo nextest run -p hardener-state --test checkpoint_system` | **Checkpoints are text-only.** Restore writes content through `String::from_utf8_lossy`, so a file with non-UTF-8 bytes cannot round-trip and no test asserts that it can. Non-root remote restore degrades to content-only, because the `chmod`, `chown` and `rm` that follow the write run without sudo; the content write itself uses `sudo tee`, so the two halves have different privilege requirements. Cross-host rollback is refused outright by comparing `host_key`. Account databases are captured metadata-only on purpose, which the `ContentAbsence` discriminant distinguishes from a read that failed, so a rollback that could not read what it was asked to no longer reports success. The oracles that re-read a system after a rollback are `scripts/test/verify-rollback.sh` and sections 12A and 12B of `scripts/test/full-test-suite.sh`, and every one of them is container-and-root only. The two full-test-suite sections need that suite's `--apply` flag as well, and 12A needs a container no earlier `--apply` run has touched, or it reports its reading void. The kernel arm of `scripts/test/verify-rollback.sh` reads a runtime `sysctl` value back only where `/proc/sys/net` is writable, which needs a container holding its own network namespace. Its only runner now passes `--private-network`, which is sufficient under `--pipe` (`--boot` is not required, measured 2026-08-08), and the arm was read green that day: seeded to 0, raised to 1 by the apply, back to 0 after the rollback. Where the namespace is absent the arm still skips, and the script exits 2 rather than 0 so a skip cannot be recorded as a reading. **A rollback now reports what it left diverged from the configuration it restored, for two of the eight plugins.** `RollbackResult.rollback_divergences` carries a row when kernel-hardening's sysctl or firewall-hardening's ufw still disagrees with the restored state after the reload, and a row when either probe could not answer at all; the other six plugins are asked nothing, because no probe has been written for them. This is reporting only: no rollback behaviour, exit code or `rollback_success` value changed to add it. `scripts/test/verify-rollback.sh` gained an eighth arm, TEST 8, asserting exactly this against a real container, and it was read green on 2026-08-08: 23 of 23, none skipped, replacing the 21-of-21 reading above. That run also measured the kernel probe's output, 15 rows of which 12 were `Diverged` and 3 `Unverifiable`, the 3 being the glob source `/usr/lib/sysctl.d/50-default.conf` and the two managed keys its patterns could name, `net.ipv4.conf.all.rp_filter` and `net.ipv4.conf.all.accept_source_route`. The 26-of-26 run below re-measured that breakdown against the post-change binary and read it identical, 15 rows, 12 `Diverged` and 3 `Unverifiable`, the same three subjects, so the `/etc/sysctl.conf` work moved no row in it. **The kernel probe also reads `/etc/sysctl.conf`, which no boot applier on a systemd host reads** (#140): a parameter named only there stays `Diverged`, and the sentence says the value is lost at the next reboot rather than that no file names it. Where the probe cannot tell which applier runs at boot the row is `Unverifiable` instead, and where an unprivileged run cannot read a drop-in at all every disagreeing parameter is reported `Unverifiable` rather than `Diverged`, because `effective.blocks_all` is a whole-host flag and a probe that cannot read the files is not entitled to accuse the host. A ninth arm, TEST 9, asks that of a real container, and the suite was read green on 2026-08-08 at **26 of 26, none failed and none skipped** (TEST 9 asks three questions, which is why 23 became 26 rather than 24), reporting `net.ipv4.conf.all.log_martians` as `Diverged`. |

### The compliance renderers

| Claim | Evidence | Command | Ceiling |
|---|---|---|---|
| A control the engine does not assess is reported as ManualReview and never as a green Pass | `crates/hardener-compliance/tests/assessment_honesty.rs` (6 tests), `crates/hardener-compliance/src/generator/tests.rs` (19 tests), `crates/hardener-compliance/tests/report_tests.rs` (9 tests) | `cargo nextest run -p hardener-compliance --test assessment_honesty` | Coverage is declared by each plugin's own `coverage()` function, so the honesty guarantee is only as good as those declarations: a plugin that over-declares turns a ManualReview into a Pass and nothing here would notice. The framework catalogues themselves are curated for CIS and ISO 27001 and derived from coverage for the rest, so a mapping error in a derived framework is a data defect no test in this crate can see. |
| Every output format renders a report the intended consumer can read | `crates/hardener-compliance/src/output/text/tests.rs` (4 tests), `crates/hardener-compliance/src/output/json/tests.rs` (2 tests), `crates/hardener-compliance/src/output/csv/tests.rs` (4 tests), `crates/hardener-compliance/src/output/html/tests.rs` (3 tests), `crates/hardener-compliance/src/output/pdf/tests.rs` (2 tests) | `cargo nextest run -p hardener-compliance output::` | **Fifteen tests, of which ten assert on substrings of the rendered string, one asserts a prefix and a byte length on it rather than a substring, and four assert on a helper rather than on any rendered output (`test_csv_escape`, `test_csv_formula_injection_guard`, `test_html_escape`, `test_truncate_string`).** No test parses a rendered report back with the consumer that will read it: the JSON is never handed to a deserialiser, the CSV never to a CSV reader, the HTML never to a parser, and the PDF row checks only that the output starts with `%PDF-` and exceeds 1000 bytes, so a structurally invalid document no reader can open would pass. The CSV escaping and formula-injection guard are the strongest of the four helper tests, being asserted directly on the escaper that the injection risk lives in. |

### The fleet verbs

| Claim | Evidence | Command | Ceiling |
|---|---|---|---|
| `batch scan`, `report`, `apply` and `rollback` reach every host in the inventory, default to a dry run, and refuse a host whose privilege probe fails | `crates/hardener-cli/src/commands/batch/tests.rs` (69 run, 1 `#[ignore]`d eyeball helper), `crates/hardener-cli/src/ssh_config/tests.rs` (4 tests), `crates/hardener-cli/tests/ssh_refusal.rs` (12 tests) | `cargo nextest run -p hardener-cli commands::batch` | The 69 in-crate tests are target parsing, output shaping and refusal policy over fixtures. None of them opens a connection, so multi-host behaviour against real hosts, partial failure across a fleet, and a privilege refusal from a host that genuinely refuses are all unproven at grade 3. |
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
