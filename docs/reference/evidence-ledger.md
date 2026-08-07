# Evidence Ledger

**Last Updated**: 2026-08-07

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
| Evidence | The files that carry the proof, as repo-relative paths in backticks. A validator added later in this phase reads this column and fails the build when a path cited here no longer exists, so a row cannot outlive the file it points at. |
| Command | What a reader runs to watch the evidence pass, with no privileged setup unless the cell says otherwise. In most rows this is deliberately the part of the Evidence column a reader can run unprivileged rather than all of it, and what it leaves out is named in that row's Ceiling. |
| Ceiling | What the row does **not** prove. Where the only evidence is a mock, it says so. Where the evidence is an `#[ignore]`d test the default suite never runs, it says so, because a regression there is invisible to `cargo test`. |

---

## Baseline, as measured on 2026-08-07

Numbers taken from commands rather than from prose. Re-measure before amending
them; do not copy a figure from an older document.

| Measurement | Command | Reading |
|---|---|---|
| Workspace version measured | `grep -m1 '^version' Cargo.toml` | 1.5.1 |
| Tests the default suite runs | `cargo nextest run --workspace` | 1706 passed, 40 skipped |
| Test binaries reporting a result | `cargo test --workspace` piped through `grep -c "^test result:"` | 60 |
| Documentation and naming validators | `python3 scripts/validate/validate_all.py` | All 19 validations passed |
| Test annotations in the tree | `grep -rEc '^\s*#\[(tokio::)?test\]' crates src-tauri` summed | 1746 |

The gap between 1746 annotations and 1706 executions is exactly 40, and all 40
are `#[ignore]`d tests, listed by
`cargo nextest list --workspace --run-ignored ignored-only`. Every one of them
is named in the rows below. Nothing in the tree is skipped for a reason this
ledger does not record.

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

## Ceilings that apply to every row

These are stated once here rather than repeated in every cell below.

- **Nothing automated runs above grade 2.** `.github/workflows/ci.yml` runs
  `cargo test --workspace $WORKSPACE_EXCLUDE`, where `WORKSPACE_EXCLUDE` is
  `--exclude linux-hardener-desktop --exclude hardener-ui`. It executes no
  `#[ignore]`d test and no shell suite, and those two exclusions make CI's set
  strictly smaller than the 1706 recorded above, so a green CI run is a weaker
  reading than that number. Every grade-3 result in this ledger was produced by
  a person running a container by hand, and the date of the last such run is in
  `docs/reference/distribution-validation.md`, not here.
- **`scripts/test/differential-suite.sh` applies six plugins at most.** Its
  `DIFF_PLUGINS` list is ssh, pam, permissions, firewall and kernel, and the
  services plugin joins only in a booted run. `audit-hardening` and
  `mac-hardening` are in neither list, so no oracle anywhere asks either
  plugin's scan against a live system. Their applies are not equally placed:
  section 12A of `scripts/test/full-test-suite.sh` reads audit's whole write
  surface back off a real filesystem after an apply and again after a rollback,
  while `mac-hardening`'s apply is skipped outright inside a container, which is
  the only place this suite runs, so nothing reads mac's apply back at all. Its
  scan does get an unconditional exit-status check, and that is the whole of it.
- **An unbooted container cannot be asked about the kernel.** Under
  `systemd-nspawn --pipe`, `/proc/sys/net` is the host's and read-only, so the
  suite records those rows as unaskable rather than passing them.
- **The desktop application has no row here yet.** Its Tauri IPC surface and its
  Leptos frontend are not covered by anything in this table, so nothing in it
  should be read as a claim about the GUI.

---

## Capabilities

### The eight plugins

| Claim | Evidence | Command | Ceiling |
|---|---|---|---|
| `audit-hardening` reports the auditd state its checks describe, and its apply writes the rules it names | `crates/hardener-plugins/tests/audit_mock_tests.rs` (37 tests), `crates/hardener-plugins/src/audit/tests.rs` (14 tests), `crates/hardener-plugins/tests/audit_tests.rs` (4 run, 1 `#[ignore]`d behind root), `scripts/test/full-test-suite.sh` (section 12A: the rules file the apply writes, the compiled `audit.rules` line count, and the whole `/etc/audit` tree diffed pre-apply against post-rollback) | `cargo nextest run -p hardener-plugins --test audit_mock_tests` | **Mock only for the scan.** `auditctl` and `augenrules` are asked in no test and in no script in this tree, and `audit-hardening` is absent from the differential suite's plugin list, so every claim about what this plugin *reports* is the plugin agreeing with a fixture it was handed. The apply is better placed: section 12A of `scripts/test/full-test-suite.sh` runs it on a real host and then judges the filesystem rather than the exit status, requiring that the rules file appeared, that a rollback removed it, that `/etc/audit` diffs identical to its pre-apply state, and that the compiled `audit.rules` line count came back. That runs only inside a container, as root, by hand, behind the suite's `--apply` flag, and only in a container no earlier `--apply` run has touched: where the rules file is already present the section reports the reading void rather than passing it. The single real-host Rust test is `#[ignore]`d because it modifies system audit configuration, so a default `cargo test` still asserts nothing about auditd at all. |
| `firewall-hardening` reports the active backend's rules, and its apply installs the rules it names | `crates/hardener-plugins/tests/firewall_mock_tests.rs` (61 tests), `crates/hardener-plugins/src/firewall/tests.rs` (71 tests), `crates/hardener-plugins/tests/firewall_tests.rs` (6 run, 4 `#[ignore]`d), `scripts/test/differential-suite.sh` (3 firewall rows against `nft list ruleset`), `scripts/containers/nftables-fixture.sh` | `cargo nextest run -p hardener-plugins --test firewall_mock_tests` | Three backends are supported (nftables, firewalld, ufw) and the live oracle asks only the one the fixture container installs, which is nftables. The firewalld and ufw paths are `#[ignore]`d on "only run on systems with that backend installed" and have grade-1 evidence only. A fixture container can also boot the wrong distribution and still pass, so a live result is worth nothing until `/etc/os-release` has been read over the connection that produced it. |
| `kernel-hardening` reports the sysctl values it names, and its apply leaves the running kernel enforcing them | `crates/hardener-plugins/tests/kernel_mock_tests.rs` (59 tests), `crates/hardener-plugins/src/kernel/tests.rs` (8 tests), `crates/hardener-plugins/src/kernel/persistence/tests.rs` (6 tests), `crates/hardener-plugins/tests/kernel_tests.rs` (4 run, 1 `#[ignore]`d behind root), `scripts/test/differential-suite.sh` (11 parameters read back with `sysctl`, plus 10 seeded looser-than-target controls and 1 seeded stricter-than-baseline control) | `cargo nextest run -p hardener-plugins --test kernel_mock_tests` | The default suite is grade 1 throughout: `/proc/sys` is never touched. The only oracle is the differential suite, and all 11 of its kernel rows are recorded unaskable unless the run is booted with its own network namespace, because otherwise `/proc/sys/net` belongs to the host and is read-only. A further 7 parameters are declared permanently unaskable and are proven nowhere. |
| `mac-hardening` reports whether SELinux or AppArmor is enforcing, and its apply raises the mode it names | `crates/hardener-plugins/tests/mac_mock_tests.rs` (28 tests), `crates/hardener-plugins/src/mac/tests.rs` (18 tests), `crates/hardener-plugins/tests/mac_tests.rs` (4 run, 1 `#[ignore]`d behind root) | `cargo nextest run -p hardener-plugins --test mac_mock_tests` | **Mock only, with no live oracle anywhere.** `getenforce`, `sestatus` and `aa-status` are asked in no test and in no script in this tree, and `mac-hardening` is absent from the differential suite's plugin list. The mock decides which of the two systems is present by planting `/sys/fs/selinux` metadata, so the detection logic is proven against a fixture and never against a host that actually runs either one. |
| `pam-hardening` reports the password and lockout policy the stack will enforce, including inline overrides | `crates/hardener-plugins/tests/pam_mock_tests.rs` (79 tests), `crates/hardener-plugins/src/pam/tests.rs` (20 tests), `crates/hardener-plugins/src/pam/layer_drift/tests.rs` (8 tests), `crates/hardener-plugins/src/pam/login_defs/tests.rs` (2 tests), `crates/hardener-plugins/tests/pam_tests.rs` (4 run, 1 `#[ignore]`d behind root), `scripts/test/differential-suite.sh` (3 login.defs rows via `chage` and `passwd -S`, 2 pwquality enforcement rows: `module-loaded`, which offers no password at all and holds the PAM stack text against the tool's own minlen findings, and `weak-password-refused`, which carries both probes in the one check and requires the weak password refused and the strong one accepted) | `cargo nextest run -p hardener-plugins --test pam_mock_tests` | Apply deliberately refuses to edit `/etc/pam.d/*` and reports a manual action instead, so the strongest claim available for the stack files is that the tool told the truth about what a person must do, not that it did it. `PASS_MIN_DAYS` is unaskable on Arch, whose shadow is built without the field, so that row is absent from a run on the project's own development distribution. The pwquality oracle needs the module actually loaded, which is a booted container, and neither probe password ever reaches the live PAM stack: both are piped to `pwscore`, libpwquality's own CLI, which applies the same configuration file the module would. That makes the file's consumer the thing answering rather than a second parser, and it leaves the path from a real authentication attempt through PAM to a refusal tested nowhere. |
| `permissions-hardening` reports the modes and ownership on the paths it names, and its apply sets them | `crates/hardener-plugins/tests/permissions_mock_tests.rs` (37 tests), `crates/hardener-plugins/src/permissions/tests.rs` (14 tests), `crates/hardener-plugins/tests/permissions_tests.rs` (4 run, 1 `#[ignore]`d behind root), `scripts/test/differential-suite.sh` (9 permission rows read back with `stat`) | `cargo nextest run -p hardener-plugins --test permissions_mock_tests` | The live oracle asks `stat` about 9 paths, which covers modes and nothing else: no oracle anywhere reads back ownership or an ACL after an apply. The remote path, where this plugin runs through `SshExecutor`, has grade-1 evidence only. Shadow and gshadow use a no-loosen mask, so a host already stricter than the target is left alone, and the oracle rows are written to accept that rather than to demand equality. |
| `service-minimisation` reports which units systemd will start at boot, and its apply disables or masks the units it names | `crates/hardener-plugins/tests/services_mock_tests.rs` (20 tests), `crates/hardener-plugins/src/services/tests.rs` (10 tests), `crates/hardener-plugins/tests/services_tests.rs` (4 run, 1 `#[ignore]`d behind root), `scripts/test/differential-suite.sh` (3 rows via `systemctl is-enabled`, `is-active` and `readlink`), `scripts/test/full-test-suite.sh` (section 12B: the mask symlink read off the filesystem after an apply and after a rollback, booted hosts only) | `cargo nextest run -p hardener-plugins --test services_mock_tests` | The smallest mock suite of the eight, at 20 tests against 79 for pam. Under `--pipe` this plugin's scan errors and its apply does nothing, so it joins the compared set only in a booted run; the differential suite declares its rows unaskable rather than letting an empty reading compare equal to an empty reading and pass. `systemctl mask` leaves a link into `/dev/null`, which is the case the rollback guard finds hardest, so this plugin and the checkpoint row below share a failure mode; section 12B of `scripts/test/full-test-suite.sh` is the reading that can catch it, and it needs a booted container run with the suite's `--apply` flag. |
| `ssh-hardening` reports the effective sshd configuration, including drop-ins and includes, and its apply leaves sshd serving what it reported | `crates/hardener-plugins/tests/ssh_mock_tests.rs` (80 tests), `crates/hardener-plugins/src/ssh/include/tests.rs` (10 tests), `crates/hardener-plugins/src/ssh/dropin/tests.rs` (2 tests), `crates/hardener-plugins/tests/ssh_tests.rs` (7 run, 1 `#[ignore]`d behind root), `scripts/test/differential-suite.sh` (7 rows read back through `sshd -T` itself, plus seeded no-loosen rows and a reload cycle) | `cargo nextest run -p hardener-plugins --test ssh_mock_tests` | The best-evidenced plugin in the tree, because sshd is its own oracle and `sshd -T` cannot be satisfied by this project's parser agreeing with this project's writer. The ceiling is availability, not depth: that oracle runs only inside a container, as root, started by hand. The crypto allow-lists are intersected with `ssh -Q` at runtime, so what a given host ends up offering depends on its OpenSSH build and is not pinned by any test. |

### The two executors

| Claim | Evidence | Command | Ceiling |
|---|---|---|---|
| `LocalExecutor` reads and writes the local filesystem as the plugins expect, and refuses paths it must not reach | `crates/hardener-core/src/executor/local/tests.rs` (12 tests against a real temporary filesystem), `crates/hardener-core/tests/mock_executor_tests.rs` (15 tests pinning the mock to the same contract) | `cargo nextest run -p hardener-core executor::local` | This is the only executor the default suite exercises against a real filesystem, and it does so entirely in unprivileged temporary directories. Nothing in a default run writes a root-owned file, runs `sudo tee`, or chmods a path outside the test's own tree, so the privileged behaviour that every apply depends on is proven only by the container suites. The `MockExecutor` conformance tests keep the two implementations answering the same shape, which is a weaker guarantee than answering the same values. |
| `SshExecutor` performs the same reads and writes against a remote host over a key-authenticated connection | `crates/hardener-core/tests/ssh_executor_tests.rs` (3 run, 12 `#[ignore]`d behind `SSH_TEST_HOST`), `crates/hardener-plugins/tests/ssh_integration_tests.rs` (2 run, 12 `#[ignore]`d), `scripts/containers/boot-ssh-test-container.sh`, `crates/hardener-cli/tests/ssh_refusal.rs` (12 tests) | `cargo test -p hardener-core --test ssh_executor_tests -- --ignored`, after running `scripts/containers/boot-ssh-test-container.sh` under `sudo` and then, in your own shell, exporting the variables it prints and running the `ssh-add` it prints. The script prints those lines for you to paste; a child process cannot export into the shell that invoked it. | Only 3 of the 15 tests run by default, and those three assert config shape and description formatting: nothing that touches a wire runs in the default suite or in CI, so **a regression in the SSH transport is invisible to `cargo test`**. Both suites do fail loudly rather than silently when `SSH_TEST_HOST` is unset, which is the correct behaviour and is not shared by the fleet row below. There is no password authentication path by design, so nothing here covers one. |

### Checkpoint and rollback

| Claim | Evidence | Command | Ceiling |
|---|---|---|---|
| A checkpoint captures the files an apply is about to change, and a rollback restores the bytes and modes it captured | `crates/hardener-state/tests/checkpoint_system.rs` (14 tests), `crates/hardener-state/src/manager/tests.rs` (48 tests), `crates/hardener-state/tests/signing_tests.rs` (11 tests), `scripts/test/verify-rollback.sh`, `scripts/test/differential-suite.sh` (a rollback and reload cycle read back through `sshd -T`), `scripts/test/full-test-suite.sh` (sections 12A and 12B, which read the audit tree and the services mask link back off a real filesystem after a rollback) | `cargo nextest run -p hardener-state --test checkpoint_system` | **Checkpoints are text-only.** Restore writes content through `String::from_utf8_lossy`, so a file with non-UTF-8 bytes cannot round-trip and no test asserts that it can. Non-root remote restore degrades to content-only, because the `chmod`, `chown` and `rm` that follow the write run without sudo; the content write itself uses `sudo tee`, so the two halves have different privilege requirements. Cross-host rollback is refused outright by comparing `host_key`. Account databases are captured metadata-only on purpose, which the `ContentAbsence` discriminant distinguishes from a read that failed, so a rollback that could not read what it was asked to no longer reports success. The oracles that re-read a system after a rollback are `scripts/test/verify-rollback.sh` and sections 12A and 12B of `scripts/test/full-test-suite.sh`, and every one of them is container-and-root only. The two full-test-suite sections need that suite's `--apply` flag as well, and 12A needs a container no earlier `--apply` run has touched, or it reports its reading void. |

### The compliance renderers

| Claim | Evidence | Command | Ceiling |
|---|---|---|---|
| A control the engine does not assess is reported as ManualReview and never as a green Pass | `crates/hardener-compliance/tests/assessment_honesty.rs` (6 tests), `crates/hardener-compliance/src/generator/tests.rs` (18 tests), `crates/hardener-compliance/tests/report_tests.rs` (9 tests) | `cargo nextest run -p hardener-compliance --test assessment_honesty` | Coverage is declared by each plugin's own `coverage()` function, so the honesty guarantee is only as good as those declarations: a plugin that over-declares turns a ManualReview into a Pass and nothing here would notice. The framework catalogues themselves are curated for CIS and ISO 27001 and derived from coverage for the rest, so a mapping error in a derived framework is a data defect no test in this crate can see. |
| Every output format renders a report the intended consumer can read | `crates/hardener-compliance/src/output/text/tests.rs` (4 tests), `crates/hardener-compliance/src/output/json/tests.rs` (2 tests), `crates/hardener-compliance/src/output/csv/tests.rs` (4 tests), `crates/hardener-compliance/src/output/html/tests.rs` (3 tests), `crates/hardener-compliance/src/output/pdf/tests.rs` (3 tests) | `cargo nextest run -p hardener-compliance output::` | **Sixteen tests, of which ten assert on substrings of the rendered string, one asserts a prefix and a byte length on it rather than a substring, four assert on a helper rather than on any rendered output (`test_csv_escape`, `test_csv_formula_injection_guard`, `test_html_escape`, `test_truncate_string`), and one asserts nothing at all: `test_pdf_formatter_default`, in `crates/hardener-compliance/src/output/pdf/tests.rs`, binds a `PdfFormatter` and ends.** No test parses a rendered report back with the consumer that will read it: the JSON is never handed to a deserialiser, the CSV never to a CSV reader, the HTML never to a parser, and the PDF row checks only that the output starts with `%PDF-` and exceeds 1000 bytes, so a structurally invalid document no reader can open would pass. The CSV escaping and formula-injection guard are the strongest of the four helper tests, being asserted directly on the escaper that the injection risk lives in. |

### The fleet verbs

| Claim | Evidence | Command | Ceiling |
|---|---|---|---|
| `batch scan`, `report`, `apply` and `rollback` reach every host in the inventory, default to a dry run, and refuse a host whose privilege probe fails | `crates/hardener-cli/src/commands/batch/tests.rs` (69 run, 1 `#[ignore]`d eyeball helper), `crates/hardener-cli/src/ssh_config/tests.rs` (4 tests), `crates/hardener-cli/tests/ssh_refusal.rs` (12 tests) | `cargo nextest run -p hardener-cli commands::batch` | The 69 in-crate tests are target parsing, output shaping and refusal policy over fixtures. None of them opens a connection, so multi-host behaviour against real hosts, partial failure across a fleet, and a privilege refusal from a host that genuinely refuses are all unproven at grade 3. |
| Each of the four fleet verbs completes against a live remote host | `crates/hardener-cli/tests/batch_ssh_integration.rs` (4 tests, all 4 `#[ignore]`d behind `SSH_TEST_HOST`), `scripts/containers/boot-ssh-test-container.sh` | `cargo test -p hardener-cli --test batch_ssh_integration -- --ignored`, after running `scripts/containers/boot-ssh-test-container.sh` under `sudo` and then, in your own shell, exporting the variables it prints and running the `ssh-add` it prints. The script prints those lines rather than exporting them, so a reader who skipped the paste has `SSH_TEST_HOST` unset, which is exactly the state the ceiling beside this cell warns about. | Four tests, one happy path per verb, and none runs in the default suite or in CI. **Worse, this file reports success when it ran nothing:** each test opens with an early return when `SSH_TEST_HOST` is unset, so the command in the Command column exits 0 with "4 passed" on a machine with no container booted. The two SSH suites in the executor row fail loudly in the same situation. Until that is fixed, a green reading from this row is evidence of nothing unless the operator confirms a host was set. |

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
