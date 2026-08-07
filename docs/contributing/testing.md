# Testing Commands

Commands for running unit tests, integration tests, container-based root tests, cross-distro validation, and GUI tests.

---

## Unit and Integration Tests (Cargo)

### Run all tests

```bash
cargo test --workspace
```

Runs every test across all 11 workspace members (the ten crates under `crates/`
plus `src-tauri`). Measured 2026-08-07: 1711 passed, 0 failed, 47 ignored, over
60 result lines. The
ignored ones are mostly the root-only and live-sshd tests described further down,
with a few that want a particular firewall backend installed; they are not
failures and an ordinary `cargo test` does not run them.

Any count in this file is a record of one measurement on one day, not a property
of the tree. Where a number matters, run the command and read what it says.

### Faster runner: cargo nextest

```bash
cargo nextest run --workspace       # the unit and integration tests, in parallel
cargo test --doc --workspace        # the doctests nextest does not run
```

`cargo nextest` is installed on this machine (0.9.140) and runs the same tests
faster, one process per test. **It does not run doctests at all.** That is a
property of nextest rather than a configuration in this repository, so a gate
built out of `cargo nextest run` alone has not compiled or run a single `///`
example in `crates/`, and the workspace has them. Either pair it with
`cargo test --doc`, as above, or use plain `cargo test --workspace`, which runs
both halves itself.

### CI subset (excludes GUI crates)

```bash
cargo test --workspace --exclude linux-hardener-desktop --exclude hardener-ui
```

Excludes the Tauri backend and WASM frontend crates; used in CI where GUI dependencies may not be available.

### Single crate

```bash
cargo test -p hardener-core                  # Core engine tests
cargo test -p hardener-plugins               # Plugin tests
cargo test -p hardener-cli                   # CLI argument parsing and command tests
cargo test -p hardener-state                 # Checkpoint, signing, audit log tests
cargo test -p hardener-common                # Utility and error type tests
cargo test -p hardener-compliance            # Compliance framework tests
cargo test -p hardener-scheduler             # Daemon and scheduling tests
cargo test -p hardener-distro                # Distribution detection tests
cargo test -p hardener-types                 # Shared type tests
```

### Show test output

```bash
cargo test -- --nocapture                    # Print stdout/stderr from passing tests
```

### Run ignored tests (require root)

```bash
sudo cargo test -- --ignored
```

Some tests require root privileges and are marked `#[ignore]`. These test operations like file permission changes that need elevated access.

---

## Test Container Creation

All root-level and destructive tests run inside `systemd-nspawn` containers, never on the host. Each script creates a minimal container under `/var/lib/machines/`.

All five containers are created by one script, `create-container.sh`, which takes the distro as its first argument:

```bash
sudo ./scripts/containers/create-container.sh arch              # Create container
sudo ./scripts/containers/create-container.sh arch enter         # Enter existing container interactively
sudo ./scripts/containers/create-container.sh arch clean         # Remove container completely
```

| Distro argument | Container name |
|-----------------|----------------|
| `arch` (primary) | `hardener-test` |
| `debian` | `hardener-test-debian` |
| `fedora` | `hardener-test-fedora` |
| `rhel` (Rocky Linux, RHEL-compatible) | `hardener-test-rhel` |
| `opensuse` | `hardener-test-opensuse` |

Enabling `sshd`, `auditd` and `bluetooth` is a required step, not a best-effort
one: if it fails the script reports what the service manager said and refuses to
finish, because a container missing the services under test produces suite
results that look like passes. Every bootstrap installs all three packages, so a
failure there means the bootstrap did not do what it reported doing. The one
call that decides this is `enable_test_services` in `create-container.sh`, and
each per-distro bootstrap routes through it.

`bluez` is there for a reason of its own, and it is what makes suite section 12B
askable at all. Until it was installed, no container image carried a unit the
service-minimisation plugin manages, so every `systemctl is-enabled` reading
across the five hosts came back `not-found` and the plugin had nothing to report.
A check written against that fixture would have asserted nothing while reading in
a log as coverage.

### SSH integration fixture (booted container)

The suites above run containers via `nspawn --pipe` (no network, no sshd). The
`#[ignore]` SSH integration tests need a *booted* container with networking and
an authorised key instead; the SSH executor is key/agent-auth only, so the
containers' root password is not usable:

```bash
sudo ./scripts/containers/boot-ssh-test-container.sh            # boot hardener-test with --network-veth, inject test key
sudo ./scripts/containers/nftables-fixture.sh                   # optional: stop the incumbent and load one input-hook chain, so the nftables backend is the one selected
# then, using the env exports the script prints:
export SSH_TEST_HOST=<addr> SSH_TEST_USER=root SSH_TEST_PORT=22 SSH_TEST_KEY=~/.ssh/hardener_test_ed25519
ssh-add "$SSH_TEST_KEY"
cargo test -p hardener-core --test ssh_executor_tests -- --ignored      # executor primitives
cargo test -p hardener-cli --test batch_ssh_integration -- --ignored    # batch scan/report/apply/rollback end-to-end
sudo machinectl stop hardener-test                   # tear down
```

The batch tests are read-only against the fixture (scan/report scan; apply and
rollback run as dry-runs). Without `SSH_TEST_HOST` they skip.

### Booted suite containers (`--booted`)

Under `--pipe` systemd never starts, so anything that asks the service manager a
question is untestable. `--booted` runs the same suite as a child of the
container's own systemd:

```bash
sudo ./scripts/test/run-cross-distro-tests.sh --distro arch --apply --booted
```

Measured on arch 2026-07-30 against the identical run under `--pipe`: of 138
verdicts exactly one changes, `Apply ssh-hardening` from
`(partial apply: expected in container)` to a clean pass, because the service
restart now works. Inside the firewall apply, ten
`iptables-restore: Permission denied` and fifteen
`sysctl: permission denied on key "net.ipv4.*"` disappear.

The container gets `--private-network`, not `--network-veth`, and the choice is
load-bearing in both directions:

- **It must own a network namespace.** nspawn grants `CAP_NET_ADMIN` only to a
  container that does, which is exactly why `iptables-restore` fails under
  `--pipe`. Never add `--capability=CAP_NET_ADMIN` to a container sharing the
  host's namespace: these suites run
  `hardener apply --plugin firewall-hardening`, and those rules would land in
  the host's own netfilter.
- **It does not need a veth pair.** `--private-network` and `--network-veth`
  give an identical capability set (`CapEff 00000000fdecbfff`), the same
  read-write `/proc/sys/net`, and the same working `iptables`. The veth variant
  only adds a `ve-*` interface on the host and addressing at both ends, which
  no suite uses.

`/proc/sys` stays read-only either way, so the seven `fs.*` and `kernel.*`
parameters remain unreachable and the in-container
`apply --plugin kernel-hardening` cannot touch the host. **Do not mount it
writable to enable a kernel oracle.** The eleven `net.ipv4.*` parameters do
become writable, inside the container's namespace only.

Take a container reading through `systemd-run --machine`, never `nsenter`.
nsenter enters the namespaces but keeps the caller's capabilities, so it reports
the host's `CapEff 000001ffffffffff` and makes a forbidden operation look
permitted.

**Host prerequisite: ufw's netfilter extensions must already be loaded.** A
container cannot autoload a kernel module, because `CAP_SYS_MODULE` is cleared
and must stay cleared, so the extensions ufw's baseline rules need have to be
present on the host before the run. Without them the firewall apply fails with
`Extension limit revision 0 not supported, missing kernel module?` followed by
`RULE_APPEND failed (No such file or directory)`, which reads like a tool defect
and is not one:

```bash
sudo modprobe -a xt_limit xt_LOG ipt_REJECT ip6t_REJECT ip6t_rt xt_hl xt_multiport xt_recent
```

Note `-a`. Without it `modprobe` loads the first module and treats the rest as
*parameters* to it, which fails silently in the sense that it reports success
having loaded one of eight.

**With those loaded, `--booted` reaches 126/126 on arch** (2026-07-30, arch,
`--apply`, container recreated first), against 125/126 under `--pipe` in the
same run. Exactly two verdicts differ and nothing else moves:

```
- [FAIL] Apply firewall-hardening (the plugin reported no result at all)
+ [PASS] Apply firewall-hardening
- [PASS] Apply ssh-hardening (partial apply: expected in container)
+ [PASS] Apply ssh-hardening
```

That was the last failing test in the container suites.

Those totals are a record of that run and not the size of a run today: sections
12A and 12B did not exist on 2026-07-30 and section 23 has since grown. A booted
`--apply` run now declares 149 checks, and the suite refuses a run that records
any other number. See "The size of a run is declared" below.

---

## Root Test Suites (Inside Containers)

These scripts must be run inside a container (`create-container.sh arch enter`), not on the host.

### Root test suite (focused)

```bash
sudo ./scripts/test/root-test-suite.sh                    # Read-only tests only
sudo ./scripts/test/root-test-suite.sh --apply             # Include destructive apply + rollback tests
```

Tests hardener operations that require root: scanning as root, checkpoint creation, plugin apply/rollback.

Without `--apply`: only tests scanning and checkpoint operations (non-destructive).
With `--apply`: also tests applying hardening changes and rolling them back (modifies system config files, then restores them).

### Full test suite (comprehensive, 28 sections)

```bash
sudo ./scripts/test/full-test-suite.sh                     # Sections 1-12, 17-22, 24-26 (no apply)
sudo ./scripts/test/full-test-suite.sh --apply             # All 28 sections including apply and rollback
```

More thorough than `root-test-suite.sh`. Covers CLI argument parsing, every plugin's scan output, checkpoint lifecycle, compliance reports, daemon commands, systemd integration, history commands, and per-plugin apply/rollback cycles.

The sections are numbered 1 to 26, with **12A** and **12B** sitting beside 12, so
there are 28 of them. Both of the lettered ones are rollback sections and both
run first inside the apply block; the ordering is load bearing and the reason is
below.

Without `--apply`: skips 12A and 12B, sections 13-16 (per-plugin apply and
rollback) and section 23 (per-plugin lifecycle).
With `--apply`: runs all 28 sections including destructive per-plugin lifecycle
testing.

#### 12A: a rollback removes the audit plugin's rules file

`test_audit_rollback_restores` applies `audit-hardening`, rolls it back, and then
reads the filesystem rather than the tool's summary. Three things must be true
afterwards: `/etc/audit/rules.d/hardening.rules` is gone, `find /etc/audit` lists
exactly the paths it listed before the apply, and `/etc/audit/audit.rules` is
back at its pre-apply line count.

The apply's exit status is deliberately not asserted. Auditd cannot start in a
container, so `augenrules --load` and the service restart both fail and the
plugin reports the run unsuccessful having already written its rules file.
Asserting exit 0 would assert something false about the host. The positive
control is the rules file existing after the apply, because a rollback of an
apply that wrote nothing satisfies every assertion by having nothing to undo.

The checkpoint is chosen by name and then by age, through the shared
`checkpoints_named` reading, and the count is asserted rather than the position
trusted: every rollback writes its own "Before rollback to '<name>'" snapshot
carrying the target's name as a substring, so a name filter alone matches the
state after the change as readily as the one before it. 12A takes the oldest
match, because it asks what the host looked like before the first change.

The compiled rule set is judged on its line count, not on a text search. An
earlier version grepped the compiled file for "hardening" and reported that the
tool's rules were absent on all five hosts while the counts said the file had
grown and stayed grown: `augenrules` strips the comment header, so the word can
never appear there. A control whose search term cannot match can only return the
reassuring answer. `line_count` keeps `absent` and `unreadable` apart from a
number for the same reason, and an unreadable reading fails the row instead of
comparing equal to another unreadable one.

Seven checks: the precondition, the apply having written the file, exactly one
checkpoint carrying the apply's name, the rollback exiting 0, the rules file
gone, the tree identical, and the compiled line count back.

#### 12B: a services rollback unmasks what the apply masked

`test_services_rollback_restores` is 12A's sibling for
`service-minimisation`. Where audit's defect was a file its apply wrote, this
plugin's is a symlink `systemctl mask` creates,
`/etc/systemd/system/bluetooth.service` pointing at `/dev/null`. That link
outlived its own rollback in three separate ways, each fixed separately and none
of them visible to this suite at the time: the checkpoint did not declare the
path, the restore refused it because the guard resolved the link to `/dev/null`
and out of every allowlist, and restoring the enablement symlink failed with
ENOENT because disabling had emptied and removed its parent directory. All three
shipped, and the suite read the same totals before and after every one of them.

After the rollback: the mask link is gone, `systemctl is-enabled bluetooth` reads
the same word it read before the apply, and `/etc/systemd/system` lists exactly
the paths it listed before. The enablement half is a genuinely different failure
from the mask half, which is why it is a row of its own: a rollback can remove
the mask correctly and still leave the unit disabled.

The reading is taken on the **word** `systemctl is-enabled` prints and never on
its exit status, because `static` and `indirect` print their own word and exit 0,
`enabled-runtime` exits 0 while the next boot discards it, and `disabled` and
`masked` exit non-zero.

**This section needs a booted host**, and says so rather than failing
confusingly: `systemctl mask` and `systemctl is-enabled` both need systemd as
PID 1, which `nspawn --pipe` does not provide. Under `--pipe` it records its one
precondition check and skips, naming `--booted` as the flag that would let it
run. `host_is_booted` is the single predicate behind both the skip and the
expected size of the section, so the two cannot come to disagree about what a
booted host is.

The fixture it rests on is `bluez`, which `scripts/containers/create-container.sh`
installs and enables on all five images.

Seven checks booted, in the same shape as 12A: the precondition, the apply having
masked the unit, exactly one checkpoint carrying the apply's name, the rollback
exiting 0, the mask link gone, the unit enabled again, and
`/etc/systemd/system` identical. One check unbooted, the precondition that then
skips the rest.

#### 23: the per-plugin lifecycle, and the checkpoint it rolls back

`test_per_plugin_lifecycle` runs kernel, ssh and permissions through scan,
apply, re-scan, rollback, re-scan. By the time it runs, sections 13 to 15 have
already hardened the host, so each apply here is a **second** apply and finds
nothing to do. That fixes what the section can honestly ask. "Did the rollback
remove what the apply created" is unaskable at this position, because there is
nothing to remove and the assertion would pass against a rollback that did
nothing whatever; that question belongs to 12A and 12B, which run before anything
hardens the host.

What it does ask is idempotency and non-damage: the finding count must be
unmoved by the second apply, and unmoved again by the rollback that follows.
A rollback that removed a drop-in it should have restored raises the count, and
that is the fault these two readings can see. The comparison is equality with
four named outcomes (`unmoved`, `rose`, `fell`, `void`), because the `-le` it
replaced was satisfied by nothing having happened, so its false branch was
unreachable on every host and read in the log as coverage.

**The rollback is paired with its apply through
`ApplyResult::apply_checkpoint_id`**, read out of that apply's own result
document by `apply_checkpoint_id_of`, and not by name or by recency. Selecting
the newest checkpoint carrying the plugin's name was tried and was wrong on all
five distributions in a way worth keeping: the ssh plugin takes no checkpoint
when it has nothing to do, so the newest one bearing its name was the one section
14 took before the host was hardened at all. Rolling that back removed the
hardening, the count went from 0 to 10 findings, and the failure message asserted
a cause that was false. The tool did what it was asked; the check asked for the
wrong checkpoint. `head -1` over an unfiltered listing, which the section did for
far longer, rolled back a stranger's and said nothing at all.

A plugin whose apply took no checkpoint is a declared outcome rather than a
fault. Its three rows are recorded and skipped, with the reason named, rather
than rolled back to some other apply's checkpoint. Six checks per plugin over
three plugins, so 18.

#### The size of a run is declared, and a wrong size is refused

The number this suite prints has moved twice without anybody deciding it should,
126 to 133 when 12A landed and 133 to 140 when 12B did. Nothing held it, so a
section that quietly stopped recording checks would have read as a shorter run
rather than as a fault, which is the same shape as a check that passes by
matching nothing.

`suite_section_sizes` therefore declares how many checks **each** section
records, `expected_test_total` sums them, and `require_expected_total` refuses a
run whose recorded total differs. As measured off the function itself:

| Run | Declared checks |
|-----|-----------------|
| `--apply` in a booted container | **149** |
| `--apply` in an unbooted (`--pipe`) container | **143** |
| without `--apply` | **109** |

The refusal is reported through `log_fail`, as a **counted failure**, and not by
the exit status alone. The reason is in the runner:
`run-cross-distro-tests.sh` writes `PASS` into `test-results/summary.txt` for any
distribution whose failure count is zero, so a refusal carried only by the exit
code would read as a pass in the file most likely to be looked at first. Moving
the failure count moves both.

Each declaration is counted off the **pinned** lengths of the plugin, framework,
scenario, format and severity tables (`PLUGINS_EXPECTED` and its siblings) rather
than off the tables themselves. Read from `${#PLUGINS[@]}`, an expectation would
follow the table it exists to police: dropping a plugin would lower both sides
and a run eight checks short would still read as complete. `require_suite_tables`
runs in the preflight, before any section, and refuses a run whose tables are not
the size they declare.

#### Recreate the containers before every `--apply` run

`--apply` hardens every container it touches, and nothing in the suite undoes the
audit apply section 15 performs. Both 12A and 12B ask whether a rollback
**removes** something an apply created, and that can only be asked of a host
where it does not exist yet: where it already does, the checkpoint captures it
with content, the restore correctly writes those bytes back, the removal path is
never exercised, and a pass would say nothing about it.

This is enforced rather than advised. Each section checks its own precondition
and, finding the artefact already present, records a **failure** naming the
recreate command, so a second `--apply` run in the same container ends red
instead of quietly proving less:

```bash
for d in arch debian fedora rhel opensuse; do
    sudo ./scripts/containers/create-container.sh "$d" clean --no-confirm
    sudo ./scripts/containers/create-container.sh "$d" || { echo "CREATE FAILED: $d"; break; }
done
```

An undeterminable result is a failure here, never a skip. Unaskability is a
property of the invocation, declared in advance, which is why 12B skips under
`--pipe` and neither section skips on a dirty container.

The ordering follows from the same rule: 12A and 12B run **first** inside the
apply block, before `test_apply_kernel`, `test_apply_other_plugins` and
`test_apply_all`. Add new apply sections after them, never before. They are
independent of each other in either order, because audit's checkpoint declares
paths under `/etc/audit` only and services' declares `/etc/systemd/system` and
its own mask links.

#### Self-test (safe anywhere)

```bash
bash scripts/test/full-test-suite.sh --self-test            # classification and diagnostics, safe anywhere
```

Needs no root and no container. It drives the decisions the suite makes rather
than the system it makes them about:

- the apply classification that separates an apply which partially succeeded,
  which a container is expected to produce, from one that never ran, which it is
  not. Inside a container both exit 1, so the suite tells them apart by whether
  the tool left a result document behind, and asking for the wrong document key
  must fail or a dry run would read as an apply. The document's own
  `apply_success` is read as well: for a single plugin the exit code is exactly
  that field, so an exit code disagreeing with it means one of the two is wrong.
- the dry-run row's pairing of exit code and validation report. A document
  existing was once the whole test, which left the row unable to fail; it now
  fails a run that exited 0 while its report carries a Critical or High issue,
  and a run that exited non-zero with nothing in its report to explain it.
  Critical and High are what `ValidationReport::has_blocking_issue` counts, so
  the row asks the document the question the CLI asked itself, and a Medium note
  is pinned as advisory because PAM layer drift emits one on every host whose
  `/etc` file masks its vendor copy. The blocking issues are printed into the
  log, so a run can say which blocker fired rather than only that one did.
- `line_count`'s three outcomes, which section 12A depends on: a count, `absent`,
  and `unreadable` kept apart, with the empty file pinned as zero lines rather
  than as absent. The unreadable arm needs an unprivileged reader and says so
  when run under sudo instead of quietly not running.
- `checkpoints_named`, including that a plugin's own checkpoints come back
  newest first without the rollback snapshot that names it.
- `scan_finding_count`, `apply_checkpoint_id_of` (an apply that took none says
  `none`, though its changes mention a checkpoint id) and all four arms of
  `finding_count_verdict`.
- the size guard: the three declared totals above, that a shortened table is
  refused while the expected total stays where it was, and that a refused run
  moves the failure count rather than only the exit status.

### Rollback verification

```bash
sudo ./scripts/test/verify-rollback.sh
```

Runs 5 targeted tests that verify checkpoint creation, apply, and rollback produce the expected system state. Must be run inside a container.

### Manual verification

```bash
sudo ./scripts/test/manual-verification-test.sh
```

Interactive step-by-step test with pauses between operations. Designed for manually inspecting system state at each stage. Must be run inside a container.

---

## Differential Suite (Ask The System, Not The Tool)

Every other suite compares the tool against itself: it applies a setting, reads
the file back with the same parser that wrote it, and reports agreement. That is
how a maximum password age of 99999 shipped as "compliant" from v1.0.0 onwards.
The differential suite applies hardening and then asks each setting's real
consumer what is in force:

| Setting | Oracle | Why not read the file |
|---------|--------|-----------------------|
| The `sshd_config` directives in `SSH_CHECKS` | `sshd -T` | Resolves `Include` precedence and `Match` scoping, which our parser does not |
| `PASS_MIN_DAYS`, `PASS_MAX_DAYS`, `PASS_WARN_AGE` | `useradd`, then `chage -l` with `passwd -S` behind it | `login.defs` supplies defaults for NEW accounts, so only a fresh account shows what the file means today. Arch builds shadow with no minimum-days field at all, so `PASS_MIN_DAYS` is read from `passwd -S` there: see [The directive one reader cannot report](#the-directive-one-reader-cannot-report) |
| `ENCRYPT_METHOD`, `HOME_MODE`, `UMASK` | a probe account: the scheme prefix `crypt` wrote into its shadow field, `stat -c %a` on its home, `su - probe -c umask` | These are settings the tool does **not** manage, and the file they come from is the one a masked `/etc` copy silences. Reading that file back would ask the masked copy what it says |
| The nine paths in `PERMISSION_CHECKS` | `stat -c %a` | A mode has no parser to disagree with: the value the kernel reports **is** the value in force. What the oracle adds is the comparison, because two of the nine are allowed-bits masks where a stricter mode is compliant |
| The three properties in `FIREWALL_CHECKS` | `nft list ruleset` and `systemctl is-enabled`, each diffed against a pre-apply capture | `ufw status` and `firewall-cmd --list-all` are the tools' own frontends. Netfilter is what a packet meets, and systemd is what decides whether it still will after a reboot. **The two ruleset rows require `--booted`; `boot-persistence` does not** |
| The 11 `net.ipv4.*` parameters in `KERNEL_CHECKS` | `sysctl -n` | The file under `/etc/sysctl.d` is what the tool wrote, not what the kernel runs, and a reader sharing one mistake with the writer agrees with it and disagrees with Linux. **Requires `--booted`** |

Two assertions per directive, because both have failed in production: the system
satisfies what this run requires of it, and `scan`'s verdict agrees with the
system.

**The firewall rows are one assertion each, not two**, because there is no
per-rule tool verdict to compare against: the plugin's only scan finding is
`{backend}-disabled`, which says nothing about an individual rule. Four things
about that oracle were measured on real containers rather than reasoned about,
and each would otherwise have produced a check that passes on broken code:

- **`iptables -S` cannot see firewalld.** After a successful apply on Fedora it
  prints three policy lines and nothing else, because every rule firewalld wrote
  lives in `table inet firewalld`. An `iptables -S` oracle matches nothing on
  three of five distributions, and matching nothing is this suite's pass
  condition. Its policy lines are still read, because ufw expresses its default
  disposition there and nowhere else.
- **Presence is not evidence, because the baseline is not empty.** Fedora's
  container starts with 344 lines of firewalld ruleset already loaded, including
  `ct state {established, related} accept` and `iifname "lo" accept`. Arch starts
  at 4. The same presence assertion would be honest on Arch and vacuous three
  distributions over, so everything is compared against a pre-apply capture.
- **A firewalld DROP zone target renders as a bare `drop`** replacing the zone
  chain's trailing `reject with icmpx admin-prohibited`. A pattern written for
  `policy drop` matches firewalld never. The self-test pins this: relaxing the
  check to accept `reject` makes an unhardened Fedora container pass the oracle,
  and four assertions fail when it is mutated that way.
- **A ruleset carries nothing about the next boot.** A firewall started by hand
  renders identically to one that comes back after a reboot, so both rules-based
  rows stayed green against the Arch container whose `ufw` unit had no
  `multi-user.target.wants` symlink at all. Measured, by comparing the run
  before the repair existed against the run after it: all 68 assertion lines
  are byte-identical on all five distributions, so nothing in the suite would
  have caught the repair regressing. `boot-persistence` asks `systemctl
  is-enabled` instead, either side of the apply, and judges on systemd's word
  rather than its exit status: `enabled-runtime` and `static` both exit zero and
  neither survives a reboot.

**`ssh-still-accepted` is a safety property, not proof the tool acted**, and the
code says so. On firewalld that rule exists before the apply as well, because the
default `public` zone allows the ssh service, so it would pass against a tool
that did nothing. It earns its place because a firewall that drops inbound *and*
drops ssh has locked the operator out, and no other check would notice.

**`boot-persistence` says in its own message whether its row is
discriminating.** Only Arch is load-bearing there: Fedora, RHEL and openSUSE
ship firewalld already enabled, and Debian's `ufw` package enables the unit at
install, so four of the five would read `enabled` without the repair. The
pass message therefore compares against the pre-apply reading and names which
case it is, because a wording that read the same on all five would make one row
of evidence look like five.

**That pre-apply reading asks every candidate unit, and not the one the
pre-apply ruleset names.** Deriving it from the ruleset was a defect of exactly
the kind this row exists to prevent. On Arch and Debian `ufw` is installed but
not enabled before the apply, so its chains do not exist, the pre-apply backend
reads as none, and systemd was never asked at all. The row then filled that gap
by crediting the apply, which is true on Arch and almost certainly false on
Debian, whose firewall survived a reboot before the repair existed and whose
`ufw` package enables the unit at install. `FIREWALL_UNIT_CANDIDATES` therefore
holds both units, both are asked before the apply and recorded as
`<unit>|<word>` pairs, and the row looks up the unit its own post-apply reading
names. A before state that could not be read, or that systemd worded in a way
the suite cannot name, leaves the row passing on its after reading while saying
it cannot tell whether the apply is what did it: filling that gap with a claim
is the whole defect, and making it in a different branch would be worth nothing.
The candidate list and `firewall_backend_kind` have to name the same backends
and nothing in the run path makes them, so the self-test reads the kinds back
out of that function's own body, and the row says so in its own message if the
two come apart during a run.

The row is deliberately **not** gated on `--booted`,
unlike the kernel rows: whether `systemctl is-enabled` answers inside an
unbooted `--pipe` container is unmeasured, so a run that cannot ask goes red
rather than quiet. An answer that is neither `enabled` nor one of the six states
the tool repairs is a failure, never a skip, and the failure carries the word
systemd used, because a masked unit must be unmasked before enabling it can
work.

**The firewall plugin's pre-apply control is not the finding-count one** the
other three get. Its only finding is `{backend}-disabled`, and firewalld is
already active in three of the five containers, so a finding-count control would
fail there against a tool behaving correctly. It asks the stronger question
instead: was inbound traffic already dropped before the apply? If it was, the
post-apply check proves nothing whatever it reports.

**A reading satisfying a requirement is not always string equality**, which is
why `requirement_satisfied` carries a direction. `/etc/shadow` and `/etc/gshadow`
are compared against an allowed-bits mask of `0640`: a stricter mode sets no bit
the mask disallows and is compliant, so Arch's `0600` and RHEL's `0000` are both
correct and the tool deliberately leaves them alone. An equality oracle would
have reported a defect on three of the five distributions against a tool behaving
exactly as designed. The comparison lives in one place for the same reason the
product side keeps its own in `strictness.rs`: a second copy behind the verdict
question would answer differently for precisely the readings the mask exists for.

**A path absent from both layers still contributes two assertions.** The tool
treats an absence confirmed at `/etc` and at `/usr/etc` as nothing to report, so
the requirement there is that it reports nothing, and a tool inventing a finding
for a path that is not there fails. What is given up is the mode comparison, and
the run prints how many paths gave it up rather than leaving a reader to notice a
shorter proof.

**Absent from `/etc` is not absent from the host**, and the first container run of
this oracle proved why. openSUSE keeps `sudoers` at `/usr/etc/sudoers` with
nothing at `/etc/sudoers`, at mode 0444 against a 0440 target, so both the tool
and the first version of this oracle said nothing and agreed with each other: two
silences comparing equal, which is the shape the suite exists to refuse. The
capture now asks the vendor layer whenever `/etc` holds nothing, mirroring
`vendor_path_for`, and a vendor reading is compared against the same target by the
same rule.

For a vendor row the **first** assertion records the reading rather than demanding
compliance, and that is deliberate: this tool never writes `/usr/etc`, so a
violating vendor file is a state it reports and cannot correct, and requiring
compliance would leave the suite permanently red against a tool behaving exactly
as designed. The message states the mode and the requirement so the violation is
visible, and the verdict assertion is the one that can fail: the tool must report
a finding when the vendor mode violates and stay silent when it does not, pinned
in all four directions by the self-test.

One assertion per unmanaged setting, because there is no tool-reported
counterpart: the value after apply must be the value before it. The tool claims
nothing about these, so any change at all is damage whatever the new value is,
and the check is written as that invariant rather than as an expected value.
Hardcoding one would make it distribution-specific for no gain: the same run
reads `$y$` on four distributions and `$6$` on openSUSE, `0022` on four and
`0002` on debian.

**The run applies twice**, and one assertion per reading in
`IDEMPOTENCE_CHECKS` says the second apply changed nothing: every managed
permission mode as one reading, `sshd -T` in full, `/etc/ssh/sshd_config.d` as
filenames and contents, and what `login.defs` means to a fresh account. The
permission reading is taken **first**, because reading `login.defs` creates and
removes a probe account and `useradd` and `userdel` rewrite `/etc/passwd` and
`/etc/shadow`: taking it ahead of that keeps one probe cycle out from between the
two readings being compared. It cannot keep all of them out, since one cycle
still runs between that baseline and the post-apply capture, and that is why the
shared failure message names no cause: it reports that the reading moved between
the two applies rather than that the second apply moved it, because for this
reading the probe account could have. It also makes permissions the second
plugin in the repo whose apply is checked for idempotency at all, ssh having
been the only one,
and ssh failed that check twice. Idempotency is an invariant rather than a nicety, because
the scheduler applies on a cadence: an apply that undoes the previous one is a
fleet host returning to an unhardened state on a timer while reporting success
every time. A single-apply oracle structurally cannot see that, which is how a
defect that deleted the tool's own `sshd_config.d` fragment on the second run
survived a green 125/125.

The readings are whole rather than per directive, because the defect this
catches need not touch a directive anyone thought to list. A consequence worth
knowing: every other check now runs against the state after **two** applies, so
a directive a second apply un-hardens fails its own check as well as the
idempotency one.

This family is the reason a green run was never proof on its own. Every other
check asks whether a setting the tool targets reached its target; none asked
whether the rest of the file survived, which is exactly how a masked
`/etc/login.defs` stayed invisible.

Each of the three has been watched failing on a real container, which is the
only evidence that a check can fail at all: replacing the vendor file with the
one-directive `/etc/login.defs` that releases up to 1.5.0 wrote moves
`ENCRYPT_METHOD` from sha512 to DES and `HOME_MODE` from 0700 to 755 on
openSUSE Leap, and `UMASK` from 0002 to 0022 on debian. Which distribution
demonstrates which depends on what that distribution's `login.defs` actually
drives, so a check looking inert on one host is not evidence it is inert.

The second assertion is the harder one to state honestly, because after a
successful apply it expects `scan` to report no finding, and no finding is also
what the tool emits when it did not check. `scan --format json` carries a second
array, `unchecked`, whose ids are identical to the finding ids, and a directive
listed there is scored as a failure rather than as agreement: the ssh plugin
moves all of its directives into it at once when `sshd_config` cannot be read,
and still reports the scan as successful. The JSON also omits `scan_success`
altogether, so a plugin whose scan failed emits exactly what a compliant host
emits. Against that, the suite takes a second `scan` capture before `apply`, and
requires each plugin to have reported at least one finding while the container
was still unhardened. Without it, every finding filter would pass by matching
nothing on every green run.


### Password quality actually being enforced

`PWQUALITY_ENFORCEMENT_CHECKS` asks whether the file the tool writes is read by
anything. `/etc/security/pwquality.conf` is consumed by `pam_pwquality.so` and
by nothing else, so a host whose PAM stack never loads that module enforces no
password policy however the file is written. Every check that reads the file
agrees with itself, and with the tool, while the system enforces nothing: the
purest form of this project's second root-cause family, the tool tested against
itself.

Two readings, one check each. The first compares the stack
(`/etc/pam.d/system-auth`, `password-auth`, `common-password`) against the
tool's `pam-minlen` verdict, and requires them to say the same thing: a stack
that loads the module must leave the tool with nothing to report after apply,
and a stack that does not must leave it reporting the directive unenforced. The
second asks libpwquality itself, through `pwscore`, and is the positive control
the first cannot supply: a policy that refuses every password and one that
refuses none both make a one-sided filter look correct, so the weak password
must be refused **and** the probe password accepted in the same breath.

A stack with no readable file is refused rather than read as "no module", for
the same reason a filter that matches nothing is not a pass: absence concluded
from nothing scores a host this run never looked at. `pwscore` being absent is a
real answer rather than a skip, since no libpwquality means no
`pam_pwquality.so` either.

### The preview an operator approved, against the apply that followed

`run_preview_agreement_checks` is the one family here whose subject is the
tool's own output on both sides, and that is not the shortcut it looks like.
Everywhere else, reading the tool back is the defect this suite exists to catch.
Here the property **is** that the tool's two accounts of itself agree, and no
reading of the host can supply it, because a preview describes a future and
leaves nothing behind to measure. The defect it is written against was a firewall
dry run that did not preview the boot enable its apply then made; only the mock
tests noticed, and no container run asked the question at all.

One row per compared plugin, in one direction only: an apply that applied changes
the preview never named is the failure, because the preview is what an operator
approves and a run longer than its preview applied something nobody was shown.
The reverse, a preview naming work the apply then did not do, is ordinary. The
dry run is captured before the apply, for the same reason as every other
pre-apply capture, and the comparison uses the **first** apply's output, since
`run_full_suite` applies twice and a second apply on an already hardened host
reports almost nothing.

`run_preview_agreement_control` is the sixth check and is not optional: every
row above passes when the preview said nothing to contradict, and a filter that
matches nothing says nothing, so both sides must have answered for **every**
compared plugin and the refusal names the plugin and the side it was missing
from.

### Findings the hardening is expected to introduce

"Hardening introduces no new finding" is false, and a check asserting it would
fail a tool behaving exactly as designed. Measured on the arch and debian
containers: the firewall plugin enables ufw, ufw applies its own sysctl file when
its unit starts, that unit is ordered after `systemd-sysctl`, and the file sets
`log_martians` to 0 against a target of 1. The parameter genuinely stops
surviving a reboot, and the tool is right to report it, only after the apply.

So `INTRODUCED_FINDING_ALLOWANCES` is a registry rather than a prohibition, the
same shape and for the same reason as `validate_write_sites.py`: an introduced
finding passes when it is declared there with a written reason, and fails naming
itself when it is not, which forces the decision at the moment the finding first
appears rather than the day it misleads somebody. Entries are matched on the
whole id and keyed on the plugin as well, never on a prefix, because a pattern
written before the decision cannot carry it.

One row per compared plugin again, plus a control, because both scan documents
were captured on every run and, until this existed, nothing asked either of them
anything about the firewall or kernel ids at all: a commit that added a kernel
finding appearing only after apply passed a full run 75/75, and the run said
nothing whatever about the commit it was run for. The control requires that the
two documents cover every compared plugin and that the apply **resolved** at
least one finding, since a comparison in which nothing was read introduces
nothing, and nothing introduced is the pass condition of every row above.

### Declared unaskable, which is not a skip

`record_unaskable` sits beside `record_pass` and `record_fail`. It keeps its own
counter, `CHECKS_UNASKABLE`, prints every row it records by name, and stays
outside `CHECKS_TOTAL`, so the `Total`, `Passed` and `Failed` numbers the
host-side runner parses mean exactly what they meant before it existed.

**It does not weaken the rule that an oracle which cannot answer is a failure.**
The distinction is *when* unaskability is decided. A property of the fixture,
known before the run and written into a table with its reason, is unaskable: a
container has no writable `/proc/sys`, and that is true before a single check
runs. A property of the run, discovered at the moment a read comes back empty,
stays a failure: "I asked and got nothing" is the silence this suite exists to
refuse, and reaching for `record_unaskable` where a read fails would turn the
mechanism into the escape hatch it was built to avoid.

That is also why the count is named on its own line rather than folded into any
of the four labels:

```
  Skipped:      0
  Unaskable:    7 (declared above, not asked on this fixture)
```

`Skipped` stays 0 and always will. A green run carrying an `Unaskable` line is
not full coverage, and the line exists so that it cannot be read as though it
were.

### The directive one reader cannot report

`LOGIN_DEFS_CHECKS` carries two readers per row, not one. The first is the
`chage -l` label the directive is reported under; the second is the `passwd -S`
field carrying the same setting, and it is consulted only where the first comes
up empty.

The second reader exists because Arch cannot answer `PASS_MIN_DAYS` through
`chage` at all. Its shadow build has no minimum-days field: `chage -l` prints no
such line, `chage --help` offers no `-m`, and the word appears nowhere in the
binary, which rules out a translated label and a privilege difference alike.
Measured on `shadow 4.20.0.arch1-1`. The other four distributions report the
label and go on using it.

Two properties of that arrangement are deliberate.

**The fallback is per directive, not a replacement.** `passwd -S` reports all
three values and could have replaced `chage` outright, which would be the
smaller diff. It was not taken: `chage` is proven against four distributions and
`passwd -S` against none, so swapping the reader would have put four passing
runs at risk to fix the one that could not pass. The row that needs the second
reader uses it; the rows that do not, do not.

**A fallback that answered everything would be invisible**, because it would
return the right value on every row and no run would ever notice. The self-test
closes that by giving the two readers *disagreeing* fixtures: the `passwd -S`
line says 99 and 88 where `chage` says 42 and 11, so a fallback that had started
answering `PASS_MAX_DAYS` reads 99 and goes red. Only an absent label falls
through. A pattern `grep` rejected is a malformed table entry, and answering it
from elsewhere would hide the defect behind a plausible value.

**On Arch the second reader answers, and the answer is that the host cannot
carry the value.** `passwd -S` reports the probe account's minimum as `-1`,
because Arch's `useradd` leaves the field empty while honouring `PASS_MAX_DAYS`
and `PASS_WARN_AGE` from the same file. One `useradd` run taking two of the
three directives and dropping the third is what rules out a file-reading
problem: the file is read, the minimum is simply not implemented.

So `PASS_MIN_DAYS` is **declared unaskable** there, the way the kernel rows are
when `/proc/sys` is the host's, rather than failed. `SHADOW_MIN_DAYS` is the
second mode signal and works like `KERNEL_BOOTED`: probed once before any check
runs, printed in the header as `Shadow minimum password age: 0` or `1`, and the
expected total branches on it. The two modes are independent facts, so the
subtraction applies to both arms. Both rows are declared rather than one,
matching `record_unresolved`, so the totals stay comparable between a host that
could be asked and one that could not.

The probe asks `chage --help` for `-m/--mindays`, which is the same question
`min_days_enforceable` in the pam plugin asks of the same tool, so the suite and
the product cannot come to disagree about what a host can do. A probe that
printed nothing is **fatal** rather than an assumption either way, because it
decides which totals the run expects. That is stricter than the plugin, which
falls through to comparing the value, and deliberately so: the plugin must not
lose a check it could still make, and the suite must not mis-total a run.

When neither reader has the directive, the failure carries what each of them
actually printed. The Arch run that raised this said only that the label was
missing, so the log could not show what `chage` had said and the cause needed a
container to find.

### The kernel oracle, and the parameters it cannot ask about

`KERNEL_CHECKS` holds 11 `net.ipv4.*` parameters, one assertion each: `sysctl -n`
is asked what the kernel enforces, and the reading is compared against the
target in that parameter's own direction. One assertion rather than two, as with
the firewall rows, because the plugin publishes no per-parameter verdict to
compare a reading against.

**It covers 11 of the 18 parameters the kernel plugin manages, and the other 7
are named rather than quietly left out.** `nspawn` mounts `/proc/sys` read-only,
and it is the **host's**: a write is refused, and a read reports the host's value
rather than the container's. Only `/proc/sys/net` is remounted read-write, and
only for a container holding its own network namespace, which is why every
askable row is a `net.ipv4.` parameter and why these 7 are not:

- `kernel.randomize_va_space`, `kernel.kptr_restrict`, `kernel.dmesg_restrict`
  and `kernel.yama.ptrace_scope`
- `fs.suid_dumpable`, `fs.protected_hardlinks` and `fs.protected_symlinks`

Each sits in `KERNEL_UNASKABLE` with its reason beside it and prints a `----`
row in every run, so the gap is on the log rather than in the reader's head.

**The comparison carries a direction**, for the reason `requirement_satisfied`
does: a host already stricter than the target is compliant, and an equality
oracle would report a defect against a tool behaving exactly as designed.
`rp_filter` is the sharp row, and it is sharp against the arithmetic. 0 is off,
2 is loose mode, which accepts a packet whose source is reachable through any
interface, and 1 is strict mode, which requires the interface it arrived on. The
larger number is the weaker setting, so no numeric direction can express that
row at all and it carries the value space itself as `ranked:0,2,1`, weakest
first.

**One row is seeded stricter than the tool's own target before the first
apply**, because a container arrives with nothing above the baseline, and an
oracle that only ever watches a host being raised to its target can never watch
one being lowered from above it. The seed is `net.ipv4.tcp_syncookies` written
to `2` against a tool target of `1`: 2 sends SYN cookies unconditionally rather
than only under pressure, so a host at 2 is ahead of the target rather than
broken, and a reading of 2 after the apply is the evidence that the tool
declined to un-harden it. `rp_filter` is deliberately **not** that row, though it
looks like the obvious candidate: 2 there ranks below strict mode 1, so seeding
it would seed a looser value, a correct tool would tighten it, and the check
would report a defect against every distribution.

**The other ten rows are seeded LOOSER than the tool's target**, and that is the
mirror of the seed above rather than a repeat of it. The stricter seed proves
the tool declines to un-harden a host already above its target; nothing proved
the opposite question could be asked at all on a host that arrived compliant.
The RHEL container is exactly that host: it ships every managed parameter at or
above its target, so `run_kernel_preapply_control` correctly refused to certify
checks that would have passed whether or not the tool had run, and the container
could not reach a clean total however often the run was repeated.

The looser value each row carries is not arbitrary, and follows from the
direction that scores it:

| direction | seed | why that value |
|---|---|---|
| `at-most 0` | `1` | unambiguously looser in the one direction the row is compared in |
| `at-least 1` | `0` | the same, the other way up |
| `ranked:0,2,1` | `0` | the weakest position in the declared space |

`rp_filter` is the trap in that last row rather than the obvious case: its space
is ranked weakest-first, so its looser value is 0 and **not** the larger number.
Seeding 2 would seed loose mode, which ranks below strict mode 1, and a correct
tool would tighten it.

`tcp_syncookies` is the eleventh row and is deliberately absent from the looser
table, because the stricter table has it. One parameter cannot carry both seeds:
whichever write landed second would decide the reading, and the check that lost
would be scoring the other one's seed. Its `KERNEL_CHECKS` row is therefore
still vacuous, and `run_seeded_kernel_check` asks the sharper question about it
instead. The self-test pins the arithmetic, so an eleventh askable parameter
cannot be added without a seed in one table or the other.

Three properties of the looser seeds are deliberate.

**They are written on every distribution**, not only where the control would
otherwise fail. Seeding only the hosts that needed it would have the five runs
measuring five different things, and the one host whose behaviour had changed
would be the one with nothing to be compared against.

**Each write is read back before the run continues.** The stricter seed needs no
read-back because `run_seeded_kernel_check` reads that parameter again after the
apply, so a write the kernel accepted and then ignored fails there. The looser
seeds have no rows of their own: they add no assertion, and what they change is
whether the existing control can be satisfied. Unread, a seed that did not take
would leave the control scoring the value the container shipped while the log
said a seed had been placed. The read-back is per parameter, so a seed loop that
wrote every row and then checked only the first is caught. The control's pass
names the seeded parameters as seeded, for the same reason: every run now
arrives holding ten, and evidence that read the same for a seeded row and a
naturally away one would let a log claim a container was non-compliant when the
suite had made it so.

**The control fails a seeded row it finds already at its target.** The seed's own
read-back cannot see that case: it proves what the kernel reported at seed time,
and the control scores a capture taken afterwards. Without the check the control
would pass on the nine rows that did arrive loosened while the tenth went into
the run exactly as vacuous as it was before being seeded.

**Be clear about what this costs the control.** On a booted run it can no longer
record the failure it was written for: the seeds abort unless their read-backs
return the loosened values, the pre-apply capture is taken from that same
kernel, and ten rows are then away by construction. The control has become an
assertion that the seeds took rather than a discovery about the host. That is a
tautology, not a hole, and the difference matters: if the kernel plugin did
nothing at all, the seeds would still be standing afterwards and
`run_kernel_checks` would fail all ten rows. Nothing goes green that should not,
and since #47 the ten rows that used to pass on an already-compliant host
whether or not the tool ran now cannot.

**A run that is not booted asks the kernel nothing.** The signal is
`HARDENER_DIFF_BOOTED`, exported by `run-cross-distro-tests.sh` on the
`systemd-run --machine` invocation inside `nspawn_suite_booted` and nowhere
else, and anything other than the literal `1` means not booted. It is never
inferred from what the fixture happens to permit, because a mode concluded from
a failed read is one value standing for several outcomes, which is the family of
defect this project keeps closing. The header prints
`Booted (kernel oracle): 0` or `Booted (kernel oracle): 1` beside the binary
version, so a reader meeting an old log can see which arithmetic applied to it.

**The totals move with the mode, and both kernel tables are pinned.** A run
records **70 checks when it is not booted and 83 when it is**, less two on a
host whose shadow has no minimum-password-age field (see below), so **68 and 81
on Arch**, and
`expected_check_total` carries an arm for each: the 11 kernel rows and the
stricter-seeded row are checks the tables ask for only where they can be asked
at all. The ten looser-seeded rows move no total, because the rows they loosen
are already counted among the 11 and what the seeds change is whether the
control can be satisfied rather than how many assertions a run makes.
The unaskable count runs the other way, **7 when booted and 19 when not**, the
19 being the 11 rows the mode puts out of reach, the 7 the mount does, and the
stricter-seeded row whose seed could not be written. `KERNEL_CHECKS_EXPECTED` and
`KERNEL_UNASKABLE_EXPECTED` are both pinned in `require_check_tables`, for one
reason beyond the usual: the failure mode here is a red row being quietly
"fixed" by moving it out of `KERNEL_CHECKS` and into `KERNEL_UNASKABLE`, and
with both sizes pinned that move fails the guard twice rather than passing.

### Full run (container + root)

```bash
sudo ./scripts/test/differential-suite.sh              # inside the container
sudo ./scripts/test/run-cross-distro-tests.sh --differential --distro arch   # from the host
```

It refuses to start outside a container, and it refuses to start as a non-root
user. It applies hardening and creates a probe account, so it is destructive by
design and never safe on a real system. From the host it replaces the full suite
for that run: `--differential` always applies, whether or not `--apply` is given,
and results land in `test-results/<distro>.log` like any other run.

Each run opens by printing the binary's path and its `--version` string, so a
log can be attributed to a commit long afterwards rather than by reconstructing
which build happened to be current. A binary whose `--version` fails or prints
nothing is recorded as `UNAVAILABLE` with the reason, never as a blank beside
the path.

`jq` is required, along with `grep`, `sshd`, `ssh-keygen`, `useradd`,
`userdel`, `chage`, `id`, `chpasswd`, `stat`, `su` and `passwd`. A missing one aborts the
run by name before any check runs. The account rows the probe reads are parsed
by the shell rather than by `awk`, which is in neither the dnf-family nor the
openSUSE package set the container script installs. An oracle that cannot answer
is a failure here, never a skip: a skipped check that reads as a pass is the
disease being treated.

The binary under test must be built from this tree. Its `scan --format json`
output has to carry both a `findings` and an `unchecked` array per plugin, and
each `unchecked` entry has to carry an `unchecked_check_id`; a build old enough
to predate `unchecked` is refused rather than counted as reporting nothing.
Setting `BINARY` names the binary exactly: an explicit path that is not
executable aborts the run instead of falling back to a build from the tree, which
would report a run of one binary as a run of another.

### Self-test (safe anywhere)

```bash
bash scripts/test/differential-suite.sh --self-test
```

Needs neither root nor a container. It drives the text extractors, the freshness
guard that refuses a capture taken before `apply`, the probe's create-and-remove
safety, and all three plugins' finding-id conventions against fixtures,
including the doubled dash in `perm--etc-shadow` that a filter written without it
would silently miss. `jq` is the only external command it needs.

The idempotency family is proven here too, because its readings want root and a
container: the fragment listing against a temporary directory that is missing,
empty and then populated, the refusal of an unknown reading key, and each of the
four ways a baseline can fail to describe what one apply produced. The
comparison itself is driven through a stubbed reading and watched in both
directions, since a reading compared against itself passes whatever the tool
did.

The vendor survival family is proven here in both directions, because its whole
job is to notice a value changing: an unchanged value agrees, a changed one does
not, a reading that could not be taken on either side fails the check rather
than skipping it, and a shadow field carrying no usable hash (`!`, `*`, or a
`!`-prefixed hash) is refused rather than reported, since those are stable
across an apply and would otherwise pass as a setting that survived while
proving nothing.

It also pins the shapes of `scan` output that would otherwise read as a clean
bill of health: a plugin object missing its `findings` or `unchecked` array, an
`unchecked` entry whose `unchecked_check_id` has been renamed, more than one JSON
document on stdout, a directive the tool listed as unchecked, and a pre-apply
capture in which a plugin reported nothing.

The lengths of the check tables are pinned there as literals as well. A total
counted off the tables cannot notice one of them being edited down: with the ssh
table emptied, a run over the `login.defs` directives alone would agree with
itself, exit 0, and be reported as a PASS. So the size the run is measured
against is counted off `SSH_CHECKS_EXPECTED`, `SEEDED_SSH_CHECKS_EXPECTED`,
`LOGIN_DEFS_CHECKS_EXPECTED`, `VENDOR_SURVIVAL_CHECKS_EXPECTED`,
`IDEMPOTENCE_CHECKS_EXPECTED`, `PWQUALITY_ENFORCEMENT_CHECKS_EXPECTED`,
`PERMISSION_CHECKS_EXPECTED`, `FIREWALL_CHECKS_EXPECTED`,
`KERNEL_CHECKS_EXPECTED`, `SEEDED_KERNEL_CHECKS_EXPECTED` and
`DIFF_PLUGINS_EXPECTED`, which the tables are then checked against, rather than
off the tables themselves. `KERNEL_UNASKABLE_EXPECTED` and
`INTRODUCED_FINDING_ALLOWANCES_EXPECTED` are pinned alongside them in
`require_check_tables` but contribute to no total: a row that was never asked is
not a check that ran, and the allowance registry exists so that a red
introduced-finding row cannot be quieted by appending an entry without the
number beside the table moving in the same diff.

Adding a directive therefore means changing four literals in
`scripts/test/differential-suite.sh`, not one: the `*_EXPECTED` constant beside
its table, that same length re-pinned in the self-test (`the ssh table holds
seven directives`), the total the run is sized at, which `expected_check_total`
computes at **68** unbooted and **81** booted, and the number of directives the
pre-apply control covers (`19`). `VENDOR_SURVIVAL_CHECKS`, `IDEMPOTENCE_CHECKS` and
`PWQUALITY_ENFORCEMENT_CHECKS` are sized the same way, and contribute one check
each rather than two. Every one of them fails loudly, over two `--self-test` runs,
because the total is counted off the constant and only moves once the constant
has been raised. Adding the idempotency table did exactly that: the self-test
refused the run at `got '28', want '25'` until the literal was raised on
purpose, and the pwquality enforcement pair did it again at
`got '30', want '28'`. The permissions table did it a third time: adding nine
paths and a third plugin moved the total from 30 to 51, and the self-test refused
the run until both literals were raised on purpose. The `permission-modes`
idempotency reading did it a fourth time, refusing the run at
`got '51', want '52'`. The firewall oracle and then the kernel oracle did it
again. `boot-persistence` did it a seventh time, and failed twice over as the
firewall tables are meant to: with `FIREWALL_CHECKS_EXPECTED` left at 2 the
self-test reads `got '55', want '56'` and `require_check_tables` refuses the
three-entry table beside it. The preview-agreement oracle and the
introduced-finding registry then did it twice more, six checks each and neither
of them affected by the mode. The per-distribution total now stands at **68** for
a run that is not booted and **81** for one that is, both pinned as literals in
`--self-test`.

### What a failure means

A failure means the operating system disagrees with what the tool reported, or
that an oracle could not be read. Neither is a flaky test: a disagreement is a
product defect and is exactly what this suite exists to find, and an oracle that
cannot answer leaves a directive unproven, which is recorded as a failure rather
than skipped. Each `FAIL` line names the directive, and where the two disagree,
the value the system holds and what this run requires of it:

- `the system holds 'X' but this run requires 'Y'`: `apply` did not take effect.
  For the two mask rows the requirement reads `no bit outside 'Y'` instead,
  because a stricter mode is compliant there and a message claiming the run
  requires `640` would be false of a directive that also accepts `600`.
- `the tool claims a compliance the system does not have`: `scan` reported
  nothing while the system holds something other than the target. This is the
  shape of the `login.defs` defect, and of the openSUSE vendor-file defect where
  the mode in force sat at `/usr/etc` and the tool had looked only at `/etc`.
- `the tool reports N finding(s) ... while the system holds 'X' and this run
  requires 'Y'`: `scan` is flagging a host that is in fact compliant.
- `the tool did not check '<id>'`: the id came back in the `unchecked` array.
  The tool verified nothing for that directive, which is neither agreement with
  the system nor a contradiction of it, and the usual cause is a config file the
  scan could not read.
- `idempotency <key>: this reading moved between the two applies`: the second
  apply did not leave the reading where the first one did, so applying on a
  cadence does not hold the host where one apply put it. The message names no
  cause on purpose: for `permission-modes` the probe account that reading
  `login.defs` creates and removes rewrites `/etc/passwd` and `/etc/shadow`, so
  the apply is not the only candidate. The `diff|` lines beneath it name the
  lines that moved, in both directions.
- `before apply the tool reported no finding for any of the N compared
  directives`: the pre-apply control failed for that plugin. Either its scan
  produced nothing, which this JSON cannot distinguish from a compliant host, or
  the harness's filter for it matches nothing.
- `Recorded N check(s) where the tables ask for M`: the run was shorter than the
  tables it was built from, so some directives went unproven.

Investigate the plugin, not the harness. If the harness itself is wrong, the
self-test is where the fix is proven.

---

## Cross-Distro Testing

Runs the full test suite across multiple distribution containers from the host.

### Cargo target directory resolution

The host-side test runners no longer assume binaries live under `./target`. Each
resolves the real cargo target directory in this order:

1. `$CARGO_TARGET_DIR`, if set.
2. `cargo metadata --format-version 1 --no-deps` → `target_directory` (honours a
   `[build] target-dir` in `~/.cargo/config.toml`), when cargo is on `PATH`.
3. `./target` (the default for a fresh clone); if the wanted binary is absent
   there but present under the invoking user's `~/.cache/cargo-target` (checked
   via `$SUDO_USER` when running under sudo), that directory is used instead.

When the resolved directory is not `./target`, the container runners additionally
bind-mount it read-only at `/project/target`, so the in-container scripts
(`full-test-suite.sh`, `test-package-install.sh`, `tauri-gui-test-inner.sh`,
`verify-rollback.sh`) keep finding binaries at their documented paths unchanged.

### All distributions

```bash
sudo ./scripts/test/run-cross-distro-tests.sh              # Read-only, all distros
sudo ./scripts/test/run-cross-distro-tests.sh --apply       # Destructive, all distros
```

Iterates through all 5 container types (Arch, Debian, Fedora, Rocky, openSUSE), copies the musl binary into each, and runs the full test suite.

### Single distribution

```bash
sudo ./scripts/test/run-cross-distro-tests.sh --distro arch
sudo ./scripts/test/run-cross-distro-tests.sh --distro debian
sudo ./scripts/test/run-cross-distro-tests.sh --distro fedora
sudo ./scripts/test/run-cross-distro-tests.sh --distro rhel
sudo ./scripts/test/run-cross-distro-tests.sh --distro opensuse
```

### Differential suite instead of the full suite

```bash
sudo ./scripts/test/run-cross-distro-tests.sh --differential
```

Runs `differential-suite.sh` in each container in place of `full-test-suite.sh`,
through the same nspawn invocation and the same per-distro logs and summary
table. See the differential suite section above; it is always destructive.

### With GUI tests

```bash
sudo ./scripts/test/run-cross-distro-tests.sh --apply --gui
```

Runs CLI tests plus Playwright GUI tests inside each container.

### Rebuild binary first

```bash
sudo ./scripts/test/run-cross-distro-tests.sh --rebuild
```

Recompiles the musl binary (`x86_64-unknown-linux-musl/release/hardener` under the resolved cargo target directory) before copying it into containers. Use this after code changes.

Test results are written to `test-results/<distro>.log`.

---

## GUI Tests

### Web UI tests (Playwright, all distros)

```bash
sudo ./scripts/test/gui/run-gui-tests.sh                       # All distro containers
sudo ./scripts/test/gui/run-gui-tests.sh --distro arch          # Arch container only
sudo ./scripts/test/gui/run-gui-tests.sh --distro debian        # Debian container only
```

Orchestrates Playwright tests inside nspawn containers with Xvfb (virtual display). Tests the Leptos web frontend served by Trunk.

Uses `scripts/test/gui/gui-test-inner.sh` internally (the script that runs inside the container).

### Tauri desktop GUI tests (Arch only)

```bash
sudo ./scripts/test/gui/run-tauri-gui-tests.sh
```

Tests the native Tauri desktop application using xdotool for window interaction. Runs inside the Arch container (`hardener-test`).

Uses `scripts/test/gui/tauri-gui-test-inner.sh` internally.

### Direct Playwright commands

From the `gui-tests/` directory (inside a container, not the host):

```bash
cd gui-tests
npm install                                            # Install @playwright/test
npx playwright test                                    # Run all tests
npx playwright test --reporter=list                    # Verbose output
```

Test results are written to `test-results/gui/`.

---

## CI Pipeline Commands

These run automatically via GitHub Actions; listed here for reference and local reproduction.

### ci.yml (every push/PR to main)

```bash
cargo check --workspace --exclude linux-hardener-desktop --exclude hardener-ui
cargo test --workspace --exclude linux-hardener-desktop --exclude hardener-ui
cargo clippy --workspace --exclude linux-hardener-desktop --exclude hardener-ui -- -D warnings
cargo fmt --all -- --check
cargo audit
cargo check -p hardener-ui --target wasm32-unknown-unknown
cargo build --release --target x86_64-unknown-linux-gnu -p hardener-cli
cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli
```

### release.yml (on tags matching `v[0-9]+.[0-9]+.[0-9]+`)

```bash
cargo test --workspace --exclude linux-hardener-desktop --exclude hardener-ui
cargo build --release --target x86_64-unknown-linux-gnu -p hardener-cli
cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli
cargo build --release --target aarch64-unknown-linux-gnu -p hardener-cli
```

Produces three release tarballs and creates a GitHub release. The aarch64 job
installs `gcc-aarch64-linux-gnu` and sets
`CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER`; there is no local equivalent to
run unless you have that cross linker installed.

### codeql.yml (push/PR to `main`, and weekly)

CodeQL analysis over Rust, JavaScript/TypeScript, Python and GitHub Actions, all
in `build-mode: none`, on every push and pull request to `main` and on a schedule
(Mondays, 06:00 UTC). It has no local reproduction: results go to the
repository's security tab.

**Last Updated**: 2026-08-07
