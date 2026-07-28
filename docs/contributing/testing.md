# Testing Commands

Commands for running unit tests, integration tests, container-based root tests, cross-distro validation, and GUI tests.

---

## Unit and Integration Tests (Cargo)

### Run all tests

```bash
cargo test --workspace
```

Runs every test across all 11 crates. Currently 660+ tests.

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

### SSH integration fixture (booted container)

The suites above run containers via `nspawn --pipe` (no network, no sshd). The
`#[ignore]` SSH integration tests need a *booted* container with networking and
an authorised key instead; the SSH executor is key/agent-auth only, so the
containers' root password is not usable:

```bash
sudo ./scripts/containers/boot-ssh-test-container.sh            # boot hardener-test with --network-veth, inject test key
# then, using the env exports the script prints:
export SSH_TEST_HOST=<addr> SSH_TEST_USER=root SSH_TEST_PORT=22 SSH_TEST_KEY=~/.ssh/hardener_test_ed25519
ssh-add "$SSH_TEST_KEY"
cargo test -p hardener-core --test ssh_executor_tests -- --ignored      # executor primitives
cargo test -p hardener-cli --test batch_ssh_integration -- --ignored    # batch scan/report/apply/rollback end-to-end
sudo machinectl stop hardener-test                   # tear down
```

The batch tests are read-only against the fixture (scan/report scan; apply and
rollback run as dry-runs). Without `SSH_TEST_HOST` they skip.

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

### Full test suite (comprehensive, 26 sections)

```bash
sudo ./scripts/test/full-test-suite.sh                     # Sections 1-12, 17-22, 24-26 (no apply)
sudo ./scripts/test/full-test-suite.sh --apply              # All 26 sections including apply and rollback
```

More thorough than `root-test-suite.sh`. Covers CLI argument parsing, every plugin's scan output, checkpoint lifecycle, compliance reports, daemon commands, systemd integration, history commands, and per-plugin apply/rollback cycles.

Without `--apply`: skips sections 13-16 (per-plugin apply and rollback) and section 23 (per-plugin lifecycle).
With `--apply`: runs all 26 sections including destructive per-plugin lifecycle testing.

```bash
bash scripts/test/full-test-suite.sh --self-test            # classification only, safe anywhere
```

Needs no root and no container. It drives the decisions the suite makes rather
than the system it makes them about, currently the one that separates an apply
that partially succeeded, which a container is expected to produce, from an
apply that never ran, which it is not. Inside a container both exit 1, so the
suite tells them apart by whether the tool left a result document behind.

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
| `PASS_MIN_DAYS`, `PASS_MAX_DAYS`, `PASS_WARN_AGE` | `useradd` then `chage -l` | `login.defs` supplies defaults for NEW accounts, so only a fresh account shows what the file means today |
| `ENCRYPT_METHOD`, `HOME_MODE`, `UMASK` | a probe account: the scheme prefix `crypt` wrote into its shadow field, `stat -c %a` on its home, `su - probe -c umask` | These are settings the tool does **not** manage, and the file they come from is the one a masked `/etc` copy silences. Reading that file back would ask the masked copy what it says |

Two assertions per directive, because both have failed in production: the system
holds the value the tool targeted, and `scan`'s verdict agrees with the system.

One assertion per unmanaged setting, because there is no tool-reported
counterpart: the value after apply must be the value before it. The tool claims
nothing about these, so any change at all is damage whatever the new value is,
and the check is written as that invariant rather than as an expected value.
Hardcoding one would make it distribution-specific for no gain: the same run
reads `$y$` on four distributions and `$6$` on openSUSE, `0022` on four and
`0002` on debian.

**The run applies twice**, and one assertion per reading in
`IDEMPOTENCE_CHECKS` says the second apply changed nothing: `sshd -T` in full,
`/etc/ssh/sshd_config.d` as filenames and contents, and what `login.defs` means
to a fresh account. Idempotency is an invariant rather than a nicety, because
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

`jq` is required, along with `sshd`, `ssh-keygen`, `useradd`, `userdel`,
`chage`, `id`, `chpasswd`, `stat` and `su`. A missing one aborts the run by name
before any check runs. The account rows the probe reads are parsed by the shell
rather than by `awk`, which is in neither the dnf-family nor the openSUSE
package set the container script installs. An oracle
that cannot answer is a failure here, never a skip: a skipped check that reads as
a pass is the disease being treated.

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
safety, and both plugins' finding-id conventions against fixtures. `jq` is the
only external command it needs.

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
against is counted off `SSH_CHECKS_EXPECTED`, `LOGIN_DEFS_CHECKS_EXPECTED`,
`VENDOR_SURVIVAL_CHECKS_EXPECTED`, `IDEMPOTENCE_CHECKS_EXPECTED` and
`DIFF_PLUGINS_EXPECTED`, which the tables are then checked against, rather than
off the tables themselves.

Adding a directive therefore means changing four literals in
`scripts/test/differential-suite.sh`, not one: the `*_EXPECTED` constant beside
its table, that same length re-pinned in the self-test (`the ssh table holds
seven directives`), the total the run is sized at (`28`), and the number of
directives the pre-apply control covers (`10`). `VENDOR_SURVIVAL_CHECKS` and
`IDEMPOTENCE_CHECKS` are sized the same way, and contribute one check each
rather than two. Every one of them fails loudly, over two `--self-test` runs,
because the total is counted off the constant and only moves once the constant
has been raised. Adding the idempotency table did exactly that: the self-test
refused the run at `got '28', want '25'` until the literal was raised on
purpose.

### What a failure means

A failure means the operating system disagrees with what the tool reported, or
that an oracle could not be read. Neither is a flaky test: a disagreement is a
product defect and is exactly what this suite exists to find, and an oracle that
cannot answer leaves a directive unproven, which is recorded as a failure rather
than skipped. Each `FAIL` line names the directive, and where the two disagree,
the value the system holds and the value the tool targeted:

- `the system holds 'X' but the tool targets 'Y'`: `apply` did not take effect.
- `the tool claims a compliance the system does not have`: `scan` reported
  nothing while the system holds something other than the target. This is the
  shape of the `login.defs` defect.
- `the tool reports N finding(s) ... while the system holds the target value`:
  `scan` is flagging a host that is in fact compliant.
- `the tool did not check '<id>'`: the id came back in the `unchecked` array.
  The tool verified nothing for that directive, which is neither agreement with
  the system nor a contradiction of it, and the usual cause is a config file the
  scan could not read.
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

Produces three release tarballs and creates a GitHub release.

**Last Updated**: 2026-07-28
