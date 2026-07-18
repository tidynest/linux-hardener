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
sudo ./scripts/create-container.sh arch              # Create container
sudo ./scripts/create-container.sh arch enter         # Enter existing container interactively
sudo ./scripts/create-container.sh arch clean         # Remove container completely
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
sudo ./scripts/boot-ssh-test-container.sh            # boot hardener-test with --network-veth, inject test key
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
sudo ./scripts/root-test-suite.sh                    # Read-only tests only
sudo ./scripts/root-test-suite.sh --apply             # Include destructive apply + rollback tests
```

Tests hardener operations that require root: scanning as root, checkpoint creation, plugin apply/rollback.

Without `--apply`: only tests scanning and checkpoint operations (non-destructive).
With `--apply`: also tests applying hardening changes and rolling them back (modifies system config files, then restores them).

### Full test suite (comprehensive, 26 sections)

```bash
sudo ./scripts/full-test-suite.sh                     # Sections 1-12, 17-26 (no apply)
sudo ./scripts/full-test-suite.sh --apply              # All 26 sections including apply and rollback
```

More thorough than `root-test-suite.sh`. Covers CLI argument parsing, every plugin's scan output, checkpoint lifecycle, compliance reports, daemon commands, systemd integration, history commands, and per-plugin apply/rollback cycles.

Without `--apply`: skips sections 13-16 (per-plugin apply and rollback).
With `--apply`: runs all 26 sections including destructive per-plugin lifecycle testing.

### Rollback verification

```bash
sudo ./scripts/verify-rollback.sh
```

Runs 5 targeted tests that verify checkpoint creation, apply, and rollback produce the expected system state. Must be run inside a container.

### Manual verification

```bash
sudo ./scripts/manual-verification-test.sh
```

Interactive step-by-step test with pauses between operations. Designed for manually inspecting system state at each stage. Must be run inside a container.

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
sudo ./scripts/run-cross-distro-tests.sh              # Read-only, all distros
sudo ./scripts/run-cross-distro-tests.sh --apply       # Destructive, all distros
```

Iterates through all 5 container types (Arch, Debian, Fedora, Rocky, openSUSE), copies the musl binary into each, and runs the full test suite.

### Single distribution

```bash
sudo ./scripts/run-cross-distro-tests.sh --distro arch
sudo ./scripts/run-cross-distro-tests.sh --distro debian
sudo ./scripts/run-cross-distro-tests.sh --distro fedora
sudo ./scripts/run-cross-distro-tests.sh --distro rhel
sudo ./scripts/run-cross-distro-tests.sh --distro opensuse
```

### With GUI tests

```bash
sudo ./scripts/run-cross-distro-tests.sh --apply --gui
```

Runs CLI tests plus Playwright GUI tests inside each container.

### Rebuild binary first

```bash
sudo ./scripts/run-cross-distro-tests.sh --rebuild
```

Recompiles the musl binary (`x86_64-unknown-linux-musl/release/hardener` under the resolved cargo target directory) before copying it into containers. Use this after code changes.

Test results are written to `test-results/<distro>.log`.

---

## GUI Tests

### Web UI tests (Playwright, all distros)

```bash
sudo ./scripts/run-gui-tests.sh                       # All distro containers
sudo ./scripts/run-gui-tests.sh --distro arch          # Arch container only
sudo ./scripts/run-gui-tests.sh --distro debian        # Debian container only
```

Orchestrates Playwright tests inside nspawn containers with Xvfb (virtual display). Tests the Leptos web frontend served by Trunk.

Uses `scripts/gui-test-inner.sh` internally (the script that runs inside the container).

### Tauri desktop GUI tests (Arch only)

```bash
sudo ./scripts/run-tauri-gui-tests.sh
```

Tests the native Tauri desktop application using xdotool for window interaction. Runs inside the Arch container (`hardener-test`).

Uses `scripts/tauri-gui-test-inner.sh` internally.

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

### release.yml (on tags matching `v*.*.*`)

```bash
cargo test --workspace
cargo build --release --target x86_64-unknown-linux-gnu -p hardener-cli
cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli
cargo build --release --target aarch64-unknown-linux-gnu -p hardener-cli
```

Produces three release tarballs and creates a GitHub release.

**Last Updated**: 2026-07-18
