# Project Scripts

**Last Updated**: 2026-08-01

This directory contains utility scripts for the Linux Hardening Tool project.

## Directory Layout

| Subdirectory | Contents |
|--------------|----------|
| `containers/` | systemd-nspawn container lifecycle: `create-container.sh` (all five distros), `boot-ssh-test-container.sh` (booted SSH fixture) |
| `test/` | Host-side test suites and orchestrators: cross-distro, package-install, root/full suites, desktop tests, rollback verification, parallel runner |
| `test/gui/` | GUI test runners and inner scripts (Web UI and Tauri desktop), plus the host desktop UX/functional suites |
| `test/polkit/` | Polkit authentication matrix tests and agent detection helper |
| `validate/` | Documentation and naming validators (`validate_*.py`) plus the auto-updater `update_all_docs.py` |
| `release/` | `release.sh` (version bumping, changelog, release gate) |
| `dev/` | `tauri-dev.sh` (Tauri development launcher) |
| `badges/` | `generate.js` (regenerates the README status badges as local SVGs under `docs/assets/badges/`, using shields.io's renderer offline) plus the vendored logo glyphs |
| `lib/` | Shared shell helpers sourced by the test scripts: `common.sh` (logging, colours, guards) and `parallel.sh` (job control for `--parallel`) |

`build_identity.rs` stays at the `scripts/` root: it is referenced as a
`build =` script by both `crates/hardener-cli/Cargo.toml` and
`crates/hardener-ui/Cargo.toml`.

## Quick Reference

| Task | Command |
|------|---------|
| **Start Tauri dev** | `./scripts/dev/tauri-dev.sh` |
| **Validate all docs** | `./scripts/validate/validate_all.py` |
| **Quick validation** | `./scripts/validate/validate_all.py --quick` |
| **Auto-fix docs** | `./scripts/validate/update_all_docs.py --apply` |
| **Check naming** | `./scripts/validate/validate_naming.py` |
| **Verify versions** | `./scripts/release/release.sh --verify` |
| **Dry-run release** | `./scripts/release/release.sh patch --dry-run` |
| **Actual release** | `./scripts/release/release.sh patch` |
| **Create test container (Arch)** | `sudo ./scripts/containers/create-container.sh arch` |
| **Enter test container** | `sudo ./scripts/containers/create-container.sh arch enter` |
| **Create Debian container** | `sudo ./scripts/containers/create-container.sh debian` |
| **Create Fedora container** | `sudo ./scripts/containers/create-container.sh fedora` |
| **Create openSUSE container** | `sudo ./scripts/containers/create-container.sh opensuse` |
| **Create Rocky 10 container** | `sudo ./scripts/containers/create-container.sh rhel` |
| **Verify rollback** | `sudo ./scripts/test/verify-rollback.sh` |
| **Run root tests** | `sudo ./scripts/test/root-test-suite.sh` |
| **Run root tests (full)** | `sudo ./scripts/test/root-test-suite.sh --apply` |
| **Full test suite** | `sudo ./scripts/test/full-test-suite.sh` |
| **Manual verification** | `sudo ./scripts/test/manual-verification-test.sh` |
| **Cross-distro tests** | `sudo ./scripts/test/run-cross-distro-tests.sh --apply` |
| **Cross-distro + GUI** | `sudo ./scripts/test/run-cross-distro-tests.sh --apply --gui` |
| **Single distro test** | `sudo ./scripts/test/run-cross-distro-tests.sh --distro arch` |
| **GUI tests (Web UI)** | `sudo ./scripts/test/gui/run-gui-tests.sh` |
| **Tauri GUI tests** | `sudo ./scripts/test/gui/run-tauri-gui-tests.sh` |
| **Desktop tests (host)** | `./scripts/test/run-desktop-tests.sh` |
| **PARALLEL: All tests** | `sudo ./scripts/test/run-all-tests-parallel.sh --apply` |
| **PARALLEL: All + desktop** | `sudo ./scripts/test/run-all-tests-parallel.sh --apply --desktop` |
| **PARALLEL: All + kitty** | `sudo ./scripts/test/run-all-tests-parallel.sh --apply --kitty` |
| **PARALLEL: CLI only** | `sudo ./scripts/test/run-cross-distro-tests.sh --parallel --apply` |
| **PARALLEL: GUI only** | `sudo ./scripts/test/gui/run-gui-tests.sh --parallel` |
| **Package install tests** | `sudo ./scripts/test/run-package-tests.sh` |
| **Single distro pkg test** | `sudo ./scripts/test/run-package-tests.sh --distro arch` |

---

## Cargo Target Directory Resolution

The host-side runners (`run-cross-distro-tests.sh`, `run-package-tests.sh`,
`run-tauri-gui-tests.sh`, `run-desktop-tests.sh`, `test-polkit-matrix.sh`,
`test-polkit.sh` in no-agent mode) do not assume binaries live under `./target`. All
of them source the shared `resolve_target_dir` function from `scripts/lib/common.sh`
(via a `$SCRIPT_DIR`-relative path, `../lib/` or `../../lib/` depending on the
caller's depth). In-container scripts that also need it (`test-package-install.sh`)
source it the same way, resolving under the `/project` bind mount, since the
container runners bind-mount the whole repository there. The function resolves, in
order:

1. `$CARGO_TARGET_DIR`, if set.
2. `cargo metadata` → `target_directory` (honours `[build] target-dir` in
   `~/.cargo/config.toml`), when cargo is on `PATH`.
3. `./target`; if the wanted binary is absent there but present under the
   invoking user's `~/.cache/cargo-target` (via `$SUDO_USER` under sudo), the
   cache directory is used.

Musl artefacts (`x86_64-unknown-linux-musl/release/...`) resolve from the same
root. When the resolved directory is not `./target`, the container runners
bind-mount it read-only at `/project/target`, so in-container scripts
(`full-test-suite.sh`, `test-package-install.sh`, `tauri-gui-test-inner.sh`,
`verify-rollback.sh`, `root-test-suite.sh`, `manual-verification-test.sh`) keep
their documented `/project/target/...` paths unchanged.

---

## Tauri Development Launcher

**Script**: `tauri-dev.sh`

**Purpose**: Bulletproof Tauri dev server launcher for Arch Linux + Hyprland + NVIDIA. Automatically detects session type and applies WebKitGTK workarounds to prevent blank windows and crashes.

**Usage**:
```bash
# Standard launch
./scripts/dev/tauri-dev.sh

# Pass additional arguments to cargo tauri dev
./scripts/dev/tauri-dev.sh --release
```

**What It Does**:

1. **Session Detection**: Identifies Wayland/X11/Hyprland environment
2. **NVIDIA Workaround**: Sets `WEBKIT_DISABLE_DMABUF_RENDERER=1` if NVIDIA GPU detected
3. **Hyprland Workaround**: Sets `WEBKIT_DISABLE_COMPOSITING_MODE=1` for Hyprland sessions
4. **Pre-flight Checks**:
   - Verifies `webkit2gtk-4.1` and `librsvg` packages installed
   - Ensures `wasm32-unknown-unknown` target available
   - Kills existing processes on port 1420
   - Terminates lingering app processes

**Environment Variables Set**:
| Variable | Condition | Purpose |
|----------|-----------|---------|
| `WEBKIT_DISABLE_DMABUF_RENDERER=1` | NVIDIA GPU detected | Fixes blank window on NVIDIA+Wayland |
| `WEBKIT_DISABLE_COMPOSITING_MODE=1` | Hyprland session | Fixes resize crashes in Hyprland |
| `RUST_BACKTRACE=1` | Always | Better error messages |
| `RUST_LOG=info` | Default (overridable) | Logging level |

**When To Use**:
- Always use this script instead of raw `cargo tauri dev` on Wayland systems
- Essential for NVIDIA GPU users on Wayland
- Required for Hyprland window manager

**Manual Alternative** (if script unavailable):
```bash
WEBKIT_DISABLE_COMPOSITING_MODE=1 cargo tauri dev
```

**Exit Codes**:
- `0`: Dev server exited normally
- `1`: Pre-flight check failed (missing package, etc.)

**Dependencies**:
- Bash
- `lspci` or `nvidia-smi` (for GPU detection)
- `pacman` (for package verification)
- `lsof` (for port conflict detection)

---

## Master Validation Script

**Script**: `validate_all.py`

**Purpose**: Runs all documentation validators in one go and provides a unified summary.

**Usage**:
```bash
# Run all validations
./scripts/validate/validate_all.py

# Auto-fix issues where possible
./scripts/validate/validate_all.py --fix

# Quick mode (skip slower checks)
./scripts/validate/validate_all.py --quick
```

**What It Runs**:
| Validator | Script | Description |
|-----------|--------|-------------|
| Version Synchronisation | `release.sh --verify` | Checks version numbers match |
| file-map.md Completeness | `validate_file_map.py` | All source files documented |
| Plugin Documentation | `validate_plugin_docs.py` | Plugin tables match source |
| Tauri Commands | `validate_tauri_docs.py` | Tauri commands documented |
| Last Updated Dates | `validate_last_updated.py` | Dates current with git |
| Doc Comment Attachment | `validate_doc_attachment.py` | No `///` block silently reassigned to the following item |
| File Creation Sites | `validate_write_sites.py` | Every file-creating plugin call site carries a written reason its parent directory exists, and a written answer to whether a rollback reaches what it creates; every literal `cp` copies with both `-p` and `--no-dereference` |
| Unit State Reads | `validate_unit_state_reads.py` | Every `systemctl is-enabled` call site says whether it judges systemd's word or its exit status, and why, with the answer cross-checked against the code |
| Doc Sync Targets | `validate_doc_targets.py` | The updater's declared targets and the tree agree in both directions. Forward: every target it declares resolves, the file exists and the pattern matches something, because a target matching nothing is skipped silently and the run reports success for work it never attempted. Inverse: no markdown file outside an archive carries a version line without being a declared target, because a list of files to rewrite cannot notice a file that should be on it |
| Badges | `validate_badges.py` | Every badge under `docs/assets/badges/` renders the label and message `scripts/badges/generate.js` declares for it, so the documented regeneration step cannot silently revert a hand-edited SVG; the `aur`, `version` and `rust` badges are additionally compared against `packaging/PKGBUILD`, and against `Cargo.toml`'s `version` and `rust-version`, which are the authorities for them |
| Policy Exception Sites | `validate_policy_exception_sites.py` | Every scan finding that hardcodes `finding_policy_exception: None` carries a comment saying why, because a `None` fails a compliance control on a deviation the operator wrote down and approved, and counting the sites cannot tell an oversight from a decision |
| CHANGELOG Headings | `validate_changelog_headings.py` | No release entry repeats a change-type heading. A second `### Fixed` under one version hides its own entries from a reader who found the first, and splits a release's published notes between two identical headings on no principle. Compared on the exact heading text, so `### Added (Testing Infrastructure)` beside `### Fixed (GUI Tests)` is two sections rather than a duplicate pair |
| .SRCINFO | `validate_srcinfo.py` | `packaging/.SRCINFO` says what `packaging/PKGBUILD` declares. The AUR reads only `.SRCINFO`, so a stale one describes a package that is not the one it builds; it had fallen three releases behind. Compared field by field always, and byte for byte against a fresh `makepkg --printsrcinfo` where `makepkg` exists |
| Test Assertions | `validate_test_assertions.py` | Every test reaches an assertion on every path through its body. An assertion buried inside an `if` with no `else`, or inside a loop over a computed collection, does not run when the condition does not hold, so the test exits 0 having checked nothing and still counts towards the suite total. A `match` whose every arm asserts, an `if`/`else` chain that ends in a bare `else` with every branch asserting, and a `for` over an array literal written at the site all satisfy it, because none of those can be skipped |
| CLI Documentation | `validate_cli_docs.py` | CLI commands documented |
| Compliance Frameworks | `validate_compliance_docs.py` | Framework list matches enum |

**Modes**:
- Default: Runs all 16 validators
- `--quick`: Skips CLI and Compliance validators (faster)
- `--fix`: Passes `--fix` to validators that support it

**Exit Codes**:
- `0`: All validations passed
- `1`: One or more validations failed

**Example Output**:
```
############################################################
#  Linux System Hardener - Documentation Validator         #
############################################################

============================================================
Running: Version Synchronisation
============================================================
...

############################################################
#  Summary                                                 #
############################################################

  ✓ Version Synchronisation: passed
  ✓ file-map.md Completeness: passed
  ✓ Plugin Documentation: passed
  ✓ Tauri Command Documentation: passed
  ✓ Last Updated Dates: passed
  ✓ Doc Comment Attachment: passed
  ✓ CLI Documentation: passed
  ✓ Compliance Framework List: passed

All 16 validations passed!
```

**Integration with CI/CD**:
```yaml
- name: Validate Documentation
  run: ./scripts/validate/validate_all.py
```

**Dependencies**:
- Python 3.9+
- Bash (for release.sh)
- Git (for date validation)

---

## Naming Convention Validator

**Script**: `validate_naming.py`

**Purpose**: Validates that all Rust code follows the naming conventions defined in `docs/reference/naming-conventions.md`

**Usage**:
```bash
# Run from project root
./scripts/validate/validate_naming.py

# Or with python3 explicitly
python3 scripts/validate/validate_naming.py
```

**What It Checks**:
- ✅ Struct names use PascalCase
- ✅ Enum names use PascalCase
- ✅ Trait names use PascalCase (and don't end with "Trait")
- ✅ Function names use snake_case
- ✅ Constant names use SCREAMING_SNAKE_CASE
- ✅ No forbidden abbreviations (mgr, ctx, cfg, cmd, etc.)
- ✅ British English spellings (authorise, colour, organisation)

**Exit Codes**:
- `0`: All naming conventions validated successfully
- `1`: Naming convention errors found

**Example Output**:
```
🔍 Validating naming conventions...

❌ Found 2 naming convention error(s):

  crates/hardener-core/src/plugin.rs:45
    [Function Name] Function 'scanSystem' should use snake_case
    Suggestion: scan_system

  crates/hardener-plugins/src/kernel/mod.rs:12
    [Constant Name] Constant 'KernelParams' should use SCREAMING_SNAKE_CASE
    Suggestion: KERNEL_PARAMS

⚠️  Found 1 naming convention warning(s):

  crates/hardener-core/src/context.rs:78
    [Abbreviation] Avoid abbreviation 'ctx'
    Suggestion: Use 'context' instead

Summary: 2 errors, 1 warnings

Refer to docs/reference/naming-conventions.md for complete naming standards.
```

**Integration with CI/CD**:

This script can be added to CI/CD pipeline to enforce naming conventions.

Example GitHub Actions workflow:
```yaml
- name: Validate Naming Conventions
  run: ./scripts/validate/validate_naming.py
```

**Dependencies**:
- Python 3.7+
- No external packages required (uses standard library only)

---

## Pre-Commit Hook

**File**: `.git/hooks/pre-commit`

**Purpose**: Automatically validates naming conventions before allowing commits

**Setup**:

Nothing in this repository installs the hook, so a fresh clone does not have one and runs no naming validation on commit. To add it by hand:

```bash
printf '#!/bin/sh\nexec ./scripts/validate/validate_naming.py\n' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Once installed it runs on every `git commit` command. Until then, run `./scripts/validate/validate_naming.py` yourself.

**How It Works**:

1. When you run `git commit`, the hook executes automatically
2. It runs `./scripts/validate/validate_naming.py` to check naming conventions
3. If validation passes (0 errors): commit proceeds ✅
4. If validation fails (errors found): commit is blocked ❌

**Example Output (Passing)**:
```bash
$ git commit -m "Add PAM plugin structure"
🔍 Running pre-commit checks...

📋 Validating naming conventions...
🔍 Validating naming conventions...

✅ All naming conventions validated successfully!

✅ All pre-commit checks passed!

[main a1b2c3d] Add PAM plugin structure
 3 files changed, 150 insertions(+)
```

**Example Output (Failing)**:
```bash
$ git commit -m "Add PAM plugin"
🔍 Running pre-commit checks...

📋 Validating naming conventions...
🔍 Validating naming conventions...

❌ Found 2 naming convention error(s):

  crates/hardener-plugins/src/pam/mod.rs:15
    [Struct Name] Struct 'pamPlugin' should use PascalCase
    Suggestion: PamPlugin

❌ Pre-commit checks failed!

Naming convention errors found.
Please fix the issues above before committing.

Refer to docs/reference/naming-conventions.md for naming standards.

To commit anyway (not recommended), use: git commit --no-verify
```

**Bypassing the Hook**:

If you absolutely need to commit without validation (not recommended):
```bash
git commit --no-verify -m "Your message"
```

**Disabling the Hook**:

To temporarily disable:
```bash
# Rename the hook
mv .git/hooks/pre-commit .git/hooks/pre-commit.disabled

# Re-enable later
mv .git/hooks/pre-commit.disabled .git/hooks/pre-commit
```

**Customisation**:

The pre-commit hook can be extended to run additional checks:
- `cargo fmt --check` - Verify formatting
- `cargo clippy` - Lint checks
- `cargo test` - Run tests (may be slow)

Edit `.git/hooks/pre-commit` to add more checks.

---

## Release Script

**Script**: `release.sh`

**Purpose**: Automates the version bump and release process

**Usage**:
```bash
# Dry run (shows what would happen without making changes)
./scripts/release/release.sh patch --dry-run
./scripts/release/release.sh minor --dry-run
./scripts/release/release.sh major --dry-run

# Actual release
./scripts/release/release.sh patch   # 0.1.0 -> 0.1.1
./scripts/release/release.sh minor   # 0.1.0 -> 0.2.0
./scripts/release/release.sh major   # 0.1.0 -> 1.0.0
```

**What It Does**:
1. Validates you're on the `main` branch with clean working directory
2. Runs cargo test and clippy
3. Updates version in Cargo.toml
4. Updates CHANGELOG.md with new version section
5. Creates git commit and tag
6. Pushes to GitHub and GitLab remotes

**Exit Codes**:
- `0`: Release completed successfully
- `1`: Error (wrong branch, dirty working directory, tests failed)

For complete release documentation, see [docs/contributing/releasing.md](../docs/contributing/releasing.md).

---

## File Map Validator

**Script**: `validate_file_map.py`

**Purpose**: Validates that `docs/reference/file-map.md` accurately reflects all Rust source files in the workspace.

**Usage**:
```bash
# Run from project root
./scripts/validate/validate_file_map.py

# Generate stub entries for missing files
./scripts/validate/validate_file_map.py --fix
```

**What It Checks**:
- All `.rs` files in `crates/` and `src-tauri/src/` are documented
- No deleted files remain documented in file-map.md
- Files are listed under their correct crate sections
- A description claiming "N tests" agrees with the file it describes, counted
  from its `#[test]` and `#[tokio::test]` declarations

**Exit Codes**:
- `0`: file-map.md is complete and accurate
- `1`: Discrepancies found (missing or extra files, or a test count the source
  does not support)

**Example Output (Discrepancies Found)**:
```
Validating file-map.md completeness...

Files missing from file-map.md (3):

  hardener-state:
    - crates/hardener-state/src/scan_history.rs
    - crates/hardener-state/src/scan_manager.rs

  hardener-ui:
    - crates/hardener-ui/src/components/tabs.rs

file-map.md validation failed

Run with --fix to generate stub entries for missing files.
```

**Example Output (--fix mode)**:
```
Suggested stub entries:

# Add to hardener-state section:
| `crates/hardener-state/src/scan_history.rs` | Scan History | Implemented |
| `crates/hardener-state/src/scan_manager.rs` | Scan Manager | Implemented |
```

**Exclusions**:
- Shared test utilities (`/tests/common/`) are excluded; test files themselves are NOT
- Build artifacts (`/target/`) are excluded

**Dependencies**:
- Python 3.9+
- No external packages required (uses standard library only)

---

## Plugin Documentation Validator

**Script**: `validate_plugin_docs.py`

**Purpose**: Validates that plugin documentation in README.md and architecture.md matches actual plugin implementations in source code.

**Usage**:
```bash
# Run from project root
./scripts/validate/validate_plugin_docs.py
```

**What It Checks**:
- All plugins in source code are documented in README.md
- All plugins in source code are documented in architecture.md
- Plugin registry contains all implemented plugins
- No stale/removed plugins remain in documentation

**Exit Codes**:
- `0`: All plugin documentation is accurate
- `1`: Discrepancies found

**Example Output (Discrepancies Found)**:
```
Validating plugin documentation...

Found 8 plugins in source code:
  - Audit Rules Hardening (audit-hardening)
  - Kernel Hardening (kernel-hardening)
  ...

Checking README.md...
  Missing from README.md:
    - New Plugin Name
  Extra in README.md (not in source):
    - Deleted Plugin Name

Checking docs/architecture/architecture.md...
  ✓ All 8 plugins documented

Checking plugin registry...
  ✓ Registry has all 8 plugins

Plugin documentation validation failed
```

**Source of Truth**:
- Plugin metadata is extracted from `crates/hardener-plugins/src/*/mod.rs`
- Each plugin's `metadata()` function defines the canonical name and ID

**Dependencies**:
- Python 3.9+
- No external packages required (uses standard library only)

---

## CLI Documentation Validator

**Script**: `validate_cli_docs.py`

**Purpose**: Validates that CLI documentation in README.md matches the actual CLI implementation in `cli.rs`.

**Usage**:
```bash
# Run from project root
./scripts/validate/validate_cli_docs.py
```

**What It Checks**:
- All CLI commands have examples in README.md
- All subcommands have examples
- Key global flags (--ssh, --config, --format, etc.) are demonstrated

**Exit Codes**:
- `0`: All CLI documentation is complete (or only warnings)
- `1`: Missing command documentation (errors found)

**Example Output**:
```
Validating CLI documentation...

Found 9 commands in cli.rs:
  - apply
  - checkpoint (list, create, delete, show)
  - daemon (start, run-once, status)
  ...

Found 8 global flags:
  --config
  --format
  --ssh
  ...

Checking command documentation...
  Commands missing from README.md:
    - history
  Documented: 8/9

Checking subcommand documentation...
  ✓ All subcommands have examples

Checking global flag documentation...
  ✓ All key global flags documented

CLI documentation validation failed
```

**Source of Truth**:
- Commands parsed from `crates/hardener-cli/src/cli.rs`
- Clap derive macros define the canonical command structure

**Dependencies**:
- Python 3.9+
- No external packages required (uses standard library only)

---

## Compliance Documentation Validator

**Script**: `validate_compliance_docs.py`

**Purpose**: Validates that every framework in the `ComplianceFramework` enum (the source of truth) is listed in the documentation framework tables.

**Usage**:
```bash
# Run from project root
./scripts/validate/validate_compliance_docs.py
```

**What It Checks**:
- Every `ComplianceFramework` enum variant appears in the architecture.md framework table
- The same for the docs/ROADMAP.md framework table
- Per-control *counts* are no longer statically validated: post-rework the control catalogues are split between curated files (`cis.rs`, `iso27001.rs`) and plugin-declared coverage aggregated at runtime, so a static count is not meaningful here

**Exit Codes**:
- `0`: every enum framework is documented in each table
- `1`: drift between the enum and the docs

**Example Output**:
```
Validating compliance framework documentation...

Found 7 frameworks in ComplianceFramework enum: CIS, HIPAA, ISO27001, NIST, PCIDSS, STIG, GDPR

Checking docs/architecture/architecture.md...
  ✓ All 7 frameworks documented

Checking docs/ROADMAP.md...
  ✓ All 7 frameworks documented

All compliance documentation is accurate
```

**Source of Truth**:
- The `ComplianceFramework` enum in `crates/hardener-types/src/lib.rs`

**Dependencies**:
- Python 3.9+
- No external packages required (uses standard library only)

---

## Tauri Command Validator

**Script**: `validate_tauri_docs.py`

**Purpose**: Validates that Tauri command documentation in file-map.md matches actual implementations in `commands.rs`, and that frontend bindings call valid commands.

**Usage**:
```bash
# Run from project root
./scripts/validate/validate_tauri_docs.py
```

**What It Checks**:
- All `#[tauri::command]` functions in `src-tauri/src/commands.rs` are documented in file-map.md
- Command signatures (arguments, return types) match between source and documentation
- All `invoke_command()` calls in `tauri_bindings.rs` reference valid command names

**Exit Codes**:
- `0`: All Tauri commands are documented correctly
- `1`: Discrepancies found

**Example Output**:
```
Validating Tauri command documentation...

Found 6 Tauri commands in commands.rs:
  - generate_compliance_report(frameworks: Vec<String>) -> Vec<ComplianceReport>
  - get_checkpoints() -> Vec<CheckpointInfo>
  - run_scan() -> Vec<ScanResult>
  ...

Checking file-map.md documentation...
  ✓ All 6 commands documented correctly

Checking tauri_bindings.rs invoke calls...
  ✓ All 3 bindings call valid commands

All Tauri command documentation is accurate
```

**Example Output (Discrepancies Found)**:
```
Checking file-map.md documentation...
  Commands missing from file-map.md:
    - new_command
  Signature mismatches:
    - run_scan: return type differs (source: Vec<ScanResult>, doc: ScanResult)

Checking tauri_bindings.rs invoke calls...
  Invalid command invocations:
    - scan_system() calls 'scan_system' which doesn't exist in commands.rs

Tauri command validation failed
```

**Dependencies**:
- Python 3.9+
- No external packages required (uses standard library only)

---

## Documentation Auto-Updater

**Script**: `update_all_docs.py`

**Purpose**: Automatically updates documentation files with data from source code. Safe, idempotent updates that won't break prose.

**Usage**:
```bash
# Preview changes (dry-run)
./scripts/validate/update_all_docs.py

# Apply changes
./scripts/validate/update_all_docs.py --apply
```

**What It Auto-Fixes**:
| Category | Action |
|----------|--------|
| Last Updated dates | Syncs to git commit dates |
| file-map.md | Adds stub entries for new source files |
| Compliance counts | Updates framework control counts |
| Tauri signatures | Regenerates command signatures |
| Version references | Syncs to Cargo.toml version |

**What It Cannot Fix** (requires manual attention):
- Plugin names and descriptions in README.md
- CLI command examples and explanations
- Architecture prose and design docs
- Removing stale/deleted entries

**Integration with release.sh**:

This script is automatically called during the release process:
```
release.sh
  ├── Step 2b: update_all_docs.py --apply
  └── Step 2c: validate_all.py --quick
```

If validation fails after auto-update, you'll be prompted to continue or abort.

**Exit Codes**:
- `0`: All updates successful
- `1`: Manual fixes needed (see output)

**Example Output**:
```
############################################################
#  Documentation Auto-Updater                              #
############################################################

Running in preview mode (use --apply to write changes)

Updating Last Updated dates...
  ✓ Would update: docs/architecture/architecture.md: 2025-12-01 → 2025-12-06

Checking file-map.md for missing files...
  ✓ Would update: Added stub for crates/hardener-state/src/new_file.rs

Updating compliance framework counts...
  ✓ Would update: architecture.md: CIS → 38

Checking for issues requiring manual attention...
  ! Manual fix needed: Plugin 'New Plugin' missing from README.md

Summary: 3 pending updates, 1 manual fix needed
```

**Dependencies**:
- Python 3.9+
- Git (for date lookup)

---

## Last Updated Date Validator

**Script**: `validate_last_updated.py`

**Purpose**: Validates that "Last Updated" dates in markdown files are current with git history, and can auto-fix stale dates.

**Usage**:
```bash
# Check for stale dates
./scripts/validate/validate_last_updated.py

# Auto-fix stale dates
./scripts/validate/validate_last_updated.py --fix
```

**What It Checks**:
- Scans all `.md` files in project root, `docs/`, and `scripts/`
- Compares documented "Last Updated" date against git commit history
- Flags dates that are more than 7 days older than last git modification
- Reports files missing "Last Updated" dates (warning only)

**Supported Date Formats**:
```markdown
**Last Updated**: 2026-07-02
*Last Updated*: 2025-12-06
Last Updated: 2025-12-06
```

**Exit Codes**:
- `0`: All dates are current (or only missing dates, which are warnings)
- `1`: Stale dates found (unless --fix is used)

**Example Output**:
```
Validating 'Last Updated' dates in markdown files...

Found 15 markdown files to check

Current files (2):
  ✓ docs/reference/naming-conventions.md: 2025-12-04
  ✓ scripts/README.md: 2025-12-06

Files without 'Last Updated' date (13):
  - README.md
  - docs/ROADMAP.md
  ...

Warning: 13 file(s) missing 'Last Updated' date
```

**Example Output (Stale Dates)**:
```
Stale dates found (2):
  ✗ docs/architecture/architecture.md
      Documented: 2025-11-15
      Git shows:  2025-12-06 (21 days newer)

Run with --fix to update stale dates automatically
```

**Dependencies**:
- Python 3.9+
- Git (for commit history lookup)
- No external packages required

---

## Safe Root Testing Infrastructure

Three scripts for comprehensive root-level testing in isolated containers.

### Why Isolated Testing?

The hardener modifies critical system files (`/etc/sysctl.conf`, `/etc/ssh/sshd_config`, firewall rules, etc.). Testing these operations on a real system risks:
- Breaking SSH access
- Locking yourself out
- Misconfiguring services

**Solution**: Use a systemd-nspawn container that provides complete isolation with full systemd support.

---

### Test Container Creator

**Script**: `create-container.sh`

**Purpose**: Creates and manages the isolated systemd-nspawn test containers for all five supported distributions. The distro is the first argument; the Arch container is the primary one used by most suites.

**Usage**:
```bash
# Create Arch container (one-time, ~2-3 minutes)
sudo ./scripts/containers/create-container.sh arch

# Enter existing container
sudo ./scripts/containers/create-container.sh arch enter

# Clean up container
sudo ./scripts/containers/create-container.sh arch clean

# Clean up without the confirmation prompt
sudo ./scripts/containers/create-container.sh arch clean --no-confirm
```

**Options**: `--no-confirm` answers the `clean` deletion prompt with yes, and may appear in any argument position. It exists for the recreate-then-measure loop: a measurement taken against a container that survived the loop is not a baseline, and five prompts in a row is where that gets skipped. Any other unrecognised option is refused rather than ignored, so a mistyped flag cannot leave the loop waiting on a keypress.

**What It Does**:
1. Creates an Arch Linux rootfs at `/var/lib/machines/hardener-test`
2. Installs required packages (`openssh`, `audit`, `ufw`, `nftables`)
3. Configures test users (`root:test`, `testuser:test` with passwordless sudo)
4. Bind-mounts project at `/project` for testing pre-built binaries

**Container Features**:
| Feature | Value |
|---------|-------|
| Location | `/var/lib/machines/hardener-test` |
| Root password | `test` |
| Test user | `testuser` / `test` |
| Project mount | `/project` (read-write) |
| Systemd | Full support (unlike Docker) |

**Exit Codes**:
- `0`: Operation completed successfully
- `1`: Error (missing permissions, package install failed)

**Dependencies**:
- `systemd-nspawn` (part of systemd)
- `pacstrap` (Arch Linux only)
- Root privileges

---

### Distribution Containers

`create-container.sh` covers all five distributions used for cross-distribution validation; the per-distro bootstrap mechanics differ:

| Distro argument | Distribution | Package Manager |
|-----------------|--------------|-----------------|
| `arch` | Arch Linux | pacman (pacstrap) |
| `debian` | Debian 13 (Trixie) | apt/debootstrap |
| `fedora` | Fedora 44 | podman export |
| `rhel` | Rocky Linux 10 | podman export |
| `opensuse` | openSUSE Leap 16.0 | podman export |

**Usage** (same pattern for all):
```bash
# Create container
sudo ./scripts/containers/create-container.sh <distro>

# Enter container
sudo ./scripts/containers/create-container.sh <distro> enter

# Clean up
sudo ./scripts/containers/create-container.sh <distro> clean

# Recreate all five for a clean baseline, no prompts
for d in arch debian fedora rhel opensuse; do
    sudo ./scripts/containers/create-container.sh "$d" clean --no-confirm
    sudo ./scripts/containers/create-container.sh "$d" || { echo "CREATE FAILED: $d"; break; }
done
```

**Container Locations**:
| Distribution | Location |
|--------------|----------|
| Arch | `/var/lib/machines/hardener-test` |
| Debian | `/var/lib/machines/hardener-test-debian` |
| Fedora | `/var/lib/machines/hardener-test-fedora` |
| RHEL/Rocky | `/var/lib/machines/hardener-test-rhel` |
| openSUSE | `/var/lib/machines/hardener-test-opensuse` |

> **Note:** The RHEL/Rocky container is optional - Fedora validation covers the entire Red Hat family.

**Key Differences by Family**:
| Feature | Arch | Debian | Red Hat | SUSE |
|---------|------|--------|---------|------|
| Firewall | ufw | ufw | firewalld | firewalld |
| MAC | AppArmor (optional) | AppArmor | SELinux | AppArmor |
| Bootstrap tool | pacstrap | debootstrap | podman export | podman export |
| Covers | Manjaro, EndeavourOS | Ubuntu, Mint, Pop!_OS | RHEL, CentOS, Rocky | SLES |

All containers:
- Include required packages (openssh, audit, firewall tools, etc.)
- Have test users configured (`root:test`, `testuser:test`)
- Bind-mount project at `/project`
- Provide full systemd support

---

### Rocky Linux Container

**Script**: `create-container.sh rhel`

**Purpose**: Creates a Rocky Linux 10 container for cross-distro testing. Uses `podman export` from the official `rockylinux/rockylinux:10` image to produce a rootfs at `/var/lib/machines/hardener-test-rhel`.

**Usage**:
```bash
# Create container (requires podman)
sudo ./scripts/containers/create-container.sh rhel

# Enter container
sudo ./scripts/containers/create-container.sh rhel enter

# Clean up
sudo ./scripts/containers/create-container.sh rhel clean
```

**How It Works**:
1. Pulls the official `rockylinux/rockylinux:10` container image via `podman`
2. Exports the image root filesystem, then installs test packages (`openssh-server`, `audit`, `firewalld`, `nftables`) inside via `systemd-nspawn`
3. Configures test users (`root:test`, `testuser:test` with passwordless sudo)
4. Exports the container filesystem via `podman export`
5. Extracts it to `/var/lib/machines/hardener-test-rhel` for use with `systemd-nspawn`

**Why Podman Export?**: Rocky Linux does not have a native bootstrap tool like `pacstrap` or `debootstrap`. The podman approach creates an equivalent rootfs from the official image.

**Dependencies**:
- `podman`
- Root privileges

---

### Rollback Verification Script

**Script**: `verify-rollback.sh`

**Purpose**: Runs 5 targeted tests with 10 assertions to verify that the rollback system works correctly inside a Fedora nspawn container. Validates the complete apply-then-rollback cycle for multiple plugins.

**Usage**:
```bash
# Run inside a container (or via nspawn from host)
sudo ./scripts/test/verify-rollback.sh
```

**Test Cases**:
| # | Test | Assertions |
|---|------|-----------|
| 1 | Kernel rollback | sysctl runtime values restored, config file removed |
| 2 | SSH rollback | `sshd_config` byte-identical after rollback |
| 3 | Permissions rollback | Directory modes restored, mixed actions (permissions/skipped) |
| 4 | JSON output validation | Valid `RollbackResult` with per-file `restore_action` |
| 5 | Multi-checkpoint | Sequential applies create separate checkpoints, both roll back correctly |

**Exit Codes**:
- `0`: All 10 assertions passed
- `1`: One or more assertions failed

**Dependencies**:
- Bash
- Pre-built musl binary at `/project/target/release/hardener`
- Root privileges
- Container environment (Fedora recommended)

---

### Root Test Suite

**Script**: `root-test-suite.sh`

**Purpose**: Comprehensive automated test suite for root operations. Tests are organized into the following categories covering all CLI functionality.

**Usage**:
```bash
# Inside container: run safe tests (read-only + dry-run)
sudo ./scripts/test/root-test-suite.sh

# Run full tests INCLUDING apply + rollback
sudo ./scripts/test/root-test-suite.sh --apply
```

**Test Categories**:
| Category | Tests | Description |
|----------|-------|-------------|
| Environment | 4 | Container detection, binary exists |
| Basic commands | 2 | Version, help, plugins |
| Scan (root) | 9 | All 8 plugins with root access |
| Reports | 8 | All 7 frameworks + JSON + PDF |
| Dry-run | 5 | All plugins show estimated changes |
| Daemon/History | 2 | Database path, scan history |
| Systemd | 2 | Generate, status commands |
| Checkpoint | 1 | List checkpoints |
| Apply + Rollback | 3 | Actual hardening + verification (with `--apply`) |

**Test Modes**:
| Test | Without `--apply` | With `--apply` |
|------|-------------------|----------------|
| Read-only operations | ✅ Runs | ✅ Runs |
| Dry-run validation | ✅ Runs | ✅ Runs |
| **Apply hardening** | ⏭️ Skipped | ✅ Runs |
| **Rollback** | ⏭️ Skipped | ✅ Runs |

**Safety Features**:
1. **Container detection**: Warns if not running in container
2. **Explicit opt-in**: Destructive tests require `--apply` flag
3. **Pre-flight checks**: Verifies binary exists and is executable

**Exit Codes**:
- `0`: All tests passed
- `1`: One or more tests failed

**Example Output**:
```
============================================================
  Linux System Hardener - Root Test Suite
============================================================
Environment: systemd-nspawn container
Binary: /project/target/release/hardener v0.3.3
============================================================

[1/36] Checking container environment...                    [PASS]
[2/36] Verifying root privileges...                         [PASS]
...
============================================================
  Results: 35/36 passed, 0 failed, 1 skipped
============================================================
```

**Dependencies**:
- Bash
- Pre-built binary at `/project/target/release/hardener`
- Root privileges

---

### Full Test Suite

**Script**: `full-test-suite.sh`

**Purpose**: Comprehensive non-interactive test that exercises **every single capability** of the hardener in one automated run. Tests all commands, all 8 plugins, all 7 frameworks, all output formats, and all apply/rollback operations.

**Usage**:
```bash
# Inside container: run safe tests (read-only, dry-run, scan)
sudo ./scripts/test/full-test-suite.sh

# Run ALL tests INCLUDING apply + rollback
sudo ./scripts/test/full-test-suite.sh --apply
```

**What It Tests** (28 test sections, 149 individual tests on a booted container
under `--apply`, 143 unbooted, 109 without `--apply`):

| Section | Tests |
|---------|-------|
| 1. Basic Commands | --version, --help, all subcommand help |
| 2. Scan All Plugins | Individual scan for all 8 plugins |
| 3. Scan Filters | All 5 severity levels, --audit, --exit-code |
| 4. Scan Output Formats | text, json, csv, html |
| 5. Reports All Frameworks | cis, stig, nist, pcidss, hipaa, gdpr, iso27001 |
| 6. Reports All Scenarios | server, workstation, government, healthcare, financial, gdpr, all |
| 7. Report Output Formats | text, json, csv, html, pdf (generates PDFs for all frameworks) |
| 8. Dry-Run All Plugins | --dry-run for all 8 plugins |
| 9. Checkpoint Operations | list, create, show, delete |
| 10. Daemon Commands | status, run-once |
| 11. History Commands | list, show, export |
| 12. Systemd Commands | generate, install, status, uninstall |
| 12A. Rollback Undoes The Audit Apply | Apply audit hardening, roll it back, and assert on the filesystem that the rules file is gone, that `/etc/audit` lists exactly the paths it listed beforehand, and that the compiled rule set is back at its pre-apply line count (--apply only). Runs FIRST inside the apply block by necessity: it asks whether a rollback *removes* a created file, which cannot be asked once section 15 has already created it. Needs a container no `--apply` run has touched, and reports its reading void rather than passing where it finds one. |
| 12B. Rollback Undoes The Services Apply | Apply service minimisation, roll it back, and assert on the filesystem that the mask link `systemctl mask` created is gone, that the unit is enabled again, and that `/etc/systemd/system` lists exactly the paths it listed beforehand (--apply only). Runs inside the apply block beside 12A and for the same reason. Needs a host running systemd, which `--pipe` does not provide: there it records its precondition check and skips, naming `--booted` as the flag that would let it run. |
| 13. Apply Kernel | Apply kernel hardening + verify changes |
| 14. Apply Other Plugins | Apply 5 remaining plugins (ssh, permissions, pam, firewall, service-minimisation); audit and mac are skipped in containers. Kernel is handled in section 13. |
| 15. Apply --all | Apply all plugins at once |
| 16. Rollback | Rollback to checkpoint, verify restoration |
| 17. Global --format Flag | Test global format flag with various commands |
| 18. Error Handling | Invalid plugin, framework, checkpoint ID |
| 19. Post-Apply Verification | Final scan + compliance report |
| 20. Scan History Persistence | scan -> history list -> verify UUID present |
| 21. History Filtering | --limit, --status filters |
| 22. Plugin Filter Combinations | Short names (kernel, ssh), mixed, multi-plugin |
| 23. Per-Plugin Lifecycle | Apply, re-scan, roll back, re-scan, for kernel, ssh and permissions (--apply only). The host arrives hardened by sections 13 to 15, so each apply here is a second apply: the finding count must be unmoved by it, and unmoved by the rollback that follows. The checkpoint is the one the apply's own result document names, so a plugin whose apply had nothing to do and took none is reported as such rather than rolled back to another apply's checkpoint. What a rollback *removes* cannot be asked at this position and is asked by 12A and 12B instead. |
| 24. Config File Loading | Valid/invalid config file paths |
| 25. Report Combinations | Framework + scenario + format combos |
| 26. Flag Combinations | --quiet + --format, --audit + --format, multi-flag |

**Output**:
- Detailed test log: `/tmp/hardener-full-test-TIMESTAMP.log`
- Generated reports: `/tmp/hardener-test-reports/`
- PDF reports for all 7 compliance frameworks

**Test Modes**:

The `--apply` flag gates destructive tests (sections 12A, 12B, 13-16 and 23). Without it, those sections are skipped. **Section 19 is not gated**: `test_post_scan_verify` is called after both `DO_APPLY` blocks close, so it runs last on every run. Container-mode auto-detection skips 6 environment-dependent tests inside `systemd-nspawn`, and an unbooted container skips section 12B as well. A booted `--apply` run skips 9 in total: the other three are section 23's rollback rows for a plugin whose apply took no checkpoint, and unlike the first six those three are counted as checks before being skipped, which is why 146 passed and 0 failed does not add up to the declared 149.

`--apply` hardens every container it touches, and nothing in the suite undoes the audit apply section 15 performs. Recreate the container before each `--apply` run (`sudo ./scripts/containers/create-container.sh <distro>`), or sections 12A and 12B will report their precondition broken and the run will end red.

**The size of a run is declared rather than discovered.** Each section says how many checks it records, and the suite refuses a run whose total differs, as a counted failure rather than as a non-zero exit alone: the cross-distro runner writes PASS into `summary.txt` for any distribution whose failure count is zero, so a refusal carried by the exit status would read there as a pass. A section that returned early therefore shows as a short run rather than lowering the total quietly, which is how the total moved from 126 to 133 to 140 with nothing noticing. The declarations are counted off the pinned lengths of the plugin, framework, scenario, format and severity tables rather than off the tables themselves, so shortening one of those moves one side of the comparison and not the other; the preflight refuses a run whose tables are not the size they declare.

The suite's own decision logic can be driven without root or a container: `./scripts/test/full-test-suite.sh --self-test` exercises the apply classification, the dry-run row's pairing of exit code and validation report, the three-way file reading (`count` / `absent` / `unreadable`) section 12A depends on, and the size guard, including that a shortened table is refused while the expected total stays where it was. The dry-run and apply rows are driven end to end over documents no host produces on demand, by a stand-in tool that supplies a chosen document and a chosen exit code, because the pairing of the two is the whole of what those rows decide.

**Exit Codes**:
- `0`: All tests passed
- `1`: One or more tests failed

**Example Output**:
```
╔══════════════════════════════════════════════════════════════════════════╗
║   LINUX SYSTEM HARDENER - FULL TEST SUITE                               ║
║   Tests EVERYTHING: all commands, plugins, formats, apply & rollback    ║
╚══════════════════════════════════════════════════════════════════════════╝

╔════════════════════════════════════════════════════════════════════╗
║ 1. BASIC COMMANDS                                                  ║
╚════════════════════════════════════════════════════════════════════╝

  [TEST] hardener --version
  [PASS] hardener --version
  ...

╔════════════════════════════════════════════════════════════════════╗
║ TEST SUMMARY                                                       ║
╚════════════════════════════════════════════════════════════════════╝

  Total Tests:  127
  Passed:       127
  Failed:       0
  Skipped:      6
  Pass Rate:    100%

╔════════════════════════════════════════╗
║     ALL TESTS PASSED SUCCESSFULLY!     ║
╚════════════════════════════════════════╝
```

**Logging Functions**:
| Function | Purpose | Counts in Summary? |
|----------|---------|-------------------|
| `log_test` | Start a test, increment TOTAL | Yes |
| `log_pass` | Mark test passed, increment PASSED | Yes |
| `log_fail` | Mark test failed, increment FAILED | Yes |
| `log_skip` | Mark test skipped, increment SKIPPED | Yes |
| `log_check` | Verification step (not a test) | No |

The `log_check()` function displays a green [PASS] but doesn't increment any counters, making it ideal for preflight checks and verification steps.

**Dependencies**:
- Bash
- Pre-built binary at `/project/target/release/hardener`
- Root privileges
- Container environment (recommended)

---

### Cross-Distro Test Runner

**Script**: `run-cross-distro-tests.sh`

**Purpose**: Orchestrates `full-test-suite.sh` across all supported Linux distributions using `systemd-nspawn --pipe`. Runs tests non-interactively inside each container, captures output, parses results, and generates a summary report. Single command, zero interaction.

**Usage**:
```bash
# Run all distros with apply tests
sudo ./scripts/test/run-cross-distro-tests.sh --apply

# Test single distro
sudo ./scripts/test/run-cross-distro-tests.sh --distro arch --apply

# Rebuild musl binary first, then test
sudo ./scripts/test/run-cross-distro-tests.sh --rebuild --apply

# Safe mode (no apply/rollback tests)
sudo ./scripts/test/run-cross-distro-tests.sh
```

**Options**:
| Flag | Description |
|------|-------------|
| `--apply` | Enable destructive tests (apply + rollback) inside containers |
| `--gui` | Run Playwright GUI tests after CLI tests (requires WASM build in `dist/`) |
| `--distro NAME` | Test single distro: `arch`, `debian`, `fedora`, `rhel`, `opensuse` |
| `--parallel` | Run distros in parallel instead of serially (~5x speedup) |
| `--jobs N` | Max parallel jobs (with `--parallel`; default: 3) |
| `--rebuild` | Build musl static binary before testing |
| `--differential` | Run `differential-suite.sh` instead of `full-test-suite.sh` |
| `--help` | Show usage |

**`--differential`** runs a different kind of test. Instead of comparing the
tool against itself, it applies hardening inside the container and then asks
each setting's real consumer what is in force: `sshd -T` for SSH, and
`chage -l` on an account created after the apply for `/etc/login.defs`, with
`passwd -S` behind it for the one directive Arch's shadow cannot report, and
`stat -c %a` for the nine paths in `PERMISSION_CHECKS`. Every directive is
checked twice, that the system satisfies what the run requires of it and that
`scan` agrees with the system. Satisfying is not always equality: two of the
nine permission paths are compared against an allowed-bits mask, where a
stricter mode is compliant and the tool correctly leaves it alone. A value that
cannot be determined is a failure rather than a skip, and a pre-apply control
proves the checks match real output rather than passing by matching nothing.

A permission path `/etc` does not hold is read at `/usr/etc` instead, which is
where openSUSE keeps the file actually in force, and only an absence confirmed at
both layers is treated as nothing to compare. For such a row the mode is recorded
rather than required, because the tool never writes the vendor layer, so the
assertion that can fail is whether `scan` reported the violation.

The run applies twice, and four readings are compared across the two applies:
every managed permission mode, `sshd -T` in full, the `sshd_config.d` fragments
as names and contents, and what `login.defs` means to a fresh account. An apply
that undoes the previous one is a fleet host drifting back to an unhardened state
on a timer while every scan reports success, and a single-apply run cannot see
that. A complete run comes to 70 checks per distribution unbooted and 83 booted,
and a run recording fewer than the tables ask for is refused rather than reported
as a pass.

It needs a container that has never been hardened, because that pre-apply
control requires findings to exist, and it needs `jq` (the suite refuses
loudly if it is missing). `differential-suite.sh --self-test` runs the pure
text extractors and every refusal path with no root and no container, 410
assertions in all.

**How It Works**:

1. For each distribution, verifies the container exists at `/var/lib/machines/<name>`
2. Executes `full-test-suite.sh` inside the container via `systemd-nspawn --pipe`
3. Captures all output to `test-results/<distro>.log`
4. Strips ANSI escape codes and parses pass/fail/skip counts from the log
5. Generates `test-results/summary.txt` with aggregated results
6. Prints colour-coded summary table to stdout
7. Exits non-zero if any distro had failures

**Container Mapping**:
| Distro | Container Path | Creation Method |
|--------|---------------|----------------|
| arch | `/var/lib/machines/hardener-test` | pacstrap |
| debian | `/var/lib/machines/hardener-test-debian` | debootstrap |
| fedora | `/var/lib/machines/hardener-test-fedora` | podman export |
| rhel | `/var/lib/machines/hardener-test-rhel` | podman export (Rocky 10) |
| opensuse | `/var/lib/machines/hardener-test-opensuse` | podman export (Leap 16.0 image) |

**Output Files**:
```
test-results/
  arch.log           # Full output from Arch container
  debian.log         # Full output from Debian container
  fedora.log         # Full output from Fedora container
  rhel.log           # Full output from Rocky 10 container
  opensuse.log       # Full output from openSUSE container
  summary.txt        # Aggregated results table
```

**Safety**:
- Tests run exclusively inside `systemd-nspawn` containers, never on the host
- `full-test-suite.sh` hard-exits if not running inside a container
- Three-layer protection: nspawn isolation + container detection + `--apply` gating
- `test-results/` directory is gitignored

**Example Output**:
```
Cross-Distro Test Runner
Distros: 5  |  Apply: true

Testing: arch (hardener-test)
  [DONE] 123/123 passed, 6 skipped

Testing: debian (hardener-test-debian)
  [DONE] 123/123 passed, 6 skipped

...

CROSS-DISTRO SUMMARY

Distro        Total   Pass   Fail    Skip   Status
--------      -----   ----   ----    ----   ------
arch            127    127      0       6     PASS
debian          127    127      0       6     PASS
fedora          127    127      0       6     PASS
rhel            127    127      0       6     PASS
opensuse        127    127      0       6     PASS

All distros passed.
```

**Dependencies**:
- Bash
- systemd-nspawn (part of systemd)
- Pre-built musl binary (or use --rebuild)
- Root privileges
- Container filesystems at `/var/lib/machines/`

---

### Parallel Mode (`--parallel`)

Both `run-cross-distro-tests.sh` and `run-gui-tests.sh` accept `--parallel` to run all distros **in parallel** using background processes instead of serially. Each container has its own network namespace, so no port conflicts.

**Usage**:
```bash
# Run all distros in parallel with apply tests
sudo ./scripts/test/run-cross-distro-tests.sh --parallel --apply

# Limit parallel jobs
sudo ./scripts/test/run-cross-distro-tests.sh --parallel --apply --jobs 3

# Web UI tests in parallel
sudo ./scripts/test/gui/run-gui-tests.sh --parallel

# Limit parallel jobs
sudo ./scripts/test/gui/run-gui-tests.sh --parallel --jobs 2
```

**Speed Comparison** (5 distros, with `--apply`):
| Mode | Time | Speedup |
|------|------|---------|
| Serial (default) | ~15 min | 1x |
| Parallel (8 cores) | ~3 min | 5x |

**Output**: Same files as serial mode (`test-results/<distro>.log`, `test-results/gui/<distro>-webui.log`).

---

### Master Parallel Test Runner

**Script**: `run-all-tests-parallel.sh`

**Purpose**: Runs **ALL** test suites in parallel: unit tests, CLI cross-distro, and GUI web UI. Single command for complete validation.

**Usage**:
```bash
# Run everything in parallel (fastest full validation)
sudo ./scripts/test/run-all-tests-parallel.sh --apply

# Run everything including desktop tests
sudo ./scripts/test/run-all-tests-parallel.sh --apply --desktop

# Run in separate kitty windows (visual separation)
sudo ./scripts/test/run-all-tests-parallel.sh --apply --kitty

# Quick test: unit tests only, skip containers
sudo ./scripts/test/run-all-tests-parallel.sh --no-cli --no-gui

# Skip unit tests, just containers
sudo ./scripts/test/run-all-tests-parallel.sh --apply --no-unit
```

**Options**:
| Flag | Description |
|------|-------------|
| `--apply` | Enable destructive tests (apply + rollback) |
| `--desktop` | Include desktop GUI tests (runs after containers, as user) |
| `--no-cli` | Skip CLI cross-distro tests |
| `--no-gui` | Skip GUI web UI tests |
| `--no-unit` | Skip unit tests (cargo test) |
| `--jobs N` | Max parallel jobs per suite (default: auto-detect) |
| `--kitty` | Open each test suite in a separate kitty window |
| `--rebuild` | Build musl binary before testing |
| `--help` | Show usage |

**Kitty Mode**:
With `--kitty`, each test suite opens in its own terminal window:
- Visual separation of output
- Easy to monitor progress
- Press Enter in each window to close after completion

**Desktop Tests**:
Desktop tests run after container tests complete because:
- They require user session (not root)
- They need exclusive window focus (wtype/hyprctl)
- They test real Tauri IPC, not mocked

**Output**:
```
test-results/
  unit-tests.log        # Cargo test output
  cli-tests.log         # Parallel CLI runner output
  gui-tests.log         # Parallel GUI runner output
  desktop-tests.log     # Desktop runner output
  summary.txt           # CLI per-distro summary
  gui/gui-summary.txt   # GUI per-distro summary
  desktop/              # Desktop test screenshots
```

**Dependencies**:
- Bash
- systemd-nspawn (for container tests)
- Cargo (for unit tests)
- kitty terminal (only if using `--kitty` flag)
- Root privileges (for container tests)

---

### Manual Verification Test

**Script**: `manual-verification-test.sh`

**Purpose**: Step-by-step interactive test with visible evidence for each operation. Ideal for verifying scan, apply, and rollback actually work correctly.

**Usage**:
```bash
# Inside container
sudo ./scripts/test/manual-verification-test.sh
```

**Test Cycles**:
| Cycle | Purpose |
|-------|---------|
| 1. Scan | Record BEFORE state, run scan, review findings |
| 2. Apply | Dry-run preview, apply changes, verify AFTER state |
| 3. Rollback | Get checkpoint ID, rollback, verify restoration |
| 4. Re-scan | Confirm final security state |

**Interactive Features**:
- Pauses after each step for review
- Shows actual `/proc/sys/` values before and after
- Displays config file contents
- Extracts checkpoint ID automatically for rollback

**Evidence Displayed**:
```
[EVIDENCE] Current kernel parameter values:
  kernel.kptr_restrict    = 1
  kernel.dmesg_restrict   = 0
  kernel.randomize_va_space = 2
  ...

[EVIDENCE] Contents of /etc/sysctl.d/99-hardener.conf:
  kernel.kptr_restrict = 2
  kernel.dmesg_restrict = 1
  ...
```

**Exit Codes**:
- `0`: Test completed (review evidence manually)
- `1`: Pre-flight check failed

**When to Use**:
- Verifying the checkpoint/rollback system works
- Debugging apply operations
- Demonstrating hardener functionality
- Learning what each operation does

**Dependencies**:
- Bash
- Pre-built binary at `/project/target/release/hardener`
- Root privileges

---

## GUI Test Scripts (Playwright)

Four scripts orchestrate Playwright-based GUI testing of the Web UI inside nspawn containers.

---

### Web UI Test Runner

**Script**: `run-gui-tests.sh`

**Purpose**: Host orchestrator that runs 113 Playwright Web UI tests across all 5 distributions. For each distro, copies the WASM build and test files into the container, then delegates to `gui-test-inner.sh` via `systemd-nspawn --pipe`.

**Usage**:
```bash
# Run GUI tests on all 5 distros
sudo ./scripts/test/gui/run-gui-tests.sh

# Run distros in parallel
sudo ./scripts/test/gui/run-gui-tests.sh --parallel

# Or via the cross-distro runner
sudo ./scripts/test/run-cross-distro-tests.sh --gui
```

**What It Does**:
1. Verifies WASM build exists in `crates/hardener-ui/dist/`
2. For each distro container, copies `gui-tests/` and `dist/` into the container
3. Executes `gui-test-inner.sh` inside the container via nspawn
4. Captures output to `test-results/gui/<distro>-webui.log`
5. Collects theme screenshots to `test-results/gui/screenshots/webui/`
6. Generates `test-results/gui/gui-summary.txt`

**Exit Codes**:
- `0`: All tests passed on all distros
- `1`: One or more tests failed

---

### Web UI Container Inner Script

**Script**: `gui-test-inner.sh`

**Purpose**: Runs inside the nspawn container. Starts Xvfb virtual display, launches the SPA Python server on port 8787, installs npm dependencies, then executes Playwright tests.

**What It Does**:
1. Starts Xvfb on display `:99`
2. Generates `index.html` dynamically from `dist/index.html` (SRI `integrity` attributes stripped, `tauri-mock.js` injected before the first `<script type="module">` tag) using a Python one-liner, then launches `spa-server.py` serving the modified file
3. Auto-detects system Chromium path per distribution
4. Runs `npx playwright test` with the detected browser
5. Cleans up Xvfb and server on exit

**Distro-Specific Setup**:
| Distribution | Chromium Path | Extra Setup |
|--------------|--------------|-------------|
| Arch | `/usr/bin/chromium` | -- |
| Debian | `/usr/bin/chromium` | -- |
| Fedora | `/usr/lib64/chromium-browser/headless_shell` | `chromium-headless` package |
| Rocky 10 | `/usr/bin/chromium-browser` | EPEL + CRB repos, Node.js 20 module |
| openSUSE | `/usr/bin/chromium` | `--gpg-auto-import-keys`, specific lib names |

**Dependencies** (installed inside container):
- Xvfb, Python 3, Node.js, npm, system Chromium

---

### Tauri Desktop Test Runner

**Script**: `run-tauri-gui-tests.sh`

**Purpose**: Host orchestrator for Tauri desktop GUI tests. Similar to `run-gui-tests.sh` but targets the Tauri desktop application instead of the Web UI.

**Usage**:
```bash
sudo ./scripts/test/gui/run-tauri-gui-tests.sh
```

---

### Tauri Desktop Container Inner Script

**Script**: `tauri-gui-test-inner.sh`

**Purpose**: Runs inside the Arch nspawn container for Tauri desktop tests. Starts Xvfb on display `:99`, launches the Tauri binary (`target/debug/linux-hardener-desktop`), and tests 5 of 7 IPC commands using `xdotool` (commands requiring `pkexec` are skipped). Captures screenshots via `xwd` + ImageMagick.

**Usage**:
```bash
# Called automatically by run-tauri-gui-tests.sh, not invoked directly
/bin/bash /project/scripts/test/gui/tauri-gui-test-inner.sh
```

---

### Desktop GUI Test Runner (Host)

**Script**: `run-desktop-tests.sh`

**Purpose**: Starts Tauri desktop app automatically, runs UX + functional tests with wtype/hyprctl on the host Wayland session, then cleans up. Unlike container tests, this tests the real desktop app with real IPC.

**Usage**:
```bash
# Run all desktop tests (starts app if not running)
./scripts/test/run-desktop-tests.sh

# Run only UX tests (keyboard navigation)
./scripts/test/run-desktop-tests.sh --ux-only

# Run only functional tests (scans, reports)
./scripts/test/run-desktop-tests.sh --fn-only

# Run in a new kitty window
./scripts/test/run-desktop-tests.sh --kitty

# Keep app running after tests (for debugging)
./scripts/test/run-desktop-tests.sh --no-cleanup
```

**Options**:
| Flag | Description |
|------|-------------|
| `--kitty` | Open tests in a new kitty window |
| `--ux-only` | Run only UX tests (keyboard navigation) |
| `--fn-only` | Run only functional tests (scans, reports) |
| `--no-cleanup` | Leave Tauri app running after tests |
| `--help` | Show usage |

**Requirements**:
| Tool | Purpose |
|------|---------|
| `hyprctl` | Window detection and focus |
| `wtype` | Keyboard input simulation |
| `grim` | Screenshots |
| `python3` | JSON parsing |

**What It Tests**:
| Category | Tests | Description |
|----------|-------|-------------|
| UX Tests | 49 | Page navigation (Ctrl+1-5), theme cycling (Alt+T), tab keyboard nav, findings grid, skip link, fullscreen (F11) |
| Functional Tests | 46 | Security scan, compliance reports, checkpoint create, remote host form, scheduler config, error handling |

**Output**:
```
test-results/desktop/    Desktop test screenshots
  ux-*.png               UX test screenshots (49 files)
  fn-*.png               Functional test screenshots (46 files)
/tmp/test-grouped/       Working directory for test output
```

**Integration with Master Runner**:
```bash
# Run everything including desktop (desktop runs after containers)
sudo ./scripts/test/run-all-tests-parallel.sh --apply --desktop
```

**Dependencies**:
- Hyprland compositor (or hyprctl-compatible)
- wtype, grim, python3
- Tauri binary: `target/debug/linux-hardener-desktop`

---

## Package Install Test Scripts

Two scripts validate that the distribution packages (AUR, deb, rpm) install correctly and produce a working system.

---

### Package Install Test Runner

**Script**: `run-package-tests.sh`

**Purpose**: Host orchestrator that validates package installs across all 5 distributions. For each distro, copies the musl binary and `test-package-install.sh` into the container, then runs the inner script via `systemd-nspawn --pipe`. Mirrors the structure of `run-cross-distro-tests.sh` but focuses on packaging: install, validate, functional test, uninstall.

**Usage**:
```bash
# Run on all 5 distros
sudo ./scripts/test/run-package-tests.sh

# Single distro
sudo ./scripts/test/run-package-tests.sh --distro arch

# With destructive tests (apply + rollback)
sudo ./scripts/test/run-package-tests.sh --apply

# Rebuild musl binary first
sudo ./scripts/test/run-package-tests.sh --rebuild
```

**Options**:
| Flag | Description |
|------|-------------|
| `--apply` | Enable apply + rollback tests inside containers |
| `--distro NAME` | Test single distro: `arch`, `debian`, `fedora`, `rhel`, `opensuse` |
| `--rebuild` | Build musl static binary before testing |
| `--help` | Show usage |

**Output Files**:
```
test-results/
  pkg-arch.log         # Package test output for Arch
  pkg-debian.log       # Package test output for Debian
  pkg-fedora.log       # Package test output for Fedora
  pkg-rhel.log         # Package test output for Rocky 10
  pkg-opensuse.log     # Package test output for openSUSE
  pkg-summary.txt      # Aggregated results table
```

**Exit Codes**:
- `0`: All distros passed
- `1`: One or more distros had failures

**Dependencies**:
- Bash
- systemd-nspawn (part of systemd)
- Pre-built musl binary (or use --rebuild)
- Root privileges
- Container filesystems at `/var/lib/machines/`

---

### Package Install Validation (Inner Script)

**Script**: `test-package-install.sh`

**Purpose**: Runs inside the nspawn container via `run-package-tests.sh`. Simulates a distribution package install by mirroring the PKGBUILD `package()` function, then validates the complete file layout, permissions, and basic functionality.

**Usage**:
```bash
# Called automatically by run-package-tests.sh, not invoked directly
/bin/bash /project/scripts/test/test-package-install.sh [--apply]
```

**What It Validates**:
| Category | Checks |
|----------|--------|
| Binary install | Binary at `/usr/bin/hardener`, executable |
| Man page | Installed at `/usr/share/man/man1/hardener.1.gz` |
| Systemd unit | `hardener.service` present and loadable |
| Config files | Default config at `/etc/linux-hardener/config.toml` |
| Permissions | Config dir `0755`, signing key `0400` |
| Desktop entry | `.desktop` file and polkit rule installed |
| Functional | `hardener --version`, `hardener scan --dry-run` |

**Exit Codes**:
- `0`: All tests passed
- `1`: One or more tests failed

**Dependencies**:
- Bash
- Pre-built musl binary at `/project/target/*/release/hardener`
- Root privileges
- Container environment

---

## Future Scripts

Additional utility scripts can be added here:
- Documentation generation
- Code generation helpers
- Performance benchmarking scripts

---
