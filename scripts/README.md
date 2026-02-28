# Project Scripts

**Last Updated**: 2026-02-28

This directory contains utility scripts for the Linux Hardening Tool project.

## Quick Reference

| Task | Command |
|------|---------|
| **Start Tauri dev** | `./scripts/tauri-dev.sh` |
| **Validate all docs** | `./scripts/validate_all.py` |
| **Quick validation** | `./scripts/validate_all.py --quick` |
| **Auto-fix docs** | `./scripts/update_all_docs.py --apply` |
| **Check naming** | `./scripts/validate_naming.py` |
| **Verify versions** | `./scripts/release.sh --verify` |
| **Dry-run release** | `./scripts/release.sh patch --dry-run` |
| **Actual release** | `./scripts/release.sh patch` |
| **Create test container** | `sudo ./scripts/create-test-container.sh` |
| **Enter test container** | `sudo ./scripts/create-test-container.sh enter` |
| **Create Debian container** | `sudo ./scripts/create-debian-container.sh` |
| **Create Fedora container** | `sudo ./scripts/create-fedora-container.sh` |
| **Create openSUSE container** | `sudo ./scripts/create-opensuse-container.sh` |
| **Create Rocky 9 container** | `sudo ./scripts/create-rhel-container.sh` |
| **Verify rollback** | `sudo ./scripts/verify-rollback.sh` |
| **Run root tests** | `sudo ./scripts/root-test-suite.sh` |
| **Run root tests (full)** | `sudo ./scripts/root-test-suite.sh --apply` |
| **Full test suite** | `sudo ./scripts/full-test-suite.sh` |
| **Manual verification** | `sudo ./scripts/manual-verification-test.sh` |
| **Cross-distro tests** | `sudo ./scripts/run-cross-distro-tests.sh --apply` |
| **Cross-distro + GUI** | `sudo ./scripts/run-cross-distro-tests.sh --apply --gui` |
| **Single distro test** | `sudo ./scripts/run-cross-distro-tests.sh --distro arch` |
| **GUI tests (Web UI)** | `sudo ./scripts/run-gui-tests.sh` |
| **Tauri GUI tests** | `sudo ./scripts/run-tauri-gui-tests.sh` |
| **Desktop tests (host)** | `./scripts/run-desktop-tests.sh` |
| **PARALLEL: All tests** | `sudo ./scripts/run-all-tests-parallel.sh --apply` |
| **PARALLEL: All + desktop** | `sudo ./scripts/run-all-tests-parallel.sh --apply --desktop` |
| **PARALLEL: All + kitty** | `sudo ./scripts/run-all-tests-parallel.sh --apply --kitty` |
| **PARALLEL: CLI only** | `sudo ./scripts/run-cross-distro-tests-parallel.sh --apply` |
| **PARALLEL: GUI only** | `sudo ./scripts/run-gui-tests-parallel.sh` |
| **Package install tests** | `sudo ./scripts/run-package-tests.sh` |
| **Single distro pkg test** | `sudo ./scripts/run-package-tests.sh --distro arch` |

---

## Tauri Development Launcher

**Script**: `tauri-dev.sh`

**Purpose**: Bulletproof Tauri dev server launcher for Arch Linux + Hyprland + NVIDIA. Automatically detects session type and applies WebKitGTK workarounds to prevent blank windows and crashes.

**Usage**:
```bash
# Standard launch
./scripts/tauri-dev.sh

# Pass additional arguments to cargo tauri dev
./scripts/tauri-dev.sh --release
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
./scripts/validate_all.py

# Auto-fix issues where possible
./scripts/validate_all.py --fix

# Quick mode (skip slower checks)
./scripts/validate_all.py --quick
```

**What It Runs**:
| Validator | Script | Description |
|-----------|--------|-------------|
| Version Synchronisation | `release.sh --verify` | Checks version numbers match |
| FILE_MAP.md Completeness | `validate_file_map.py` | All source files documented |
| Plugin Documentation | `validate_plugin_docs.py` | Plugin tables match source |
| Tauri Commands | `validate_tauri_docs.py` | Tauri commands documented |
| Last Updated Dates | `validate_last_updated.py` | Dates current with git |
| CLI Documentation | `validate_cli_docs.py` | CLI commands documented |
| Compliance Counts | `validate_compliance_docs.py` | Framework counts accurate |

**Modes**:
- Default: Runs all 7 validators
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
  ✓ FILE_MAP.md Completeness: passed
  ✓ Plugin Documentation: passed
  ✓ Tauri Command Documentation: passed
  ✓ Last Updated Dates: passed
  ✓ CLI Documentation: passed
  ✓ Compliance Framework Counts: passed

All 7 validations passed!
```

**Integration with CI/CD**:
```yaml
- name: Validate Documentation
  run: ./scripts/validate_all.py
```

**Dependencies**:
- Python 3.9+
- Bash (for release.sh)
- Git (for date validation)

---

## Naming Convention Validator

**Script**: `validate_naming.py`

**Purpose**: Validates that all Rust code follows the naming conventions defined in `docs/NAMING_CONVENTIONS.md`

**Usage**:
```bash
# Run from project root
./scripts/validate_naming.py

# Or with python3 explicitly
python3 scripts/validate_naming.py
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

Refer to docs/NAMING_CONVENTIONS.md for complete naming standards.
```

**Integration with CI/CD**:

This script can be added to CI/CD pipeline to enforce naming conventions.

Example GitHub Actions workflow:
```yaml
- name: Validate Naming Conventions
  run: ./scripts/validate_naming.py
```

**Dependencies**:
- Python 3.7+
- No external packages required (uses standard library only)

---

## Pre-Commit Hook

**File**: `.git/hooks/pre-commit`

**Purpose**: Automatically validates naming conventions before allowing commits

**Setup**:

The pre-commit hook is already installed and executable in your repository. It will automatically run on every `git commit` command.

**How It Works**:

1. When you run `git commit`, the hook executes automatically
2. It runs `./scripts/validate_naming.py` to check naming conventions
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

Refer to docs/NAMING_CONVENTIONS.md for naming standards.

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
./scripts/release.sh patch --dry-run
./scripts/release.sh minor --dry-run
./scripts/release.sh major --dry-run

# Actual release
./scripts/release.sh patch   # 0.1.0 -> 0.1.1
./scripts/release.sh minor   # 0.1.0 -> 0.2.0
./scripts/release.sh major   # 0.1.0 -> 1.0.0
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

For complete release documentation, see [docs/RELEASING.md](../docs/RELEASING.md).

---

## File Map Validator

**Script**: `validate_file_map.py`

**Purpose**: Validates that `docs/FILE_MAP.md` accurately reflects all Rust source files in the workspace.

**Usage**:
```bash
# Run from project root
./scripts/validate_file_map.py

# Generate stub entries for missing files
./scripts/validate_file_map.py --fix
```

**What It Checks**:
- All `.rs` files in `crates/` and `src-tauri/src/` are documented
- No deleted files remain documented in FILE_MAP.md
- Files are listed under their correct crate sections

**Exit Codes**:
- `0`: FILE_MAP.md is complete and accurate
- `1`: Discrepancies found (missing or extra files)

**Example Output (Discrepancies Found)**:
```
Validating FILE_MAP.md completeness...

Files missing from FILE_MAP.md (3):

  hardener-state:
    - crates/hardener-state/src/scan_history.rs
    - crates/hardener-state/src/scan_manager.rs

  hardener-ui:
    - crates/hardener-ui/src/components/tabs.rs

FILE_MAP.md validation failed

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
- Test files (`/tests/`) are excluded from validation
- Build artifacts (`/target/`) are excluded

**Dependencies**:
- Python 3.9+
- No external packages required (uses standard library only)

---

## Plugin Documentation Validator

**Script**: `validate_plugin_docs.py`

**Purpose**: Validates that plugin documentation in README.md and ARCHITECTURE.md matches actual plugin implementations in source code.

**Usage**:
```bash
# Run from project root
./scripts/validate_plugin_docs.py
```

**What It Checks**:
- All plugins in source code are documented in README.md
- All plugins in source code are documented in ARCHITECTURE.md
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

Checking docs/ARCHITECTURE.md...
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
./scripts/validate_cli_docs.py
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

**Purpose**: Validates that compliance framework control counts in documentation match actual implementations.

**Usage**:
```bash
# Run from project root
./scripts/validate_compliance_docs.py
```

**What It Checks**:
- Control counts in docs/ARCHITECTURE.md framework table
- Control counts in ROADMAP.md framework table
- All frameworks in source are documented

**Exit Codes**:
- `0`: All compliance framework counts are accurate
- `1`: Discrepancies found

**Example Output**:
```
Validating compliance framework documentation...

Found 6 frameworks in source code:
  - CIS: 38 controls
  - GDPR: 12 controls
  - HIPAA: 14 controls
  ...

Checking ARCHITECTURE.md...
  Count mismatches:
    - HIPAA: documented 15+, actual 14

Compliance documentation validation failed

Suggested updates based on actual counts:
| Framework | Controls | Description |
|-----------|----------|-------------|
| CIS | 38 | Center for Internet Security Benchmarks |
...
```

**Approximate Counts**:
- Documentation can use "35+" to indicate "at least 35"
- Script validates actual count is >= documented minimum
- Exact counts (without "+") must match exactly

**Source of Truth**:
- Control counts from `crates/hardener-compliance/src/frameworks/*.rs`
- Each `ComplianceMapping` struct represents one control

**Dependencies**:
- Python 3.9+
- No external packages required (uses standard library only)

---

## Tauri Command Validator

**Script**: `validate_tauri_docs.py`

**Purpose**: Validates that Tauri command documentation in FILE_MAP.md matches actual implementations in `commands.rs`, and that frontend bindings call valid commands.

**Usage**:
```bash
# Run from project root
./scripts/validate_tauri_docs.py
```

**What It Checks**:
- All `#[tauri::command]` functions in `src-tauri/src/commands.rs` are documented in FILE_MAP.md
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

Checking FILE_MAP.md documentation...
  ✓ All 6 commands documented correctly

Checking tauri_bindings.rs invoke calls...
  ✓ All 3 bindings call valid commands

All Tauri command documentation is accurate
```

**Example Output (Discrepancies Found)**:
```
Checking FILE_MAP.md documentation...
  Commands missing from FILE_MAP.md:
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
./scripts/update_all_docs.py

# Apply changes
./scripts/update_all_docs.py --apply
```

**What It Auto-Fixes**:
| Category | Action |
|----------|--------|
| Last Updated dates | Syncs to git commit dates |
| FILE_MAP.md | Adds stub entries for new source files |
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
  ✓ Would update: docs/ARCHITECTURE.md: 2025-12-01 → 2025-12-06

Checking FILE_MAP.md for missing files...
  ✓ Would update: Added stub for crates/hardener-state/src/new_file.rs

Updating compliance framework counts...
  ✓ Would update: ARCHITECTURE.md: CIS → 38

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
./scripts/validate_last_updated.py

# Auto-fix stale dates
./scripts/validate_last_updated.py --fix
```

**What It Checks**:
- Scans all `.md` files in project root, `docs/`, and `scripts/`
- Compares documented "Last Updated" date against git commit history
- Flags dates that are more than 7 days older than last git modification
- Reports files missing "Last Updated" dates (warning only)

**Supported Date Formats**:
```markdown
**Last Updated**: 2025-12-06
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
  ✓ docs/NAMING_CONVENTIONS.md: 2025-12-04
  ✓ scripts/README.md: 2025-12-06

Files without 'Last Updated' date (13):
  - README.md
  - ROADMAP.md
  ...

Warning: 13 file(s) missing 'Last Updated' date
```

**Example Output (Stale Dates)**:
```
Stale dates found (2):
  ✗ docs/ARCHITECTURE.md
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

**Script**: `create-test-container.sh`

**Purpose**: Creates and manages an isolated Arch Linux systemd-nspawn container for safe root testing.

**Usage**:
```bash
# Create container (one-time, ~2-3 minutes)
sudo ./scripts/create-test-container.sh

# Enter existing container
sudo ./scripts/create-test-container.sh enter

# Clean up container
sudo ./scripts/create-test-container.sh clean
```

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

### Distribution Container Scripts

In addition to the Arch Linux container, there are distribution-specific container scripts for cross-distribution validation:

| Script | Distribution | Package Manager |
|--------|--------------|-----------------|
| `create-test-container.sh` | Arch Linux | pacman |
| `create-debian-container.sh` | Debian 12 (Bookworm) | apt/debootstrap |
| `create-fedora-container.sh` | Fedora 41 | dnf |
| `create-rhel-container.sh` | Rocky Linux 9 | podman export |
| `create-opensuse-container.sh` | openSUSE Leap 15.6 | zypper |

**Usage** (same pattern for all):
```bash
# Create container
sudo ./scripts/create-<distro>-container.sh

# Enter container
sudo ./scripts/create-<distro>-container.sh enter

# Clean up
sudo ./scripts/create-<distro>-container.sh clean
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
| Bootstrap tool | pacstrap | debootstrap | dnf | zypper |
| Covers | Manjaro, EndeavourOS | Ubuntu, Mint, Pop!_OS | RHEL, CentOS, Rocky | SLES |

All containers:
- Include required packages (openssh, audit, firewall tools, etc.)
- Have test users configured (`root:test`, `testuser:test`)
- Bind-mount project at `/project`
- Provide full systemd support

---

### Rocky Linux Container Creator

**Script**: `create-rhel-container.sh`

**Purpose**: Creates a Rocky Linux 9 container for cross-distro testing. Uses `podman export` from the official `rockylinux:9` image to produce a rootfs at `/var/lib/machines/hardener-test-rhel`.

**Usage**:
```bash
# Create container (requires podman)
sudo ./scripts/create-rhel-container.sh

# Enter container
sudo ./scripts/create-rhel-container.sh enter

# Clean up
sudo ./scripts/create-rhel-container.sh clean
```

**How It Works**:
1. Pulls the official `rockylinux:9` container image via `podman`
2. Runs the image and installs required packages (`openssh-server`, `audit`, `firewalld`, `nftables`)
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
sudo ./scripts/verify-rollback.sh
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
sudo ./scripts/root-test-suite.sh

# Run full tests INCLUDING apply + rollback
sudo ./scripts/root-test-suite.sh --apply
```

**Test Categories**:
| Category | Tests | Description |
|----------|-------|-------------|
| Environment | 4 | Container detection, binary exists |
| Basic commands | 2 | Version, help, plugins |
| Scan (root) | 9 | All 8 plugins with root access |
| Reports | 8 | All 6 frameworks + JSON + PDF |
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

**Purpose**: Comprehensive non-interactive test that exercises **every single capability** of the hardener in one automated run. Tests all commands, all 8 plugins, all 6 frameworks, all output formats, and all apply/rollback operations.

**Usage**:
```bash
# Inside container: run safe tests (read-only, dry-run, scan)
sudo ./scripts/full-test-suite.sh

# Run ALL tests INCLUDING apply + rollback
sudo ./scripts/full-test-suite.sh --apply
```

**What It Tests** (26 test sections, 123 individual tests):

| Section | Tests |
|---------|-------|
| 1. Basic Commands | --version, --help, all subcommand help |
| 2. Scan All Plugins | Individual scan for all 8 plugins |
| 3. Scan Filters | All 5 severity levels, --audit, --compliance, --exit-code |
| 4. Scan Output Formats | text, json, csv, html |
| 5. Reports All Frameworks | cis, stig, nist, pcidss, hipaa, gdpr |
| 6. Reports All Scenarios | server, workstation, government, healthcare, financial, gdpr, all |
| 7. Report Output Formats | text, json, csv, html, pdf (generates PDFs for all frameworks) |
| 8. Dry-Run All Plugins | --dry-run for all 8 plugins |
| 9. Checkpoint Operations | list, create, show, delete |
| 10. Daemon Commands | status, run-once |
| 11. History Commands | list, show, export |
| 12. Systemd Commands | generate, install, status, uninstall |
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
| 23. Per-Plugin Lifecycle | Apply -> verify findings reduced -> rollback (--apply only) |
| 24. Config File Loading | Valid/invalid config file paths |
| 25. Report Combinations | Framework + scenario + format combos |
| 26. Flag Combinations | --quiet + --format, --audit + --format, multi-flag |

**Output**:
- Detailed test log: `/tmp/hardener-full-test-TIMESTAMP.log`
- Generated reports: `/tmp/hardener-test-reports/`
- PDF reports for all 6 compliance frameworks

**Test Modes**:

The `--apply` flag gates destructive tests (sections 13-16, 19, 23). Without it, those sections are skipped. Container-mode auto-detection automatically skips 6 environment-dependent tests when running inside `systemd-nspawn` containers.

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

  Total Tests:  123
  Passed:       123
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
sudo ./scripts/run-cross-distro-tests.sh --apply

# Test single distro
sudo ./scripts/run-cross-distro-tests.sh --distro arch --apply

# Rebuild musl binary first, then test
sudo ./scripts/run-cross-distro-tests.sh --rebuild --apply

# Safe mode (no apply/rollback tests)
sudo ./scripts/run-cross-distro-tests.sh
```

**Options**:
| Flag | Description |
|------|-------------|
| `--apply` | Enable destructive tests (apply + rollback) inside containers |
| `--gui` | Run Playwright GUI tests after CLI tests (requires WASM build in `dist/`) |
| `--distro NAME` | Test single distro: `arch`, `debian`, `fedora`, `rhel`, `opensuse` |
| `--rebuild` | Build musl static binary before testing |
| `--help` | Show usage |

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
| fedora | `/var/lib/machines/hardener-test-fedora` | dnf bootstrap |
| rhel | `/var/lib/machines/hardener-test-rhel` | podman export (Rocky 9) |
| opensuse | `/var/lib/machines/hardener-test-opensuse` | zypper bootstrap |

**Output Files**:
```
test-results/
  arch.log           # Full output from Arch container
  debian.log         # Full output from Debian container
  fedora.log         # Full output from Fedora container
  rhel.log           # Full output from Rocky 9 container
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
arch            123    123      0       6     PASS
debian          123    123      0       6     PASS
fedora          123    123      0       6     PASS
rhel            123    123      0       6     PASS
opensuse        123    123      0       6     PASS

All distros passed.
```

**Dependencies**:
- Bash
- systemd-nspawn (part of systemd)
- Pre-built musl binary (or use --rebuild)
- Root privileges
- Container filesystems at `/var/lib/machines/`

---

### Parallel Cross-Distro Test Runner

**Script**: `run-cross-distro-tests-parallel.sh`

**Purpose**: Same as `run-cross-distro-tests.sh` but runs all distros **in parallel** using background processes. ~5x faster when testing all 5 distros.

**Usage**:
```bash
# Run all distros in parallel with apply tests
sudo ./scripts/run-cross-distro-tests-parallel.sh --apply

# Limit parallel jobs (default: auto-detect from CPU cores)
sudo ./scripts/run-cross-distro-tests-parallel.sh --apply --jobs 3

# Single distro (same as sequential, but uses same script)
sudo ./scripts/run-cross-distro-tests-parallel.sh --distro arch --apply
```

**Options**:
| Flag | Description |
|------|-------------|
| `--apply` | Enable destructive tests (apply + rollback) inside containers |
| `--distro NAME` | Test single distro: `arch`, `debian`, `fedora`, `rhel`, `opensuse` |
| `--jobs N` | Max parallel jobs (default: auto-detect from `nproc`) |
| `--rebuild` | Build musl static binary before testing |
| `--help` | Show usage |

**Speed Comparison** (5 distros, with `--apply`):
| Runner | Time | Speedup |
|--------|------|---------|
| Sequential | ~15 min | 1x |
| Parallel (8 cores) | ~3 min | 5x |

**Output**: Same as sequential runner — logs in `test-results/<distro>.log`

---

### Parallel Web UI Test Runner

**Script**: `run-gui-tests-parallel.sh`

**Purpose**: Same as `run-gui-tests.sh` but runs all distros **in parallel**. Each container has its own network namespace, so no port conflicts.

**Usage**:
```bash
# Run all distros in parallel
sudo ./scripts/run-gui-tests-parallel.sh

# Limit parallel jobs
sudo ./scripts/run-gui-tests-parallel.sh --jobs 2
```

**Options**:
| Flag | Description |
|------|-------------|
| `--distro NAME` | Test single distro |
| `--jobs N` | Max parallel jobs (default: auto-detect) |
| `--help` | Show usage |

---

### Master Parallel Test Runner

**Script**: `run-all-tests-parallel.sh`

**Purpose**: Runs **ALL** test suites in parallel: unit tests, CLI cross-distro, and GUI web UI. Single command for complete validation.

**Usage**:
```bash
# Run everything in parallel (fastest full validation)
sudo ./scripts/run-all-tests-parallel.sh --apply

# Run everything including desktop tests
sudo ./scripts/run-all-tests-parallel.sh --apply --desktop

# Run in separate kitty windows (visual separation)
sudo ./scripts/run-all-tests-parallel.sh --apply --kitty

# Quick test: unit tests only, skip containers
sudo ./scripts/run-all-tests-parallel.sh --no-cli --no-gui

# Skip unit tests, just containers
sudo ./scripts/run-all-tests-parallel.sh --apply --no-unit
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
sudo ./scripts/manual-verification-test.sh
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

**Purpose**: Host orchestrator that runs 84 Playwright Web UI tests across all 5 distributions. For each distro, copies the WASM build and test files into the container, then delegates to `gui-test-inner.sh` via `systemd-nspawn --pipe`.

**Usage**:
```bash
# Run GUI tests on all 5 distros
sudo ./scripts/run-gui-tests.sh

# Or via the cross-distro runner
sudo ./scripts/run-cross-distro-tests.sh --gui
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
| Rocky 9 | `/usr/bin/chromium-browser` | EPEL + CRB repos, Node.js 20 module |
| openSUSE | `/usr/bin/chromium` | `--gpg-auto-import-keys`, specific lib names |

**Dependencies** (installed inside container):
- Xvfb, Python 3, Node.js, npm, system Chromium

---

### Tauri Desktop Test Runner

**Script**: `run-tauri-gui-tests.sh`

**Purpose**: Host orchestrator for Tauri desktop GUI tests. Similar to `run-gui-tests.sh` but targets the Tauri desktop application instead of the Web UI.

**Usage**:
```bash
sudo ./scripts/run-tauri-gui-tests.sh
```

---

### Tauri Desktop Container Inner Script

**Script**: `tauri-gui-test-inner.sh`

**Purpose**: Runs inside the Arch nspawn container for Tauri desktop tests. Starts Xvfb on display `:99`, launches the Tauri binary (`target/debug/linux-hardener-desktop`), and tests 5 of 7 IPC commands using `xdotool` (commands requiring `pkexec` are skipped). Captures screenshots via `xwd` + ImageMagick.

**Usage**:
```bash
# Called automatically by run-tauri-gui-tests.sh — not invoked directly
/bin/bash /project/scripts/tauri-gui-test-inner.sh
```

---

### Desktop GUI Test Runner (Host)

**Script**: `run-desktop-tests.sh`

**Purpose**: Starts Tauri desktop app automatically, runs UX + functional tests with wtype/hyprctl on the host Wayland session, then cleans up. Unlike container tests, this tests the real desktop app with real IPC.

**Usage**:
```bash
# Run all desktop tests (starts app if not running)
./scripts/run-desktop-tests.sh

# Run only UX tests (keyboard navigation)
./scripts/run-desktop-tests.sh --ux-only

# Run only functional tests (scans, reports)
./scripts/run-desktop-tests.sh --fn-only

# Run in a new kitty window
./scripts/run-desktop-tests.sh --kitty

# Keep app running after tests (for debugging)
./scripts/run-desktop-tests.sh --no-cleanup
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
sudo ./scripts/run-all-tests-parallel.sh --apply --desktop
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

**Purpose**: Host orchestrator that validates package installs across all 5 distributions. For each distro, copies the musl binary and `test-package-install.sh` into the container, then runs the inner script via `systemd-nspawn --pipe`. Mirrors the structure of `run-cross-distro-tests.sh` but focuses on packaging — install, validate, functional test, uninstall.

**Usage**:
```bash
# Run on all 5 distros
sudo ./scripts/run-package-tests.sh

# Single distro
sudo ./scripts/run-package-tests.sh --distro arch

# With destructive tests (apply + rollback)
sudo ./scripts/run-package-tests.sh --apply

# Rebuild musl binary first
sudo ./scripts/run-package-tests.sh --rebuild
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
  pkg-rhel.log         # Package test output for Rocky 9
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
# Called automatically by run-package-tests.sh — not invoked directly
/bin/bash /project/scripts/test-package-install.sh [--apply]
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
