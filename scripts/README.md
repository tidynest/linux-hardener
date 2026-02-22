# Project Scripts

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
| **Run root tests** | `sudo ./scripts/root-test-suite.sh` |
| **Run root tests (full)** | `sudo ./scripts/root-test-suite.sh --apply` |
| **Full test suite** | `sudo ./scripts/full-test-suite.sh` |
| **Manual verification** | `sudo ./scripts/manual-verification-test.sh` |

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
| `crates/hardener-state/src/scan_history.rs` | Scan History | TODO |
| `crates/hardener-state/src/scan_manager.rs` | Scan Manager | TODO |
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

### Root Test Suite

**Script**: `root-test-suite.sh`

**Purpose**: Comprehensive automated test suite for root operations. Runs 36 tests covering all CLI functionality.

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
# Inside container as root
sudo ./scripts/full-test-suite.sh
```

**What It Tests** (19 test sections, 102 individual tests):

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
| 14. Apply Other Plugins | Apply all 8 plugins individually |
| 15. Apply --all | Apply all plugins at once |
| 16. Rollback | Rollback to checkpoint, verify restoration |
| 17. Global --format Flag | Test global format flag with various commands |
| 18. Error Handling | Invalid plugin, framework, checkpoint ID |
| 19. Post-Apply Verification | Final scan + compliance report |

**Output**:
- Detailed test log: `/tmp/hardener-full-test-TIMESTAMP.log`
- Generated reports: `/tmp/hardener-test-reports/`
- PDF reports for all 6 compliance frameworks

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

  Total Tests:  102
  Passed:       102
  Failed:       0
  Skipped:      1
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

## Future Scripts

Additional utility scripts can be added here:
- Distribution testing automation
- Documentation generation
- Code generation helpers
- Performance benchmarking scripts

---

**Last Updated**: 2026-02-22
