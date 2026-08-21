# Project Scripts

**Last Updated**: 2026-08-21

This directory contains utility scripts for the Linux Hardening Tool project.

## Directory Layout

| Subdirectory | Contents |
|--------------|----------|
| `containers/` | systemd-nspawn container lifecycle: `create-container.sh` (all six distros), `boot-ssh-test-container.sh` (booted SSH fixture; unlocks root key login left disabled by an earlier hardening run, then confirms a real login before reporting ready), `nftables-fixture.sh` (makes nftables the selected backend in a container; stops every other running machine first and confirms the container's own `/etc/os-release` before touching it, since the fixed veth address it uses only ever admits one machine safely) |
| `test/` | Host-side test suites and orchestrators: cross-distro, package-install, root/full suites, desktop tests, rollback verification, parallel runner, plus `release-readiness-root.sh` which batches every root-only suite into one invocation |
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
| **Refresh doc screenshots** | `cd scripts/screenshots && python3 build.py && (python3 serve.py &) && node capture-docs.js` |
| **Check naming** | `./scripts/validate/validate_naming.py` |
| **Verify versions** | `./scripts/release/release.sh --verify` |
| **Dry-run release** | `./scripts/release/release.sh patch --dry-run` |
| **Actual release** | `./scripts/release/release.sh patch` |
| **Create test container (Arch)** | `sudo ./scripts/containers/create-container.sh arch` |
| **Enter test container** | `sudo ./scripts/containers/create-container.sh arch enter` |
| **Create Debian container** | `sudo ./scripts/containers/create-container.sh debian` |
| **Create Ubuntu container** | `sudo ./scripts/containers/create-container.sh ubuntu` |
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
| **Release readiness pre-check** | `./scripts/test/release-readiness-root.sh --dry-run` |
| **Release readiness (all root suites)** | `sudo ./scripts/test/release-readiness-root.sh` |
| **Release readiness (one suite)** | `sudo ./scripts/test/release-readiness-root.sh --only differential` |

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
| Policy Exception Sites | `validate_policy_exception_sites.py` | Every scan finding that hardcodes `finding_exception: ExceptionOutcome::NotConfigured` carries a comment saying why, because a hardcoded `NotConfigured` fails a compliance control on a deviation the operator wrote down and approved, and counting the sites cannot tell an oversight from a decision |
| Persisted Finding Fields | `validate_persisted_finding_fields.py` | Every field the `Finding` rebuild in `ScanHistoryManager::get_result_findings` (`crates/hardener-state/src/scan_manager.rs`) gives a hardcoded default, rather than reading from the database row, carries a comment saying why, because a default such as `None` compiles, passes any test that does not assert on it, and drops the persisted value silently, which is how `finding_exception_key` shipped as a hardcoded `None` |
| GUI Mock Fixtures | `validate_gui_mock_fixtures.py` | Every payload `gui-tests/tauri-mock.js` returns carries the fields the Rust type requires and no field it does not have, and every enum-valued field names a real variant. The fixture is a hand-written mirror of those types and nothing read it, so eight drifts accumulated in it unnoticed: a missing field empties the view that consumes it and the Playwright suite reports what looks like a stale selector, while the frontend's "missing field" message goes into an alert box no test asserts on. The payloads are obtained by running the mock against a stubbed `window`, not by parsing it, so what is compared is what serde actually receives. A field serde can supply, `Option<T>` or `#[serde(default)]`, is not required |
| Documented Exception Keys | `validate_documented_exception_keys.py` | Every exception key `docs/reference/configuration.md` publishes exists as a string literal in the plugins, because a key matching nothing is silence rather than an error: the exception never fires and the host is hardened against a deviation its operator documented and approved. The in-code tests pin the keys against themselves, so renaming a constant and its test together leaves the reference promising a key that is gone. Checks documentation against source only; a key that exists and is documented nowhere is not covered |
| Evidence Ledger | `validate_evidence_ledger.py` | Every path `docs/reference/evidence-ledger.md` cites anywhere in the file still exists, not only the ones in its Evidence column: citations also sit in Command and Ceiling cells and in the surrounding prose, and none of them is exempt. A row whose file was renamed or deleted goes on asserting coverage that is gone, and nothing else in the tree reads those paths as anything but prose. The count is cross-checked against the ledger's own structure rather than merely required to be non-zero, because any non-empty reading passes an existence test: every row of a capability table must cite at least one path in its Evidence cell, so stripping that column, emptying a single row's cell, or deleting the table and keeping the prose each fail rather than reporting a smaller healthy number. Whether the named test exercises the claim beside it is a review-time judgement and is not covered |
| CHANGELOG Headings | `validate_changelog_headings.py` | No release entry repeats a change-type heading. A second `### Fixed` under one version hides its own entries from a reader who found the first, and splits a release's published notes between two identical headings on no principle. Compared on the exact heading text, so `### Added (Testing Infrastructure)` beside `### Fixed (GUI Tests)` is two sections rather than a duplicate pair |
| .SRCINFO | `validate_srcinfo.py` | `packaging/.SRCINFO` says what `packaging/PKGBUILD` declares. The AUR reads only `.SRCINFO`, so a stale one describes a package that is not the one it builds; it had fallen three releases behind. Compared field by field always, and byte for byte against a fresh `makepkg --printsrcinfo` where `makepkg` exists |
| Test Assertions | `validate_test_assertions.py` | Every test in the tree reaches an assertion on every path through its body. An assertion buried inside an `if` with no `else`, or inside a loop over a collection this script cannot count, does not run when the condition does not hold, so the test exits 0 having checked nothing and still counts towards the suite total. A `match` whose every arm asserts, an `if`/`else` chain that ends in a bare `else` with every branch asserting, and a `for` over a table written at the site all satisfy it, because none of those can be skipped; the table counts as written at the site whether it sits in the `for` header or is bound just above it by a non-`mut` `let` or `const`. A loop over a table declared in another file does not satisfy it, deliberately: an emptied table is exactly the silent vacuity this check exists to catch. **Scope is now the whole tree** (`validate_all.py` passes `--all`). It was not until issue #130: registered with no arguments the check globbed the integration-test directories only, 646 of the tree's tests across 42 files, and read no test living in a `src/` module, which is where most of this workspace's tests are. It reported that narrow set clean while a test asserting nothing at all sat in the unread half. Widening it surfaced 46 findings, all since resolved, and repaired three shapes the walk had been getting wrong, one of which had been silently skipping 37 tests. That 46 is the check as it stood before the widening, run with `--all` against `3e22d29`, the commit the widening landed on; against this branch's base it reads 47. The tree and the check version belong beside the number, because a bare count here is what went stale once already |
| Markdown Links | `validate_doc_links.py` | Every markdown link in a tracked `.md` file resolves for a reader who has only the repository, including the half invisible to the maintainer: a target that sits on their own disk but is gitignored, which opens in their editor and 404s for everyone who clones. Relative targets are resolved against the linking file's own directory rather than matched as text; anchors are not resolved |
| CLI Documentation | `validate_cli_docs.py` | Every command and subcommand in `cli.rs` appears in each reference surface, `docs/reference/cli.md` and the man page, and has a worked example in `README.md`. The reference surfaces are errors and README is a warning, because README is a tour rather than a reference. This check read README alone until 2026-08-12 while carrying a name that implied all of it: nothing had ever opened the man page, and an audit found ten defects in it, two of them an operator would act on. Reading roff needs its markup taken seriously, since subcommands sit in an `.RI [ a | b | c ]` alternation rather than beside the command and `run-once` is written `run\-once`, and a parser missing either reports documented subcommands as missing |
| Compliance Frameworks | `validate_compliance_docs.py` | Framework list matches enum |
| Cross-Document Facts | `validate_cross_document_facts.py` | A fact stated in more than one document against the site that owns it. Every other validator here reads structure, so a claim in a sentence in a second file was invisible to all of them, and the copy further from where the work happens is the one that goes stale. The canonical source is named per fact: the tree where the tree decides it, one named document where a measurement does. A dated reading is never registered, because a reading naming its own date is supposed to keep saying what it says; only present-tense claims are held. A registered pattern that stops matching is an error and not a skip |
| Ignore Rules | `validate_gitignore.py` | Every path a document says is ignored still is, and no file is tracked and ignored at once without a registered reason. Some of these claims are instructions rather than description: `docs/superpowers/` and `.rust-sec-ci.toml` being ignored is the stated reason `git add -A` is safe here, and a reader following that after a rule changed would put specifications and a CI configuration into a release commit. The reverse state is quieter, and one file was already in it: git honours the index, so the rule does nothing while every reader of `.gitignore` is told otherwise. Whether an ignore rule is still needed is not checked, since a stale rule matching nothing is harmless and nagging about one gets a check turned off |
| Colour Contrast | `validate_contrast.py` | Every foreground and background pair `crates/hardener-ui/styles.css` declares together in one rule clears WCAG AA, across all seven themes. Translucent fills are composited rather than skipped: an `rgba()` background is weighed over every opaque `--bg-*` surface the theme declares and scored on the best of those ratios, so a failure holds whatever the real ancestor turns out to be. That took the pairs checked from 182 to 322, the 140 new ones coming from 18 rules that declare an alpha background, every severity badge among them. Deliberately not every token against every surface: that pairing was tried, reported five themes failing on combinations that may never render, and contradicted the screenshots. A theme can ship its worst contrast on its most destructive control and look entirely conventional doing it, which is how a High Contrast `.btn-danger` sat at 1.9:1 through eight reviewers |
| Version Locations | `validate_version_locations.py` | Every file stating the CURRENT version agrees with `Cargo.toml`, and any tracked file carrying a current-version marker that is not registered fails rather than passing unseen. `release.sh --verify` reads four such files; this reads thirteen. Historical mentions, changelog headings and older debian stanzas are silent by design, since they are supposed to keep saying what they say after a bump |
| Test Counts | `validate_test_counts.py` | The test-count figures in `docs/reference/evidence-ledger.md` against the tree, without running cargo. Counts a `grep` can reproduce are reproduced; the rest are pinned to each other by the identities the ledger states in prose, so a figure edited alone fails even though nothing about it was measured. Other documents stating a count as current, rather than as a dated reading, are held to the ledger. Every other validator here reads structure, so a number in a sentence was invisible to all of them: one count reached four values across six documents, and the ledger's own validator row sat two behind the registry |

**Modes**:
- Default: Runs all 26 checks in the table above, which are 25 Python validators plus the one shell check, `release.sh --verify`
- `--quick`: Skips CLI and Compliance validators (faster)
- `--fix`: Passes `--fix` to validators that support it

**Exit Codes**:
- `0`: All validations passed
- `1`: One or more validations failed

**Example Output**:
```
############################################################
#  Linux Hardener - Documentation Validator         #
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
  ...
  ✓ CLI Documentation: passed
  ✓ Compliance Framework List: passed

All 26 validations passed!
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

## Cross-Document Fact Validator

**Script**: `validate_cross_document_facts.py`

**Purpose**: Holds a fact stated in more than one document to the site that owns it. Every other validator here reads structure, so a claim in a sentence in a second file was invisible to all of them, and the copy further from where the work happens is the one that goes stale. The canonical source is named per fact: the tree where the tree decides it, one named document where a measurement does.

**Usage**:
```bash
# Run from project root
./scripts/validate/validate_cross_document_facts.py
```

**What It Checks**:
- Each registered fact against its own canonical source, not against another document's copy
- A registered pattern that matches nothing is an error, not a skip: a pattern matching nothing is what makes a validator report green while checking nothing
- A registered pattern that matches more than one place is also an error, because which one was checked would depend on file order
- A capture that is not an integer is reported rather than silently ignored
- Dated readings are deliberately excluded: a reading naming its own date is supposed to keep saying what it says, so only present-tense claims are held

**Exit Codes**:
- `0`: every registered site agrees with its canonical source
- `1`: a site has drifted, a pattern matched zero or more than one place, or a capture was not an integer

**Example Output**:
```
Validating facts stated in more than one document...

  compliance frameworks: the tree says 10
    OK scripts/README.md agrees at 10
    OK scripts/README.md agrees at 10
  GUI Playwright tests: the tree says 165
    OK docs/reference/distribution-validation.md agrees at 165
    OK scripts/README.md agrees at 165
    OK docs/reference/distribution-validation.md agrees at 165
    OK docs/reference/distribution-validation.md agrees at 165
  themes.spec.js parameterised site line: the tree says 200
    OK docs/reference/distribution-validation.md agrees at 200
  contrast.spec.js parameterised site line: the tree says 710
    OK docs/reference/distribution-validation.md agrees at 710
  hardening.spec.js parameterised site line: the tree says 464
    OK docs/reference/distribution-validation.md agrees at 464
  contrast sweep routes: the tree says 12
    OK docs/reference/distribution-validation.md agrees at 12
    OK docs/reference/file-map.md agrees at 12
  GUI Playwright test call sites: the tree says 117
    OK docs/reference/distribution-validation.md agrees at 117
    OK docs/reference/distribution-validation.md agrees at 117
  theme sweep states: the tree says 6
    OK gui-tests/tests/themes.spec.js agrees at 6
    OK docs/reference/distribution-validation.md agrees at 6
    OK docs/reference/distribution-validation.md agrees at 6
    OK docs/reference/file-map.md agrees at 6
    OK scripts/README.md agrees at 6
  theme sweep screenshots: the tree says 42
    OK gui-tests/tests/themes.spec.js agrees at 42
    OK gui-tests/tests/themes.spec.js agrees at 42
    OK docs/reference/distribution-validation.md agrees at 42
    OK docs/reference/distribution-validation.md agrees at 42
    OK docs/reference/file-map.md agrees at 42
    OK scripts/README.md agrees at 42
  registered sites: the tree says 25
    OK scripts/README.md agrees at 25

All 25 registered sites agree with their source
  Dated readings are deliberately not registered.
```

This block said 156 across 4 sites until 2026-08-20, two days after the suite reached 157, and 157 across 6 until 2026-08-21: the same defect it exists to illustrate, in the entry describing the validator that exists to catch it. **The `All N registered sites` line is now registered**, against the registry itself rather than against the tree or another document. It is deliberately self-referential, and registering it proved itself in the same edit: the run went red immediately, the registry summing to 18 where this block still said 17, because adding the site moved the number the site states. It is the only line here that moves on EVERY registry change rather than only on a change to what it describes.

**The per-fact numbers above remain illustrative and unheld.** Each duplicates a fact already registered against a different site, so a stale one here is a stale copy rather than an unchecked claim, and a pattern unique enough to pin one of them inside a fenced sample would be anchored to the sample's line order. The trade is deliberate: one integer that cannot go stale, rather than five that are pinned to the shape of a code block.

**Source of Truth**:
- Named per fact in the script's `REGISTRY`. For the compliance framework count, the `ComplianceFramework` enum in `crates/hardener-types/src/lib.rs`, read via `validate_compliance_docs.py`'s `parse_enum_frameworks`. For the GUI Playwright test count, `gui-tests/tests/*.spec.js` themselves as of 2026-08-21: `_spec_cases` walks each spec with its comments and string bodies blanked, keeps a stack of the enclosing `for...of` loops, and gives each `test()` the product of that stack, so a parameterised site contributes its cases rather than one. It reproduces `npx playwright test --list` exactly, 165 cases over 117 call sites. **Until that day this fact read the row marked current in the Reading table of [distribution-validation.md](../docs/reference/distribution-validation.md), the document this validator also checks**, so it could confirm that the consumers agreed with the row and never that the row was true; that row is now a checked site instead. Deriving rather than running the collector keeps `validate_all.py` free of `gui-tests/node_modules`, which is gitignored and absent from a fresh clone. The ceiling is the shapes the walk understands - `for...of` over an inline array, or over a `const NAME = [` array in the spec or in `helpers.js` - and any other parameterisation is refused by name at the `test()` it reaches rather than counted as one. For the GUI Playwright call-site count, the same specs counted by a plain regex with no brace tracking, registered on 2026-08-20 when the fact above had no tree definition and kept as the total check that proves the walk read its source: `_suite_shape` compares the two and refuses if they disagree. For the three parameterised-site LINE numbers and the contrast sweep's route count, the specs again; all four were prose that had rotted, three of them line numbers displaced by edits elsewhere in their own files

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

# Prove the date derivation against a throwaway repository
./scripts/validate/update_all_docs.py --selftest
```

**Idempotency is enforced rather than asserted.** It did not hold until
2026-08-14: the date came from the last commit touching a file for any reason,
including the tool's own stamp, so `--apply` made every file it wrote stale
again and a second run demanded a newer date for a document nobody had edited
(#172). `--selftest` builds a real repository, commits a content change, then a
stamp-only change, and fails if the second is taken as the answer. Six cases,
including a root commit, two stamp-only commits in a row, and a commit that
moves the stamp *and* the body, which must count.

**What It Auto-Fixes**:
| Category | Action |
|----------|--------|
| Last Updated dates | Syncs to the last commit that changed the file's content, ignoring commits that only move the stamp |
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
**Last Updated**: 2026-08-18
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

**Purpose**: Creates and manages the isolated systemd-nspawn test containers for all six supported distributions. The distro is the first argument; the Arch container is the primary one used by most suites.

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

`create-container.sh` covers all six distributions the cross-distribution runner iterates; the per-distro bootstrap mechanics differ. **All six have a dated result**, Ubuntu included: it joined on 2026-08-07 and was recorded VALIDATED on 2026-08-14, 149 declared and recorded, 147 passed, 0 failed, 8 skipped, identical to the other five. See [distribution-validation.md](../docs/reference/distribution-validation.md). This sentence said "no suite has been run inside it" until 2026-08-18, eleven days after the first result appeared and two days after the same claim was corrected in [testing.md](../docs/contributing/testing.md); one fact in two places, and only one of them was fixed:

| Distro argument | Distribution | Package Manager |
|-----------------|--------------|-----------------|
| `arch` | Arch Linux | pacman (pacstrap) |
| `debian` | Debian 13 (Trixie) | apt/debootstrap |
| `ubuntu` | Ubuntu 24.04 LTS (Noble) | apt/debootstrap |
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

# Recreate all six for a clean baseline, no prompts
for d in arch debian ubuntu fedora rhel opensuse; do
    sudo ./scripts/containers/create-container.sh "$d" clean --no-confirm
    sudo ./scripts/containers/create-container.sh "$d" || { echo "CREATE FAILED: $d"; break; }
done
```

**Container Locations**:
| Distribution | Location |
|--------------|----------|
| Arch | `/var/lib/machines/hardener-test` |
| Debian | `/var/lib/machines/hardener-test-debian` |
| Ubuntu | `/var/lib/machines/hardener-test-ubuntu` |
| Fedora | `/var/lib/machines/hardener-test-fedora` |
| RHEL/Rocky | `/var/lib/machines/hardener-test-rhel` |
| openSUSE | `/var/lib/machines/hardener-test-opensuse` |
| Arch, nftables only | `/var/lib/machines/hardener-test-nftables` |

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

**Purpose**: Runs 14 targeted tests to verify that the rollback system works correctly inside an nspawn container: TEST 1-9 ask whether a value returned to its pre-apply state, and TEST 10-14 ask whether each plugin's scan (ssh-hardening, service-minimisation, audit-hardening, permissions-hardening, pam-hardening) correctly reports a divergence forced onto the host behind the rollback's back. Validates the complete apply-then-rollback cycle for multiple plugins. The runner is `release-readiness-root.sh --only rollback`, which runs the script twice against the same arch container: once under `--pipe` (TEST 1-9 plus TEST 12-14, which need no service manager; TEST 10-11 record their precondition and skip) and once more booted (TEST 10-14 only, all askable). Measured 2026-08-11 at commit `dd85255f`: the `--pipe` pass read 30 of 32 checks passed, 2 skipped, 0 failed; the booted pass read 5 of 5, 0 skipped.

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
| 6 | PAM rollback | `PASS_MAX_DAYS` in `/etc/login.defs` seeded to shadow's 99999, moved by the apply, read back by value and by file hash |
| 7 | Firewall rollback | Whichever backend the plugin selects: its own configuration and what the host is actually enforcing |
| 8 | Divergence reporting | A rollback leaving a sysctl no surviving file names reports it as `Diverged` rather than plain success |
| 9 | Legacy `/etc/sysctl.conf` | A parameter named only in that file stays `Diverged`, with the sentence saying the value is lost at the next reboot rather than that no file names it |
| 10 | What `ssh-hardening` reports after a rollback | Needs `--booted`; forces a divergence via `systemctl mask` and checks the plugin reports it |
| 11 | What `service-minimisation` reports after a rollback | Needs `--booted`; forces a divergence via `systemctl start` on a masked unit |
| 12 | What `audit-hardening` reports after a rollback | Runs unbooted; forces a divergence via `auditctl` reaching the kernel audit subsystem |
| 13 | What `permissions-hardening` reports after a rollback | Runs unbooted; forces `/etc/shadow` to mode 666 after the checkpoint and checks the rollback restores it |
| 14 | What `pam-hardening` reports after a rollback | Runs unbooted; forces a line appended to `/etc/security/faillock.conf` after the checkpoint |

**Exit Codes**:
- `0`: Every check ran and passed
- `1`: One or more checks failed
- `2`: Every check that ran passed and at least one was skipped

**Dependencies**:
- Bash
- Pre-built musl binary at `/project/target/release/hardener`
- Root privileges
- Container environment. The runner, `release-readiness-root.sh --only rollback`,
  builds and uses the arch container, which is what the readings above
  were taken on

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
| Environment | 4 | Root check, binary exists, container detection, `--version` |
| Basic commands | 2 | `hardener --help`, `hardener plugins` |
| Scan (root) | 9 | Full scan, 6 of 8 plugins individually (kernel, firewall, audit, ssh, pam, permissions; not services or mac), severity filter, `--exit-code` |
| Reports | 8 | 6 of the 10 `ComplianceFramework` variants (cis, stig, nist, pcidss, hipaa, gdpr) + JSON + PDF |
| Dry-run | 5 | `--all --dry-run`, then 4 of 8 plugins individually (kernel, firewall, permissions, ssh) |
| Daemon/History | 2 | Database path, scan history |
| Systemd | 2 | Generate, status commands |
| Checkpoint | 1 | List checkpoints |
| Apply + Rollback | 5 | Apply kernel hardening, verify, checkpoint created, rollback, verify rollback (with `--apply`) |

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
  Linux Hardener - Root Test Suite
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

**Purpose**: Comprehensive non-interactive test of the hardener in one automated run. Tests all commands, all 8 plugins, **all 10 compliance frameworks**, all output formats, and all apply/rollback operations. It read "every single capability" and "all 7 frameworks" until 2026-08-16, then "7 of the 10" until 2026-08-19, both of which the `FRAMEWORKS` array did not support: SOC 2, NIST 800-171 r3 and FedRAMP were in `ComplianceFramework::ALL` and rendered by no run of this suite. The array names all ten as of 2026-08-19 and all six distributions rendered them at `5652bb45`. See [what-is-not-proven.md](../docs/reference/what-is-not-proven.md).

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
| 4. Scan Output Formats | text and json rendered; csv and html refused at the parse |
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
- PDF reports for all 10 compliance frameworks

**Test Modes**:

The `--apply` flag gates destructive tests (sections 12A, 12B, 13-16 and 23). Without it, those sections are skipped. **Section 19 is not gated**: `test_post_scan_verify` is called after both `DO_APPLY` blocks close, so it runs last on every run. Container-mode auto-detection skips 6 environment-dependent tests inside `systemd-nspawn`, and an unbooted container skips section 12B as well. A booted `--apply` run skips 8 in total: the other two are section 23's rollback rows for a plugin whose apply took no checkpoint, and unlike the first six those two are counted as checks before being skipped, which is why 147 passed and 0 failed does not add up to the declared 149. The row establishing that the plugin took no checkpoint is a pass rather than a third skip: `apply_real_change_count` reads the apply's own change list, so a no-op is confirmed rather than assumed, and an apply that changed the host while recording no checkpoint fails there instead of being reported as having nothing to do.

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
| `--booted` | Boot the container under systemd instead of `--pipe`, so services, audit and firewall are testable |
| `--gui` | Run Playwright GUI tests after CLI tests (requires WASM build in `dist/`) |
| `--distro NAME` | Test single distro: `arch`, `debian`, `ubuntu`, `fedora`, `rhel`, `opensuse` |
| `--parallel` | Run distros in parallel instead of serially, up to `--jobs` of them at a time |
| `--jobs N` | Max parallel jobs (with `--parallel`; default: 3) |
| `--rebuild` | Build musl static binary before testing |
| `--differential` | Run `differential-suite.sh` instead of `full-test-suite.sh` |
| `--self-test` | Assert the runner's own count parsing and reporting, then exit. Needs no root, no container and no binary, and refuses any other flag beside it |
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
that. A complete run comes to **93 checks per distribution unbooted and 99
booted**, 98 of them where the container never had `bluetooth.service` running,
and a run recording fewer than the tables ask for is refused rather than
reported as a pass. Both runner paths declare their own network namespace, so
an unbooted run here asks all 11 kernel rows; the size of a run holding neither
signal is **80**, and no runner produces it. Do not read these as fixed: they
are pinned as literals in `differential-suite.sh --self-test`, which is where to
read them, and they moved by ten on 2026-08-09 when the audit and MAC oracles
landed while this sentence and its copy in
[testing.md](../docs/contributing/testing.md) both said 70 and 89 for nine days.

**The services rows need `--booted`.** `systemctl mask` and `systemctl
is-enabled` want systemd as PID 1, which `nspawn --pipe` does not provide, so
under `--pipe` the plugin is left out of the compared set entirely and its rows
are declared unaskable rather than answered. Booted, three questions are asked
of `bluetooth`: whether systemd will still start it at the next boot, whether
`/etc/systemd/system/bluetooth.service` is a link to `/dev/null` rather than
merely absent from the wants directory, and whether a unit that was running was
stopped. The last declares itself unaskable where the unit was never running,
because a row that reports a pass on every distribution without the tool
having stopped anything proves nothing.

`bluetooth` is the subject because `containers/create-container.sh` installs
`bluez` on every image and enables the unit, deliberately: the plugin raises
a finding only for a unit that is enabled or active, and every image shipped
with none of the five units it assesses.

**All eight plugins now have differential coverage, and two of them have it
with a stated ceiling** (issue #47). The audit oracle is `augenrules`, the audit
package's own merge tool, which needs no running auditd: the apply's reload
fails inside a container by design and the merge happens before that failure, so
what the rows read is what the next boot would load rather than what is being
audited now. The MAC oracle is the inverse of every other one here. This
machine's kernel carries neither SELinux nor AppArmor, so the suite proves the
apply leaves `/etc/selinux`, `/etc/apparmor` and `/etc/apparmor.d` untouched,
which catches the plugin writing a configuration onto a host that can never read
it and catches nothing about enforcement. Reading enforcement back needs a
virtual machine and is issue #18, not a gap in this suite.

It needs a container that has never been hardened, because that pre-apply
control requires findings to exist, and it needs `jq` (the suite refuses
loudly if it is missing). `differential-suite.sh --self-test` runs the pure
text extractors and every refusal path with no root and no container, and it
reports the same result whether or not the environment declares the run booted.
Its assertion count is deliberately not restated here: it grows with every
extractor check added and nothing reads it, so it rots unnoticed. Read it off
the run itself with `--self-test 2>/dev/null | grep -c '^ *ok '`, which was 588
on 2026-08-16. The 584 that stood here before had gone stale exactly that way.

**How It Works**:

1. For each distribution, verifies the container exists at `/var/lib/machines/<name>`
2. Executes `full-test-suite.sh` inside the container via `systemd-nspawn --pipe`
3. Captures all output to `test-results/<distro>.log`, or `test-results/differential-<distro>.log` under `--differential`
4. Strips ANSI escape codes and parses pass/fail/skip counts from the log
5. Generates `test-results/summary.txt` with aggregated results (`differential-summary.txt` under `--differential`)
6. Prints colour-coded summary table to stdout
7. Exits non-zero if any distro had failures

**Container Mapping**:
| Distro | Container Path | Creation Method |
|--------|---------------|----------------|
| arch | `/var/lib/machines/hardener-test` | pacstrap |
| debian | `/var/lib/machines/hardener-test-debian` | debootstrap |
| ubuntu | `/var/lib/machines/hardener-test-ubuntu` | debootstrap (24.04 LTS Noble) |
| fedora | `/var/lib/machines/hardener-test-fedora` | podman export |
| rhel | `/var/lib/machines/hardener-test-rhel` | podman export (Rocky 10) |
| opensuse | `/var/lib/machines/hardener-test-opensuse` | podman export (Leap 16.0 image) |
| arch-nftables | `/var/lib/machines/hardener-test-nftables` | pacstrap, ufw left out (#47) |

**Output Files**:
```
test-results/
  arch.log           # Full output from Arch container
  debian.log         # Full output from Debian container
  ubuntu.log         # Full output from Ubuntu container
  fedora.log         # Full output from Fedora container
  rhel.log           # Full output from Rocky 10 container
  opensuse.log       # Full output from openSUSE container
  summary.txt        # Aggregated results table

  differential-<distro>.log   # The same, one per distro, under --differential
  differential-summary.txt    # so a differential run cannot overwrite a full one
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

**Speed Comparison** (measured on 5 distros, with `--apply`):
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

**Purpose**: Host orchestrator that runs the Playwright Web UI suite across every distro in `DISTRO_ORDER`. The suite is **165 tests in 11 files**, and that is a result rather than a static count: it ran 165 of 165 on all six distributions on 2026-08-21, none failed, skipped or flaky, one worker and no name filter, Ubuntu included, 3.7 to 4.7 minutes each and 44 screenshots each. Recorded in [distribution-validation.md](../docs/reference/distribution-validation.md). The count is still mostly generated rather than literal, which is why `npx playwright test --list` is the way to read it: `themes.spec.js` produces 42 from 7 themes x 6 states, and `hardening.spec.js`'s T-DIVG-03 produces 2 from two viewport widths. For each distro, copies the WASM build and test files into the container, then delegates to `gui-test-inner.sh` via `systemd-nspawn --pipe`.

**Four verdicts, not two.** `PASS` (exit 0), `DEGRADED` (98), `MISSING` (99, no container), `FAIL` (anything else). **`DEGRADED` means every test passed AND a package install did not**: `run_install` in `gui-test-inner.sh` records the failed step in `DEPS_FAILED`, and the run is rescued only because the container was already provisioned, so the next one may not be. Repair rather than rebuild, then re-run:

```bash
sudo systemd-nspawn -q -D /var/lib/machines/hardener-test-debian --pipe /bin/bash -c 'apt-get update && apt-get -y -f install && apt-get install -y python3 chromium nodejs npm'
```

That branch first executed on 2026-08-21, by appending a nonexistent package to the arch install line and running `--grep T-FAPPLY`: `pacman` reported `target not found`, skipped the four real packages as already up to date, 9 tests passed, and the runner reported `DEGRADED` and exited non-zero. The probe is only meaningful against an ALREADY-PROVISIONED container - on a bare one the tests fail and the verdict is `FAIL`, which proves nothing about 98. That run is also what found the inline verdict calling a degraded run `[FAIL] Tests failed (exit code: 98)` while the summary called it `DEGRADED`; the line a reader watching the scroll sees was sending them to look for a failing test.

**Usage**:
```bash
# Run GUI tests on every distro in DISTRO_ORDER
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

**Purpose**: Runs inside the nspawn container. Launches the SPA Python server on port 8787, installs npm dependencies, then executes Playwright tests.

**What It Does**:
1. Generates `index.html` dynamically from `dist/index.html` (SRI `integrity` attributes stripped, `tauri-mock.js` injected before the first `<script type="module">` tag) using a Python one-liner, then launches `spa-server.py` serving the modified file
2. Auto-detects system Chromium path per distribution
3. Runs `npx playwright test` with the detected browser
4. Cleans up the server on exit

No X server is started. `playwright.config.js` sets `headless: true`, and Fedora's binary is `headless_shell`, which has no X support at all and runs the suite regardless.

**Distro-Specific Setup**:
| Distribution | Chromium Path | Extra Setup |
|--------------|--------------|-------------|
| Arch | `/usr/bin/chromium` | -- |
| Debian, Ubuntu | `/usr/bin/chromium` | -- |
| Fedora | `/usr/lib64/chromium-browser/headless_shell` | `chromium-headless` package |
| Rocky 10 | `/usr/bin/chromium-browser` | EPEL + CRB repos |
| openSUSE | `/usr/bin/chromium` | `--gpg-auto-import-keys`, `nodejs-default`/`npm-default` |

**Dependencies** (installed inside container):
- Python 3, Node.js, npm, system Chromium

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
| UX Tests | 43 | Page navigation (Ctrl+1-5), theme cycling (Alt+T), tab keyboard nav, findings grid, skip link, fullscreen (F11) |
| Functional Tests | 46 | Security scan, compliance reports, checkpoint create, remote host form, scheduler config, error handling |

These are the `pass` assertions in `gui/tauri-ux-test.sh` and
`gui/tauri-functional-test.sh` (`grep -cE '^\s*pass ' <script>`), and they sum to
the 89 desktop checks [file-map.md](../docs/reference/file-map.md) states.
**Do not read them off the screenshots**, which is a different count: the UX
script takes 42, one fewer than it asserts, so `ux-*.png` and the row above it
are meant to disagree by one. The row said **49** from 2026-02-28 until
2026-08-18 and was **never true** on either metric: `tauri-ux-test.sh` was not
created until 2026-07-18, four and a half months after the number describing it
was written, and it has never held a `ux-43` screenshot. The correction to 43
reached file-map.md on 2026-08-16 and did not reach here.

**Output**:
```
test-results/desktop/    Desktop test screenshots
  ux-*.png               UX test screenshots (42 files)
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

**Purpose**: Host orchestrator that validates package installs across every distro in `DISTRO_ORDER`. For each distro, copies the musl binary and `test-package-install.sh` into the container, then runs the inner script via `systemd-nspawn --pipe`. Mirrors the structure of `run-cross-distro-tests.sh` but focuses on packaging: install, validate, functional test, uninstall.

**Usage**:
```bash
# Run on every distro in DISTRO_ORDER
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
| `--distro NAME` | Test single distro: `arch`, `debian`, `ubuntu`, `fedora`, `rhel`, `opensuse` |
| `--rebuild` | Build musl static binary before testing |
| `--help` | Show usage |

**Output Files**:
```
test-results/
  pkg-arch.log         # Package test output for Arch
  pkg-debian.log       # Package test output for Debian
  pkg-ubuntu.log       # Package test output for Ubuntu
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

## Release Readiness Root Batch

**Script**: `release-readiness-root.sh`

**Purpose**: run every suite that needs root in one invocation, so a single
privileged prompt buys all of them. An unprivileged session cannot start a
systemd-nspawn container, which blocks the cross-distro suite, the differential
suite, the packaging install tests, the Web UI suite and the rollback readback.
Those are where the deepest evidence in this project comes from.

**Usage**:

```bash
# Unprivileged pre-check: every read-only gate, plus the plan. Run this first.
./scripts/test/release-readiness-root.sh --dry-run

# The real run
sudo ./scripts/test/release-readiness-root.sh

# One suite (safe on its own: each suite rebuilds its own containers)
sudo ./scripts/test/release-readiness-root.sh --only differential
```

**What it runs**, in order:

| Suite | Invocation | Containers |
|-------|-----------|------------|
| `polkit` | `polkit/test-polkit-matrix.sh` | none, host check |
| `cross-distro` | `run-cross-distro-tests.sh --apply --booted` | all six, rebuilt first |
| `differential` | `run-cross-distro-tests.sh --differential --booted` | all six, rebuilt first |
| `package` | `run-package-tests.sh --apply` | all six, rebuilt first |
| `gui` | `gui/run-gui-tests.sh` | all six, rebuilt first |
| `rollback` | `verify-rollback.sh` under `systemd-nspawn --pipe` | arch, rebuilt first |

The polkit matrix runs first because it is cheap and needs no container: a
failure there is worth knowing before an hour of container work. Its three
interactive tests are not run, because they block on a human at an
authentication dialog; the matrix reports them as skips.

**Containers are rebuilt before every suite that uses one.** A completed
differential run leaves its container hardened, and the next suite against it
fails a rotating subset that reads as a regression when each of those failures
is really a pre-apply control working. The rule is uniform so there is no
per-suite exception to get wrong, and it is what makes `--only` trustworthy.
Each clean and create is judged on two signals rather than one. The container
directory is checked directly on both sides, because a clean that silently did
nothing would leave the previous run's hardened container in place; and the
create's exit status is checked as well, because the arch, debian and ubuntu
bootstraps create the directory before they populate it, so a bootstrap that
dies halfway leaves the path in place. Either signal alone would let a
half-built container reach a suite. `create-container.sh` refuses a container
that already exists with exit status 3 rather than the 0 it used to return, so
the two signals now agree instead of disagreeing.

**Binary freshness gate**: the run refuses to start unless the musl binary
matches the working tree on all three of:

1. semantic version against `[workspace.package]` in `Cargo.toml`;
2. embedded build commit against `git rev-parse --short HEAD`;
3. no tracked `*.rs`, `Cargo.toml` or `Cargo.lock` newer than the binary, which
   is what catches an uncommitted edit that leaves the commit unchanged.

After the cross-distro and differential suites it also greps the verified
version string back out of each per-distro log, so a container that reached a
different binary through its bind mount is caught rather than assumed. There is
no override: the runners already check that a binary exists, and a run that
attributed a container failure to code the binary did not contain is what this
gate exists to prevent. Rebuild as your normal user, never under sudo, or the
artefacts in `~/.cache/cargo-target` end up root-owned:

```bash
cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli
```

**Output**: `test-results/release-readiness/`

| File | Contents |
|------|----------|
| `00-preflight.log` | Binary path, version, tree version, commit, working-tree status. Written before any suite |
| `<suite>.log` | That suite's own stdout and stderr |
| `<suite>-containers.log` | That suite's container clean and create output |
| `<suite>/` | The suite runner's own artefacts, copied aside |
| `summary.txt` | The status table |

The per-suite subdirectories exist because the sub-runners write to fixed names
in one shared results directory, so a suite's artefacts are copied aside as soon
as it finishes and stay attributable to it. The full and the differential suite
no longer collide there either: the differential run prefixes its per-distro
logs and its summary with `differential-`.

**Exit codes**:
- `0`: every selected suite passed
- `1`: pre-flight failed, or a suite reported `FAIL` or `NOTRUN`

A suite that could not run is reported as `NOTRUN`, never as a skip and never
as a pass, and it makes the exit code non-zero. `--dry-run` needs no privileges
and exits non-zero for the same reasons the real run would, so a session that
was going to abort in its first minute aborts before the root prompt.

**Dependencies**: root, `systemd-nspawn`, `machinectl`, `systemd-run`, `git`,
a current musl binary, a network throughout (the container bootstraps fetch
packages, and the GUI suite installs Playwright inside each container), and
`crates/hardener-ui/dist/index.html` from `trunk build --release` for the GUI
suite. Without the GUI artefacts every other suite still runs and the GUI suite
is recorded `NOTRUN`.

---

## Future Scripts

Additional utility scripts can be added here:
- Documentation generation
- Code generation helpers
- Performance benchmarking scripts

---
