# Project Scripts

This directory contains utility scripts for the Linux Hardening Tool project.

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
# Future integration (Phase 5, Week 27)
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

[master a1b2c3d] Add PAM plugin structure
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
1. Validates you're on main/master branch with clean working directory
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

## Future Scripts

Additional utility scripts can be added here:
- Distribution testing automation
- Documentation generation
- Code generation helpers
- Performance benchmarking scripts

---

**Last Updated**: 2025-12-04
