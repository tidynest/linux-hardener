# Releasing Linux System Hardener

This document describes the versioning strategy and release process for Linux System Hardener.

---

## Versioning Strategy

This project follows [Semantic Versioning 2.0.0](https://semver.org/):

```
MAJOR.MINOR.PATCH
```

- **MAJOR**: Breaking changes to CLI, config format, or plugin API
- **MINOR**: New features, plugins, or backwards-compatible enhancements
- **PATCH**: Bug fixes, security patches, documentation updates

### Pre-release Versions

For pre-release versions, use suffixes:

- `1.0.0-alpha.1` - Alpha releases (incomplete features)
- `1.0.0-beta.1` - Beta releases (feature complete, testing)
- `1.0.0-rc.1` - Release candidates (final testing)

---

## Commit Message Convention

We use [Conventional Commits](https://www.conventionalcommits.org/) for automated changelog generation:

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type | Description | CHANGELOG Section |
|------|-------------|-------------------|
| `feat` | New feature | Added |
| `fix` | Bug fix | Fixed |
| `docs` | Documentation | Documentation |
| `style` | Formatting (no code change) | Styling |
| `refactor` | Code restructuring | Changed |
| `perf` | Performance improvement | Performance |
| `test` | Adding tests | Testing |
| `build` | Build system changes | Build |
| `ci` | CI/CD changes | CI/CD |
| `chore` | Maintenance tasks | Miscellaneous |
| `security` | Security improvements | Security |

### Scopes

| Scope | Description |
|-------|-------------|
| `cli` | Command-line interface |
| `core` | Core plugin framework |
| `plugins` | Plugin implementations |
| `config` | Configuration system |
| `state` | Checkpoint/rollback system |
| `compliance` | Compliance reporting |
| `scheduler` | Scheduled scanning and daemon |
| `ui` | Desktop GUI |
| `deps` | Dependencies |

### Examples

```bash
# Feature
feat(cli): add --compliance flag for scan command

# Bug fix
fix(plugins): correct SSH directive parsing for comments

# Breaking change
feat(config)!: change config file format from JSON to TOML

BREAKING CHANGE: Config files must be migrated to TOML format.
```

---

## Release Process

### Quick Release (Recommended)

Use the release script:

```bash
# Dry run first
./scripts/release.sh patch --dry-run

# Actual release
./scripts/release.sh patch   # 0.1.0 -> 0.1.1
./scripts/release.sh minor   # 0.1.1 -> 0.2.0
./scripts/release.sh major   # 0.2.0 -> 1.0.0
```

The release script automatically:
1. Runs tests and clippy
2. Auto-updates documentation (`update_all_docs.py --apply`):
   - Syncs "Last Updated" dates to git commit dates
   - Adds stub entries to FILE_MAP.md for new source files
   - Updates compliance framework control counts
   - Syncs version references to Cargo.toml
3. Validates documentation (`validate_all.py --quick`)
4. Updates version in `Cargo.toml` and documentation files
5. Updates test count in `README.md`
6. Updates `CHANGELOG.md`
7. Creates git commit and tag
8. Pushes to `main` on GitHub and GitLab
9. Pushes the release tag to both remotes

If documentation validation fails, you'll be prompted to continue or abort the release.

### Manual Release

If you prefer manual control:

```bash
# 1. Ensure clean working directory
git status

# 2. Run tests
cargo test --workspace
cargo clippy --workspace

# 3. Update version in Cargo.toml
vim Cargo.toml  # Update workspace.package.version

# 4. Update CHANGELOG.md
vim CHANGELOG.md  # Move Unreleased to new version section

# 5. Update Cargo.lock
cargo update --workspace

# 6. Commit
git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "chore(release): bump version to X.Y.Z"

# 7. Tag
git tag -a vX.Y.Z -m "Release X.Y.Z"

# 8. Push
git push origin main --tags
git push gitlab main --tags
```

### Using cargo-release

For those who prefer `cargo-release`:

```bash
# Install
cargo install cargo-release

# Release (follows release.toml configuration)
cargo release patch --execute
cargo release minor --execute
cargo release major --execute
```

---

## CI/CD Pipelines

### GitHub Actions

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | Push/PR to `main` | Tests, clippy, fmt, build |
| `release.yml` | Tag `v*` | Build binaries, create release |

> **Note:** GitHub Actions CI/CD is connected and functional. Workflows trigger on
> push/PR to the `main` branch for continuous integration. For releases, you can
> either push a version tag to trigger automated builds or use `./scripts/release.sh`.

### GitLab CI

| Stage | Jobs | Purpose |
|-------|------|---------|
| check | check, fmt, clippy | Code quality |
| test | test, security-audit | Testing |
| build | build:linux-* | Release binaries |
| release | release | Create GitLab release |

### Artifacts

Releases produce these artifacts:

| Artifact | Target | Description |
|----------|--------|-------------|
| `hardener-linux-x86_64.tar.gz` | x86_64-unknown-linux-gnu | Standard Linux binary |
| `hardener-linux-x86_64-musl.tar.gz` | x86_64-unknown-linux-musl | Static binary (portable) |
| `hardener-linux-aarch64.tar.gz` | aarch64-unknown-linux-gnu | ARM64 Linux binary |

### Branch Synchronisation

The `main` branch is kept in sync on both GitHub and GitLab. The release script handles this automatically:

```
origin (GitHub)     gitlab (GitLab)
└── main    <──────>  main
```

When releasing, the script pushes to `main` on both remotes.

---

## Changelog Generation

### Automatic Generation

Use `git-cliff` for automated changelog:

```bash
# Install
cargo install git-cliff

# Generate full changelog
git-cliff --output CHANGELOG.md

# Generate changelog since last tag
git-cliff --unreleased --output CHANGELOG.md

# Preview without writing
git-cliff --unreleased
```

### Manual Maintenance

The CHANGELOG follows [Keep a Changelog](https://keepachangelog.com/) format:

```markdown
## [Unreleased]

### Added
- New feature description

### Changed
- Changed behaviour description

### Fixed
- Bug fix description

### Security
- Security improvement description
```

---

## Version Locations

Version is defined in the workspace root and inherited by all crates:

| File | Field | Purpose |
|------|-------|---------|
| `Cargo.toml` | `workspace.package.version` | Rust crate version |
| `CHANGELOG.md` | `## [X.Y.Z]` | Release documentation |
| `src-tauri/tauri.conf.json` | `version` | Desktop app version |
| `packaging/PKGBUILD` | `pkgver` (reset `pkgrel=1`) | Arch/AUR package version |
| `packaging/linux-system-hardener.spec` | `Version:` + `%changelog` | RPM package version |
| `packaging/debian/changelog` | top stanza `(X.Y.Z-1)` | Debian package version |

All crates use `version.workspace = true` to inherit the workspace version.
`Cargo.lock` workspace entries are refreshed with `cargo update --workspace` after the bump.

**AUR** (separate repo `ssh://aur@aur.archlinux.org/linux-system-hardener.git`): after the
`vX.Y.Z` tag is pushed, bump `pkgver`, run `updpkgsums` to fill `sha256sums` from the tag
tarball, regenerate `.SRCINFO` (`makepkg --printsrcinfo > .SRCINFO`), then commit and push.

---

## Hotfix Process

For urgent fixes to released versions:

```bash
# 1. Create hotfix branch from tag
git checkout -b hotfix/0.1.1 v0.1.0

# 2. Apply fix
vim src/...
git commit -m "fix(cli): critical bug description"

# 3. Bump patch version
./scripts/release.sh patch

# 4. Merge back to main
git checkout main
git merge hotfix/0.1.1
git push origin main --tags
```

---

## Pre-release Checklist

Before any release:

- [ ] All tests pass (`cargo test --workspace`)
- [ ] No clippy warnings (`cargo clippy --workspace`)
- [ ] Code is formatted (`cargo fmt --check`)
- [ ] CHANGELOG.md is updated
- [ ] Documentation is current
- [ ] Security audit passes (`cargo audit`)
- [ ] Dependency policy passes (`cargo deny check` — licenses, advisories, bans)
- [ ] Working directory is clean
- [ ] On `main` branch

---

## Tooling Setup

### Required Tools

```bash
# Rust toolchain
rustup update stable

# Release tools
cargo install cargo-release
cargo install git-cliff
cargo install cargo-audit
```

### Recommended Git Hooks

The project includes a pre-commit hook for naming conventions. Additional hooks can be added:

```bash
# .git/hooks/pre-push (example)
#!/bin/bash
cargo test --workspace
```

---

## Support

For release issues:

1. Check CI pipeline logs
2. Verify all prerequisites are met
3. Consult this document
4. Open an issue if needed

**Last Updated**: 2026-05-24
