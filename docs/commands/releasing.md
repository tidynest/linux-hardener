# Release Commands

Commands for versioning, releasing, and changelog generation.

For the full release workflow (branching strategy, hotfix process, pre-release checklist), see [../RELEASING.md](../RELEASING.md).

---

## Release Script

### Dry run (preview all steps without making changes)

```bash
./scripts/release.sh patch --dry-run
./scripts/release.sh minor --dry-run
./scripts/release.sh major --dry-run
```

Shows exactly what would happen: version bump, files modified, tests run, tags created, remotes pushed — but writes nothing and pushes nothing.

### Actual release

```bash
./scripts/release.sh patch              # 0.3.3 -> 0.3.4
./scripts/release.sh minor              # 0.3.3 -> 0.4.0
./scripts/release.sh major              # 0.3.3 -> 1.0.0
```

Performs the full release sequence:

1. Runs `cargo test --workspace` and `cargo clippy --workspace`
2. Auto-updates documentation (`./scripts/update_all_docs.py --apply`)
3. Validates documentation (`./scripts/validate_all.py --quick`)
4. Bumps version in `Cargo.toml`, `CHANGELOG.md`, `README.md`, `docs/architecture/ARCHITECTURE.md`
5. Runs `cargo update --workspace`
6. Creates a git commit and annotated tag (`vX.Y.Z`)
7. Pushes `main` and the tag to both `origin` (GitHub) and `gitlab` remotes

### Version verification only

```bash
./scripts/release.sh --verify
```

Checks that the version string is consistent across all files (`Cargo.toml`, `tauri.conf.json`, documentation). No changes are made.

### Help

```bash
./scripts/release.sh --help
```

---

## Changelog Generation

Uses [git-cliff](https://git-cliff.org/) with Conventional Commits. Configured in `cliff.toml`.

### Full changelog

```bash
git cliff --output CHANGELOG.md
```

Regenerates the entire `CHANGELOG.md` from all tagged commits.

### Unreleased changes only

```bash
git cliff --unreleased
```

Previews changes since the last tag (prints to stdout).

### Generate for a specific version

```bash
git cliff --tag v0.3.4 --output CHANGELOG.md
```

Generates changelog as if the current unreleased commits were tagged `v0.3.4`.

---

## cargo-release (Alternative)

An alternative to `release.sh` using [cargo-release](https://github.com/crate-ci/cargo-release). Follows `release.toml` configuration.

### Install

```bash
cargo install cargo-release
```

### Release

```bash
cargo release patch --execute
cargo release minor --execute
cargo release major --execute
```

Without `--execute`, it performs a dry run.

**Last Updated**: 2026-02-26
