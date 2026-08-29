# Releasing Linux Hardener

This document describes the versioning strategy and release process for Linux Hardener.

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
feat(cli): add --timings flag for scan command

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
./scripts/release/release.sh patch --dry-run

# Actual release, as the checklist runs it: tag locally, publish separately
./scripts/release/release.sh patch --no-push   # 0.1.0 -> 0.1.1
./scripts/release/release.sh minor --no-push   # 0.1.1 -> 0.2.0
./scripts/release/release.sh major --no-push   # 0.2.0 -> 1.0.0
```

**Use `--no-push`.** Without it the script performs steps 9 and 10 below,
publishing the branch and the tag in the same run that creates them, and the
release-readiness gates are then reading a tag the world already has. The flag
stops after the tag and prints the push commands, so a failed gate costs
`git tag -d` and a `git reset --hard HEAD~1` rather than a retraction. The
reasoning is under [Release Checklist](#release-checklist).

The release script automatically:
1. Runs tests and clippy
2. Auto-updates documentation (`update_all_docs.py --apply`):
   - Syncs "Last Updated" dates to git commit dates
   - Adds stub entries to docs/reference/file-map.md for new source files
   - Updates compliance framework control counts
   - Syncs version references to Cargo.toml
3. Validates documentation (`validate_all.py --quick`)
4. Updates the version in `Cargo.toml` (`workspace.package.version`), then runs
   `update_all_docs.py --apply` a second time so the four version markers
   (architecture.md, data-flow.md and README.md's `**Version**` markers, plus
   SECURITY.md's supported-release sentence) follow the bump rather than the
   version it replaced, and asserts all four against `Cargo.toml` afterwards.
   Also rewrites `packaging/assets/hardener.1` (the `.TH` header) and
   `src-tauri/tauri.conf.json`
5. Rewrites the test count in `README.md`, in `docs/assets/badges/tests.svg` and
   in the `tests` `message` in `scripts/badges/generate.js`, taken from the
   `cargo test` run in step 1, and the version in
   `docs/assets/badges/version.svg` and the `version` `message` beside it
6. Updates `CHANGELOG.md`
7. Refreshes `Cargo.lock` (`cargo update --workspace`)
8. Creates git commit and tag
9. Pushes to `main` on GitHub and GitLab **unless `--no-push` was given**
10. Pushes the release tag to both remotes, under the same condition

If documentation validation fails, you'll be prompted to continue or abort the release.

The test-count step asserts on the number of matches it made and aborts the
release when a pattern matches nothing. That is not defensive decoration: an
earlier version of it looked for a "Total Tests:" line that `README.md` had
stopped carrying, matched nothing, exited 0 and printed a success it had not
achieved, and the published count fell 86 tests behind across several releases.

> **Note:** The README status badges are vendored SVGs under
> `docs/assets/badges/`, generated by `scripts/badges/generate.js`, and
> **running the generator is always manual** (`cd scripts/badges && node
> generate.js`). The release script never runs it, because
> `scripts/badges/node_modules` is gitignored and a release must not need the
> network. Instead it rewrites both sides in place: step 3c writes the number in
> `docs/assets/badges/tests.svg` and the version in
> `docs/assets/badges/version.svg`, and the matching `message` literals in
> `generate.js`, so a later regeneration reproduces the badges rather than
> reverting them. That pairing is not optional: `validate_badges.py` compares the
> committed SVG against the generator, so moving one without the other fails the
> next validation run.
>
> The `aur` badge is the one left behind on purpose. It tracks the version
> actually published to the AUR, which is `packaging/PKGBUILD`, and that is
> bumped by hand; a badge validation failure between the release and that bump is
> the AUR step still being owed. See `scripts/badges/README.md`.

### Version Verification Only

```bash
./scripts/release/release.sh --verify
```

Compares the workspace version in `Cargo.toml` against six files and no
others: `docs/architecture/architecture.md` (`**Version:**`),
`packaging/assets/hardener.1` (the `.TH` header),
`src-tauri/tauri.conf.json`, `packaging/linux-hardener.spec` (`Version:`),
`packaging/debian/changelog` (the top stanza) and `docs/NEXT.md` (the
`**Current Version**` marker). No changes are made. `PKGBUILD` and
`.SRCINFO` are **not** checked here and are not touched by the release
script at all: they track the published AUR package, not the workspace
version.

`./scripts/release/release.sh --help` prints the full option list.

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
> either push a version tag to trigger automated builds or use `./scripts/release/release.sh`.

GitLab has no CI of its own; it receives `main` and the release tag as a push
mirror only, and `cargo audit` runs in GitHub CI on every push.

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

Use `git-cliff` for automated changelog. Conventional Commits parsing is
configured in `cliff.toml`.

```bash
# Install
cargo install git-cliff

# Generate full changelog
git-cliff --output CHANGELOG.md

# Generate changelog since last tag
git-cliff --unreleased --output CHANGELOG.md

# Preview without writing
git-cliff --unreleased

# Generate as if the unreleased commits were tagged vX.Y.Z
git-cliff --tag vX.Y.Z --output CHANGELOG.md
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

| File | Field | Purpose | Updated by `release.sh` |
|------|-------|---------|-------------------------|
| `Cargo.toml` | `workspace.package.version` | Rust crate version | Yes, step 3 |
| `Cargo.lock` | workspace entries | Lockfile | Yes, step 5 |
| `CHANGELOG.md` | `## [X.Y.Z]` | Release documentation | Yes, step 4 |
| `docs/architecture/architecture.md` | `**Version:**` | Architecture doc header | Yes, step 3b |
| `docs/reference/data-flow.md` | `**Version:**` | Data-flow doc header | Yes, step 3b |
| `README.md` | `**Version**:` | README footer | Yes, step 3b |
| `SECURITY.md` | supported-release sentence | Security policy | Yes, step 3b |
| `packaging/assets/hardener.1` | `.TH` header | Man page version | Yes, step 3b |
| `src-tauri/tauri.conf.json` | `version` | Desktop app version | Yes, step 3b |
| `scripts/badges/generate.js` | `version` `message` | Badge declaration | Yes, step 3c |
| `docs/assets/badges/version.svg` | rendered label | README version badge | Yes, step 3c |
| `packaging/PKGBUILD` | `pkgver` (reset `pkgrel=1`) | Arch/AUR package version | No, manual |
| `packaging/linux-hardener.spec` | `Version:` + `%changelog` | RPM package version | `Version:` yes, step 3d; `%changelog` manual |
| `packaging/debian/changelog` | top stanza `(X.Y.Z-1)` | Debian package version | header yes, step 3d; bullets manual |
| `scripts/badges/generate.js` | `aur` `message` | AUR badge declaration | No, manual, tracks `PKGBUILD` |
| `docs/assets/badges/aur.svg` | rendered label | README AUR badge | No, manual, tracks `PKGBUILD` |
| `SECURITY.md` | supported-versions table | Security policy | No, manual |
| `docs/NEXT.md` | `**Current Version**:` and the opening prose | Working notes | the number yes, step 3d; prose manual |
| `docs/ROADMAP.md` | current-release prose | Working notes | No, manual |

What remains manual is manual because it cannot be a version substitution:
the AUR badge pair tracks `PKGBUILD` rather than the tag, SECURITY.md's
supported-versions table is a table, and the prose in `docs/NEXT.md` and
`docs/ROADMAP.md` says things a number cannot. The pure version strings in
the spec, the debian stanza header and NEXT.md's marker are written by
step 3d and read back by `--verify`, so they can no longer drift between
two hand-edits; the `%changelog` stanza, the debian bullets and the prose
still wait on the checklist below.

The first four doc rows arrive through `update_all_docs.py`, which owns them
(architecture.md, data-flow.md and README.md's `**Version**` markers, plus
SECURITY.md's supported-release sentence, matched separately since it names the
release in prose rather than as a marker), and step 3b runs it **after** the
bump for that reason. It also runs at step 2b, before the bump, where it syncs
them to the version being replaced; that used to be the only run, so
`architecture.md` stayed correct through its own sed while `README.md` and
`data-flow.md` shipped a version behind. Step 3b now asserts all four against
the workspace version afterwards, and imports the target list from the updater
rather than restating it, so a target added there is covered here. Only
SECURITY.md's supported-versions table stays manual: growing it to name a new
series and retire an old one is a judgement call the sentence sync cannot make.

All crates use `version.workspace = true` to inherit the workspace version.
`Cargo.lock` workspace entries are refreshed with `cargo update --workspace` after the bump.

**AUR** (separate repo `ssh://aur@aur.archlinux.org/linux-hardener.git`): after the
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

# 3. Bump patch version and tag, publishing nothing
./scripts/release/release.sh patch --no-push

# 4. Merge back to main
git checkout main
git merge hotfix/0.1.1
git push origin main --tags
```

`--no-push` is not optional here either. A hotfix is the case where the
temptation to skip the gap between tagging and publishing is strongest and the
cost of a retraction is highest, and the reasoning under
[Release Checklist](#release-checklist) applies unchanged: the gates read the
tagged commit, so the tag has to exist before they run and stay unpublished
until they pass. This step read `release.sh patch` until 2026-08-18, which
tagged and pushed in one run and contradicted the instruction at the top of this
document.

---

## Release Checklist

Three phases, in order. The first is the one that used to be the whole list,
and a release that stops there ships correct crates with stale packaging.

Every item after the tag exists because nothing automates it: the AUR
publish is a submission, the changelog stanzas and the prose markers need a
human's sentences, and `PKGBUILD` moves only when the package does. (The
pure version strings - the spec's `Version:`, the debian stanza header,
NEXT.md's marker - are written by step 3d since 2026-08-29 and read back by
`--verify`; the rows are the manual half of [Version
Locations](#version-locations), which is the table to consult rather than
this list when you want to know what holds a version string.)

### Before the tag

- [ ] All tests pass (`cargo test --workspace`)
- [ ] No clippy warnings (`cargo clippy --workspace`)
- [ ] Code is formatted (`cargo fmt --check`)
- [ ] Validators pass (`python3 scripts/validate/validate_all.py`)
- [ ] CHANGELOG.md is updated, and the `[Unreleased]` section is the size of
      the release rather than the size of the last one. Measure it:
      `git rev-list --count --no-merges <last tag>..main`
- [ ] Documentation is current
- [ ] Security audit passes (`cargo audit`)
- [ ] Dependency policy passes (`cargo deny check`: licenses, advisories, bans)
- [ ] Working directory is clean
- [ ] On `main` branch

### At the tag

**The tag is created before it is published, and the gap between the two is
where the gates run.** This phase used to list the script first and the gates
second, which could not be carried out: the script tags and pushes in one run,
so by the time the tagged commit existed it was already on both remotes, and a
failing gate meant retracting a published tag rather than deleting a local one.
`--no-push` is what separates the two, and `git` already separates `tag` from
`push` for this reason.

- [ ] `./scripts/release/release.sh <major|minor|patch> --dry-run` first
- [ ] `./scripts/release/release.sh <major|minor|patch> --no-push`, which writes
      every "Yes" row of [Version Locations](#version-locations), commits the
      bump and creates the tag, **publishing nothing**
- [ ] Rebuild from the tagged commit and read the version back, because the
      gates below run against a binary and an artefact rather than a tree:
      `cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli`
      and, for the GUI suite, `cd crates/hardener-ui && trunk build --release`
- [ ] **The release-readiness gates G1 through G8 all pass at the tagged
      commit**, not only before the release branch was cut. G9 is this
      procedure, and it is the last gate for the reason that the other eight
      are about the tree it ships: issues closed or deferred with a reason,
      differential coverage or a stated ceiling, the five-distribution matrix
      green and dated against a binary whose version was read back, mutation
      testing on the integrity-critical crates, dead code resolved, the GUI
      exercised and eyeballed, every document current, and the claim ledger and
      ceiling document accurate. Re-running them at the tag is what makes them
      claims about the release rather than about a commit that preceded it.
- [ ] Publish, and only now, the branch and the tag to both remotes. The script
      prints these:

      git push origin main && git push origin vX.Y.Z
      git push gitlab main && git push gitlab vX.Y.Z

- [ ] **If any gate fails, unwind instead of pushing:** `git tag -d vX.Y.Z` then
      `git reset --hard HEAD~1`. That is the whole reason the tag was withheld,
      and it is only cheap while nothing has fetched it

### After the tag, all by hand

- [ ] `packaging/PKGBUILD`: bump `pkgver`, reset `pkgrel=1`
- [ ] `packaging/linux-hardener.spec`: a new `%changelog` stanza (`Version:` was
      already bumped by step 3d at the tag)
- [ ] `packaging/debian/changelog`: fill the bullets of the top stanza step 3d
      inserted with a TODO header
- [ ] Publish to the AUR, following the note under [Version
      Locations](#version-locations). Read it before starting: while the
      one-time rename note stands, publishing is a **new submission** and not a
      push to the existing package
- [ ] AUR badge pair once that package is live, not before: the `aur` `message`
      in `scripts/badges/generate.js` and `docs/assets/badges/aur.svg`. They
      track `PKGBUILD` rather than the tag, so a badge updated at the tag
      advertises a package nobody can install yet
- [ ] `SECURITY.md`: the supported-versions table gains the new series with the
      previous one moved down. (The current-release sentence is not a manual
      step here: step 3b already wrote it, same mechanism as the README.md and
      architecture.md rows.)
- [ ] `docs/ROADMAP.md` and `docs/NEXT.md`: the prose naming the current
      release. Name the tag and no commit count; a count is stale the day it is
      written, which is why `git rev-list --count v<X.Y.Z>..main` is given
      instead of a number
- [ ] **Install the first packaged build on a real host and run it** before
      announcing anything. A package that builds is not a package that installs
- [ ] Delete the one-time rename note in this file once the release carrying it
      has shipped. A one-time note left in place is a permanent instruction to
      do a one-time thing

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

**The project ships no git hook.** `.git/hooks/` is not tracked and git never
clones hooks, so a fresh clone runs no naming validation on commit and nothing
in this repository installs one. Any hook is hand-installed and personal; see
[scripts/README.md](../../scripts/README.md) for the one-liner that runs
`validate_naming.py`. This sentence read "The project includes a pre-commit
hook" until 2026-08-18, which told a new contributor that naming was enforced
for them when it was not.

Additional hooks can be added the same way:

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

**Last Updated**: 2026-08-30
