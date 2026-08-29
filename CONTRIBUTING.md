# Contributing to Linux Hardener

Thank you for your interest in contributing to Linux Hardener! This document provides guidelines and information for contributors.

## Code of Conduct

This project adheres to a code of conduct that all contributors are expected to follow. Please be respectful, inclusive, and professional in all interactions.

## Getting Started

### Prerequisites

- Rust 1.88 or later
- Linux system (for full functionality testing)
- Git

### Development Setup

```bash
# Clone the repository
git clone https://github.com/tidynest/linux-hardener.git
cd linux-hardener

# Format code
cargo fmt --all

# Lint (this is the gate: warnings are errors)
cargo clippy --workspace --all-targets -- -D warnings

# Build the project
cargo build --workspace

# Run tests
cargo test --workspace
```

Those four commands are the full local gate. Run all four before opening a pull
request, in that order.

This is a virtual workspace, so `cargo build` and `cargo test` without
`--workspace` already select every member. The flag is written out because the
CI jobs use it with `--exclude`, and matching the shape makes the difference
easy to see.

`--workspace` includes `linux-hardener-desktop` (the Tauri backend under
`src-tauri/`) and `hardener-ui` (the Leptos frontend), which need GTK and
WebKitGTK development packages present on the host. CI skips both crates for
exactly that reason (see `WORKSPACE_EXCLUDE` in `.github/workflows/ci.yml`). If
you have not installed those system packages, scope your commands to the crate
you are changing, for example `cargo test -p hardener-plugins`. System packages,
rustup targets and the desktop and WASM builds are covered in
[docs/contributing/building.md](docs/contributing/building.md).

### Git Hooks

This repository tracks no git hooks and nothing in it installs one. A
`.git/hooks/pre-commit` running `scripts/validate/validate_naming.py` is a local
convenience some maintainers add by hand; **a fresh clone has none, and there is
no pre-push hook either.** Nothing local runs clippy, the tests, the format check
or the naming validator for you, so a green commit says nothing at all unless you
installed that hook yourself. Run the four gate commands above, and run
`./scripts/validate/validate_naming.py` before you commit.

### Finding Something to Work On

Open work lives on the [issue tracker](https://github.com/tidynest/linux-hardener/issues),
and that is the right place to start rather than guessing at a gap:

- [`good first issue`](https://github.com/tidynest/linux-hardener/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
  marks self-contained work with the context already written down.
- [`help wanted`](https://github.com/tidynest/linux-hardener/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
  marks issues where a contributor is actively welcome.
- Issues carry a priority label (`P2`, `P3`) and a kind label (`bug`,
  `enhancement`, `testing`, `documentation`, `packaging`, `security`).

Please comment on an issue before starting substantial work on it, so two people
do not write the same patch.

### Development Scripts

The `scripts/` directory contains automation tools for development:

```bash
# Validate all documentation is in sync with code
./scripts/validate/validate_all.py

# Auto-fix documentation (dates, counts, stubs)
./scripts/validate/update_all_docs.py --apply

# Check naming conventions
./scripts/validate/validate_naming.py

# Release a new version (dry-run first!)
./scripts/release/release.sh patch --dry-run
```

See [scripts/README.md](scripts/README.md) for complete documentation of all scripts.

`validate_naming.py` reports errors and warnings separately, and only errors
block a commit. It currently prints 0 errors alongside a large body of
pre-existing warnings (mostly `[Abbreviation]` notes on names such as `cmd` and
`ctx`). Those are known and are not yours to clear: do not rename existing
symbols to silence them. Keep the error count at zero.

## Coding Standards

### Rust Conventions

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `rustfmt` for consistent formatting (`cargo fmt --all`)
- All code must pass `cargo clippy --workspace --all-targets -- -D warnings`
- Prefer a let-chain over a nested `if`: write
  `if let Some(a) = x && let Some(b) = a.y()` rather than one `if let` inside
  another. The workspace is on edition 2024 and the codebase uses this
  throughout
- Maintain >90% test coverage for new code

### Naming Conventions

Please follow the naming conventions documented in [docs/reference/naming-conventions.md](docs/reference/naming-conventions.md). Key points:

- **Structs/Enums/Traits**: PascalCase
- **Functions/Methods**: snake_case
- **Constants**: SCREAMING_SNAKE_CASE
- **Modules/Files**: snake_case
- **Crates**: kebab-case

### British English

This project uses British English for all documentation, comments, and user-facing text:

- `colour` not `color`
- `authorise` not `authorize`
- `minimisation` not `minimization`
- `behaviour` not `behavior`

CSS property names and other language keywords keep their own spelling, so
`color:` in `styles.css` stays as it is.

### Punctuation

Documentation and comments use ASCII punctuation only. **No em dashes and no en
dashes**; use a comma, a colon, a pair of brackets or a full stop instead. No
tracked Markdown file in the repository contains either character, and a patch
that introduces one will be sent back.

### Code Quality

- Avoid `unwrap()` and `panic!()` - use proper error handling
- All public APIs must be documented
- Security-critical code must include safety comments
- Use meaningful variable and function names

## Development Workflow

### Branching Strategy

- `main` - primary development branch (default)
- Features: `feat/description`
- Bug fixes: `fix/description`
- Test work: `test/description`
- Documentation: `docs/description`

The prefix matches the commit type below, so `feat/multi-host-batch-scan` and
`fix/rollback-recreates-vanished-directory` are the shape the history uses.

### Making Changes

1. Fork the repository
2. Create a branch from `main`, prefixed as above
3. Make your changes
4. Write/update tests
5. Run the four gate commands
6. Submit a pull request

### Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/) for automated changelog generation:

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

**Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`,
`ci`, `chore`, `security`. Only the type is significant to the changelog
generator: `cliff.toml` groups commits by type, and `security` is also inferred
from a body mentioning security.

**Scope** names the area you touched and is not drawn from a fixed list.
The ones the history uses most are `ui`, `suite`, `cli`, `core`, `common`,
`state`, `config`, `compliance`, `scheduler`, `desktop`, `release`, `packaging`,
`containers`, a plugin name (`ssh`, `pam`, `kernel`, `firewall`, `permissions`,
`services`, `audit`, `mac`), or a document (`readme`, `changelog`, `guide`).
Pick the narrowest one that is true.

Examples:
```bash
feat(cli): add --compliance flag for scan command
fix(plugins): correct SSH directive parsing for comments
docs(readme): update installation instructions
```

For details, see [docs/contributing/releasing.md](docs/contributing/releasing.md).

## Pull Request Checklist

Before submitting a PR, ensure:

- [ ] Code is formatted (`cargo fmt --all`)
- [ ] Clippy passes (`cargo clippy --workspace --all-targets -- -D warnings`)
- [ ] Code compiles (`cargo build --workspace`)
- [ ] All tests pass (`cargo test --workspace`)
- [ ] Documentation is updated, and `./scripts/validate/validate_all.py` passes
- [ ] Commit messages are clear
- [ ] PR description explains the changes, and names the issue it closes

No hook checks these for you. See [Git Hooks](#git-hooks) above.

## Types of Contributions

### Bug Reports

When filing a bug report, please include:

- Linux distribution and version
- Rust version (`rustc --version`)
- Steps to reproduce
- Expected vs actual behaviour
- Relevant log output

### Feature Requests

For feature requests, please include:

- Description of the feature
- Use case / motivation
- Potential implementation approach (if known)

### Security Plugins

If you want to contribute a new security plugin, start with
[docs/contributing/plugin-authoring.md](docs/contributing/plugin-authoring.md),
then:

1. Review existing plugins in `crates/hardener-plugins/`
2. Follow the `HardeningPlugin` trait interface
3. Include comprehensive test coverage
4. Document the security controls implemented
5. Declare per-control coverage from the plugin's `coverage()` function and
   register it in `coverage_table()` in `hardener-plugins`, so the report can
   emit a real Pass or Fail instead of `ManualReview`
6. Map to relevant compliance frameworks where applicable. There are ten, and
   `ComplianceFramework::ALL` in `hardener-types` is the single source for the
   list: CIS, STIG, NIST 800-53, PCI-DSS, HIPAA, GDPR, ISO 27001:2022, SOC 2,
   NIST 800-171 and FedRAMP

### Documentation

Documentation improvements are always welcome:

- Fix typos or unclear explanations
- Add examples
- Improve installation instructions
- Translate documentation

[docs/contributing/documentation.md](docs/contributing/documentation.md)
describes the documentation conventions and the validators. Run
`./scripts/validate/validate_all.py` after a documentation change: several
counts and tables in the docs are checked against the code that produces them.

## Testing

[docs/contributing/testing.md](docs/contributing/testing.md) is the full guide,
covering the container fixtures, the cross-distro suite and the differential
suite. What follows is the minimum you need to run locally.

### Running Tests

```bash
# Run all tests
cargo test --workspace

# Run tests for a specific crate
cargo test -p hardener-core

# Run tests with output
cargo test --workspace -- --nocapture

# Run ignored tests (require root, or a fixture, or both)
sudo cargo test --workspace -- --ignored
```

Most ignored tests want `SSH_TEST_HOST` pointing at a booted container
(`scripts/containers/boot-ssh-test-container.sh`); the rest need root because
they modify real system configuration. Without the fixture they are skipped, not
failed.

`hardener-cli` is a binary crate, so use `cargo test -p hardener-cli` rather
than `--lib`, which selects nothing there.

A name filter such as `cargo test rollback` skips every test whose name does not
contain the word, including tests that cover the same behaviour under a
different name. The full suite is the only complete answer.

### Writing Tests

- Unit tests go in the same file as the code
- Integration tests go in `tests/` directories
- Use descriptive test names: `test_kernel_plugin_scan_detects_insecure_aslr`
- Use `#[tokio::test]` for async tests; the plugin `scan`/`apply`/`rollback`/`validate` methods are async, while pure helper tests stay synchronous `#[test]`

## Project Structure

```
linux-hardener/
├── crates/
│   ├── hardener-types/       # WASM-compatible shared type definitions
│   ├── hardener-core/        # Core plugin infrastructure
│   ├── hardener-common/      # Shared utilities and error types
│   ├── hardener-distro/      # Distribution detection
│   ├── hardener-plugins/     # Security plugins
│   ├── hardener-state/       # State management
│   ├── hardener-compliance/  # Compliance mapping (PDF export via the default-on `pdf` feature)
│   ├── hardener-scheduler/   # Scheduled scanning daemon
│   ├── hardener-cli/         # Command-line interface (binary "hardener")
│   └── hardener-ui/          # Leptos WASM frontend
├── src-tauri/                # Desktop app backend (package linux-hardener-desktop)
├── gui-tests/                # Playwright end-to-end suite; runs only inside a
│                             # container, via scripts/test/gui/run-gui-tests.sh
├── packaging/                # PKGBUILD, RPM spec, Debian, polkit policy, man page
├── scripts/                  # Development utilities
├── docs/                     # Documentation
└── .github/workflows/        # GitHub Actions CI/CD (connected and functional)
```

## Releasing

See [docs/contributing/releasing.md](docs/contributing/releasing.md) for the complete release process, including:

- Semantic versioning strategy
- Conventional commits format
- Release script usage
- CI/CD pipeline details

## Review Process

1. A maintainer will review your PR
2. Feedback may be provided for changes
3. Once approved, the PR will be merged
4. Significant contributions will be acknowledged in release notes

## License

By contributing, you agree that your contributions will be licensed under the Apache License, Version 2.0, the same license as the project.

## Contact

- **Email**: tidynest@proton.me
- **Issues**: [GitHub Issues](https://github.com/tidynest/linux-hardener/issues)
- **Security**: do not open a public issue. [SECURITY.md](SECURITY.md) has the
  private reporting route.

Thank you for contributing to Linux Hardener!

**Last Updated**: 2026-08-18
