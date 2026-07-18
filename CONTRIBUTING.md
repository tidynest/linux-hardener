# Contributing to Linux System Hardener

Thank you for your interest in contributing to Linux System Hardener! This document provides guidelines and information for contributors.

## Code of Conduct

This project adheres to a code of conduct that all contributors are expected to follow. Please be respectful, inclusive, and professional in all interactions.

## Getting Started

### Prerequisites

- Rust 1.85 or later
- Linux system (for full functionality testing)
- Git

### Development Setup

```bash
# Clone the repository
git clone https://github.com/tidynest/linux-system-hardener.git
cd linux-system-hardener

# Build the project
cargo build

# Run tests
cargo test

# Run clippy for linting
cargo clippy --all-targets --all-features

# Format code
cargo fmt
```

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

## Coding Standards

### Rust Conventions

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `rustfmt` for consistent formatting
- All code must pass `cargo clippy` without warnings
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

### Code Quality

- Avoid `unwrap()` and `panic!()` - use proper error handling
- All public APIs must be documented
- Security-critical code must include safety comments
- Use meaningful variable and function names

## Development Workflow

### Branching Strategy

- `main` - primary development branch (default)
- Feature branches: `feature/description`
- Bug fixes: `fix/description`

### Making Changes

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes
4. Write/update tests
5. Run the full test suite
6. Submit a pull request

### Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/) for automated changelog generation:

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

**Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `security`

**Scopes**: `cli`, `core`, `plugins`, `config`, `state`, `compliance`, `scheduler`, `ui`, `deps`

Examples:
```bash
feat(cli): add --compliance flag for scan command
fix(plugins): correct SSH directive parsing for comments
docs(readme): update installation instructions
```

For details, see [docs/contributing/releasing.md](docs/contributing/releasing.md).

## Pull Request Checklist

Before submitting a PR, ensure:

- [ ] Code compiles without warnings (`cargo build`)
- [ ] All tests pass (`cargo test`)
- [ ] Clippy passes (`cargo clippy --all-targets`)
- [ ] Code is formatted (`cargo fmt --check`)
- [ ] Documentation is updated
- [ ] Commit messages are clear
- [ ] PR description explains the changes

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

If you want to contribute a new security plugin:

1. Review existing plugins in `crates/hardener-plugins/`
2. Follow the `HardeningPlugin` trait interface
3. Include comprehensive test coverage
4. Document the security controls implemented
5. Map to relevant compliance frameworks (CIS, STIG, NIST, PCI-DSS, HIPAA, GDPR, ISO 27001) where applicable

### Documentation

Documentation improvements are always welcome:

- Fix typos or unclear explanations
- Add examples
- Improve installation instructions
- Translate documentation

## Testing

### Running Tests

```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p hardener-core

# Run tests with output
cargo test -- --nocapture

# Run ignored tests (requires root)
sudo cargo test -- --ignored
```

### Writing Tests

- Unit tests go in the same file as the code
- Integration tests go in `tests/` directories
- Use descriptive test names: `test_kernel_plugin_scan_detects_insecure_aslr`
- Use `#[tokio::test]` for async tests (all plugin tests are async)

## Project Structure

```
linux-system-hardener/
├── crates/
│   ├── hardener-types/       # WASM-compatible shared type definitions
│   ├── hardener-core/        # Core plugin infrastructure
│   ├── hardener-common/      # Shared utilities and error types
│   ├── hardener-distro/      # Distribution detection
│   ├── hardener-plugins/     # Security plugins
│   ├── hardener-state/       # State management
│   ├── hardener-compliance/  # Compliance mapping (PDF behind feature flag)
│   ├── hardener-scheduler/   # Scheduled scanning daemon
│   ├── hardener-cli/         # Command-line interface
│   └── hardener-ui/          # Leptos WASM frontend
├── src-tauri/                # Desktop app backend
├── scripts/                  # Development utilities
├── docs/                     # Documentation
├── .github/workflows/        # GitHub Actions CI/CD (connected and functional)
└── .gitlab-ci.yml            # GitLab CI/CD (also functional)
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
- **Issues**: [GitHub Issues](https://github.com/tidynest/linux-system-hardener/issues)

Thank you for contributing to Linux System Hardener!

**Last Updated**: 2026-06-28
