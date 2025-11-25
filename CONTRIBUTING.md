# Contributing to Linux System Hardener

Thank you for your interest in contributing to Linux System Hardener! This document provides guidelines and information for contributors.

## Code of Conduct

This project adheres to a code of conduct that all contributors are expected to follow. Please be respectful, inclusive, and professional in all interactions.

## Getting Started

### Prerequisites

- Rust 1.75 or later
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

## Coding Standards

### Rust Conventions

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `rustfmt` for consistent formatting
- All code must pass `cargo clippy` without warnings
- Maintain >80% test coverage for new code

### Naming Conventions

Please follow the naming conventions documented in [docs/NAMING_CONVENTIONS.md](docs/NAMING_CONVENTIONS.md). Key points:

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

- `main` - stable release branch
- `master` - development branch (default)
- Feature branches: `feature/description`
- Bug fixes: `fix/description`

### Making Changes

1. Fork the repository
2. Create a feature branch from `master`
3. Make your changes
4. Write/update tests
5. Run the full test suite
6. Submit a pull request

### Commit Messages

- Use clear, descriptive commit messages
- Start with a verb in imperative mood: "Add", "Fix", "Update"
- Keep the first line under 72 characters
- Add details in the body if needed

Example:
```
Add kernel parameter validation for ASLR settings

- Implement check for kernel.randomize_va_space
- Add test cases for valid and invalid values
- Update documentation
```

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
5. Map to relevant compliance frameworks (CIS, STIG) where applicable

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

## Project Structure

```
linux-system-hardener/
├── crates/
│   ├── hardener-core/        # Core plugin infrastructure
│   ├── hardener-common/      # Shared types
│   ├── hardener-distro/      # Distribution detection
│   ├── hardener-plugins/     # Security plugins
│   ├── hardener-state/       # State management
│   ├── hardener-compliance/  # Compliance mapping
│   └── hardener-ui/          # User interface
├── src-tauri/                # Desktop app backend
├── scripts/                  # Development utilities
└── docs/                     # Documentation
```

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
