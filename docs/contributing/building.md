# Building Commands

Commands for compiling the CLI, desktop GUI, and WASM frontend.

The workspace is on Rust **edition 2024** (`Cargo.toml`, `workspace.package`), so
it needs a toolchain of **1.85 or newer**: that edition stabilised in 1.85, which
is where the figure comes from rather than from a measurement. It is declared as
`rust-version = "1.85"` beside the edition and inherited by every member, so
cargo refuses an older toolchain with a message naming the version rather than
letting it fail later as a compiler error. The README's rust badge says the same
(`scripts/badges/generate.js`) and `validate_badges.py` holds it to the declared
value.

There is still no `rust-toolchain.toml` pinning a version, and CI installs
`dtolnay/rust-toolchain@stable`, so the tree is expected to build on current
stable. **Nothing builds it on 1.85**, so the declaration states the intended
floor rather than a verified one: code that quietly starts requiring a newer
release would compile here, compile in CI, and fail only for someone on 1.85. A
CI job building on the declared version is what would close that.

Binary paths below assume the default cargo target directory (`./target`). With
`CARGO_TARGET_DIR` or a `[build] target-dir` in `~/.cargo/config.toml`, output
lands under the configured directory instead; the repository's test scripts
resolve this automatically (see `docs/contributing/testing.md`).

---

## CLI Binary

### Debug build (fast compilation, no optimisations)

```bash
cargo build -p hardener-cli
```

Binary: `target/debug/hardener`

### Release build (LTO, stripped, optimised)

```bash
cargo build --release -p hardener-cli
```

Binary: `target/release/hardener`

Build takes longer (minutes) but produces a smaller, faster binary. Uses the release profile defined in workspace `Cargo.toml` (LTO, codegen-units=1, opt-level=3, stripped).

### Full workspace build

```bash
cargo build                    # Debug, all crates
cargo build --release          # Release, all crates
```

Builds every crate in the workspace including CLI, core, plugins, state, and the Tauri backend.

### Cross-compilation targets

```bash
# Static musl binary (used for container testing)
cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli

# Standard GNU binary
cargo build --release --target x86_64-unknown-linux-gnu -p hardener-cli

# ARM64 binary
cargo build --release --target aarch64-unknown-linux-gnu -p hardener-cli
```

Binary locations follow the pattern `target/<target-triple>/release/hardener`.

These require the corresponding rustup targets to be installed (see "Rustup Targets" below).

---

## Desktop GUI (Tauri)

### Development mode (hot-reload)

```bash
./scripts/dev/tauri-dev.sh
```

Preferred method. The script auto-detects your session type (Wayland/X11), applies NVIDIA and Hyprland workarounds, checks that required system packages are installed, and then launches `cargo tauri dev`. It also exports `HARDENER_UI_DIR` (the absolute path to `crates/hardener-ui`) so Tauri's `beforeDevCommand` and `beforeBuildCommand` hooks locate the frontend regardless of the working directory they run from.

Internally, Tauri runs `trunk serve` (WASM frontend on port 1420) and compiles the Rust backend. Changes to either trigger a rebuild.

To pass extra arguments through to `cargo tauri dev`:

```bash
./scripts/dev/tauri-dev.sh -- --release
```

The direct command without the wrapper script:

```bash
cargo tauri dev
```

This skips the environment detection and NVIDIA workarounds. Use the script if you are on Wayland, Hyprland, or NVIDIA hardware.

### Production build

```bash
cargo tauri build
```

Produces distributable packages: `.AppImage`, `.deb`, and `.rpm` (configured in `src-tauri/tauri.conf.json`).

### Environment info

```bash
cargo tauri info
```

Prints Tauri version, system dependencies, and environment details for debugging build issues.

---

## WASM Frontend (Trunk)

The Leptos frontend in `crates/hardener-ui/` is compiled to WASM via Trunk. You rarely need these directly; `cargo tauri dev` and `cargo tauri build` run them automatically.

### Dev server

```bash
cd crates/hardener-ui && trunk serve
```

Starts a development server on `http://127.0.0.1:1420` with file watching and automatic WASM rebuilds. This is what `cargo tauri dev` runs as its `beforeDevCommand`; the actual hook is `cd "${HARDENER_UI_DIR:-crates/hardener-ui}" && trunk serve`, so it honours the `HARDENER_UI_DIR` override set by `tauri-dev.sh` and falls back to `crates/hardener-ui` otherwise.

### Production WASM build

```bash
cd crates/hardener-ui && trunk build --release
```

Compiles optimised WASM into `crates/hardener-ui/dist/`. This is what `cargo tauri build` runs as its `beforeBuildCommand` (the hook is `cd "${HARDENER_UI_DIR:-crates/hardener-ui}" && trunk build --release`).

### Debug WASM build

```bash
cd crates/hardener-ui && trunk build
```

Same as above but without optimisations. Faster compilation, larger output.

---

## Type Checking

### Full workspace check (faster than building)

```bash
cargo check --workspace
```

Type-checks all crates without producing binaries. Catches compilation errors without the full build cost.

### WASM target check

```bash
cargo check -p hardener-ui --target wasm32-unknown-unknown
```

Verifies the WASM frontend compiles against the `wasm32` target. Useful for catching platform-specific issues (the UI crate cannot depend on system libraries).

---

## Code Quality

### Linting

```bash
cargo clippy --workspace                     # Warnings allowed (dev use)
cargo clippy --workspace -- -D warnings      # Warnings are errors (CI mode)
```

Both check all crates. The CI variant (`-D warnings`) fails on any lint warning.

### Formatting

```bash
cargo fmt                                    # Format all source files in-place
cargo fmt --all -- --check                   # Check formatting without modifying (CI mode)
```

The `--check` variant exits non-zero if any file would be reformatted. Run `cargo fmt` to fix.

### Security audit

```bash
cargo audit
```

Scans `Cargo.lock` for known security advisories in dependencies. Uses `.cargo/audit.toml` for configuration (e.g. ignored advisories).

### Documentation generation

```bash
cargo doc                                    # Generate rustdoc for all crates
cargo doc --open                             # Generate and open in browser
```

---

## Rustup Targets

Required for cross-compilation and WASM builds.

```bash
rustup target add wasm32-unknown-unknown     # Required for GUI (Leptos/Trunk)
rustup target add x86_64-unknown-linux-musl  # Required for container test binaries
rustup target add aarch64-unknown-linux-gnu  # Required for ARM64 release builds
rustup target list --installed               # List currently installed targets
```

---

## Dependency Management

```bash
cargo update --workspace                     # Update all dependencies in Cargo.lock
```

**Last Updated**: 2026-08-01
