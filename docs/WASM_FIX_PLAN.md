# WASM Compilation Fix Plan

> **Status**: ✅ COMPLETED (2025-12-05)
>
> This plan was successfully implemented. The GUI now compiles to `wasm32-unknown-unknown` and runs in Tauri.

## Problem Summary

The `hardener-ui` crate fails to compile to WASM (`wasm32-unknown-unknown`) due to transitive dependencies on system libraries:

```
error: the wasm*-unknown-unknown targets are not supported by default,
you may need to enable the "js" feature.

error: This wasm target is unsupported by mio. If using Tokio, disable
the net feature.
```

**Dependency chain causing issues:**
```
hardener-ui (WASM target)
├── hardener-core (has tokio, mio, openssh, nix)
├── hardener-common (has tempfile -> getrandom)
└── hardener-compliance
    ├── hardener-core
    └── krilla (PDF library - no WASM support)
```

---

## Research Findings

### 1. Leptos + Tauri Best Practices

- **Recommended pattern**: Separate shared types into a dedicated crate
- The Crux framework popularised this "shared types" crate pattern
- Community confirms this is the standard solution for Tauri/Leptos apps

### 2. Feature Flag Limitations

- **Critical**: Cargo cannot conditionally enable features based on target architecture
- Target-specific dependencies work, but feature activation does not
- `build.rs` workarounds run after dependency resolution (too late)

### 3. Krilla PDF Library

- No WASM support documented or implied
- Heavy dependencies unsuitable for browser
- PDF generation is fundamentally native-only for this use case

### 4. getrandom + tokio in WASM

- getrandom 0.3+ requires `wasm_js` feature AND rustflags
- tokio's `net` feature incompatible with WASM
- `tempfile` crate transitively pulls getrandom

### 5. Current Dependency Analysis

| Crate | WASM-Problematic Dependencies |
|-------|------------------------------|
| `hardener-common` | `tempfile` (pulls `getrandom`, `rustix`) |
| `hardener-core` | `openssh`, `nix`, `hostname` (behind `system` feature) |
| `hardener-compliance` | `krilla` (no WASM support) |

---

## Recommended Solution: Extract Types Crate

Create `hardener-types` with only `serde` + `chrono` dependencies.

### Why This Over Alternatives

| Option | Verdict | Reason |
|--------|---------|--------|
| Fix Feature Flags | Not viable | Cargo can't conditionally enable by target |
| **Extract Types Crate** | **Recommended** | Clean separation, follows patterns |
| Pure IPC (JSON only) | Not recommended | No compile-time type safety |
| Hybrid | Fallback | Still complex |

---

## Implementation Steps

### Step 1: Create `hardener-types` Crate

```
crates/hardener-types/
├── Cargo.toml
└── src/
    └── lib.rs
```

**`crates/hardener-types/Cargo.toml`**:
```toml
[package]
name = "hardener-types"
version.workspace = true
edition.workspace = true

[dependencies]
serde = { workspace = true }
chrono = { version = "0.4", features = ["serde"] }
```

### Step 2: Move Types to `hardener-types`

**From `hardener-common/src/types.rs`**:
- `PluginId`
- `Severity`
- `FindingCategory`
- `ComplianceFramework`
- `ComplianceMapping`
- `ControlStatus`
- `FindingPolicyException`

**From `hardener-core/src/plugin.rs`**:
- `PluginMetadata`
- `ScanResult`
- `Finding`
- `ApplyResult`
- `Change`
- `ChangeType`
- `ValidationReport`
- `ValidationIssue`

**From `hardener-compliance/src/report.rs`**:
- `ComplianceReport`
- `ControlResult`
- `ComplianceSummary`

### Step 3: Update Workspace `Cargo.toml`

```toml
[workspace]
members = [
    "crates/hardener-types",  # Add first
    # ... existing members
]

[workspace.dependencies]
hardener-types = { path = "crates/hardener-types" }
```

### Step 4: Update `hardener-common`

**`Cargo.toml`**:
```toml
[dependencies]
hardener-types = { workspace = true }
# Move tempfile to dev-dependencies
anyhow = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }

[dev-dependencies]
tempfile = { workspace = true }
serde_json = { workspace = true }
```

**`src/types.rs`** - Re-export for backwards compatibility:
```rust
pub use hardener_types::*;
```

### Step 5: Update `hardener-core`

**`Cargo.toml`**:
```toml
[dependencies]
hardener-types = { workspace = true }
# ... rest unchanged
```

### Step 6: Update `hardener-compliance`

**`Cargo.toml`**:
```toml
[dependencies]
hardener-types = { workspace = true }
hardener-common = { workspace = true }
hardener-core = { workspace = true, default-features = false }
clap = { version = "4.5", features = ["derive"] }
serde = { workspace = true }
serde_json = { workspace = true }
chrono = { version = "0.4", features = ["serde"] }

# PDF is native-only
krilla = { version = "0.5.0", optional = true }

[features]
default = ["pdf"]
pdf = ["krilla"]
```

**`src/output/mod.rs`**:
```rust
pub mod csv;
pub mod html;
pub mod json;
pub mod text;

#[cfg(feature = "pdf")]
pub mod pdf;

// ... existing trait and re-exports ...

#[cfg(feature = "pdf")]
pub use pdf::PdfFormatter;
```

### Step 7: Update `hardener-ui`

**`Cargo.toml`**:
```toml
[package]
name = "hardener-ui"
version = "0.1.0"
edition = "2021"  # Fix: was "2024"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
leptos = { version = "0.8.14", features = ["csr"] }
leptos_router = { version = "0.8.10" }
serde = { workspace = true }
serde_json = { workspace = true }
serde-wasm-bindgen = { workspace = true }

# Types only - WASM compatible
hardener-types = { workspace = true }

# Tauri bindings
wasm-bindgen = "0.2.105"
wasm-bindgen-futures = "0.4.55"
js-sys = "0.3.82"

tracing = { workspace = true }
```

**`src/types.rs`**:
```rust
//! Re-export types from hardener-types for UI use.
pub use hardener_types::*;

// UI-specific types
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct CheckpointInfo {
    pub checkpoint_id: String,
    pub checkpoint_name: String,
    pub checkpoint_created: String,
    pub checkpoint_user: String,
}
```

### Step 8: Create `.cargo/config.toml`

```toml
[target.wasm32-unknown-unknown]
rustflags = ["--cfg", "getrandom_backend=\"wasm_js\""]
```

---

## Verification Commands

```bash
# 1. Verify hardener-types compiles for WASM
cargo check -p hardener-types --target wasm32-unknown-unknown

# 2. Verify hardener-ui compiles for WASM
cargo check -p hardener-ui --target wasm32-unknown-unknown

# 3. Build WASM with trunk
cd crates/hardener-ui && trunk build

# 4. Verify native build still works
cargo build -p linux-hardener-desktop

# 5. Run all tests
cargo test --workspace
```

---

## Trade-offs

### Benefits
- Clean WASM compilation (zero system deps in types crate)
- Compile-time type safety between frontend and backend
- Follows Crux/Tauri community patterns
- Future-proof for web dashboard (v0.4.0)

### Costs
- ~2-3 hours refactoring work
- One additional crate in workspace
- Re-exports needed for backwards compatibility

---

## Files to Modify

1. `Cargo.toml` (workspace) - add hardener-types member and dependency
2. `crates/hardener-types/Cargo.toml` - new file
3. `crates/hardener-types/src/lib.rs` - new file with moved types
4. `crates/hardener-common/Cargo.toml` - add hardener-types, move tempfile
5. `crates/hardener-common/src/types.rs` - re-export from hardener-types
6. `crates/hardener-core/Cargo.toml` - add hardener-types
7. `crates/hardener-core/src/plugin.rs` - use types from hardener-types
8. `crates/hardener-compliance/Cargo.toml` - add pdf feature, hardener-types
9. `crates/hardener-compliance/src/output/mod.rs` - cfg-gate pdf module
10. `crates/hardener-compliance/src/report.rs` - use types from hardener-types
11. `crates/hardener-ui/Cargo.toml` - depend only on hardener-types
12. `crates/hardener-ui/src/types.rs` - simplify to re-export
13. `.cargo/config.toml` - new file for WASM rustflags

---

## References

- [Tauri Leptos Documentation](https://v2.tauri.app/start/frontend/leptos/)
- [Crux Shared Types Pattern](https://redbadger.github.io/crux/getting_started/core.html)
- [Cargo Features Reference](https://doc.rust-lang.org/cargo/reference/features.html)
- [getrandom WASM Support](https://docs.rs/getrandom)
- [Adding WASM Support to Rust Crates](https://rustwasm.github.io/docs/book/reference/add-wasm-support-to-crate.html)

**Last Updated**: 2025-12-06
