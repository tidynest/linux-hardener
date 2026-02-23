# hardener-common::error
**File:** `crates/hardener-common/src/error.rs` | **Lines:** 168 (78 prod, 90 test)

## Purpose
Defines `HardeningError`, the unified error enum for the entire workspace.

## Dependencies
- Imports from: `thiserror` — derive macro for `Display`/`Error`, `serde_json` — `#[from]` conversion, `std::io` — `#[from]` conversion, `anyhow` — manual `From` impl
- Used by: every crate in the workspace via `hardener_common::error::Result`

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `HardeningError` | enum | 14-variant error type covering all operations |
| `Result<T>` | type alias | `std::result::Result<T, HardeningError>` |

## Data Flow
External error → `From` impl → `HardeningError` variant → `Display` → user-facing message

## Variants (14)
| Variant | Payload | Auto-From |
|---------|---------|-----------|
| Config | String | — |
| Database | String | — |
| Dependency | String | — |
| Executor | String | anyhow::Error |
| Notification | String | — |
| PackageManager | String | — |
| Plugin | String | — |
| Privilege | String | — |
| Rollback | String | — |
| Serialisation | serde_json::Error | #[from] |
| State | String | — |
| System | std::io::Error | #[from] |
| UnsupportedDistro | String | — |
| Validation | String | — |

## Flags
- **LOSSY CONVERSION (line 70-74):** `From<anyhow::Error>` maps all anyhow errors to `Executor`. If a state or plugin error passes through anyhow, the semantic variant is lost. Consider adding context or using a more generic variant.
