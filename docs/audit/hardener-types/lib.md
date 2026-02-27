# hardener-types::lib
**File:** `crates/hardener-types/src/lib.rs` | **Lines:** 520 (all production, no tests)

## Purpose
WASM-compatible shared DTOs — all types that cross the Tauri IPC boundary between native backend and Leptos frontend.

## Submodules
| Module | Lines | Description |
|--------|-------|-------------|
| `config_picker` | 20 | `ConfigSummary` — validated config file summary for UI display |
| `remote` | 54 | `RemoteHostProfile`, `HostsConfig`, `RemoteConnectionStatus`, `RemoteConnectionInfo` |
| `scheduler` | 51 | `SchedulerUiConfig`, `NotificationUiConfig`, `EmailUiConfig`, `WebhookUiConfig`, `TestNotificationResult` |

Note: `config_picker` and `remote` are re-exported via `pub use *`; `scheduler` is `pub mod` only.

## Dependencies
- Imports from: `serde` — Serialize/Deserialize, `chrono` — DateTime<Utc>, `std::fmt`
- Used by: every crate in the workspace (directly or via `hardener-common::types` re-exports)

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `PluginId` | newtype(String) | Unique plugin identifier with Display/From impls |
| `Severity` | enum (5) | Info, Low, Medium, High, Critical — ordered |
| `FindingCategory` | enum (8) | Audit, Auth, Crypto, FS, Kernel, MAC, Network, Services |
| `ComplianceFramework` | enum (7) | CIS, HIPAA, ISO27001, NIST, PCIDSS, STIG, GDPR |
| `ComplianceMapping` | struct | Maps a finding to a framework control |
| `ControlStatus` | enum (4) | Pass, Fail, NotApplicable (default), ManualReview |
| `FindingPolicyException` | struct | Policy override with approval metadata |
| `PluginMetadata` | struct | Plugin identity: id, name, version, category, description |
| `ScanResult` | struct | Scan output: plugin_id, success, findings, duration, error |
| `Finding` | struct (12 fields) | Single security finding with compliance mappings |
| `ApplyResult` | struct | Apply output: plugin_id, success, changes, checkpoint_id |
| `Change` | struct | Single system modification with type and status |
| `ChangeType` | enum (6) | ConfigFile, FirewallRule, KernelParam, Package, Permissions, Service |
| `ValidationReport` | struct | Config validation: issues + estimated changes |
| `ValidationIssue` | struct | Single validation problem with severity |
| `ComplianceReport` | struct | Full framework report: controls + summary |
| `ControlResult` | struct | Single control check result |
| `ComplianceSummary` | struct | Aggregate stats: passing, failing, score% |
| `FileRestoreAction` | enum (4) | Restored, Removed, PermissionsRestored, Skipped |
| `FileRestoreResult` | struct | Single file restore outcome (path, action, success, error) |
| `RollbackResult` | struct | Full rollback result (checkpoint_id, name, success, files) |

## Data Flow
```
Plugins produce: ScanResult (containing Vec<Finding>)
                 ApplyResult (containing Vec<Change>)
                 ValidationReport

Compliance maps: Finding → ComplianceMapping → ControlResult → ComplianceReport

IPC boundary:    All types serialize to JSON via serde for Tauri commands
```

## Design Notes
- Field names prefixed with parent type (e.g., `finding_severity`) to avoid JSON key collisions in IPC
- `Severity` derives `Ord` — Info < Low < Medium < High < Critical
- `ControlStatus` defaults to `NotApplicable` via `#[default]`
- `ComplianceSummary::from_controls` iterates 4x for clarity; not a hot path

## Flags
None — clean DTO crate.
