# hardener-types — Crate Audit

**Crate:** `crates/hardener-types/` | **Files:** 4 | **Lines:** 645 (all production)

## Purpose
WASM-compatible shared type definitions. Contains all DTOs that cross the Tauri IPC boundary between the native Rust backend and the Leptos/WASM frontend. Minimal dependencies (serde, chrono, std) to ensure WASM compilation.

## Architecture
```
lib.rs (520 lines) ──┬── config_picker.rs (20 lines)  Config file picker UI types
                     ├── remote.rs (54 lines)          Remote SSH scanning types
                     └── scheduler.rs (51 lines)       Scheduler configuration UI types
```

**lib.rs sections:**
1. **Plugin Types** (lines 13-240) — PluginId, Severity, FindingCategory, ComplianceFramework, ComplianceMapping, ControlStatus, FindingPolicyException
2. **Core Types** (lines 242-391) — PluginMetadata, ScanResult, Finding, ApplyResult, Change, ChangeType, FileRestoreAction, FileRestoreResult, RollbackResult, ValidationReport, ValidationIssue
3. **Compliance Report Types** (lines 393-520) — ComplianceReport, ControlResult, ComplianceSummary

## Public Interface Summary
| Category | Count | Key Items |
|----------|-------|-----------|
| Enums | 8 | Severity (ordered), FindingCategory, ComplianceFramework, ControlStatus, ChangeType, FileRestoreAction, RemoteConnectionStatus, PluginId (newtype) |
| Structs | 21 | Finding (12 fields), ScanResult, ApplyResult, ComplianceReport, SchedulerUiConfig, RemoteHostProfile, ConfigSummary, etc. |
| Methods | 3 | ComplianceFramework::full_name/description, ComplianceSummary::from_controls |

## Aggregate Flags
None — cleanest crate in the workspace.

## Unwraps
Zero.

## Verdict
Clean DTO crate. Well-documented, consistent naming, correct derive traits. Three new submodules added for scheduler, remote, and config-picker UI types.
