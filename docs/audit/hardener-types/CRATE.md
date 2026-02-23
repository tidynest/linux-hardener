# hardener-types — Crate Audit

**Crate:** `crates/hardener-types/` | **Files:** 1 | **Lines:** 467 (all production)

## Purpose
WASM-compatible shared type definitions. Contains all DTOs that cross the Tauri IPC boundary between the native Rust backend and the Leptos/WASM frontend. Minimal dependencies (serde, chrono, std) to ensure WASM compilation.

## Architecture
Single-file crate, organized into three sections:
1. **Plugin Types** (lines 13-234) — PluginId, Severity, FindingCategory, ComplianceFramework, ComplianceMapping, ControlStatus, FindingPolicyException
2. **Core Types** (lines 236-379) — PluginMetadata, ScanResult, Finding, ApplyResult, Change, ChangeType, ValidationReport, ValidationIssue
3. **Compliance Report Types** (lines 381-467) — ComplianceReport, ControlResult, ComplianceSummary

## Public Interface Summary
| Category | Count | Key Items |
|----------|-------|-----------|
| Enums | 6 | Severity (ordered), FindingCategory, ComplianceFramework, ControlStatus, ChangeType, (PluginId newtype) |
| Structs | 12 | Finding (12 fields), ScanResult, ApplyResult, ComplianceReport, etc. |
| Methods | 3 | ComplianceFramework::full_name/description, ComplianceSummary::from_controls |

## Aggregate Flags
None — cleanest crate in the workspace.

## Unwraps
Zero.

## Verdict
No changes needed. Well-documented, consistent naming, correct derive traits.
